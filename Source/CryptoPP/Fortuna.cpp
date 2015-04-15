// Fortuna.cpp - written and placed in the public domain by Jean-Pierre Muench

#include "pch.h"
#include "Fortuna.h"
#include "osrng.h"

#ifdef CRYPTOPP_WIN32_AVAILABLE
#include <Windows.h>
#endif
// compile-time switch:
// OPTION1: give random data to one pool after each other
// OPTION2: give random data to the pool with the index i = SHA256(Data)%NUM_POOLS
// #define USE_RANDOMIZED_POOLING
// #define RANDOM_POOLING_HASH SHA256

NAMESPACE_BEGIN(CryptoPP)

Fortuna_Base::Fortuna_Base() :
m_Key(0),
m_Counter(0),
m_ReseedCounter(0),
m_PoolIndex(0),
m_ReseedTimer(TimerBase::MILLISECONDS)
{
}

void Fortuna_Base::Initialize()
{
	m_Key.resize(GetCipher()->MaxKeyLength()),
	m_Counter.resize(GetCipher()->BlockSize()),
	memset(m_Key,0,m_Key.SizeInBytes());
	memset(m_Counter,0,m_Counter.SizeInBytes());
	m_ReseedTimer.StartTimer();
	for(byte i=0;i<NUM_POOLS;++i)
		GetPoolHash(i)->Restart();


}

void Fortuna_Base::IncorporateEntropyEx(const byte* Input,size_t length,byte SourceNumber)
{
	while(length>=MAX_EVENT_SIZE)
	{
		IncorporateEntropySmall(Input,static_cast<byte>(MAX_EVENT_SIZE),SourceNumber);
		Input+=MAX_EVENT_SIZE;
		length-=MAX_EVENT_SIZE;
	}
	if(length)
	{
		IncorporateEntropySmall(Input,static_cast<byte>(length),SourceNumber);
	}
}

void Fortuna_Base::IncorporateEntropySmall(const byte* Input,byte length,byte SourceNumber)
{
	if(!Input)
		throw(InvalidArgument("NULL event was passed"));
	if(!length || length>MAX_EVENT_SIZE)
		throw(InvalidArgument("Event length was invalid"));

#if CRYPTOPP_BOOL_CPP11_THREAD_SUPPORTED
	std::lock_guard<std::recursive_mutex> Guard(m_PoolMutex[m_PoolIndex]);
#endif

	GetPoolHash(m_PoolIndex)->Update(&SourceNumber,sizeof(SourceNumber));
	GetPoolHash(m_PoolIndex)->Update(&length,sizeof(length));
	GetPoolHash(m_PoolIndex)->Update(Input,length);
	m_PoolProcessedData[m_PoolIndex]+=length+sizeof(length)+sizeof(SourceNumber);

#if defined(USE_RANDOMIZED_POOLING)
	RANDOM_POOLING_HASH().CalculateTruncatedDigest(&m_PoolIndex,sizeof(m_PoolIndex),Input,length);
	m_PoolIndex%=NUM_POOLS;
#else
	m_PoolIndex++;
	m_PoolIndex%=NUM_POOLS;
#endif
}

size_t Fortuna_Base::MaxGenerateSize() const
{
	if(GetCipher()->BlockSize()>=sizeof(size_t)) // triggers for BLOCKSIZE >= 64 (x64)
		return size_t(0)-1;
	// check for overflow
	if((1ull<<(GetCipher()->BlockSize())*GetCipher()->BlockSize())<(1ull<<(GetCipher()->BlockSize()))) // triggers for ~63 bit
		return size_t(0)-1;
	return 1ull<<(GetCipher()->BlockSize())*GetCipher()->BlockSize(); // triggers most of the time
}

void Fortuna_Base::GenerateBlock(byte* output,size_t size)
{
	if(!output && size)
		throw(InvalidArgument("invalid NULL pointer was passed"));

	const size_t MaxSize = MaxGenerateSize(); // should be faster
	while(size > 0)
	{
		if(size >= MaxSize)
		{
			GenerateSmallBlock(output,MaxSize);
			output += MaxSize;
			size -= MaxSize;
		}
		else // size < MaxGenerateSize
		{
			GenerateSmallBlock(output,size);
			size=0;
		}
	}
}

void Fortuna_Base::GenerateSmallBlock(byte* output,size_t size)
{
	if(size > MaxGenerateSize())
		throw(InvalidArgument("requested too much random data at once!"));
	// reseed if neccessary
#if CRYPTOPP_BOOL_CPP11_THREAD_SUPPORTED
	{
	std::lock_guard<std::recursive_mutex> GuardReseed(m_ReseedCounterMutex);
#endif
	if(m_PoolProcessedData[0]>=MIN_POOL_SIZE
		&& (m_ReseedCounter==0 || m_ReseedTimer.ElapsedTime()>=NUMBER_MILLISECONDS_BETWEEN_RESEEDS)) // check timing
	{
		m_ReseedCounter++;

		// harvest some hashes...
		SecByteBlock HarvestedData;

		for(byte i=0;i<NUM_POOLS;++i)
		{
			if(m_ReseedCounter%(1ull<<i)==0)
			{
				HarvestedData.Grow(HarvestedData.size()+GetPoolHash(i)->DigestSize());
#if CRYPTOPP_BOOL_CPP11_THREAD_SUPPORTED
				std::lock_guard<std::recursive_mutex> Guard(m_PoolMutex[i]);
#endif
				GetPoolHash(i)->Final(&HarvestedData[HarvestedData.size()-GetPoolHash(i)->DigestSize()]);
				GetPoolHash(i)->Restart();
			}
			else
			{
				// if m_ReseedCounter%(1ull<i)!=0 then m_ReseedCounter%(1ull<j)!=0 for any j: j>i
				break;
			}
		}

		Reseed(HarvestedData,HarvestedData.size());
	}
	else
		if(m_ReseedCounter==0)
			throw(InvalidState(AlgorithmName()));
	// some entropy need to be available
#if CRYPTOPP_BOOL_CPP11_THREAD_SUPPORTED
	} // reseed mtx
#endif
#if CRYPTOPP_BOOL_CPP11_THREAD_SUPPORTED
	std::lock_guard<std::recursive_mutex> Guard(m_GeneratorMutex);
#endif

	// output data here
	bool CounterIsAllZero=true;
	for(size_t i=0;i<m_Counter.size();++i)
	{
		if(m_Counter[i]!=0)
		{
			CounterIsAllZero=false;
			break;
		}
	}
	if(CounterIsAllZero)
		throw(InvalidState(AlgorithmName()));

	simple_ptr<BlockCipher> CipherInstance(GetNewCipher());
	CipherInstance.m_p->SetKey(m_Key,m_Key.SizeInBytes());

	while(size>0)
	{
		if(size>=GetCipher()->BlockSize())
		{
			CipherInstance.m_p->ProcessBlock(m_Counter,output);
			IncrementCounterByOneLE(m_Counter,static_cast<unsigned int>(m_Counter.size()));
			output+=GetCipher()->BlockSize();
			size-=GetCipher()->BlockSize();
		}
		else // size < BLOCKSIZE
		{
			SecByteBlock Buffer(GetCipher()->BlockSize());
			CipherInstance.m_p->ProcessBlock(m_Counter,Buffer);
			memcpy(output,Buffer,size);
			IncrementCounterByOneLE(m_Counter,static_cast<unsigned int>(m_Counter.size()));
			size=0;
		}
	}

	//rekey
	SecByteBlock NewKey(GetCipher()->MaxKeyLength());
	for(size_t i=0;i<NewKey.size();i+=GetCipher()->BlockSize())
	{
		if((NewKey.size()-i)>=GetCipher()->BlockSize())
		{
			CipherInstance.m_p->ProcessBlock(m_Counter,NewKey+i);
			IncrementCounterByOneLE(m_Counter,static_cast<unsigned int>(m_Counter.size()));
		}
		else
		{
			SecByteBlock Buffer(GetCipher()->BlockSize());
			CipherInstance.m_p->ProcessBlock(m_Counter,Buffer);
			memcpy(NewKey+i,Buffer,NewKey.size()-i);
			IncrementCounterByOneLE(m_Counter,static_cast<unsigned int>(m_Counter.size()));
		}
	}
	memcpy(m_Key,NewKey,m_Key.SizeInBytes());
}

void Fortuna_Base::Reseed(const byte* NewSeed,size_t seedlen)
{
	if(!NewSeed && seedlen)
		throw(InvalidArgument("invalid NULL pointer was passed"));

	simple_ptr<HashTransformation> Reseeder(GetNewReseedHash());

#if CRYPTOPP_BOOL_CPP11_THREAD_SUPPORTED
	std::lock_guard<std::recursive_mutex> Guard(m_GeneratorMutex);
#endif

	Reseeder.m_p->Restart();
	Reseeder.m_p->Update(m_Key,m_Key.size());
	Reseeder.m_p->Update(NewSeed,seedlen);
	Reseeder.m_p->TruncatedFinal(m_Key,m_Key.size());
	IncrementCounterByOneLE(m_Counter,static_cast<unsigned int>(m_Counter.size()));

	m_ReseedTimer.StartTimer();
}

AutoSeededFortuna_Base::AutoSeededFortuna_Base(bool AllowSlowPoll,bool AllowMultithreading) :
#if CRYPTOPP_BOOL_CPP11_THREAD_SUPPORTED
	m_PollAtCalltime(!AllowMultithreading),
	m_AllowSlowPoll(AllowMultithreading && AllowSlowPoll),
	m_RunThreads(true)
#else
	m_PollAtCalltime(true),
	m_AllowSlowPoll(false)
#endif
{
	Initialize();
	// compile and run-time check
	// put this in #if/#endif clause because some variables may otherwise be undefined
#if CRYPTOPP_BOOL_CPP11_THREAD_SUPPORTED
	if(!m_PollAtCalltime)
	{
		// launch threads here
		m_FastPollThread=std::thread(&AutoSeededFortuna_Base::FastPollThreadFunction,this);

		if(m_AllowSlowPoll)
			m_SlowPollThread=std::thread(&AutoSeededFortuna_Base::SlowPollThreadFunction,this);
	}
#endif
}

AutoSeededFortuna_Base::~AutoSeededFortuna_Base()
{
#if CRYPTOPP_BOOL_CPP11_THREAD_SUPPORTED
	m_RunThreads=false;
#endif
}

void AutoSeededFortuna_Base::GenerateSmallBlock(byte* output,size_t size)
{
	if(m_PollAtCalltime)
		PollFast();
	Fortuna_Base::GenerateSmallBlock(output,size);
}

void AutoSeededFortuna_Base::ReadSeedFile(const byte* input,size_t length)
{
	Fortuna_Base::ReadSeedFile(input,length);
//	GenerateMachineSignature();
}

enum StaticSourceIDs
{
	BASIC_SYSTEM_DATA,
	SYSTEM_TIMING_DATA,
	SYSTEM_RNG_DATA,
	DRIVE_TIMING_DATA,
	NETWORK_SERVICE_DATA,
	KEYBOARD_DATA,
	MOUSE_DATA
};

#define ConvertToIntAndIncorporate(VALUE,ID) \
	Buffer=(word32)(VALUE);\
	IncorporateEntropyEx(reinterpret_cast<byte*>(&(Buffer)),sizeof(Buffer),ID)

void AutoSeededFortuna_Base::PollFast()
{
#ifdef CRYPTOPP_WIN32_AVAILABLE
	word32 Buffer;
	POINT BufferPoint;
	MEMORYSTATUSEX MemoryData;
	ConvertToIntAndIncorporate(GetActiveWindow(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetCapture(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetClipboardOwner(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetClipboardViewer(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetCurrentProcess(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetCurrentProcessId(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetCurrentThread(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetCurrentThreadId(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetCurrentTime(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetDesktopWindow(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetFocus(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetInputState(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetMessagePos(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetMessageTime(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetOpenClipboardWindow(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetProcessHeap(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetProcessWindowStation(),BASIC_SYSTEM_DATA);
	ConvertToIntAndIncorporate(GetQueueStatus(QS_ALLEVENTS),BASIC_SYSTEM_DATA);

	OSVERSIONINFOEX OSVersion;
	OSVersion.dwOSVersionInfoSize=sizeof(OSVERSIONINFOEX);
	GetVersionEx((LPOSVERSIONINFO)(&OSVersion));
	IncorporateEntropyEx((byte*)&OSVersion,sizeof(OSVersion),BASIC_SYSTEM_DATA);

	GetCaretPos(&BufferPoint);
	IncorporateEntropyEx((byte*)&BufferPoint,sizeof(POINT),BASIC_SYSTEM_DATA);
	GetCursorPos(&BufferPoint);
	IncorporateEntropyEx((byte*)&BufferPoint,sizeof(POINT),BASIC_SYSTEM_DATA);

	MemoryData.dwLength=sizeof(MEMORYSTATUSEX);
	GlobalMemoryStatusEx(&MemoryData);
	IncorporateEntropyEx((byte*)&MemoryData,sizeof(MEMORYSTATUSEX),BASIC_SYSTEM_DATA);

	FILETIME TimeBufferA,TimeBufferB,TimeBufferC,TimeBufferD;
	HANDLE HandleBuffer = GetCurrentThread();
	GetThreadTimes(HandleBuffer,&TimeBufferA,&TimeBufferB,&TimeBufferC,&TimeBufferD);
	IncorporateEntropyEx((byte*)&TimeBufferA,sizeof(FILETIME),SYSTEM_TIMING_DATA);
	IncorporateEntropyEx((byte*)&TimeBufferB,sizeof(FILETIME),SYSTEM_TIMING_DATA);
	IncorporateEntropyEx((byte*)&TimeBufferC,sizeof(FILETIME),SYSTEM_TIMING_DATA);
	IncorporateEntropyEx((byte*)&TimeBufferD,sizeof(FILETIME),SYSTEM_TIMING_DATA);
	HandleBuffer = GetCurrentProcess();
	GetProcessTimes(HandleBuffer,&TimeBufferA,&TimeBufferB,&TimeBufferC,&TimeBufferD);
	IncorporateEntropyEx((byte*)&TimeBufferA,sizeof(FILETIME),SYSTEM_TIMING_DATA);
	IncorporateEntropyEx((byte*)&TimeBufferB,sizeof(FILETIME),SYSTEM_TIMING_DATA);
	IncorporateEntropyEx((byte*)&TimeBufferC,sizeof(FILETIME),SYSTEM_TIMING_DATA);
	IncorporateEntropyEx((byte*)&TimeBufferD,sizeof(FILETIME),SYSTEM_TIMING_DATA);

	// some times at the end...
	LARGE_INTEGER PC;
	if(QueryPerformanceCounter(&PC))
		IncorporateEntropyEx((byte*)&PC,sizeof(LARGE_INTEGER),BASIC_SYSTEM_DATA);
	else
		ConvertToIntAndIncorporate(GetTickCount64(),BASIC_SYSTEM_DATA);
#endif
	SecByteBlock DataBuffer(256);
	OS_GenerateRandomBlock(true,DataBuffer,256);
	IncorporateEntropyEx(DataBuffer,256,SYSTEM_RNG_DATA);

	GenerateRDSEEDData(DataBuffer,64);
	IncorporateEntropyEx(DataBuffer,64,SYSTEM_RNG_DATA);

	GenerateRDRANDData(DataBuffer,256);
	IncorporateEntropyEx(DataBuffer,256,SYSTEM_RNG_DATA);
}

#ifdef CRYPTOPP_WIN32_AVAILABLE
class NetAPI32Loader
{
public:
typedef DWORD (WINAPI * NETSTATISTICSGET) (LPWSTR szServer, LPWSTR szService,
				     DWORD dwLevel, DWORD dwOptions,
				     LPBYTE * lpBuffer);
typedef DWORD (WINAPI * NETAPIBUFFERSIZE) (LPVOID lpBuffer, LPDWORD cbBuffer);
typedef DWORD (WINAPI * NETAPIBUFFERFREE) (LPVOID lpBuffer);

	NetAPI32Loader():
		m_LibraryHandle(NULL),m_InitSuccessful(false),
		m_NetStatisticsGetFP(NULL),m_NetApiBufferSizeFP(NULL),m_NetApiBufferFreeFP(NULL)
	{
		m_LibraryHandle=LoadLibrary("NETAPI32.DLL");
		if(m_LibraryHandle==NULL)
			return;
		//load all functions
		m_NetStatisticsGetFP = (NETSTATISTICSGET) GetProcAddress(m_LibraryHandle,"NetStatisticsGet");
		m_NetApiBufferSizeFP = (NETAPIBUFFERSIZE) GetProcAddress(m_LibraryHandle,"NetApiBufferSize");
		m_NetApiBufferFreeFP = (NETAPIBUFFERFREE) GetProcAddress(m_LibraryHandle,"NetApiBufferFree");

		//free on error
		if(m_NetStatisticsGetFP==NULL || m_NetApiBufferSizeFP==NULL || m_NetApiBufferFreeFP==NULL)
		{
			FreeLibrary(m_LibraryHandle);
			m_LibraryHandle=NULL;
			m_NetStatisticsGetFP=NULL;
			m_NetApiBufferSizeFP=NULL;
			m_NetApiBufferFreeFP=NULL;
		}
		m_InitSuccessful=true;
	}
	~NetAPI32Loader()
	{
		m_InitSuccessful=false;
		if(m_LibraryHandle!=NULL)
		{
			FreeLibrary(m_LibraryHandle);
			m_LibraryHandle=NULL;
		}
		m_NetStatisticsGetFP=NULL;
		m_NetApiBufferSizeFP=NULL;
		m_NetApiBufferFreeFP=NULL;
	}
	bool IsAvailable() const {return m_InitSuccessful;}
	NETSTATISTICSGET GetNetStatisticsGetFP() const {return m_NetStatisticsGetFP;}
	NETAPIBUFFERSIZE GetNetApiBufferSizeFP() const {return m_NetApiBufferSizeFP;}
	NETAPIBUFFERFREE GetNetApiBufferFreeFP() const {return m_NetApiBufferFreeFP;}
private:
	HMODULE m_LibraryHandle;
	bool m_InitSuccessful;
	NETSTATISTICSGET m_NetStatisticsGetFP;
	NETAPIBUFFERSIZE m_NetApiBufferSizeFP;
	NETAPIBUFFERFREE m_NetApiBufferFreeFP;
};
#endif

void AutoSeededFortuna_Base::PollSlow()
{
#ifdef CRYPTOPP_WIN32_AVAILABLE
	if(ALLOW_NETWORK_STATS)
	{
		if(Singleton<NetAPI32Loader>().Ref().IsAvailable())
		{
			byte* DataBuffer;
			DWORD BufferSize;
			wchar_t* ServerService = L"LanmanServer"; // always available
			wchar_t* WorkstationService = L"LanmanWorkstation"; // always available
			if(Singleton<NetAPI32Loader>().Ref().GetNetStatisticsGetFP()(NULL,ServerService,0,0,&DataBuffer)==0)
			{
				Singleton<NetAPI32Loader>().Ref().GetNetApiBufferSizeFP()(DataBuffer,&BufferSize);
				IncorporateEntropyEx(DataBuffer,BufferSize,NETWORK_SERVICE_DATA);
				Singleton<NetAPI32Loader>().Ref().GetNetApiBufferFreeFP()(DataBuffer);
			}
			if(Singleton<NetAPI32Loader>().Ref().GetNetStatisticsGetFP()(NULL,WorkstationService,0,0,&DataBuffer)==0)
			{
				Singleton<NetAPI32Loader>().Ref().GetNetApiBufferSizeFP()(DataBuffer,&BufferSize);
				IncorporateEntropyEx(DataBuffer,BufferSize,NETWORK_SERVICE_DATA);
				Singleton<NetAPI32Loader>().Ref().GetNetApiBufferFreeFP()(DataBuffer);
			}
		}
	}

	if(ALLOW_DISK_QUERIES)
	{
		const std::string StandardAccess = "\\\\.\\PhysicalDrive";
		for(word32 DriveIndex;;++DriveIndex)
		{
			DISK_PERFORMANCE PerfData;
			DWORD ActualSize;
			HANDLE Device;

			std::string AccesName = StandardAccess + std::to_string(DriveIndex);
			Device=CreateFile(AccesName.c_str(),0,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
			if(Device==INVALID_HANDLE_VALUE)
				break;
			if(DeviceIoControl(Device,IOCTL_DISK_PERFORMANCE,NULL,0,&PerfData,sizeof(DISK_PERFORMANCE),&ActualSize,0))
			{
				IncorporateEntropyEx((byte*)&PerfData,ActualSize,DRIVE_TIMING_DATA);
			}
			CloseHandle(Device);
		}
	}
#endif
}

void AutoSeededFortuna_Base::PollMTFast()
{

}

void AutoSeededFortuna_Base::FastPollThreadFunction()
{
	while(m_RunThreads)
	{
		PollFast();
		PollMTFast();

		std::this_thread::sleep_for(std::chrono::milliseconds(NUMBER_MILLISECONDS_BETWEEN_FAST_POLLS));
	}
}

void AutoSeededFortuna_Base::SlowPollThreadFunction()
{
	while(m_RunThreads)
	{
		PollSlow();

		std::this_thread::sleep_for(std::chrono::milliseconds(NUMBER_MILLISECONDS_BETWEEN_SLOW_POLLS));
	}
}

#ifdef CRYPTOPP_WIN32_AVAILABLE

LRESULT CALLBACK HookFunctionMouse(int Code,WPARAM wParam,LPARAM lParam)
{
	if(Code!=0)
		CallNextHookEx(NULL,Code,wParam,lParam);

	MSLLHOOKSTRUCT* Data=(MSLLHOOKSTRUCT*)lParam;

	StandardAutoSeededFortunaSingleton().IncorporateEntropyEx((byte*)&wParam,sizeof(WPARAM),MOUSE_DATA);

	StandardAutoSeededFortunaSingleton().IncorporateEntropyEx((byte*)Data,sizeof(MSLLHOOKSTRUCT),MOUSE_DATA);

	return CallNextHookEx(NULL,Code,wParam,lParam);
}

LRESULT CALLBACK HookFunctionKeyboard(int Code,WPARAM wParam,LPARAM lParam)
{
	if(Code!=0) // only allowed code HC_ACTION (=0)
		CallNextHookEx(NULL,Code,wParam,lParam);

	KBDLLHOOKSTRUCT* Data=(KBDLLHOOKSTRUCT*)lParam;

	StandardAutoSeededFortunaSingleton().IncorporateEntropyEx((byte*)&wParam,sizeof(WPARAM),KEYBOARD_DATA);

	StandardAutoSeededFortunaSingleton().IncorporateEntropyEx((byte*)Data,sizeof(KBDLLHOOKSTRUCT),KEYBOARD_DATA);

	return CallNextHookEx(NULL,Code,wParam,lParam);
}

class Hooker
{
	Hooker()
	{
		if(AutoSeededFortuna_Base::ALLOW_KEYBOARD_MONITORING)
			m_Mouse = SetWindowsHookEx(WH_KEYBOARD_LL,HookFunctionMouse,GetModuleHandle(NULL),0);
		if(AutoSeededFortuna_Base::ALLOW_MOUSE_MONITORING)
			m_Keyboard = SetWindowsHookEx(WH_MOUSE_LL,HookFunctionKeyboard,GetModuleHandle(NULL),0);
	}
	~Hooker()
	{
		if(m_Mouse)
			UnhookWindowsHookEx(m_Mouse);
		if(m_Keyboard)
			UnhookWindowsHookEx(m_Keyboard);
	}
private:
	HHOOK m_Mouse;
	HHOOK m_Keyboard;
};

#endif

void InstallHooks()
{
#ifdef CRYPTOPP_WIN32_AVAILABLE
	Singleton<Hooker>().Ref();
#endif	
}

void UninstallHooks()
{
	
}

NAMESPACE_END
