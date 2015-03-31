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
			IncrementCounterByOne(m_Counter,static_cast<unsigned int>(m_Counter.size()));
			output+=GetCipher()->BlockSize();
			size-=GetCipher()->BlockSize();
		}
		else // size < BLOCKSIZE
		{
			SecByteBlock Buffer(GetCipher()->BlockSize());
			CipherInstance.m_p->ProcessBlock(m_Counter,Buffer);
			memcpy(output,Buffer,size);
			IncrementCounterByOne(m_Counter,static_cast<unsigned int>(m_Counter.size()));
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
			IncrementCounterByOne(m_Counter,static_cast<unsigned int>(m_Counter.size()));
		}
		else
		{
			SecByteBlock Buffer(GetCipher()->BlockSize());
			CipherInstance.m_p->ProcessBlock(m_Counter,Buffer);
			memcpy(NewKey+i,Buffer,NewKey.size()-i);
			IncrementCounterByOne(m_Counter,static_cast<unsigned int>(m_Counter.size()));
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
	IncrementCounterByOne(m_Counter,static_cast<unsigned int>(m_Counter.size()));

	m_ReseedTimer.StartTimer();
}

AutoSeededFortuna_Base::AutoSeededFortuna_Base(bool AllowSlowPoll,bool AllowMultithreading) :
#if CRYPTOPP_BOOL_CPP11_THREAD_SUPPORTED
	m_PollAtCalltime(!AllowMultithreading)
#else
	m_PollAtCalltime(true)
#endif
{
	Initialize();
	// compile and run-time check
	// put this in #if/#endif clause because some variables may otherwise be undefined
#if CRYPTOPP_BOOL_CPP11_THREAD_SUPPORTED
	if(m_PollAtCalltime)
	{

	}
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
	SYSTEM_RNG_DATA
};

#define ConvertToIntAndIncorporate(VALUE,ID) \
	Buffer=(word32)(VALUE);\
	IncorporateEntropyEx(reinterpret_cast<byte*>(&(Buffer)),sizeof(Buffer),ID)

void AutoSeededFortuna_Base::PollFast()
{
#ifdef CRYPTOPP_WIN32_AVAILABLE
	word32 Buffer;
	POINT BufferPoint;
	MEMORYSTATUS MemoryData;
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

	GetCaretPos(&BufferPoint);
	IncorporateEntropyEx((byte*)&BufferPoint,sizeof(POINT),BASIC_SYSTEM_DATA);
	GetCursorPos(&BufferPoint);
	IncorporateEntropyEx((byte*)&BufferPoint,sizeof(POINT),BASIC_SYSTEM_DATA);

	MemoryData.dwLength=sizeof(MEMORYSTATUS);
	GlobalMemoryStatus(&MemoryData);
	IncorporateEntropyEx((byte*)&MemoryData,sizeof(MEMORYSTATUS),BASIC_SYSTEM_DATA);

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
}

NAMESPACE_END
