// Fortuna.cpp - written and placed in the public domain by Jean-Pierre Muench

#include "pch.h"
#include "Fortuna.h"

// compile-time switch:
// OPTION1: give random data to one pool after each other
// OPTION2: give random data to the pool with the index i = MD5(Data)%NUM_POOLS
#define USE_RANDOMIZED_POOLING
#define RANDOM_POOLING_HASH SHA256

NAMESPACE_BEGIN(CryptoPP)

Fortuna_Base::Fortuna_Base() :
m_Key(GetCipher()->MaxKeyLength()),
m_Counter(GetCipher()->BlockSize()),
m_ReseedCounter(0),
m_PoolIndex(0),
m_ReseedTimer(TimerBase::MILLISECONDS)
{
	m_ReseedTimer.StartTimer();
	for(byte i=0;i<NUM_POOLS;++i)
		GetPoolHash(i).Restart();
	GetReseedHash().Restart();
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
		Input+=length;
		length-=length;
	}
}

void Fortuna_Base::IncorporateEntropySmall(const byte* Input,byte length,byte SourceNumber)
{
	if(!Input)
		throw(InvalidArgument("NULL event was passed"));
	if(!length || length>MAX_EVENT_SIZE)
		throw(InvalidArgument("Event length was invalid"));

	GetPoolHash(m_PoolIndex).Update(&SourceNumber,sizeof(SourceNumber));
	GetPoolHash(m_PoolIndex).Update(&length,sizeof(length));
	GetPoolHash(m_PoolIndex).Update(Input,length);

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
	if((1ui64<<(GetCipher()->BlockSize())*GetCipher()->BlockSize())<(1ui64<<(GetCipher()->BlockSize()))) // triggers for ~63 bit
		return size_t(0)-1;
	return 1ui64<<(GetCipher()->BlockSize())*GetCipher()->BlockSize(); // triggers most of the time
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
			output += size;
			size -= size;
		}
	}
}

void Fortuna_Base::GenerateSmallBlock(byte* output,size_t size)
{
	if(size > MaxGenerateSize())
		throw(InvalidArgument("requested too much random data at once!"));
	// reseed if neccessary
	if(m_PoolProcessedData[0]>=MIN_POOL_SIZE && (m_ReseedTimer.ElapsedTime()>=NUMBER_MILLISECONDS_BETWEEN_RESEEDS)) // check timing
	{
		m_ReseedCounter++;

		// harvest some hashes...
		SecByteBlock HarvestedData;

		for(byte i=0;i<NUM_POOLS;++i)
		{
			if(m_ReseedCounter%(1ui64<<i)==0)
			{
				HarvestedData.Grow(HarvestedData.size()+GetPoolHash(0).DigestSize());
				GetPoolHash(i).Final(&HarvestedData[HarvestedData.size()-GetPoolHash(0).DigestSize()]);
				GetPoolHash(i).Restart();
			}
		}

		Reseed(HarvestedData,HarvestedData.size());
	}

	// some entropy need to be available
	if(m_ReseedCounter==0)
		throw(InvalidState(AlgorithmName()));
	// output data here
	bool CounterIsAllZero=true;
	for(size_t i=0;i<m_Counter.size();++i)
		if(m_Counter[i]!=0)
			CounterIsAllZero=false;
	if(CounterIsAllZero)
		throw(InvalidState(AlgorithmName()));

	while(size>0)
	{
		if(size>=GetCipher()->BlockSize())
		{
			GetCipher()->ProcessBlock(m_Counter,output);
			IncrementCounterByOne(m_Counter,static_cast<unsigned int>(m_Counter.size()));
			output+=GetCipher()->BlockSize();
			size-=GetCipher()->BlockSize();
		}
		else // size < BLOCKSIZE
		{
			SecByteBlock Buffer(GetCipher()->BlockSize());
			GetCipher()->ProcessBlock(m_Counter,Buffer);
			memcpy(output,Buffer,size);
			IncrementCounterByOne(m_Counter,static_cast<unsigned int>(m_Counter.size()));
			output+=size;
			size-=size;
		}
	}

	//rekey
	SecByteBlock NewKey(GetCipher()->MaxKeyLength());
	for(size_t i=0;i<NewKey.size();i+=GetCipher()->BlockSize())
	{
		if((NewKey.size()-i)>=GetCipher()->BlockSize())
		{
			GetCipher()->ProcessBlock(m_Counter,NewKey);
			IncrementCounterByOne(m_Counter,static_cast<unsigned int>(m_Counter.size()));
		}
		else
		{
			SecByteBlock Buffer(GetCipher()->BlockSize());
			GetCipher()->ProcessBlock(m_Counter,Buffer);
			memcpy(NewKey,Buffer,NewKey.size()-i);
			IncrementCounterByOne(m_Counter,static_cast<unsigned int>(m_Counter.size()));
		}
	}
	memcpy(m_Key,NewKey,GetCipher()->MaxKeyLength());
}

void Fortuna_Base::Reseed(const byte* NewSeed,size_t seedlen)
{
	if(!NewSeed && seedlen)
		throw(InvalidArgument("invalid NULL pointer was passed"));

	GetReseedHash().Restart();
	GetReseedHash().Update(m_Key,m_Key.size());
	GetReseedHash().Update(NewSeed,seedlen);
	GetReseedHash().TruncatedFinal(m_Key,m_Key.size());
	IncrementCounterByOne(m_Counter,static_cast<unsigned int>(m_Counter.size()));

	m_ReseedTimer.StartTimer();
}

NAMESPACE_END