// pwdbased.cpp - written and placed in the public domain by Jean-Pierre Muench

#include "pch.h"
#include "pwdbased.h"

NAMESPACE_BEGIN(CryptoPP)

void PasswordBasedKeyDerivationFunction::ThrowIfInvalidDerivedKeylength(size_t derivedLen) const
{
	if(derivedLen>MaxDerivedKeyLength())
		throw(InvalidArgument("derived key length's too large"));
}

void PasswordBasedKeyDerivationFunction::ThrowIfInvalidMCost(size_t mCost) const
{
	if(MaxMCost())
	{
		if(mCost > MaxMCost())
			throw(InvalidArgument("mCost parameter too large!"));
		if(mCost == 0)
			throw(InvalidArgument("mCost may not be zero!"));
	}
}

void PasswordBasedKeyDerivationFunction::ThrowIfInvalidTCost(size_t tCost) const
{
	if(tCost > MaxTCost())
		throw(InvalidArgument("tCost parameter too large!"));
	if(tCost == 0)
		throw(InvalidArgument("tCost may not be zero!"));
}

size_t PasswordBasedKeyDerivationFunction::GetMCostFromPeakNumberBytes(size_t PeakNumberBytes) const
{
	if(!MaxMCost())
		throw(InvalidArgument("mCost is not supported for this function"));
	size_t TestMCost = 1;
	while(MaxMemoryUsage(TestMCost)<=PeakNumberBytes)
	{
		if(TestMCost<=MaxMCost())
			TestMCost++; // check after increment and decrement at the end to get last valid result
		else
			break;
	}
		
	return TestMCost-1;
}

double PasswordBasedKeyDerivationFunction::MeasureTime(size_t mCost,size_t tCost,size_t TestDataSetSize) const
{
	ThrowIfInvalidMCost(mCost);
	ThrowIfInvalidTCost(tCost);

	SecByteBlock TestSalt(TestDataSetSize);
	SecByteBlock TestPassword(TestDataSetSize/4);
	SecByteBlock TestKey(TestDataSetSize/4);

	memset_z(TestSalt,0x5C,TestDataSetSize); // stolen from HMAC
	memset_z(TestPassword,0x36,TestDataSetSize/4); // stolen from HMAC

	ThreadUserTimer timer;
	timer.StartTimer();
	DeriveKey(TestKey,TestDataSetSize/4,TestPassword,TestDataSetSize/4,TestSalt,TestDataSetSize,tCost,mCost);
	return timer.ElapsedTimeAsDouble();
}

size_t PasswordBasedKeyDerivationFunction::SearchMCost(size_t tCost,double TimeInSeconds,size_t TestDataSetSize) const
{
	if(!MaxMCost())
		throw(InvalidArgument("this function does not support mCost!"));
	size_t ProbableMCost=1;
	while(MeasureTime(ProbableMCost,tCost,TestDataSetSize)<TimeInSeconds)
	{
		if(ProbableMCost<MaxMCost())
			ProbableMCost++;
		else
			throw(InvalidArgument("valid mCost could not be found"));
	}
	return ProbableMCost;
}

size_t PasswordBasedKeyDerivationFunction::SearchTCost(size_t mCost,double TimeInSeconds,size_t TestDataSetSize) const
{
	size_t ProbableTCost=1;
	while(MeasureTime(mCost,ProbableTCost,TestDataSetSize)<TimeInSeconds)
	{
		if(ProbableTCost<MaxTCost())
			ProbableTCost++;
		else
			throw(InvalidArgument("valid tCost could not be found"));
	}
	return ProbableTCost;
}

NAMESPACE_END