// pwdbased.h - written and placed in the public domain by Wei Dai
// modified by Jean-Pierre Muench to ensure compability with password-hashing-competition (PHC)
// all changes are placed in the public domain

#ifndef CRYPTOPP_PWDBASED_H
#define CRYPTOPP_PWDBASED_H

#include "cryptlib.h"
#include "hmac.h"
#include "hrtimer.h"
#include "integer.h"

NAMESPACE_BEGIN(CryptoPP)

//! abstract base class for password based key derivation function
class CRYPTOPP_NO_VTABLE PasswordBasedKeyDerivationFunction
{
public:
	virtual size_t MaxDerivedKeyLength() const =0;
	//! MaxMCost() returns 0 if no memory cost parameter is available
	virtual word64 MaxMCost() const =0;
	virtual word64 MaxTCost() const =0;
	//! returns the peak number of bytes allocated (by DeriveKey Function) when using specified mCost value
	//! 0 indicates that memory usage is negligible
	virtual size_t MaxMemoryUsage(word64 mCost) const =0;
	//! always returns mCost such that MaxMemoryUsage(mCost)<=PeakNumberBytes ,basically inverts MaxMemoryUsage(), default implementation is linear search
	virtual word64 GetMCostFromPeakNumberBytes(size_t PeakNumberBytes) const;
	//! measures / calculates the time needed for specified parameters
	//! TestDataSetSize: size of the test salt, TestDataSetSize/4 is password size
	virtual double MeasureTime(word64 mCost,word64 tCost,size_t TestDataSetSize=128) const;

	//! searches mCost parameter for given time and tCost, default is linear search
	//! MeasureTime(tCost,mCost)>=TimeInSeconds will always hold
	//! TestDataSetSize: size of the test salt, TestDataSetSize/4 is password size
	virtual word64 SearchMCost(word64 tCost,double TimeInSeconds,size_t TestDataSetSize=128) const;
	//! searches tCost parameter for given time and mCost, default is linear search
	//! MeasureTime(tCost,mCost)>=TimeInSeconds will always hold
	//! TestDataSetSize: size of the test salt, TestDataSetSize/4 is password size
	virtual word64 SearchTCost(word64 mCost,double TimeInSeconds,size_t TestDataSetSize=128) const;

	//! derive key from password
	/*! If timeInSeconds != 0, will iterate until time elapsed, as measured by ThreadUserTimer
		Returns actual iteration count, which is equal to iterations if timeInSeconds == 0, and not less than iterations otherwise. */
	virtual void DeriveKey(byte *derived, size_t derivedLen, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, word64 tCost, word64 mCost) const =0;
protected:
	virtual void ThrowIfInvalidDerivedKeylength(size_t derivedLen) const;
	virtual void ThrowIfInvalidTCost(size_t tCost)const;
	virtual void ThrowIfInvalidMCost(size_t mCost)const;
};

//! PBKDF1 from PKCS #5, T should be a HashTransformation class
template <class T>
class PKCS5_PBKDF1 : public PasswordBasedKeyDerivationFunction
{
public:
	size_t MaxDerivedKeyLength() const {return T::DIGESTSIZE;}
	word64 MaxMCost() const {return 0;}
	word64 MaxTCost() const {return word64(0)-1;}
	size_t MaxMemoryUsage(word64 mCost) const {return 0;}
	word64 GetMCostFromPeakNumberBytes(size_t PeakNumberBytes) const {throw(InvalidArgument("mCost is not supported for this function"));}
	word64 SearchMCost(word64 tCost,double TimeInSeconds,size_t TestDataSetSize=128) const {throw(InvalidArgument("mCost is not supported for this function"));}
	word64 SearchTCost(word64 mCost,double TimeInSeconds,size_t TestDataSetSize=128) const
	{
		SecByteBlock TestKey(TestDataSetSize/4),TestSalt(TestDataSetSize),TestPW(TestDataSetSize/4);
		memset_z(TestSalt,0x5C,TestDataSetSize); // stolen from HMAC
		memset_z(TestPW,0x36,TestDataSetSize/4); // stolen from HMAC
		return DeriveKey(TestKey,TestDataSetSize,TestPW,TestDataSetSize/4,TestSalt,TestDataSetSize,0,1,TimeInSeconds);
	}
	void DeriveKey(byte *derived, size_t derivedLen, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, word64 tCost, word64 mCost) const
	{DeriveKey(derived,derivedLen,password,passwordLen,salt,saltLen,tCost);}
	// PKCS #5 says PBKDF1 should only take 8-byte salts. This implementation allows salts of any length.
	unsigned int DeriveKey(byte *derived, size_t derivedLen, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, unsigned int iterations, double timeInSeconds=0) const;
};

//! PBKDF2 from PKCS #5, T should be a HashTransformation class
template <class T>
class PKCS5_PBKDF2_HMAC : public PasswordBasedKeyDerivationFunction
{
public:
	size_t MaxDerivedKeyLength() const 
	{
#if CRYPTOPP_BOOL_X64 == 1
		return 0xffffffffUI64 * T::DIGESTSIZE;
#else
		return 0xffffffffU;// should multiply by T::DIGESTSIZE, but gets overflow that way
#endif

	}
	word64 MaxMCost() const {return 0;}
	word64 MaxTCost() const {return word32(0)-1;}
	size_t MaxMemoryUsage(word64 mCost) const {return 0;}
	word64 GetMCostFromPeakNumberBytes(size_t PeakNumberBytes) const {throw(InvalidArgument("mCost is not supported for this function"));}
	word64 SearchMCost(word64 tCost,double TimeInSeconds,size_t TestDataSetSize=128) const {throw(InvalidArgument("mCost is not supported for this function"));}
	void DeriveKey(byte *derived, size_t derivedLen, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, word64 tCost, word64 mCost) const
	{ThrowIfInvalidTCost(tCost);(derived,derivedLen,password,passwordLen,salt,saltLen,tCost);}
	unsigned int DeriveKey(byte *derived, size_t derivedLen, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, unsigned int iterations, double timeInSeconds=0) const;
	word64 SearchTCost(word64 mCost,double TimeInSeconds,size_t TestDataSetSize=128) const
	{
		SecByteBlock TestKey(TestDataSetSize/4),TestSalt(TestDataSetSize),TestPW(TestDataSetSize/4);
		memset_z(TestSalt,0x5C,TestDataSetSize); // stolen from HMAC
		memset_z(TestPW,0x36,TestDataSetSize/4); // stolen from HMAC
		return DeriveKey(TestKey,TestDataSetSize/4,TestPW,TestDataSetSize/4,TestSalt,TestDataSetSize,1,TimeInSeconds);
	}
};

/*
class PBKDF2Params
{
public:
	SecByteBlock m_salt;
	unsigned int m_interationCount;
	ASNOptional<ASNUnsignedWrapper<word32> > m_keyLength;
};
*/

//! PBKDF from PKCS #12, appendix B, T should be a HashTransformation class
template <class T>
class PKCS12_PBKDF : public PasswordBasedKeyDerivationFunction
{
public:
	size_t MaxDerivedKeyLength() const {return size_t(0)-1;}
	word64 MaxMCost() const {return 0;}
	word64 MaxTCost() const {return word64(0)-1;}
	size_t MaxMemoryUsage(word64 mCost) const {return 0;}
	word64 GetMCostFromPeakNumberBytes(size_t PeakNumberBytes) const {throw(InvalidArgument("mCost is not supported for this function"));}
	word64 SearchMCost(word64 tCost,double TimeInSeconds,size_t TestDataSetSize=128) const {throw(InvalidArgument("mCost is not supported for this function"));}
	word64 SearchTCost(word64 mCost,double TimeInSeconds,size_t TestDataSetSize=128) const
	{
		SecByteBlock TestKey(TestDataSetSize/4),TestSalt(TestDataSetSize),TestPW(TestDataSetSize/4);
		memset_z(TestSalt,0x5C,TestDataSetSize); // stolen from HMAC
		memset_z(TestPW,0x36,TestDataSetSize/4); // stolen from HMAC
		return DeriveKey(TestKey,TestDataSetSize,0x5C,TestPW,TestDataSetSize/4,TestSalt,TestDataSetSize,0,1,TimeInSeconds);
	}
	void DeriveKey(byte *derived, size_t derivedLen, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, word64 tCost, word64 mCost) const
	{DeriveKey(derived,derivedLen,0,password,passwordLen,salt,saltLen,tCost);}
	unsigned int DeriveKey(byte *derived, size_t derivedLen, byte purpose, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, unsigned int iterations, double timeInSeconds) const;
};

template <class T>
unsigned int PKCS5_PBKDF1<T>::DeriveKey(byte *derived, size_t derivedLen, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, unsigned int iterations, double timeInSeconds) const
{
	assert(derivedLen <= MaxDerivedKeyLength());
	assert(iterations > 0 || timeInSeconds > 0);

	if (!iterations)
		iterations = 1;

	T hash;
	hash.Update(password, passwordLen);
	hash.Update(salt, saltLen);

	SecByteBlock buffer(hash.DigestSize());
	hash.Final(buffer);

	unsigned int i;
	ThreadUserTimer timer;

	if (timeInSeconds)
		timer.StartTimer();

	for (i=1; i<iterations || (timeInSeconds && (i%128!=0 || timer.ElapsedTimeAsDouble() < timeInSeconds)); i++)
		hash.CalculateDigest(buffer, buffer, buffer.size());

	memcpy(derived, buffer, derivedLen);
	return i;
}

template <class T>
unsigned int PKCS5_PBKDF2_HMAC<T>::DeriveKey(byte *derived, size_t derivedLen, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, unsigned int iterations, double timeInSeconds) const
{
	assert(derivedLen <= MaxDerivedKeyLength());
	assert(iterations > 0 || timeInSeconds > 0);

	if (!iterations)
		iterations = 1;

	HMAC<T> hmac(password, passwordLen);
	SecByteBlock buffer(hmac.DigestSize());
	ThreadUserTimer timer;

	unsigned int i=1;
	while (derivedLen > 0)
	{
		hmac.Update(salt, saltLen);
		unsigned int j;
		for (j=0; j<4; j++)
		{
			byte b = byte(i >> ((3-j)*8) & 0xFF);
			hmac.Update(&b, 1);
		}
		hmac.Final(buffer);

		size_t segmentLen = STDMIN(derivedLen, buffer.size());
		memcpy(derived, buffer, segmentLen);

		if (timeInSeconds)
		{
			timeInSeconds = timeInSeconds / ((derivedLen + buffer.size() - 1) / buffer.size());
			timer.StartTimer();
		}

		for (j=1; j<iterations || (timeInSeconds && (j%128!=0 || timer.ElapsedTimeAsDouble() < timeInSeconds)); j++)
		{
			hmac.CalculateDigest(buffer, buffer, buffer.size());
			xorbuf(derived, buffer, segmentLen);
		}

		if (timeInSeconds)
		{
			iterations = j;
			timeInSeconds = 0;
		}

		derived += segmentLen;
		derivedLen -= segmentLen;
		i++;
	}

	return iterations;
}

template <class T>
unsigned int PKCS12_PBKDF<T>::DeriveKey(byte *derived, size_t derivedLen, byte purpose, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, unsigned int iterations, double timeInSeconds) const
{
	assert(derivedLen <= MaxDerivedKeyLength());
	assert(iterations > 0 || timeInSeconds > 0);

	if (!iterations)
		iterations = 1;

	const size_t v = T::BLOCKSIZE;	// v is in bytes rather than bits as in PKCS #12
	const size_t DLen = v, SLen = RoundUpToMultipleOf(saltLen, v);
	const size_t PLen = RoundUpToMultipleOf(passwordLen, v), ILen = SLen + PLen;
	SecByteBlock buffer(DLen + SLen + PLen);
	byte *D = buffer, *S = buffer+DLen, *P = buffer+DLen+SLen, *I = S;

	memset(D, purpose, DLen);
	size_t i;
	for (i=0; i<SLen; i++)
		S[i] = salt[i % saltLen];
	for (i=0; i<PLen; i++)
		P[i] = password[i % passwordLen];


	T hash;
	SecByteBlock Ai(T::DIGESTSIZE), B(v);
	ThreadUserTimer timer;

	while (derivedLen > 0)
	{
		hash.CalculateDigest(Ai, buffer, buffer.size());

		if (timeInSeconds)
		{
			timeInSeconds = timeInSeconds / ((derivedLen + Ai.size() - 1) / Ai.size());
			timer.StartTimer();
		}

		for (i=1; i<iterations || (timeInSeconds && (i%128!=0 || timer.ElapsedTimeAsDouble() < timeInSeconds)); i++)
			hash.CalculateDigest(Ai, Ai, Ai.size());

		if (timeInSeconds)
		{
			iterations = (unsigned int)i;
			timeInSeconds = 0;
		}

		for (i=0; i<B.size(); i++)
			B[i] = Ai[i % Ai.size()];

		Integer B1(B, B.size());
		++B1;
		for (i=0; i<ILen; i+=v)
			(Integer(I+i, v) + B1).Encode(I+i, v);

		size_t segmentLen = STDMIN(derivedLen, Ai.size());
		memcpy(derived, Ai, segmentLen);
		derived += segmentLen;
		derivedLen -= segmentLen;
	}

	return iterations;
}

NAMESPACE_END

#endif
