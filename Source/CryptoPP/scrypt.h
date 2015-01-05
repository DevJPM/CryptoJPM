// scrypt.h written and placed in the public domain by Jean-Pierre Muench
#ifndef CRYPTOPP_SCRYPT_H
#define CRYPTOPP_SCRYPT_H

#include "pwdbased.h"
#include "sha.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

//! note: tCost = p, mCost = log_2(N) and r=8
class CRYPTOPP_NO_VTABLE scrypt_Base : public PasswordBasedKeyDerivationFunction
{
public:
	CRYPTOPP_CONSTANT(R = 8)
	CRYPTOPP_CONSTANT(Log2R = 3)
private:
	CRYPTOPP_COMPILE_ASSERT(R == (1 << Log2R));
public:
	size_t MaxDerivedKeyLength() const;
	word64 MaxMCost() const {return sizeof(size_t)*8-7-Log2R;} // needs 1024*N bytes, -> can address sizeof(size_t)*8 bytes at max but need those 1024 bytes
	word64 MaxTCost() const;
	size_t MaxMemoryUsage(word64 mCost) const;
	word64 GetMCostFromPeakNumberBytes(size_t PeakNumberBytes) const;
	void DeriveKey(byte *derived, size_t derivedLen, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, word64 tCost, word64 mCost) const
	{
		DeriveKey(derived,derivedLen,password,passwordLen,salt,saltLen,mCost,R,tCost);
	}
protected:
	virtual void DeriveKey(byte *derived, size_t derivedLen, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, word64 Log2N, word64 R, word64 P) const =0;
	virtual const HashTransformation& GetHash() const =0;
	void SMix(byte* Data,size_t Offset,word64 Log2N,word64 R)const;
	void BlockMix(byte* Out,const byte* In,word64 R)const;
	word64 Integerify(const byte* State,word64 R,word64 N)const;
	void OptimizedSalsa208Core(word32* InOut) const;
};

template<class HASH>
class scrypt : public scrypt_Base
{
public:
	void DeriveKey(byte *derived, size_t derivedLen, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, word64 Log2N, word64 R, word64 P) const;
	static std::string StaticAlgorithmName() {return std::string("scrypt-HMAC-") + T::StaticAlgorithmName();}
	std::string AlgorithmName() const {return std::string("scrypt-HMAC-") + m_hash.AlgorithmName();}
private:
	HASH m_InformationProvider;
	const HashTransformation& GetHash() const {return m_InformationProvider;}
};

typedef scrypt<SHA256> OriginalScrypt;

template<class HASH>
void scrypt<HASH>::DeriveKey(byte *derived, size_t derivedLen, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, word64 Log2N, word64 R, word64 P) const
{
	assert(Log2N!=0 && Log2N<=MaxMCost());
	assert(R!=0 && R <= (word32(0)-1));
	assert(P!=0 && P<=MaxTCost());
	ThrowIfInvalidDerivedKeylength(derivedLen);

	SecByteBlock ProcessingBuffer((P*R)<<7);
	PKCS5_PBKDF2_HMAC<HASH>().DeriveKey(ProcessingBuffer,ProcessingBuffer.size(),password,passwordLen,salt,saltLen,1);
	for(word64 i=0;i<P;++i)
		SMix(ProcessingBuffer,i*(R<<7),Log2N,R);
	PKCS5_PBKDF2_HMAC<HASH>().DeriveKey(derived,derivedLen,password,passwordLen,ProcessingBuffer,ProcessingBuffer.size(),1);
}

NAMESPACE_END

#endif