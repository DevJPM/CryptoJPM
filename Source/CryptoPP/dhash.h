// dhash.h - written and placed in the public domain by 

#ifndef CRYPTOPP_DHASH_H
#define CRYPTOPP_DHASH_H

#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

template<class BASE>
class CRYPTOPP_DLL DoubledHash: public BASE
{
public:
	static const char * CRYPTOPP_API StaticAlgorithmName() { return BASE::StaticAlgorithmName(); }

	DoubledHash()
	{
		Restart();
	}

	void TruncatedFinal(byte *digest, size_t digestSize)
	{
		SecByteBlock firstDigest(digestSize);
		m_hash.TruncatedFinal(firstDigest,digestSize);
		m_hash.Restart();
		m_hash.Update(firstDigest, digestSize);
		m_hash.TruncatedFinal(digest, digestSize);
	}

	unsigned int DigestSize() const { return BASE::DIGESTSIZE; }
	void Update(const byte *input, size_t length) { m_hash.Update(input, length); }
	void Restart() 
	{
		m_hash.Restart();
		SecByteBlock Zeros;
		if(m_hash.Blocksize()!=0)
			Zeros.CleanNew(m_hash.BlockSize());
		else
			Zeros.CleanNew(2*m_hash.DigestSize());
		m_hash.Update(Zeros,Zeros.size());
	}

private:
	BASE m_hash;
};


NAMESPACE_END

#endif // CRYPTOPP_DHASH_H
