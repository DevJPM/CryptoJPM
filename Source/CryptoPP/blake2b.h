// blake2b.h - written and placed in the public domain by Jean-Pierre Muench
// Thanks go to Zooko Wilcox-O'Hearn for providing the idea of implementing BLAKE2 in Crypto++/JPM
// Thanks go to Samuel Neves for the optimized C-implementation

#ifndef CRYPTOPP_BLAKE2B_H
#define CRYPTOPP_BLAKE2B_H

#include "cryptlib.h"
#include "secblock.h"
#include "seckey.h"

NAMESPACE_BEGIN(CryptoPP)

//! optimized for 64-bit platforms
class BLAKE2b : public HashTransformation
{
public:
	CRYPTOPP_CONSTANT(BLOCKSIZE = 128)
public:
	BLAKE2b(unsigned int Digestsize);
	unsigned int DigestSize() const {return m_Digestsize;}

	unsigned int BlockSize() const {return BLOCKSIZE;}
	std::string AlgorithmName() const {return "BLAKE2b-" + IntToString(m_Digestsize*8);}

	void Update(const byte *input, size_t length);
	void Restart();
	void TruncatedFinal(byte *digest, size_t digestSize);

	unsigned int OptimalBlockSize() const {return BlockSize();}
	unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word64>();}
private:
	FixedSizeSecBlock<word64,8> m_h;
	FixedSizeSecBlock<word64,2> m_t;
	FixedSizeSecBlock<word64,2> m_f;
	FixedSizeSecBlock<byte,2*BLOCKSIZE> m_buf;
	size_t   m_buflen;
	byte  m_last_node;
	byte m_Digestsize;
private:
	inline void IncrementCounter(word64 inc)
	{
		m_t[0] += inc;
		m_t[1] += ( m_t[0] < inc );
	}
	inline void SetLastBlock()
	{
		if(m_last_node)
			m_f[1]=~0ULL;
		m_f[0]=~0ULL;
	}
	void Compress(const byte* Block);
};

class BLAKE2bMAC :  public VariableKeyLength<64,1,64>, public MessageAuthenticationCode
{
public:
	CRYPTOPP_CONSTANT(BLOCKSIZE = 128)
public:
	BLAKE2bMAC(unsigned int Digestsize,const byte* Key,unsigned int Keylength);

	unsigned int BlockSize() const {return BLOCKSIZE;}
	unsigned int DigestSize() const {return static_cast<unsigned int>(m_Digestsize);}
	std::string AlgorithmName() const {return "BLAKE2b-MAC-" + IntToString(m_Digestsize*8);}

	//! restart to apply
	void UncheckedSetKey(const byte* userkey,unsigned int len)
	{
		ThrowIfInvalidKeyLength(len);
		memset_z(m_Key,0,BLOCKSIZE);
		memcpy(m_Key,userkey,len);
	}

	void Update(const byte *input, size_t length);
	void Restart();
	void TruncatedFinal(byte *digest, size_t digestSize);

	unsigned int OptimalBlockSize() const {return BlockSize();}
	unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word64>();}
private:
	FixedSizeSecBlock<word64,8> m_h;
	FixedSizeSecBlock<word64,2> m_t;
	FixedSizeSecBlock<word64,2> m_f;
	FixedSizeSecBlock<byte,2*BLOCKSIZE> m_buf;
	FixedSizeSecBlock<byte,BLOCKSIZE> m_Key;
	size_t   m_buflen;
	byte  m_last_node;
	byte m_Digestsize;
private:
	inline void IncrementCounter(word64 inc)
	{
		m_t[0] += inc;
		m_t[1] += ( m_t[0] < inc );
	}
	inline void SetLastBlock()
	{
		if(m_last_node)
			m_f[1]=~0ULL;
		m_f[0]=~0ULL;
	}
	void Compress(const byte* Block);
};



NAMESPACE_END

#endif