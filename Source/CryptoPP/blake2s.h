// blake2s.h - written and placed in the public domain by Jean-Pierre Muench
// Thanks go to Zooko Wilcox-O'Hearn for providing the idea of implementing BLAKE2 in Crypto++/JPM
// Thanks go to Samuel Neves for the optimized C-implementation

#ifndef CRYPTOPP_BLAKE2S_H
#define CRYPTOPP_BLAKE2S_H

#include "cryptlib.h"
#include "secblock.h"
#include "seckey.h"

NAMESPACE_BEGIN(CryptoPP)

//! optimized for 32-bit platforms
class BLAKE2s : public HashTransformation
{
public:
	CRYPTOPP_CONSTANT(BLOCKSIZE = 64)
public:
	BLAKE2s(unsigned int Digestsize);

	unsigned int BlockSize() const {return BLOCKSIZE;}
	unsigned int DigestSize() const {return static_cast<unsigned int>(m_Digestsize);}
	std::string AlgorithmName() const {return "BLAKE2s-" + IntToString(m_Digestsize*8);}

	void Update(const byte *input, size_t length);
	void Restart();
	void TruncatedFinal(byte *digest, size_t digestSize);

	unsigned int OptimalBlockSize() const {return BlockSize();}
	unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word32>();}
private:
	FixedSizeSecBlock<word32,8> m_h;
	FixedSizeSecBlock<word32,2> m_t;
	FixedSizeSecBlock<word32,2> m_f;
	FixedSizeSecBlock<byte,2*BLOCKSIZE> m_buf;
	size_t   m_buflen;
	byte  m_last_node;
	byte m_Digestsize;
private:
	inline void IncrementCounter(word64 inc)
	{
		uint64_t t = ( ( uint64_t )m_t[1] << 32 ) | m_t[0];
		 t += inc;
		m_t[0] = ( uint32_t )( t >>  0 );
		m_t[1] = ( uint32_t )( t >> 32 );
	}
	inline void SetLastBlock()
	{
		if(m_last_node)
			m_f[1]=~0U;
		m_f[0]=~0U;
	}
	void Compress(const byte* Block);
};

//! optimized for 32-bit platforms
class BLAKE2sMAC : public VariableKeyLength<32,1,32>, public MessageAuthenticationCode
{
public:
	CRYPTOPP_CONSTANT(BLOCKSIZE = 64)
public:
	BLAKE2sMAC(unsigned int Digestsize,const byte* Key,unsigned int Keylength);

	unsigned int BlockSize() const {return BLOCKSIZE;}
	unsigned int DigestSize() const {return static_cast<unsigned int>(m_Digestsize);}
	std::string AlgorithmName() const {return "BLAKE2s-MAC-" + IntToString(m_Digestsize*8);}

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
	unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word32>();}
private:
	FixedSizeSecBlock<word32,8> m_h;
	FixedSizeSecBlock<word32,2> m_t;
	FixedSizeSecBlock<word32,2> m_f;
	FixedSizeSecBlock<byte,2*BLOCKSIZE> m_buf;
	FixedSizeSecBlock<byte,BLOCKSIZE> m_Key;
	size_t   m_buflen;
	byte  m_last_node;
	byte m_Digestsize;
private:
	inline void IncrementCounter(word64 inc)
	{
		uint64_t t = ( ( uint64_t )m_t[1] << 32 ) | m_t[0];
		 t += inc;
		m_t[0] = ( uint32_t )( t >>  0 );
		m_t[1] = ( uint32_t )( t >> 32 );
	}
	inline void SetLastBlock()
	{
		if(m_last_node)
			m_f[1]=~0U;
		m_f[0]=~0U;
	}
	void Compress(const byte* Block);
};

NAMESPACE_END
#endif