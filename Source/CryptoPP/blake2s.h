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
	CRYPTOPP_CONSTANT(MAX_DIGEST_SIZE = 32)
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
protected:
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
	CRYPTOPP_CONSTANT(MAX_DIGEST_SIZE = 32)
public:
	BLAKE2sMAC(unsigned int Digestsize,const byte* Key,unsigned int Keylength);

	unsigned int BlockSize() const {return BLOCKSIZE;}
	unsigned int DigestSize() const {return static_cast<unsigned int>(m_Digestsize);}
	std::string AlgorithmName() const {return "BLAKE2s-MAC-" + IntToString(m_Digestsize*8);}

	size_t MinKeyLength() const {return MIN_KEYLENGTH;}
	size_t MaxKeyLength() const {return (size_t)MAX_KEYLENGTH;}
	size_t DefaultKeyLength() const {return DEFAULT_KEYLENGTH;}
	size_t GetValidKeyLength(size_t n) const {return StaticGetValidKeyLength(n);}
	SimpleKeyingInterface::IV_Requirement IVRequirement() const {return (SimpleKeyingInterface::IV_Requirement)IV_REQUIREMENT;}
	unsigned int IVSize() const {return IV_LENGTH;}

	//! restart to apply
	void UncheckedSetKey(const byte* userkey,unsigned int len, const NameValuePairs &)
	{
		ThrowIfInvalidKeyLength(len);
		memset_z(m_Key,0,BLOCKSIZE);
		memcpy(m_Key,userkey,len);
		m_Keylen=len;
	}

	void Update(const byte *input, size_t length);
	void Restart();
	void TruncatedFinal(byte *digest, size_t digestSize);

	unsigned int OptimalBlockSize() const {return BlockSize();}
	unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word32>();}
protected:
	FixedSizeSecBlock<word32,8> m_h;
	FixedSizeSecBlock<word32,2> m_t;
	FixedSizeSecBlock<word32,2> m_f;
	FixedSizeSecBlock<byte,2*BLOCKSIZE> m_buf;
	FixedSizeSecBlock<byte,BLOCKSIZE> m_Key;
	byte m_Keylen;
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

class BLAKE2sp : public HashTransformation
{
	class BLAKE2sRoot : public BLAKE2s
	{
	public:
		BLAKE2sRoot(unsigned int DigestSize);
		void Restart();
	};
	class BLAKE2sLeaf : public BLAKE2s
	{
	public:
		BLAKE2sLeaf(unsigned int DigestSize,bool IsLastNode,word64 Offset);
		void Restart();
	private:
		bool m_IsLastNode;
		word64 m_Offset;
	};
public:
	CRYPTOPP_CONSTANT(BLOCKSIZE = 64)
	CRYPTOPP_CONSTANT(MAX_DIGEST_SIZE = 32)
	CRYPTOPP_CONSTANT(PARALLELISM_DEGREE = 8)
public:
	BLAKE2sp(unsigned int Digestsize);
	unsigned int DigestSize() const {return m_Digestsize;}

	unsigned int BlockSize() const {return BLOCKSIZE;}
	std::string AlgorithmName() const {return "BLAKE2sp-" + IntToString(m_Digestsize*8);}

	void Update(const byte *input, size_t length);
	void Restart();
	void TruncatedFinal(byte *digest, size_t digestSize);

	unsigned int OptimalBlockSize() const {return BlockSize();}
	unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word64>();}
private:
	FixedSizeSecBlock<byte,PARALLELISM_DEGREE*BLOCKSIZE> m_buf;
	BLAKE2sRoot m_Root;
	std::vector<BLAKE2sLeaf> m_Leaves;
	size_t m_buflen;
	byte m_Digestsize;
private:
	void ThreadUpdate(unsigned int ID,const byte* input, size_t length);
};

class BLAKE2spMAC :  public VariableKeyLength<32,1,32>, public MessageAuthenticationCode
{
	class BLAKE2sMACRoot : public BLAKE2s
	{
	public:
		BLAKE2sMACRoot(unsigned int DigestSize,unsigned int keylen);
		void Restart();
	private:
		byte m_Keylen;
	};
	class BLAKE2sMACLeaf : public BLAKE2sMAC
	{
	public:
		BLAKE2sMACLeaf(unsigned int DigestSize,const byte* Key,unsigned int keylen,bool IsLastNode,word32 Offset);
		void Restart();
	private:
		bool m_IsLastNode;
		word32 m_Offset;
	};
public:
	CRYPTOPP_CONSTANT(BLOCKSIZE = 64)
	CRYPTOPP_CONSTANT(MAX_DIGEST_SIZE = 32)
	CRYPTOPP_CONSTANT(PARALLELISM_DEGREE = 8)
public:
	BLAKE2spMAC(unsigned int Digestsize,const byte* Key,unsigned int Keylength);

	unsigned int BlockSize() const {return BLOCKSIZE;}
	unsigned int DigestSize() const {return static_cast<unsigned int>(m_Digestsize);}
	std::string AlgorithmName() const {return "BLAKE2sp-MAC-" + IntToString(m_Digestsize*8);}

	size_t MinKeyLength() const {return MIN_KEYLENGTH;}
	size_t MaxKeyLength() const {return (size_t)MAX_KEYLENGTH;}
	size_t DefaultKeyLength() const {return DEFAULT_KEYLENGTH;}
	size_t GetValidKeyLength(size_t n) const {return StaticGetValidKeyLength(n);}
	SimpleKeyingInterface::IV_Requirement IVRequirement() const {return (SimpleKeyingInterface::IV_Requirement)IV_REQUIREMENT;}
	unsigned int IVSize() const {return IV_LENGTH;}

	//! restart to apply
	void UncheckedSetKey(const byte* userkey,unsigned int len, const NameValuePairs & Pairs)
	{
		ThrowIfInvalidKeyLength(len);
		for(unsigned int i=0;i<PARALLELISM_DEGREE;++i)
			m_Leaves.at(i).SetKey(userkey,len,Pairs);
	}

	void Update(const byte *input, size_t length);
	void Restart();
	void TruncatedFinal(byte *digest, size_t digestSize);

	unsigned int OptimalBlockSize() const {return BlockSize();}
	unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word64>();}
private:
	FixedSizeSecBlock<byte,PARALLELISM_DEGREE*BLOCKSIZE> m_buf;
	BLAKE2sMACRoot m_Root;
	std::vector<BLAKE2sMACLeaf> m_Leaves;
	size_t m_buflen;
	byte m_Digestsize;
private:
	void ThreadUpdate(unsigned int ID,const byte* input, size_t length);
};

NAMESPACE_END
#endif