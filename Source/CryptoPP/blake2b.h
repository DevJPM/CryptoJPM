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
	CRYPTOPP_CONSTANT(MAX_DIGEST_SIZE = 64)
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
protected:
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
	CRYPTOPP_CONSTANT(MAX_DIGEST_SIZE = 64)
public:
	BLAKE2bMAC(unsigned int Digestsize,const byte* Key,unsigned int Keylength);

	unsigned int BlockSize() const {return BLOCKSIZE;}
	unsigned int DigestSize() const {return static_cast<unsigned int>(m_Digestsize);}
	std::string AlgorithmName() const {return "BLAKE2b-MAC-" + IntToString(m_Digestsize*8);}

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
	unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word64>();}
protected:
	FixedSizeSecBlock<word64,8> m_h;
	FixedSizeSecBlock<word64,2> m_t;
	FixedSizeSecBlock<word64,2> m_f;
	FixedSizeSecBlock<byte,2*BLOCKSIZE> m_buf;
	FixedSizeSecBlock<byte,BLOCKSIZE> m_Key;
	byte m_Keylen;
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

class BLAKE2bp : public HashTransformation
{
	class BLAKE2bRoot : public BLAKE2b
	{
	public:
		BLAKE2bRoot(unsigned int DigestSize);
		void Restart();
	};
	class BLAKE2bLeaf : public BLAKE2b
	{
	public:
		BLAKE2bLeaf(unsigned int DigestSize,bool IsLastNode,word64 Offset);
		void Restart();
	private:
		bool m_IsLastNode;
		word64 m_Offset;
	};
public:
	CRYPTOPP_CONSTANT(BLOCKSIZE = 128)
	CRYPTOPP_CONSTANT(MAX_DIGEST_SIZE = 64)
	CRYPTOPP_CONSTANT(PARALLELISM_DEGREE = 4)
public:
	BLAKE2bp(unsigned int Digestsize);
	unsigned int DigestSize() const {return m_Digestsize;}

	unsigned int BlockSize() const {return BLOCKSIZE;}
	std::string AlgorithmName() const {return "BLAKE2bp-" + IntToString(m_Digestsize*8);}

	void Update(const byte *input, size_t length);
	void Restart();
	void TruncatedFinal(byte *digest, size_t digestSize);

	unsigned int OptimalBlockSize() const {return BlockSize();}
	unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word64>();}
private:
	FixedSizeSecBlock<byte,PARALLELISM_DEGREE*BLOCKSIZE> m_buf;
	BLAKE2bRoot m_Root;
	std::vector<BLAKE2bLeaf> m_Leaves;
	size_t m_buflen;
	byte m_Digestsize;
private:
	void ThreadUpdate(unsigned int ID,const byte* input, size_t length);
};

class BLAKE2bpMAC :  public VariableKeyLength<64,1,64>, public MessageAuthenticationCode
{
	class BLAKE2bMACRoot : public BLAKE2b
	{
	public:
		BLAKE2bMACRoot(unsigned int DigestSize,unsigned int keylen);
		void Restart();
	private:
		byte m_Keylen;
	};
	class BLAKE2bMACLeaf : public BLAKE2bMAC
	{
	public:
		BLAKE2bMACLeaf(unsigned int DigestSize,const byte* Key,unsigned int keylen,bool IsLastNode,word64 Offset);
		void Restart();
	private:
		bool m_IsLastNode;
		word64 m_Offset;
	};
public:
	CRYPTOPP_CONSTANT(BLOCKSIZE = 128)
	CRYPTOPP_CONSTANT(MAX_DIGEST_SIZE = 64)
	CRYPTOPP_CONSTANT(PARALLELISM_DEGREE = 4)
public:
	BLAKE2bpMAC(unsigned int Digestsize,const byte* Key,unsigned int Keylength);

	unsigned int BlockSize() const {return BLOCKSIZE;}
	unsigned int DigestSize() const {return static_cast<unsigned int>(m_Digestsize);}
	std::string AlgorithmName() const {return "BLAKE2bp-MAC-" + IntToString(m_Digestsize*8);}

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
	BLAKE2bMACRoot m_Root;
	std::vector<BLAKE2bMACLeaf> m_Leaves;
	size_t m_buflen;
	byte m_Digestsize;
private:
	void ThreadUpdate(unsigned int ID,const byte* input, size_t length);
};



NAMESPACE_END

#endif