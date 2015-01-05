// skein.h written and placed in the public domain by Jean-Pierre Muench

#ifndef CRYPTOPP_SKEIN_H
#define CRYPTOPP_SKEIN_H

#include "cryptlib.h"
#include "secblock.h"
#include "iterhash.h"
#include "seckey.h"

NAMESPACE_BEGIN(CryptoPP)

	/*
//! skein
class Skein : public HashTransformation
{
public:
	// BlockSize = 0 means "choose based on digest size and some nice rules"
	Skein(const unsigned int DigestSize,unsigned int BlockSize = 0);
	unsigned int BlockSize() const {return m_Blocksize;}
	unsigned int DigestSize() const {return static_cast<unsigned int>(m_DigestSize);}
	std::string AlgorithmName() const {return "Skein-" + IntToString(m_Blocksize*8) + "-" + IntToString(m_DigestSize*8);}

	unsigned int OptimalBlockSize() const {return BlockSize();}
	unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word64>();}

	void Update(const byte *input, size_t length);
	void Restart();
	void TruncatedFinal(byte *hash, size_t size);
private:
	size_t m_DigestSize; // 8 bytes are defined by specification, will be fed with 32 bits max :(
	unsigned int m_Blocksize; // can be: 32, 64 or 128
	std::auto_ptr<TweakableBlockCipher> m_Threefish; // pointer to the underlying Threefish function
	word64 m_LowerCounter;
	word32 m_UpperCounter;
	FixedSizeSecBlock<byte,128> m_State;
	SecByteBlock m_BufferForNextBlock;
private:
	void IncrementCounters(size_t n);
};*/

class CRYPTOPP_NO_VTABLE Skein_Main_Provider
{
private:
	class UBI : public HashTransformation
	{
	public:
		enum TypeValues
		{
			KEY=0,
			CFG=4,
			PRS=8,
			PK=12,
			KDF=16,
			NON=20,
			MSG=48,
			OUT=63
		};
	public:
		UBI(unsigned int Blocksize,TypeValues TypeValue,const byte* InitialState);
		unsigned int BlockSize() const {return m_Blocksize;}
		unsigned int DigestSize() const {return m_Blocksize;}
		std::string AlgorithmName() const {return "UBI-Threefish-" + IntToString(m_Blocksize*8);}

		unsigned int OptimalBlockSize() const {return BlockSize();}
		unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word64>();}

		void Update(const byte *input, size_t length);
		void Restart();
		void TruncatedFinal(byte *hash, size_t size);

		void OutTransformation(byte* OutReceiver,const size_t OutputSize,const byte* State);
	private:
		std::auto_ptr<TweakableBlockCipher> m_Threefish; // pointer to the underlying Threefish function
		TypeValues m_TypeValue;
		unsigned int m_Blocksize;
		word64 m_LowerCounter;
		word32 m_UpperCounter;
		SecByteBlock m_State;
		SecByteBlock m_BufferForNextBlock;
	private:	
		void IncrementCounters(size_t n);
	};
	class CRYPTOPP_NO_VTABLE Skein_Base
	{
	public:
		//! call restart to apply
		virtual void Personalize(const byte* PersonalizationString,size_t stringlength) {m_PersonalizationString.Assign(PersonalizationString,stringlength);}
		//! call restart to apply
		virtual void SetNonce(const byte* Nonce,size_t NonceLength) {m_Nonce.Assign(Nonce,NonceLength);}
		//! call restart to apply
		virtual void KeyUBI(const byte* Key,size_t Keylength); // setKey is occupied by MACs
		//! call restart to apply
		virtual void SetPublicKey(const byte* PublicKey,size_t Keylength) {m_PublicKey.Assign(PublicKey,Keylength);}
		//! call restart to apply
		virtual void SetKeyIdentifier(const byte* KeyIdentifier,size_t IDlength) {m_KeyID.Assign(KeyIdentifier,IDlength);}

		virtual void UpdateMsgUBI(const byte *input, size_t length) {m_MsgUBI->Update(input,length);}
		void RestartUBI();
		void TruncatedFinalMsgUBI(byte *hash, size_t size); // uses output transformation
	protected:
		//! call this as very first!
		void ConfigUBI(word64 OutputLength,unsigned int Blocksize) {m_OutputLength=OutputLength;m_BlockSize=Blocksize;}
		//! call this after keying but before giving to the user
		void ApplyAllSettings(); // restart calls this generate correct base state
	private:
		unsigned int m_BlockSize;
		FixedSizeSecBlock<byte,128> m_State;
		std::auto_ptr<UBI> m_MsgUBI; // all other UBIs will be instantiated locally
		SecByteBlock m_KeyedState; // hides key information from attackers
		SecByteBlock m_PersonalizationString;
		SecByteBlock m_Nonce;
		SecByteBlock m_PublicKey;
		SecByteBlock m_KeyID;
		word64 m_OutputLength;
	};
public:
	class Hash : public HashTransformation, public Skein_Base
	{
	public:
		// BlockSize = 0 means "choose based on digest size and some nice rules"
		Hash(const unsigned int DigestSize,unsigned int BlockSize = 0);

		void Update(const byte *input, size_t length) {UpdateMsgUBI(input,length);}
		void Restart() {ApplyAllSettings();}
		void TruncatedFinal(byte *hash, size_t size) {TruncatedFinalMsgUBI(hash,size);} // uses output transformation

		unsigned int BlockSize() const {return m_Blocksize;}
		unsigned int DigestSize() const {return static_cast<unsigned int>(m_DigestSize);}
		std::string AlgorithmName() const {return "Skein-" + IntToString(m_Blocksize*8) + "-" + IntToString(m_DigestSize*8);}

		// following is unsupported by the simple hash function
		virtual void SetNonce(const byte* Nonce,size_t NonceLength) {}
		virtual void KeyUBI(const byte* Key,size_t Keylength) {}
		virtual void SetPublicKey(const byte* PublicKey,size_t Keylength) {}
		virtual void SetKeyIdentifier(const byte* KeyIdentifier,size_t IDlength) {}

		unsigned int OptimalBlockSize() const {return BlockSize();}
		unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word64>();}
	private:
		unsigned int m_Blocksize;
		word64 m_DigestSize;
	};
	class MAC : public VariableKeyLength<64, 0, INT_MAX>, public MessageAuthenticationCode, public Skein_Base
	{
	public:
		// BlockSize = 0 means "choose based on digest size and some nice rules"
		MAC(const byte* Key,size_t keylength,const unsigned int DigestSize,unsigned int BlockSize = 0);

		size_t MinKeyLength() const {return MIN_KEYLENGTH;}
		size_t MaxKeyLength() const {return (size_t)MAX_KEYLENGTH;}
		size_t DefaultKeyLength() const {return DEFAULT_KEYLENGTH;}
		size_t GetValidKeyLength(size_t n) const {return StaticGetValidKeyLength(n);}
		SimpleKeyingInterface::IV_Requirement IVRequirement() const {return (SimpleKeyingInterface::IV_Requirement)IV_REQUIREMENT;}
		unsigned int IVSize() const {return IV_LENGTH;}

		void UncheckedSetKey(const byte *userKey, unsigned int keylength, const NameValuePairs &params)
		{KeyUBI(userKey,keylength);}

		void Update(const byte *input, size_t length) {UpdateMsgUBI(input,length);}
		void Restart() {ApplyAllSettings();}
		void TruncatedFinal(byte *hash, size_t size) {TruncatedFinalMsgUBI(hash,size);} // uses output transformation

		unsigned int BlockSize() const {return m_Blocksize;}
		unsigned int DigestSize() const {return static_cast<unsigned int>(m_DigestSize);}
		std::string AlgorithmName() const {return "Skein-MAC-" + IntToString(m_Blocksize*8) + "-" + IntToString(m_DigestSize*8);}

		// following is unsupported by the simple MAC function
		virtual void SetNonce(const byte* Nonce,size_t NonceLength) {}
		virtual void SetPublicKey(const byte* PublicKey,size_t Keylength) {}
		virtual void SetKeyIdentifier(const byte* KeyIdentifier,size_t IDlength) {}
	private:
		unsigned int m_Blocksize;
		word64 m_DigestSize;
	};
	class KDF : public VariableKeyLength<64,0,INT_MAX>, public SimpleKeyingInterface, public Skein_Base
	{
	public:
		// BlockSize = 0 means "choose based on digest size and some nice rules"
		KDF(const byte* Key,size_t keylength,const byte* KeyIdentifier,size_t IDsize,const unsigned int DerivedKeyLen,unsigned int BlockSize = 0);

		size_t MinKeyLength() const {return MIN_KEYLENGTH;}
		size_t MaxKeyLength() const {return (size_t)MAX_KEYLENGTH;}
		size_t DefaultKeyLength() const {return DEFAULT_KEYLENGTH;}
		size_t GetValidKeyLength(size_t n) const {return StaticGetValidKeyLength(n);}
		SimpleKeyingInterface::IV_Requirement IVRequirement() const {return (SimpleKeyingInterface::IV_Requirement)IV_REQUIREMENT;}
		unsigned int IVSize() const {return IV_LENGTH;}

		void UncheckedSetKey(const byte *userKey, unsigned int keylength, const NameValuePairs &params)
		{KeyUBI(userKey,keylength);}

		void SetDerivedLength(word64 DerivedLength) {m_DerivedLength=DerivedLength;};

		void Restart() {ApplyAllSettings();}
		void DeriveKey(byte *derived) {TruncatedFinalMsgUBI(derived,m_DerivedLength);} // uses output transformation

		unsigned int BlockSize() const {return m_Blocksize;}
		unsigned int DerivedSize() const {return static_cast<unsigned int>(m_DerivedLength);}
		std::string AlgorithmName() const {return "Skein-KDF-" + IntToString(m_Blocksize*8) + "-" + IntToString(m_DerivedLength*8);}

		// following is unsupported by KDF
		virtual void SetNonce(const byte* Nonce,size_t NonceLength) {}
		virtual void SetPublicKey(const byte* PublicKey,size_t Keylength) {}
		virtual void UpdateMsgUBI(const byte *input, size_t length) {}

		unsigned int OptimalBlockSize() const {return BlockSize();}
		unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word64>();}
	private:
		unsigned int m_Blocksize;
		word64 m_DerivedLength;
	};
	class SignatureHash : public HashTransformation, public Skein_Base
	{
	public:
		// BlockSize = 0 means "choose based on digest size and some nice rules"
		SignatureHash(const byte* PublicKey,size_t Keylength,const unsigned int DigestSize,unsigned int BlockSize = 0);

		void Update(const byte *input, size_t length) {UpdateMsgUBI(input,length);}
		void Restart() {ApplyAllSettings();}
		void TruncatedFinal(byte *hash, size_t size) {TruncatedFinalMsgUBI(hash,size);} // uses output transformation

		unsigned int BlockSize() const {return m_Blocksize;}
		unsigned int DigestSize() const {return static_cast<unsigned int>(m_DigestSize);}
		std::string AlgorithmName() const {return "Skein-Digital-Signature-Hash-" + IntToString(m_Blocksize*8) + "-" + IntToString(m_DigestSize*8);}

		// following is unsupported by the simple hash function
		virtual void SetNonce(const byte* Nonce,size_t NonceLength) {}
		virtual void KeyUBI(const byte* Key,size_t Keylength) {}
		virtual void SetKeyIdentifier(const byte* KeyIdentifier,size_t IDlength) {}

		unsigned int OptimalBlockSize() const {return BlockSize();}
		unsigned int OptimalDataAlignment() const {return GetAlignmentOf<word64>();}
	private:
		unsigned int m_Blocksize;
		word64 m_DigestSize;
	};
};

typedef Skein_Main_Provider::MAC SkeinMAC;
typedef Skein_Main_Provider::Hash Skein;
typedef Skein_Main_Provider::KDF SkeinKDF;
typedef Skein_Main_Provider::SignatureHash SkeinSignatureHash;

class Skein_512 : public Skein
{
public:
	CRYPTOPP_CONSTANT(DIGESTSIZE = 64)
	CRYPTOPP_CONSTANT(BLOCKSIZE = 64)
	Skein_512() : Skein(DIGESTSIZE,BLOCKSIZE){}
	static const char * StaticAlgorithmName() {return "Skein-512-512";}
};

class Skein_384 : public Skein
{
public:
	CRYPTOPP_CONSTANT(DIGESTSIZE = 48)
	CRYPTOPP_CONSTANT(BLOCKSIZE = 64)
	Skein_384() : Skein(DIGESTSIZE,BLOCKSIZE){}
	static const char * StaticAlgorithmName() {return "Skein-512-384";}
};

class Skein_256 : public Skein
{
public:
	CRYPTOPP_CONSTANT(DIGESTSIZE = 32)
	CRYPTOPP_CONSTANT(BLOCKSIZE = 64)
	Skein_256() : Skein(DIGESTSIZE,BLOCKSIZE){}
	static const char * StaticAlgorithmName() {return "Skein-512-256";}
};

class Skein_224 : public Skein
{
public:
	CRYPTOPP_CONSTANT(DIGESTSIZE = 28)
	CRYPTOPP_CONSTANT(BLOCKSIZE = 64)
	Skein_224() : Skein(DIGESTSIZE,BLOCKSIZE){}
	static const char * StaticAlgorithmName() {return "Skein-512-224";}
};

NAMESPACE_END

#endif