#ifndef CRYPTOPP_AUTHENC_H
#define CRYPTOPP_AUTHENC_H

#include "cryptlib.h"
#include "secblock.h"
#include "pubkey.h"
#include "hmac.h"

NAMESPACE_BEGIN(CryptoPP)

//! .
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE AuthenticatedSymmetricCipherBase : public AuthenticatedSymmetricCipher
{
public:
	AuthenticatedSymmetricCipherBase() : m_state(State_Start) {}

	bool IsRandomAccess() const {return false;}
	bool IsSelfInverting() const {return true;}
	void UncheckedSetKey(const byte *,unsigned int,const CryptoPP::NameValuePairs &) {assert(false);}

	void SetKey(const byte *userKey, size_t keylength, const NameValuePairs &params);
	void Restart() {if (m_state > State_KeySet) m_state = State_KeySet;}
	void Resynchronize(const byte *iv, int length=-1);
	void Update(const byte *input, size_t length);
	void ProcessData(byte *outString, const byte *inString, size_t length);
	void TruncatedFinal(byte *mac, size_t macSize);

protected:
	void AuthenticateData(const byte *data, size_t len);
	const SymmetricCipher & GetSymmetricCipher() const {return const_cast<AuthenticatedSymmetricCipherBase *>(this)->AccessSymmetricCipher();};

	virtual SymmetricCipher & AccessSymmetricCipher() =0;
	virtual bool AuthenticationIsOnPlaintext() const =0;
	virtual unsigned int AuthenticationBlockSize() const =0;
	virtual void SetKeyWithoutResync(const byte *userKey, size_t keylength, const NameValuePairs &params) =0;
	virtual void Resync(const byte *iv, size_t len) =0;
	virtual size_t AuthenticateBlocks(const byte *data, size_t len) =0;
	virtual void AuthenticateLastHeaderBlock() =0;
	virtual void AuthenticateLastConfidentialBlock() {}
	virtual void AuthenticateLastFooterBlock(byte *mac, size_t macSize) =0;

	enum State {State_Start, State_KeySet, State_IVSet, State_AuthUntransformed, State_AuthTransformed, State_AuthFooter};
	State m_state;
	unsigned int m_bufferedDataLength;
	lword m_totalHeaderLength, m_totalMessageLength, m_totalFooterLength;
	AlignedSecByteBlock m_buffer;
};

class CRYPTOPP_NO_VTABLE EncryptThenAuthenticate_Base : public AuthenticatedSymmetricCipherBase
{
public:
	// AuthenticatedSymmetricCipher
	std::string AlgorithmName() const
		{return GetSymmetricCipher().AlgorithmName() + std::string("-") + GetMAC().AlgorithmName();}
	size_t MinKeyLength() const
		{return STDMAX(GetMAC().MinKeyLength(),GetSymmetricCipher().MinKeyLength());}
	size_t MaxKeyLength() const
		{return STDMIN(GetMAC().MaxKeyLength(),GetSymmetricCipher().MaxKeyLength());}
	size_t DefaultKeyLength() const
		{return STDMAX(GetMAC().DefaultKeyLength(),GetSymmetricCipher().DefaultKeyLength());}
	size_t GetValidKeyLength(size_t n) const
		{return STDMAX(GetMAC().GetValidKeyLength(n),GetSymmetricCipher().GetValidKeyLength(n));}
	bool IsValidKeyLength(size_t n) const
		{return GetSymmetricCipher().IsValidKeyLength(n) && GetMAC().IsValidKeyLength(n);}
	unsigned int OptimalDataAlignment() const
		{return GetSymmetricCipher().OptimalDataAlignment();}
	IV_Requirement IVRequirement() const
	{
		if(GetMAC().IsResynchronizable()) // none of them should be 4 == no-IV
		{
			return STDMAX(GetMAC().IVRequirement(),GetSymmetricCipher().IVRequirement());
		}
		else
		{
			return GetSymmetricCipher().IVRequirement();
		}
	}
	unsigned int IVSize() const
		{
			if(GetMAC().IsResynchronizable())
			{
				return STDMAX(GetMAC().IVSize(),GetSymmetricCipher().IVSize());
			}
			else
			{
				return GetSymmetricCipher().IVSize();
			}
		}
	unsigned int MinIVLength() const
		{
			if(GetMAC().IsResynchronizable())
			{
				return STDMAX(GetMAC().MinIVLength(),GetSymmetricCipher().MinIVLength());
			}
			else
			{
				return GetSymmetricCipher().IVSize();
			}
		}
	unsigned int MaxIVLength() const
		{
			if(GetMAC().IsResynchronizable())
			{
				return STDMIN(GetMAC().MaxIVLength(),GetSymmetricCipher().MaxIVLength());
			}
			else
			{
				return GetSymmetricCipher().IVSize();
			}
		}
	unsigned int DigestSize() const
		{return GetMAC().TagSize();}
	lword MaxHeaderLength() const
		{return LWORD_MAX;}
	lword MaxMessageLength() const
		{return LWORD_MAX;}
	// AuthenticatedSymmetricCipherBase
	bool IsSelfInverting() const {GetSymmetricCipher().IsSelfInverting();}
private:
	bool AuthenticationIsOnPlaintext() const {return false;}
	unsigned int AuthenticationBlockSize() const {return 1;}
	void AuthenticateLastHeaderBlock() {}
	void AuthenticateLastFooterBlock(byte *mac, size_t macSize) {AccessMAC().TruncatedFinal(mac,macSize);}
	size_t AuthenticateBlocks(const byte *data, size_t len) {AccessMAC().Update(data, len);return 0;}
	void Resync(const byte *iv, size_t len);
	void SetKeyWithoutResync(const byte *userKey, size_t keylength, const NameValuePairs &params);
protected:
	const MessageAuthenticationCode & GetMAC() const {return const_cast<EncryptThenAuthenticate_Base *>(this)->AccessMAC();}
	virtual MessageAuthenticationCode & AccessMAC() =0;
	// needs P1363-KDF2-style interface
	virtual void DeriveKey(byte *output, size_t outputLength, const byte *input, size_t inputLength, const byte *derivationParams, size_t derivationParamsLength) =0;
};

template<class CIPHER_MODE,class MAC,class KDF,bool IsEncryption>
class EncryptThenAuthenticate_Final : public EncryptThenAuthenticate_Base
{
public:
	static std::string StaticAlgorithmName()
		{return CIPHER_MODE::StaticAlgorithmName() + std::string("-") + MAC::StaticAlgorithmName();}
	bool IsForwardTransformation() const
		{return IsEncryption;}
private:
	MAC m_MAC;
	CIPHER_MODE m_Cipher;
	MessageAuthenticationCode & AccessMAC() {return m_MAC;}
	SymmetricCipher & AccessSymmetricCipher() {return m_Cipher;}
	void DeriveKey(byte *output, size_t outputLength, const byte *input, size_t inputLength, const byte *derivationParams, size_t derivationParamsLength)
	{KDF::DeriveKey(output,outputLength,input,inputLength,derivationParams,derivationParamsLength)}
};

// classic Encrypt-Then-Authenticate (EtA) approach, implemented as AuthenticatedSymmetricCipher
// DO NOT USE ECB AS CIPHER MODE
// Cipher mode may be something like CTR_Mode<AES>
// MAC may be something like HMAC<SHA3_512>
// KDF may be something like P1363_KDF2<SHA3_512>, this interface is required
template<class CIPHER_MODE,class MAC,class KDF>
struct EncryptThenAuthenticate : public AuthenticatedSymmetricCipherDocumentation
{
	typedef EncryptThenAuthenticate_Final<typename CIPHER_MODE::Encryption,MAC,KDF,true> Encryption;
	typedef EncryptThenAuthenticate_Final<typename CIPHER_MODE::Decryption,MAC,KDF,false> Decryption;
};

// classic Encrypt-Then-Authenticate (EtA) approach, implemented as AuthenticatedSymmetricCipher
// DO NOT USE ECB AS CIPHER MODE
// Cipher mode may be something like CTR_Mode<AES>
// Hash may be something like SHA3_512
// KDF may be something like P1363_KDF2<SHA3_512>, defaults to P1363_KDF2<HASH>, this interface is required
template<class CIPHER_MODE,class HASH,class KDF = P1363_KDF2<HASH>>
struct EncryptThenAuthenticate_HMAC : public AuthenticatedSymmetricCipherDocumentation
{
	typedef EncryptThenAuthenticate_Final<typename CIPHER_MODE::Encryption,HMAC<HASH>,KDF,true> Encryption;
	typedef EncryptThenAuthenticate_Final<typename CIPHER_MODE::Decryption,HMAC<HASH>,KDF,false> Decryption;
};

NAMESPACE_END

#endif
