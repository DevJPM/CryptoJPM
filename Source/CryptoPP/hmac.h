// hmac.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_HMAC_H
#define CRYPTOPP_HMAC_H

#include "seckey.h"
#include "secblock.h"
#include "sha3.h"

NAMESPACE_BEGIN(CryptoPP)

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE HMAC_Base_Impl : public VariableKeyLength<16, 0, INT_MAX>, public MessageAuthenticationCode
{
public:
	virtual void UncheckedSetKey(const byte *userKey, unsigned int keylength, const NameValuePairs &params) =0;
	virtual void Restart();
	virtual void Update(const byte *input, size_t length);
	virtual void TruncatedFinal(byte *mac, size_t size) =0;
	virtual unsigned int DigestSize() const {return const_cast<HMAC_Base_Impl*>(this)->AccessHash()->DigestSize();}
	static std::string StaticAlgorithmName() {return "";} // won't be called
protected:
	virtual HashTransformation* AccessHash() =0;
	virtual void KeyHash() =0;
};

//! _
class CRYPTOPP_DLL HMAC_Base_Classic : public MessageAuthenticationCodeImpl<HMAC_Base_Impl>
{
public:
	HMAC_Base_Classic(HashTransformation * Hash) : m_innerHashKeyed(false),m_hash(Hash) {}
	void UncheckedSetKey(const byte *userKey, unsigned int keylength, const NameValuePairs &params);

	void TruncatedFinal(byte *mac, size_t size);
protected:
	byte * AccessIpad() {return m_buf;}
	byte * AccessOpad() {return m_buf + AccessHash()->BlockSize();}
	byte * AccessInnerHash() {return m_buf + 2*AccessHash()->BlockSize();}
	HashTransformation* AccessHash() {return m_hash;}
private:
	void KeyHash();

	SecByteBlock m_buf;
	bool m_innerHashKeyed;
	HashTransformation * m_hash;
};

class CRYPTOPP_DLL HMAC_Base_Compability : public MessageAuthenticationCodeImpl<HMAC_Base_Impl>
{
public:
	HMAC_Base_Compability(HashTransformation * Hash) : m_innerHashKeyed(false),m_hash(Hash) {}
	void UncheckedSetKey(const byte *userKey, unsigned int keylength, const NameValuePairs &params);

	void TruncatedFinal(byte *mac, size_t size);
protected:
	byte * AccessIpad() {return m_buf;}
	byte * AccessOpad() {return m_buf + AccessHash()->BlockSize();}
	byte * AccessInnerHash() {return m_buf + 2*AccessHash()->BlockSize();}
	HashTransformation* AccessHash() {return m_hash;}
private:
	void KeyHash();

	SecByteBlock m_buf;
	bool m_innerHashKeyed;
	HashTransformation * m_hash;
};

//! _
class CRYPTOPP_DLL HMAC_Base_Fast : public MessageAuthenticationCodeImpl<HMAC_Base_Impl>
{
public:
	HMAC_Base_Fast(HashTransformation * Hash) : m_HashKeyed(false),m_hash(Hash) {}
	void UncheckedSetKey(const byte *userKey, unsigned int keylength, const NameValuePairs &params);
	void TruncatedFinal(byte *mac, size_t size);
protected:
	virtual HashTransformation * AccessHash() {return m_hash;}
private:
	void KeyHash();

	SecByteBlock m_key;
	bool m_HashKeyed;
	HashTransformation * m_hash;
};

class CRYPTOPP_DLL HMAC_Base : public VariableKeyLength<16, 0, INT_MAX>, public MessageAuthenticationCode
{
public:
	HMAC_Base() : m_ExecutingClass(nullptr) {}
	void UncheckedSetKey(const byte *userKey, unsigned int keylength, const NameValuePairs &params);

	void Restart();
	void Update(const byte *input, size_t length);
	void TruncatedFinal(byte *mac, size_t size);
	unsigned int DigestSize() const {return const_cast<HMAC_Base*>(this)->AccessHash()->DigestSize();}
protected:
	virtual HashTransformation * AccessHash() =0;
	virtual bool IsCompabilityMode() const =0;
private:
	std::auto_ptr<HMAC_Base_Impl> m_ExecutingClass;
};

//! <a href="http://www.weidai.com/scan-mirror/mac.html#HMAC">HMAC</a>
/*! HMAC(K, text) = H(K XOR opad, H(K XOR ipad, text)) */
/*  HMAC: can only be used with a block-based hash function, like SHA-2, SHA-1, Whirlpool, ... */
template <class T>
class HMAC : public MessageAuthenticationCodeImpl<HMAC_Base, HMAC<T> >
{
public:
	CRYPTOPP_CONSTANT(DIGESTSIZE=T::DIGESTSIZE)

	HMAC(const bool CompabilityMode = true) : m_hash(), m_CompabilityMode(CompabilityMode) {}
	HMAC(const byte *key, size_t length=HMAC_Base::DEFAULT_KEYLENGTH,const bool CompabilityMode = true)
		: m_hash(), m_CompabilityMode(CompabilityMode)
		{this->SetKey(key, length);}

	static std::string StaticAlgorithmName() {return std::string("HMAC(") + T::StaticAlgorithmName() + ")";}
	std::string AlgorithmName() const {return std::string("HMAC(") + m_hash.AlgorithmName() + ")";}

private:
	HashTransformation * AccessHash() {return &m_hash;}
	bool IsCompabilityMode() const {return m_CompabilityMode;}

	T m_hash;
	const bool m_CompabilityMode;
};

NAMESPACE_END

#endif
