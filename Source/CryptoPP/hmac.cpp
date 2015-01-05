// hmac.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "hmac.h"

NAMESPACE_BEGIN(CryptoPP)

void HMAC_Base::UncheckedSetKey(const byte *userKey, unsigned int keylength, const NameValuePairs & NameValues)
{
	if(!m_ExecutingClass.get())
	{
		if(!const_cast<HMAC_Base*>(this)->AccessHash()->BlockSize())
		{
			if(const_cast<HMAC_Base*>(this)->IsCompabilityMode())
				m_ExecutingClass=std::auto_ptr<HMAC_Base_Impl>(new HMAC_Base_Compability(const_cast<HMAC_Base*>(this)->AccessHash()));
			else
				m_ExecutingClass=std::auto_ptr<HMAC_Base_Impl>(new HMAC_Base_Fast(const_cast<HMAC_Base*>(this)->AccessHash()));
		}
		else
			m_ExecutingClass=std::auto_ptr<HMAC_Base_Impl>(new HMAC_Base_Classic(const_cast<HMAC_Base*>(this)->AccessHash()));
	}
	return m_ExecutingClass->UncheckedSetKey(userKey,keylength,NameValues);
}

void HMAC_Base::Restart()
{
	return m_ExecutingClass->Restart();
}

void HMAC_Base::Update(const byte *input, size_t length)
{
	return m_ExecutingClass->Update(input,length);
}

void HMAC_Base::TruncatedFinal(byte *mac, size_t size)
{
	return m_ExecutingClass->TruncatedFinal(mac,size);
}

void HMAC_Base_Impl::Restart()
{
	AccessHash()->Restart();
}

void HMAC_Base_Impl::Update(const byte *input, size_t length)
{
	KeyHash();
	AccessHash()->Update(input, length);
}

void HMAC_Base_Classic::TruncatedFinal(byte *mac, size_t size)
{
	ThrowIfInvalidTruncatedSize(size);

	HashTransformation & hash = *AccessHash();

	if (!m_innerHashKeyed)
		KeyHash();
	hash.Final(AccessInnerHash());

	hash.Update(AccessOpad(), hash.BlockSize());
	hash.Update(AccessInnerHash(), hash.DigestSize());
	hash.TruncatedFinal(mac, size);

	m_innerHashKeyed = false;
}

void HMAC_Base_Classic::UncheckedSetKey(const byte *userKey, unsigned int keylength, const NameValuePairs &)
{
	AssertValidKeyLength(keylength);

	Restart();

	HashTransformation * hash = AccessHash();
	unsigned int blockSize = hash->BlockSize();

	if (!blockSize)
		throw InvalidArgument("HMAC: can only be used with a block-based hash function");

	m_buf.resize(2*AccessHash()->BlockSize() + AccessHash()->DigestSize());

	if (keylength <= blockSize)
		memcpy(AccessIpad(), userKey, keylength);
	else
	{
		AccessHash()->CalculateDigest(AccessIpad(), userKey, keylength);
		keylength = hash->DigestSize();
	}

	assert(keylength <= blockSize);
	memset(AccessIpad()+keylength, 0, blockSize-keylength);

	for (unsigned int i=0; i<blockSize; i++)
	{
		AccessOpad()[i] = AccessIpad()[i] ^ 0x5c;
		AccessIpad()[i] ^= 0x36;
	}
}

void HMAC_Base_Classic::KeyHash()
{
	if(!m_innerHashKeyed)
	{
		HashTransformation * hash = AccessHash();
		hash->Update(AccessIpad(), hash->BlockSize());
		m_innerHashKeyed = true;
	}
}

void HMAC_Base_Fast::UncheckedSetKey(const byte *userKey, unsigned int keylength, const NameValuePairs &)
{
	AssertValidKeyLength(keylength);

	Restart();

	HashTransformation &hash = *AccessHash();
	unsigned int DigestSize = hash.DigestSize();

	if (hash.BlockSize())
		throw InvalidArgument("HMAC-Fast: can only be used with a non-block-based hash function");

	m_key.resize(DigestSize);

	if (keylength <= DigestSize)
		memcpy(m_key, userKey, keylength);
	else
	{
		AccessHash()->CalculateDigest(m_key, userKey, keylength);
		keylength = hash.DigestSize();
	}

	assert(keylength <= DigestSize);
}

void HMAC_Base_Fast::KeyHash()
{
	if(!m_HashKeyed)
	{
		HashTransformation &hash = *AccessHash();
		hash.Update(m_key, m_key.SizeInBytes());
		m_HashKeyed = true;
	}
}

void HMAC_Base_Fast::TruncatedFinal(byte *mac, size_t size)
{
	ThrowIfInvalidTruncatedSize(size);

	HashTransformation &hash = *AccessHash();

	hash.TruncatedFinal(mac, size);

	m_HashKeyed = false;
}

void HMAC_Base_Compability::TruncatedFinal(byte *mac, size_t size)
{
	ThrowIfInvalidTruncatedSize(size);

	HashTransformation & hash = *AccessHash();

	if (!m_innerHashKeyed)
		KeyHash();
	hash.Final(AccessInnerHash());

	hash.Update(AccessOpad(), hash.DigestSize());
	hash.Update(AccessInnerHash(), hash.DigestSize());
	hash.TruncatedFinal(mac, size);

	m_innerHashKeyed = false;
}

void HMAC_Base_Compability::UncheckedSetKey(const byte *userKey, unsigned int keylength, const NameValuePairs &)
{
	AssertValidKeyLength(keylength);

	Restart();

	HashTransformation * hash = AccessHash();
	unsigned int digestsize = hash->DigestSize();

	if (!digestsize)
		throw InvalidArgument("HMAC: can only be used with a hash function");

	m_buf.resize(3*AccessHash()->DigestSize());

	if (keylength <= digestsize)
		memcpy(AccessIpad(), userKey, keylength);
	else
	{
		AccessHash()->CalculateDigest(AccessIpad(), userKey, keylength);
		keylength = hash->DigestSize();
	}

	assert(keylength <= digestsize);
	memset(AccessIpad()+keylength, 0, digestsize-keylength);

	for (unsigned int i=0; i<digestsize; i++)
	{
		AccessOpad()[i] = AccessIpad()[i] ^ 0x5c;
		AccessIpad()[i] ^= 0x36;
	}
}

void HMAC_Base_Compability::KeyHash()
{
	if(!m_innerHashKeyed)
	{
		HashTransformation * hash = AccessHash();
		hash->Update(AccessIpad(), hash->DigestSize());
		m_innerHashKeyed = true;
	}
}

NAMESPACE_END

#endif
