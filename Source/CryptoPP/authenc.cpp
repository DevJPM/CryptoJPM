// authenc.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "authenc.h"

NAMESPACE_BEGIN(CryptoPP)

void AuthenticatedSymmetricCipherBase::AuthenticateData(const byte *input, size_t len)
{
	unsigned int blockSize = AuthenticationBlockSize();
	unsigned int &num = m_bufferedDataLength;
	byte* data = m_buffer.begin();

	if (num != 0)	// process left over data
	{
		if (num+len >= blockSize)
		{
			memcpy(data+num, input, blockSize-num);
			AuthenticateBlocks(data, blockSize);
			input += (blockSize-num);
			len -= (blockSize-num);
			num = 0;
			// drop through and do the rest
		}
		else
		{
			memcpy(data+num, input, len);
			num += (unsigned int)len;
			return;
		}
	}

	// now process the input data in blocks of blockSize bytes and save the leftovers to m_data
	if (len >= blockSize)
	{
		size_t leftOver = AuthenticateBlocks(input, len);
		input += (len - leftOver);
		len = leftOver;
	}

	memcpy(data, input, len);
	num = (unsigned int)len;
}

void AuthenticatedSymmetricCipherBase::SetKey(const byte *userKey, size_t keylength, const NameValuePairs &params)
{
	m_bufferedDataLength = 0;
	m_state = State_Start;

	SetKeyWithoutResync(userKey, keylength, params);
	m_state = State_KeySet;

	size_t length;
	const byte *iv = GetIVAndThrowIfInvalid(params, length);
	if (iv)
		Resynchronize(iv, (int)length);
}

void AuthenticatedSymmetricCipherBase::Resynchronize(const byte *iv, int length)
{
	if (m_state < State_KeySet)
		throw BadState(AlgorithmName(), "Resynchronize", "key is set");

	m_bufferedDataLength = 0;
	m_totalHeaderLength = m_totalMessageLength = m_totalFooterLength = 0;
	m_state = State_KeySet;

	Resync(iv, this->ThrowIfInvalidIVLength(length));
	m_state = State_IVSet;
}

void AuthenticatedSymmetricCipherBase::Update(const byte *input, size_t length)
{
	if (length == 0)
		return;

	switch (m_state)
	{
	case State_Start:
	case State_KeySet:
		throw BadState(AlgorithmName(), "Update", "setting key and IV");
	case State_IVSet:
		AuthenticateData(input, length);
		m_totalHeaderLength += length;
		break;
	case State_AuthUntransformed:
	case State_AuthTransformed:
		AuthenticateLastConfidentialBlock();
		m_bufferedDataLength = 0;
		m_state = State_AuthFooter;
		// fall through
	case State_AuthFooter:
		AuthenticateData(input, length);
		m_totalFooterLength += length;
		break;
	default:
		assert(false);
	}
}

void AuthenticatedSymmetricCipherBase::ProcessData(byte *outString, const byte *inString, size_t length)
{
	m_totalMessageLength += length;
	if (m_state >= State_IVSet && m_totalMessageLength > MaxMessageLength())
		throw InvalidArgument(AlgorithmName() + ": message length exceeds maximum");

reswitch:
	switch (m_state)
	{
	case State_Start:
	case State_KeySet:
		throw BadState(AlgorithmName(), "ProcessData", "setting key and IV");
	case State_AuthFooter:
		throw BadState(AlgorithmName(), "ProcessData was called after footer input has started");
	case State_IVSet:
		AuthenticateLastHeaderBlock();
		m_bufferedDataLength = 0;
		m_state = AuthenticationIsOnPlaintext()==IsForwardTransformation() ? State_AuthUntransformed : State_AuthTransformed;
		goto reswitch;
	case State_AuthUntransformed:
		AuthenticateData(inString, length);
		AccessSymmetricCipher().ProcessData(outString, inString, length);
		break;
	case State_AuthTransformed:
		AccessSymmetricCipher().ProcessData(outString, inString, length);
		AuthenticateData(outString, length);
		break;
	default:
		assert(false);
	}
}

void AuthenticatedSymmetricCipherBase::TruncatedFinal(byte *mac, size_t macSize)
{
	if (m_totalHeaderLength > MaxHeaderLength())
		throw InvalidArgument(AlgorithmName() + ": header length of " + IntToString(m_totalHeaderLength) + " exceeds the maximum of " + IntToString(MaxHeaderLength()));

	if (m_totalFooterLength > MaxFooterLength())
	{
		if (MaxFooterLength() == 0)
			throw InvalidArgument(AlgorithmName() + ": additional authenticated data (AAD) cannot be input after data to be encrypted or decrypted");
		else
			throw InvalidArgument(AlgorithmName() + ": footer length of " + IntToString(m_totalFooterLength) + " exceeds the maximum of " + IntToString(MaxFooterLength()));
	}

	switch (m_state)
	{
	case State_Start:
	case State_KeySet:
		throw BadState(AlgorithmName(), "TruncatedFinal", "setting key and IV");

	case State_IVSet:
		AuthenticateLastHeaderBlock();
		m_bufferedDataLength = 0;
		// fall through

	case State_AuthUntransformed:
	case State_AuthTransformed:
		AuthenticateLastConfidentialBlock();
		m_bufferedDataLength = 0;
		// fall through

	case State_AuthFooter:
		AuthenticateLastFooterBlock(mac, macSize);
		m_bufferedDataLength = 0;
		break;

	default:
		assert(false);
	}

	m_state = State_KeySet;
}

static const byte DerivationParamCipherIV[] = "CIPHER-IV";
static const byte DerivationParamMACIV[] = "MAC-IV";
static const byte DerivationParamCipherKey[] = "CIPHER-KEY";
static const byte DerivationParamMACKey[] = "MAC-KEY";

void EncryptThenAuthenticate_Base::Resync(const byte *iv, size_t len)
{
	if(len>(size_t(0)-1)/2)
		throw(InvalidArgument("IV too large"));
	SecByteBlock IV(2*len);
	if(AccessMAC().IsResynchronizable()) // don't give the same IV to both
	{
		DeriveKey(IV,len,iv,len,DerivationParamCipherIV,9);
		DeriveKey(IV+len,len,iv,len,DerivationParamMACIV,6);
	}
	else
	{
		memcpy_s(IV,len,iv,len);
		memcpy_s(IV+len,len,iv,len);
	}

	// the cipher MUST BE RESYNCHRONIZABLE!
	AccessSymmetricCipher().Resynchronize(IV,static_cast<int>(len));
	if(AccessMAC().IsResynchronizable())
		AccessMAC().Resynchronize(IV+len,static_cast<int>(len));
}

void EncryptThenAuthenticate_Base::SetKeyWithoutResync(const byte *userKey, size_t keylength, const NameValuePairs &params)
{
	SecByteBlock Keys(2*keylength);
	// MAC-Key != CIPHER-KEY
	DeriveKey(Keys,keylength,userKey,keylength,DerivationParamCipherKey,10);
	DeriveKey(Keys+keylength,keylength,userKey,keylength,DerivationParamMACKey,7);
	AccessMAC().SetKey(Keys,keylength,params);
	AccessSymmetricCipher().SetKey(Keys+keylength,keylength,params);
}

NAMESPACE_END

#endif
