// Threefish.cpp - written and placed in the public domain by Jean-Pierre Muench


#include "pch.h"
#include "Threefish.h"
#include "misc.h"

#define KeyScheduleConst 0x1BD11BDAA9FC1A22L

NAMESPACE_BEGIN(CryptoPP)

typedef BlockGetAndPut<word64,LittleEndian> Block;
typedef GetBlock<word64,LittleEndian> CurrentGetBlock;

void Threefish_256::Base::UncheckedSetKey(const byte *userKey, unsigned int length, const NameValuePairs&)
{
	AssertValidKeyLength(length);
	const int keyWords = (length / 8);
	word64 parity = KeyScheduleConst;

	const word64* ConvertedKey = (word64*) userKey;

	for (int i = 0; i < keyWords; i++) {
		m_key[i] = ConvertedKey[i];
		ConditionalByteReverse(LITTLE_ENDIAN_ORDER,&m_key[i],&m_key[i],sizeof(m_key[i]));
		parity ^= m_key[i];
	}
	m_key[keyWords] = parity;
}

void Threefish_256::Enc::ProcessAndXorBlockWithTweak(const byte *inBlock, const byte *xorBlock, byte *outBlock,const byte* Tweak,const size_t TweakLength) const
{
	FixedSizeSecBlock<word64,(BLOCKSIZE/8)> cipherBlock;
	FixedSizeSecBlock<word64,(BLOCKSIZE/8)> plainBlock;
	FixedSizeSecBlock<word64,3> tweak;

	AssertValidTweakLength(TweakLength);

	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,tweak.BytePtr(),Tweak,TweakLength);
	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,plainBlock.BytePtr(),inBlock,BLOCKSIZE);

	tweak[2]=tweak[0]^tweak[1];

	ThreefishEncrypt256(plainBlock,cipherBlock,tweak);

	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,outBlock,cipherBlock.BytePtr(),BLOCKSIZE);
	if(xorBlock)
		xorbuf(outBlock,xorBlock,BLOCKSIZE);
}

void Threefish_256::Dec::ProcessAndXorBlockWithTweak(const byte *inBlock, const byte *xorBlock, byte *outBlock,const byte* Tweak,const size_t TweakLength) const
{
	FixedSizeSecBlock<word64,(BLOCKSIZE/8)> cipherBlock;
	FixedSizeSecBlock<word64,(BLOCKSIZE/8)> plainBlock;
	FixedSizeSecBlock<word64,3> tweak;

	AssertValidTweakLength(TweakLength);

	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,tweak.BytePtr(),Tweak,TweakLength);
	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,plainBlock.BytePtr(),inBlock,BLOCKSIZE);

	tweak[2]=tweak[0]^tweak[1];

	ThreefishDecrypt256(plainBlock,cipherBlock,tweak);

	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,outBlock,cipherBlock.BytePtr(),BLOCKSIZE);
	if(xorBlock)
		xorbuf(outBlock,xorBlock,BLOCKSIZE);
}

void Threefish_512::Base::UncheckedSetKey(const byte *userKey, unsigned int length, const NameValuePairs&)
{
	AssertValidKeyLength(length);
	const int keyWords = (length / 8);
	word64 parity = KeyScheduleConst;

	const word64* ConvertedKey = (word64*) userKey;

	for (int i = 0; i < keyWords; i++) {
		m_key[i] = ConvertedKey[i];
		ConditionalByteReverse(LITTLE_ENDIAN_ORDER,&m_key[i],&m_key[i],sizeof(m_key[i]));
		parity ^= m_key[i];
	}
	m_key[keyWords] = parity;
}

void Threefish_512::Enc::ProcessAndXorBlockWithTweak(const byte *inBlock, const byte *xorBlock, byte *outBlock,const byte* Tweak,const size_t TweakLength) const
{
	FixedSizeSecBlock<word64,(BLOCKSIZE/8)> cipherBlock;
	FixedSizeSecBlock<word64,(BLOCKSIZE/8)> plainBlock;
	FixedSizeSecBlock<word64,3> tweak;

	AssertValidTweakLength(TweakLength);

	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,tweak.BytePtr(),Tweak,TweakLength);
	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,plainBlock.BytePtr(),inBlock,BLOCKSIZE);

	tweak[2]=tweak[0]^tweak[1];

	ThreefishEncrypt512(plainBlock,cipherBlock,tweak);

	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,outBlock,cipherBlock.BytePtr(),BLOCKSIZE);
	if(xorBlock)
		xorbuf(outBlock,xorBlock,BLOCKSIZE);
}

void Threefish_512::Dec::ProcessAndXorBlockWithTweak(const byte *inBlock, const byte *xorBlock, byte *outBlock,const byte* Tweak,const size_t TweakLength) const
{
	FixedSizeSecBlock<word64,(BLOCKSIZE/8)> cipherBlock;
	FixedSizeSecBlock<word64,(BLOCKSIZE/8)> plainBlock;
	FixedSizeSecBlock<word64,3> tweak;

	AssertValidTweakLength(TweakLength);

	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,tweak.BytePtr(),Tweak,TweakLength);
	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,plainBlock.BytePtr(),inBlock,BLOCKSIZE);

	tweak[2]=tweak[0]^tweak[1];

	ThreefishDecrypt512(plainBlock,cipherBlock,tweak);

	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,outBlock,cipherBlock.BytePtr(),BLOCKSIZE);
	if(xorBlock)
		xorbuf(outBlock,xorBlock,BLOCKSIZE);
}

void Threefish_1024::Base::UncheckedSetKey(const byte *userKey, unsigned int length, const NameValuePairs&)
{
	AssertValidKeyLength(length);
	const int keyWords = (length / 8);
	word64 parity = KeyScheduleConst;

	const word64* ConvertedKey = (word64*) userKey;

	for (int i = 0; i < keyWords; i++) {
		m_key[i] = ConvertedKey[i];
		ConditionalByteReverse(LITTLE_ENDIAN_ORDER,&m_key[i],&m_key[i],sizeof(m_key[i]));
		parity ^= m_key[i];
	}
	m_key[keyWords] = parity;
}

void Threefish_1024::Enc::ProcessAndXorBlockWithTweak(const byte *inBlock, const byte *xorBlock, byte *outBlock,const byte* Tweak,const size_t TweakLength) const
{
	FixedSizeSecBlock<word64,(BLOCKSIZE/8)> cipherBlock;
	FixedSizeSecBlock<word64,(BLOCKSIZE/8)> plainBlock;
	FixedSizeSecBlock<word64,3> tweak;

	AssertValidTweakLength(TweakLength);

	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,tweak.BytePtr(),Tweak,TweakLength);
	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,plainBlock.BytePtr(),inBlock,BLOCKSIZE);

	tweak[2]=tweak[0]^tweak[1];

	ThreefishEncrypt1024(plainBlock,cipherBlock,tweak);

	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,outBlock,cipherBlock.BytePtr(),BLOCKSIZE);
	if(xorBlock)
		xorbuf(outBlock,xorBlock,BLOCKSIZE);
}

void Threefish_1024::Dec::ProcessAndXorBlockWithTweak(const byte *inBlock, const byte *xorBlock, byte *outBlock,const byte* Tweak,const size_t TweakLength) const
{
	FixedSizeSecBlock<word64,(BLOCKSIZE/8)> cipherBlock;
	FixedSizeSecBlock<word64,(BLOCKSIZE/8)> plainBlock;
	FixedSizeSecBlock<word64,3> tweak;

	AssertValidTweakLength(TweakLength);

	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,tweak.BytePtr(),Tweak,TweakLength);
	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,plainBlock.BytePtr(),inBlock,BLOCKSIZE);

	tweak[2]=tweak[0]^tweak[1];

	ThreefishDecrypt1024(plainBlock,cipherBlock,tweak);

	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,outBlock,cipherBlock.BytePtr(),BLOCKSIZE);
	if(xorBlock)
		xorbuf(outBlock,xorBlock,BLOCKSIZE);
}

#ifdef CRYPTOPP_USE_DYNAMIC_THREEFISH

void Threefish::Base::UncheckedSetKey(const byte *userKey, unsigned int length, const NameValuePairs &)
{
	AssertValidKeyLength(length);
	if(IsForwardTransformation())
	{
		switch(length)
		{
		case 32:
			return m_Instance.reset(new Threefish_256::Encryption(userKey,length));
		case 64:
			return m_Instance.reset(new Threefish_512::Encryption(userKey,length));
		case 128:
			return m_Instance.reset(new Threefish_1024::Encryption(userKey,length));
		}
	}
	else
	{
		switch(length)
		{
		case 32:
			return m_Instance.reset(new Threefish_256::Decryption(userKey,length));
		case 64:
			return m_Instance.reset(new Threefish_512::Decryption(userKey,length));
		case 128:
			return m_Instance.reset(new Threefish_1024::Decryption(userKey,length));
		}
	}
}

void Threefish::Base::ProcessAndXorBlockWithTweak(const byte *inBlock, const byte *xorBlock, byte *outBlock,const byte* Tweak,const size_t TweakLength) const
{
	if(m_Instance.get())
		return m_Instance->ProcessAndXorBlockWithTweak(inBlock,xorBlock,outBlock,Tweak,TweakLength);
	else
		throw(CryptoPP::InvalidState(this->GetAlgorithm().AlgorithmName()));
}

unsigned int Threefish::Base::BlockSize() const
{
	if(m_Instance.get())
		return m_Instance->BlockSize();
	else
		throw(CryptoPP::InvalidState(this->GetAlgorithm().AlgorithmName()));
}

size_t Threefish::Base::GetValidKeyLength(size_t n) const
{
	if(n<=32)
		return 32;
	else if(n<=64)
		return 64;
	else
		return 128;
}

#endif

NAMESPACE_END
