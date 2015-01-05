// Threefis.h - written and placed in the public domain by Jean-Pierre Muench
#ifndef CRYPTOPP_THREEFISH_H
#define CRYPTOPP_THREEFISH_H

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

struct Threefish256_Info : public FixedKeyLength<32>, public FixedBlockSize<32>, public FixedRounds<72>, public FixedTweakLength<16>
{
	static const char* StaticAlgorithmName() {return "Threefish-256";}
};

struct Threefish512_Info : public FixedKeyLength<64>, public FixedBlockSize<64>, public FixedRounds<72>, public FixedTweakLength<16>
{
	static const char* StaticAlgorithmName() {return "Threefish-512";}
};

struct Threefish1024_Info : public FixedKeyLength<128>, public FixedBlockSize<128>, public FixedRounds<80>, public FixedTweakLength<16>
{
	static const char* StaticAlgorithmName() {return "Threefish-1024";}
};

#ifdef CRYPTOPP_USE_DYNAMIC_THREEFISH
//! NOTE: BLOCKSIZE IS ONLY DUMMY, FUNCTION WILL BE OVERWRITTEN IN IMPLEMENTATION
struct Threefish_Info : public VariableKeyLength<64,32,128,32>, public FixedTweakLength<16>, public FixedBlockSize<64>
{
	static const char* StaticAlgorithmName() {return "Threefish";}
};
#endif

class Threefish_256 : public Threefish256_Info, public TweakableBlockCipherDocumentation
{
	class CRYPTOPP_NO_VTABLE Base : public TweakableBlockCipherImpl<Threefish256_Info>
	{
	public:
		void UncheckedSetKey(const byte *userKey, unsigned int length, const NameValuePairs &params);

	protected:
		FixedSizeSecBlock<word64, 5> m_key;
	};
	class CRYPTOPP_NO_VTABLE Enc : public Base
	{
		void ThreefishEncrypt256(word64* input, word64* output,word64* tweak) const;
	public:
		void ProcessAndXorBlockWithTweak(const byte *inBlock, const byte *xorBlock, byte *outBlock,const byte* Tweak,const size_t TweakLength) const;
	};
	class CRYPTOPP_NO_VTABLE Dec : public Base
	{
		void ThreefishDecrypt256(word64* input, word64* output,word64* tweak) const;
	public:
		void ProcessAndXorBlockWithTweak(const byte *inBlock, const byte *xorBlock, byte *outBlock,const byte* Tweak,const size_t TweakLength) const;
	};
public:
	typedef TweakableBlockCipherFinal<ENCRYPTION,Enc> Encryption;
	typedef TweakableBlockCipherFinal<DECRYPTION,Dec> Decryption;
};

class Threefish_512 : public Threefish512_Info, public TweakableBlockCipherDocumentation
{
	class CRYPTOPP_NO_VTABLE Base : public TweakableBlockCipherImpl<Threefish512_Info>
	{
	public:
		void UncheckedSetKey(const byte *userKey, unsigned int length, const NameValuePairs &params);

	protected:
		FixedSizeSecBlock<word64, 9> m_key;
	};
	class CRYPTOPP_NO_VTABLE Enc : public Base
	{
		void ThreefishEncrypt512(word64* input, word64* output,word64* tweak) const;
	public:
		void ProcessAndXorBlockWithTweak(const byte *inBlock, const byte *xorBlock, byte *outBlock,const byte* Tweak,const size_t TweakLength) const;
	};
	class CRYPTOPP_NO_VTABLE Dec : public Base
	{
		void ThreefishDecrypt512(word64* input, word64* output,word64* tweak) const;
	public:
		void ProcessAndXorBlockWithTweak(const byte *inBlock, const byte *xorBlock, byte *outBlock,const byte* Tweak,const size_t TweakLength) const;
	};
public:
	typedef TweakableBlockCipherFinal<ENCRYPTION,Enc> Encryption;
	typedef TweakableBlockCipherFinal<DECRYPTION,Dec> Decryption;
};

class Threefish_1024 : public Threefish1024_Info, public TweakableBlockCipherDocumentation
{
	class CRYPTOPP_NO_VTABLE Base : public TweakableBlockCipherImpl<Threefish1024_Info>
	{
	public:
		void UncheckedSetKey(const byte *userKey, unsigned int length, const NameValuePairs &params);

	protected:
		FixedSizeSecBlock<word64, 17> m_key;
	};
	class CRYPTOPP_NO_VTABLE Enc : public Base
	{
		void ThreefishEncrypt1024(word64* input, word64* output,word64* tweak) const;
	public:
		void ProcessAndXorBlockWithTweak(const byte *inBlock, const byte *xorBlock, byte *outBlock,const byte* Tweak,const size_t TweakLength) const;
	};
	class CRYPTOPP_NO_VTABLE Dec : public Base
	{
		void ThreefishDecrypt1024(word64* input, word64* output,word64* tweak) const;
	public:
		void ProcessAndXorBlockWithTweak(const byte *inBlock, const byte *xorBlock, byte *outBlock,const byte* Tweak,const size_t TweakLength) const;
	};
public:
	typedef TweakableBlockCipherFinal<ENCRYPTION,Enc> Encryption;
	typedef TweakableBlockCipherFinal<DECRYPTION,Dec> Decryption;
};

#ifdef CRYPTOPP_USE_DYNAMIC_THREEFISH
//! avoid usage of this class, unless absouletely neccessary
//! you can not query block size before setting the key
//! this class is incompatible with all modes that require an IV (-> all good modes)
class Threefish : public Threefish_Info, public TweakableBlockCipherDocumentation
{
	class CRYPTOPP_NO_VTABLE Base : public TweakableBlockCipherImpl<Threefish1024_Info>
	{
	public:
		void UncheckedSetKey(const byte *userKey, unsigned int length, const NameValuePairs &params);
		void ProcessAndXorBlockWithTweak(const byte *inBlock, const byte *xorBlock, byte *outBlock,const byte* Tweak,const size_t TweakLength) const;
		size_t GetValidKeyLength(size_t n)const;
		unsigned int BlockSize() const;
	protected:
		std::shared_ptr<TweakableBlockCipher> m_Instance;
	};
public:
public:
	typedef TweakableBlockCipherFinal<ENCRYPTION,Base> Encryption;
	typedef TweakableBlockCipherFinal<DECRYPTION,Base> Decryption;
};
#endif

NAMESPACE_END

#endif