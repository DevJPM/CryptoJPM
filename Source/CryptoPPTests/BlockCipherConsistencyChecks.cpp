#include "stdafx.h"
#include "CppUnitTest.h"

using namespace CryptoPP;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace CryptoPPTests
{	
	template<class CIPHER> void RunConsistencyCheckBlockCipher(const unsigned int Keylength,const unsigned int IVLength,const unsigned int TestByteCount)
	{
#define TEST_MACRO_ECB(Abbr) \
	std::shared_ptr<Abbr##_Mode<CIPHER>::Encryption> Encryptor##Abbr(new Abbr##_Mode<CIPHER>::Encryption(Key,Keylength));\
	std::shared_ptr<Abbr##_Mode<CIPHER>::Decryption> Decryptor##Abbr(new Abbr##_Mode<CIPHER>::Decryption(Key,Keylength));\
	Encryptor##Abbr->ProcessData(IntermediateBuffer,InBuffer,TestByteCount);\
	Decryptor##Abbr->ProcessData(CompareBuffer,IntermediateBuffer,TestByteCount);\
	Assert::IsTrue(memcmp(InBuffer,CompareBuffer,TestByteCount)==0,L#Abbr,LINE_INFO())
#define TEST_MACRO(Abbr) \
	std::shared_ptr<Abbr##_Mode<CIPHER>::Encryption> Encryptor##Abbr(new Abbr##_Mode<CIPHER>::Encryption(Key,Keylength,IV));\
	std::shared_ptr<Abbr##_Mode<CIPHER>::Decryption> Decryptor##Abbr(new Abbr##_Mode<CIPHER>::Decryption(Key,Keylength,IV));\
	Encryptor##Abbr->ProcessData(IntermediateBuffer,InBuffer,TestByteCount);\
	Decryptor##Abbr->ProcessData(CompareBuffer,IntermediateBuffer,TestByteCount);\
	Assert::IsTrue(memcmp(InBuffer,CompareBuffer,TestByteCount)==0,L#Abbr,LINE_INFO())

			SecByteBlock IV(IVLength);
			SecByteBlock Key(Keylength);
			SecByteBlock InBuffer(TestByteCount);
			SecByteBlock IntermediateBuffer(TestByteCount);
			SecByteBlock CompareBuffer(TestByteCount);

			AutoSeededRandomPool RNG;
			RNG.GenerateBlock(InBuffer,TestByteCount);
			RNG.GenerateBlock(IV,IVLength);
			RNG.GenerateBlock(Key,Keylength);

			TEST_MACRO_ECB(ECB);
			TEST_MACRO(OFB);
			TEST_MACRO(CTR);
			TEST_MACRO(CFB);			
			TEST_MACRO(CBC);

#undef TEST_MACRO
#undef TEST_MACRO_ECB
	}

	TEST_CLASS(BlockCipherConsistencyChecks)
	{
	public:
		
		TEST_METHOD(AESConsistency)
		{
			RunConsistencyCheckBlockCipher<AES>(16,16,1024);
			RunConsistencyCheckBlockCipher<AES>(24,16,1024);
			RunConsistencyCheckBlockCipher<AES>(32,16,1024);
		}
		TEST_METHOD(SerpentConsistency)
		{
			RunConsistencyCheckBlockCipher<Serpent>(16,16,1024);
			RunConsistencyCheckBlockCipher<Serpent>(24,16,1024);
			RunConsistencyCheckBlockCipher<Serpent>(32,16,1024);
		}
		TEST_METHOD(TwofishConsistency)
		{
			RunConsistencyCheckBlockCipher<Twofish>(16,16,1024);
			RunConsistencyCheckBlockCipher<Twofish>(24,16,1024);
			RunConsistencyCheckBlockCipher<Twofish>(32,16,1024);
		}
		TEST_METHOD(MARSConsistency)
		{
			RunConsistencyCheckBlockCipher<MARS>(16,16,1024);
			RunConsistencyCheckBlockCipher<MARS>(24,16,1024);
			RunConsistencyCheckBlockCipher<MARS>(32,16,1024);
		}
		TEST_METHOD(RC6Consistency)
		{
			RunConsistencyCheckBlockCipher<RC6>(16,16,1024);
			RunConsistencyCheckBlockCipher<RC6>(24,16,1024);
			RunConsistencyCheckBlockCipher<RC6>(32,16,1024);
		}
		TEST_METHOD(CAST256Consistency)
		{
			RunConsistencyCheckBlockCipher<CAST256>(16,16,1024);
			RunConsistencyCheckBlockCipher<CAST256>(24,16,1024);
			RunConsistencyCheckBlockCipher<CAST256>(32,16,1024);
		}
		TEST_METHOD(IDEAConsistency)
		{
			RunConsistencyCheckBlockCipher<IDEA>(16,8,1024);
		}
		TEST_METHOD(CamelliaConsistency)
		{
			RunConsistencyCheckBlockCipher<Camellia>(16,16,1024);
			RunConsistencyCheckBlockCipher<Camellia>(24,16,1024);
			RunConsistencyCheckBlockCipher<Camellia>(32,16,1024);
		}
		TEST_METHOD(SEEDConsistency)
		{
			RunConsistencyCheckBlockCipher<SEED>(16,16,1024);
		}
		TEST_METHOD(RC5Consistency)
		{
			RunConsistencyCheckBlockCipher<RC5>(16,8,1024);
			RunConsistencyCheckBlockCipher<RC5>(24,8,1024);
			RunConsistencyCheckBlockCipher<RC5>(32,8,1024);
		}
		TEST_METHOD(BlowfishConsistency)
		{
			RunConsistencyCheckBlockCipher<Blowfish>(16,8,1024);
			RunConsistencyCheckBlockCipher<Blowfish>(24,8,1024);
			RunConsistencyCheckBlockCipher<Blowfish>(32,8,1024);
			RunConsistencyCheckBlockCipher<Blowfish>(56,8,1024);
		}
		TEST_METHOD(TEAConsistency)
		{
			RunConsistencyCheckBlockCipher<TEA>(16,8,1024);
		}
		TEST_METHOD(XTEAConsistency)
		{
			RunConsistencyCheckBlockCipher<XTEA>(16,8,1024);
		}
		TEST_METHOD(SkipjackConsistency)
		{
			RunConsistencyCheckBlockCipher<SKIPJACK>(10,8,1024);
		}
		TEST_METHOD(SHACAL2Consistency)
		{
			RunConsistencyCheckBlockCipher<SHACAL2>(16,32,1024);
			RunConsistencyCheckBlockCipher<SHACAL2>(32,32,1024);
			RunConsistencyCheckBlockCipher<SHACAL2>(64,32,1024);
		}
		TEST_METHOD(ThreefishExplicitConsistency)
		{
			RunConsistencyCheckBlockCipher<Threefish_256>(32,32,1024);
			RunConsistencyCheckBlockCipher<Threefish_512>(64,64,1024);
			RunConsistencyCheckBlockCipher<Threefish_1024>(128,128,1024);
		}
		/*TEST_METHOD(ThreefishConsistency)
		{
			RunConsistencyCheckBlockCipher<Threefish>(32,32,1024,false);
			RunConsistencyCheckBlockCipher<Threefish>(64,64,1024,false);
			RunConsistencyCheckBlockCipher<Threefish>(128,128,1024,false);
		}*/
		TEST_METHOD(CAST128Consistency)
		{
			RunConsistencyCheckBlockCipher<CAST128>(5,8,1024);
			RunConsistencyCheckBlockCipher<CAST128>(8,8,1024);
			RunConsistencyCheckBlockCipher<CAST128>(16,8,1024);
		}

	};
}