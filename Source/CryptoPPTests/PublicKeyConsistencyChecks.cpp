#include "stdafx.h"
#include "CppUnitTest.h"

using namespace CryptoPP;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace CryptoPPTests
{
	template<class EC, class COFACTOR_OPTION,class HASH,class KDF,bool DHAES_MODE> void ECIESCheck(const OID& CurveID)
	{
		AutoSeededRandomPool RNG;
		std::shared_ptr<ECIES<EC,COFACTOR_OPTION,DHAES_MODE,HASH,KDF>::Decryptor> Decryptor(new ECIES<EC,COFACTOR_OPTION,DHAES_MODE,HASH,KDF>::Decryptor(RNG,CurveID));
		std::shared_ptr<ECIES<EC,COFACTOR_OPTION,DHAES_MODE,HASH,KDF>::Encryptor> Encryptor(new ECIES<EC,COFACTOR_OPTION,DHAES_MODE,HASH,KDF>::Encryptor(*Decryptor));

		const unsigned int BufferSize = 4096;

		SecByteBlock InBuffer(BufferSize);
		SecByteBlock IntermediateBuffer(Encryptor->CiphertextLength(BufferSize));
		SecByteBlock OutBuffer(Decryptor->MaxPlaintextLength(Encryptor->CiphertextLength(BufferSize)));

		RNG.GenerateBlock(InBuffer,BufferSize);
		
		Encryptor->Encrypt(RNG,InBuffer,BufferSize,IntermediateBuffer);
		Decryptor->Decrypt(RNG,IntermediateBuffer,Encryptor->CiphertextLength(BufferSize),OutBuffer);

		Assert::IsTrue(memcmp(InBuffer,OutBuffer,Decryptor->MaxPlaintextLength(Encryptor->CiphertextLength(BufferSize)))==0,L"",LINE_INFO());
	}

	TEST_CLASS(PublicKeyConsistencyChecks)
	{
	public:
		
		TEST_METHOD(ECIESChecks)
		{
			ECIESCheck<ECP,NoCofactorMultiplication,SHA1,P1363_KDF2<SHA1>,true>(ASN1::secp256r1());
			ECIESCheck<ECP,NoCofactorMultiplication,SHA1,P1363_KDF2<SHA1>,false>(ASN1::secp256r1());
			ECIESCheck<EC2N,NoCofactorMultiplication,SHA1,P1363_KDF2<SHA1>,true>(ASN1::sect283r1());
			ECIESCheck<EC2N,NoCofactorMultiplication,SHA1,P1363_KDF2<SHA1>,false>(ASN1::sect283r1());
			ECIESCheck<ECP,IncompatibleCofactorMultiplication,SHA1,P1363_KDF2<SHA1>,true>(ASN1::secp256r1());
			ECIESCheck<ECP,IncompatibleCofactorMultiplication,SHA1,P1363_KDF2<SHA1>,false>(ASN1::secp256r1());
			ECIESCheck<EC2N,IncompatibleCofactorMultiplication,SHA1,P1363_KDF2<SHA1>,true>(ASN1::sect283r1());
			ECIESCheck<EC2N,IncompatibleCofactorMultiplication,SHA1,P1363_KDF2<SHA1>,false>(ASN1::sect283r1());

			ECIESCheck<ECP,NoCofactorMultiplication,SHA256,P1363_KDF2<SHA256>,true>(ASN1::secp256r1());
			ECIESCheck<ECP,NoCofactorMultiplication,SHA256,P1363_KDF2<SHA256>,false>(ASN1::secp256r1());
			ECIESCheck<EC2N,NoCofactorMultiplication,SHA256,P1363_KDF2<SHA256>,true>(ASN1::sect283r1());
			ECIESCheck<EC2N,NoCofactorMultiplication,SHA256,P1363_KDF2<SHA256>,false>(ASN1::sect283r1());
			ECIESCheck<ECP,IncompatibleCofactorMultiplication,SHA256,P1363_KDF2<SHA256>,true>(ASN1::secp256r1());
			ECIESCheck<ECP,IncompatibleCofactorMultiplication,SHA256,P1363_KDF2<SHA256>,false>(ASN1::secp256r1());
			ECIESCheck<EC2N,IncompatibleCofactorMultiplication,SHA256,P1363_KDF2<SHA256>,true>(ASN1::sect283r1());
			ECIESCheck<EC2N,IncompatibleCofactorMultiplication,SHA256,P1363_KDF2<SHA256>,false>(ASN1::sect283r1());

			ECIESCheck<ECP,NoCofactorMultiplication,SHA3_256,P1363_KDF2<SHA3_256>,true>(ASN1::secp256r1());
			ECIESCheck<ECP,NoCofactorMultiplication,SHA3_256,P1363_KDF2<SHA3_256>,false>(ASN1::secp256r1());
			ECIESCheck<EC2N,NoCofactorMultiplication,SHA3_256,P1363_KDF2<SHA3_256>,true>(ASN1::sect283r1());
			ECIESCheck<EC2N,NoCofactorMultiplication,SHA3_256,P1363_KDF2<SHA3_256>,false>(ASN1::sect283r1());
			ECIESCheck<ECP,IncompatibleCofactorMultiplication,SHA3_256,P1363_KDF2<SHA3_256>,true>(ASN1::secp256r1());
			ECIESCheck<ECP,IncompatibleCofactorMultiplication,SHA3_256,P1363_KDF2<SHA3_256>,false>(ASN1::secp256r1());
			ECIESCheck<EC2N,IncompatibleCofactorMultiplication,SHA3_256,P1363_KDF2<SHA3_256>,true>(ASN1::sect283r1());
			ECIESCheck<EC2N,IncompatibleCofactorMultiplication,SHA3_256,P1363_KDF2<SHA3_256>,false>(ASN1::sect283r1());
		}

	};
}