// validat2.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "blumshub.h"
#include "rsa.h"
#include "md2.h"
#include "elgamal.h"
#include "nr.h"
#include "dsa.h"
#include "dh.h"
#include "mqv.h"
#include "fhmqv.h"
#include "luc.h"
#include "xtrcrypt.h"
#include "rabin.h"
#include "rw.h"
#include "eccrypto.h"
#include "ecp.h"
#include "ec2n.h"
#include "asn.h"
#include "rng.h"
#include "files.h"
#include "hex.h"
#include "oids.h"
#include "esign.h"
#include "osrng.h"

#include <iostream>
#include <iomanip>

#include "validate.h"

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

class FixedRNG : public RandomNumberGenerator
{
public:
	FixedRNG(BufferedTransformation &source) : m_source(source) {}

	void GenerateBlock(byte *output, size_t size)
	{
		m_source.Get(output, size);
	}

private:
	BufferedTransformation &m_source;
};

bool ValidateBBS()
{
	cout << "\nBlumBlumShub validation suite running...\n\n";

	Integer p("212004934506826557583707108431463840565872545889679278744389317666981496005411448865750399674653351");
	Integer q("100677295735404212434355574418077394581488455772477016953458064183204108039226017738610663984508231");
	Integer seed("63239752671357255800299643604761065219897634268887145610573595874544114193025997412441121667211431");
	BlumBlumShub bbs(p, q, seed);
	bool pass = true, fail;
	int j;

	const byte output1[] = {
		0x49,0xEA,0x2C,0xFD,0xB0,0x10,0x64,0xA0,0xBB,0xB9,
		0x2A,0xF1,0x01,0xDA,0xC1,0x8A,0x94,0xF7,0xB7,0xCE};
	const byte output2[] = {
		0x74,0x45,0x48,0xAE,0xAC,0xB7,0x0E,0xDF,0xAF,0xD7,
		0xD5,0x0E,0x8E,0x29,0x83,0x75,0x6B,0x27,0x46,0xA1};

	byte buf[20];

	bbs.GenerateBlock(buf, 20);
	fail = memcmp(output1, buf, 20) != 0;
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	for (j=0;j<20;j++)
		cout << setw(2) << setfill('0') << hex << (int)buf[j];
	cout << endl;

	bbs.Seek(10);
	bbs.GenerateBlock(buf, 10);
	fail = memcmp(output1+10, buf, 10) != 0;
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	for (j=0;j<10;j++)
		cout << setw(2) << setfill('0') << hex << (int)buf[j];
	cout << endl;

	bbs.Seek(1234567);
	bbs.GenerateBlock(buf, 20);
	fail = memcmp(output2, buf, 20) != 0;
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	for (j=0;j<20;j++)
		cout << setw(2) << setfill('0') << hex << (int)buf[j];
	cout << endl;

	return pass;
}

bool SignatureValidate(PK_Signer &priv, PK_Verifier &pub, bool thorough = false)
{
	bool pass = true, fail;

	fail = !pub.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2) || !priv.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "signature key validation\n";

	const byte *message = (byte *)"test message";
	const int messageLen = 12;

	SecByteBlock signature(priv.MaxSignatureLength());
	size_t signatureLength = priv.SignMessage(GlobalRNG(), message, messageLen, signature);
	fail = !pub.VerifyMessage(message, messageLen, signature, signatureLength);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "signature and verification\n";

	++signature[0];
	fail = pub.VerifyMessage(message, messageLen, signature, signatureLength);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "checking invalid signature" << endl;

	if (priv.MaxRecoverableLength() > 0)
	{
		signatureLength = priv.SignMessageWithRecovery(GlobalRNG(), message, messageLen, NULL, 0, signature);
		SecByteBlock recovered(priv.MaxRecoverableLengthFromSignatureLength(signatureLength));
		DecodingResult result = pub.RecoverMessage(recovered, NULL, 0, signature, signatureLength);
		fail = !(result.isValidCoding && result.messageLength == messageLen && memcmp(recovered, message, messageLen) == 0);
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "signature and verification with recovery" << endl;

		++signature[0];
		result = pub.RecoverMessage(recovered, NULL, 0, signature, signatureLength);
		fail = result.isValidCoding;
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "recovery with invalid signature" << endl;
	}

	return pass;
}

bool CryptoSystemValidate(PK_Decryptor &priv, PK_Encryptor &pub, bool thorough = false)
{
	bool pass = true, fail;

	fail = !pub.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2) || !priv.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "cryptosystem key validation\n";

	const byte *message = (byte *)"test message";
	const int messageLen = 12;
	SecByteBlock ciphertext(priv.CiphertextLength(messageLen));
	SecByteBlock plaintext(priv.MaxPlaintextLength(ciphertext.size()));

	pub.Encrypt(GlobalRNG(), message, messageLen, ciphertext);
	fail = priv.Decrypt(GlobalRNG(), ciphertext, priv.CiphertextLength(messageLen), plaintext) != DecodingResult(messageLen);
	fail = fail || memcmp(message, plaintext, messageLen);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "encryption and decryption\n";

	return pass;
}

bool SimpleKeyAgreementValidate(SimpleKeyAgreementDomain &d)
{
	if (d.GetCryptoParameters().Validate(GlobalRNG(), 3))
		cout << "passed    simple key agreement domain parameters validation" << endl;
	else
	{
		cout << "FAILED    simple key agreement domain parameters invalid" << endl;
		return false;
	}

	SecByteBlock priv1(d.PrivateKeyLength()), priv2(d.PrivateKeyLength());
	SecByteBlock pub1(d.PublicKeyLength()), pub2(d.PublicKeyLength());
	SecByteBlock val1(d.AgreedValueLength()), val2(d.AgreedValueLength());

	d.GenerateKeyPair(GlobalRNG(), priv1, pub1);
	d.GenerateKeyPair(GlobalRNG(), priv2, pub2);

	memset(val1.begin(), 0x10, val1.size());
	memset(val2.begin(), 0x11, val2.size());

	if (!(d.Agree(val1, priv1, pub2) && d.Agree(val2, priv2, pub1)))
	{
		cout << "FAILED    simple key agreement failed" << endl;
		return false;
	}

	if (memcmp(val1.begin(), val2.begin(), d.AgreedValueLength()))
	{
		cout << "FAILED    simple agreed values not equal" << endl;
		return false;
	}

	cout << "passed    simple key agreement" << endl;
	return true;
}

bool AuthenticatedKeyAgreementValidate(AuthenticatedKeyAgreementDomain &d)
{
	if (d.GetCryptoParameters().Validate(GlobalRNG(), 3))
		cout << "passed    authenticated key agreement domain parameters validation" << endl;
	else
	{
		cout << "FAILED    authenticated key agreement domain parameters invalid" << endl;
		return false;
	}

	SecByteBlock spriv1(d.StaticPrivateKeyLength()), spriv2(d.StaticPrivateKeyLength());
	SecByteBlock epriv1(d.EphemeralPrivateKeyLength()), epriv2(d.EphemeralPrivateKeyLength());
	SecByteBlock spub1(d.StaticPublicKeyLength()), spub2(d.StaticPublicKeyLength());
	SecByteBlock epub1(d.EphemeralPublicKeyLength()), epub2(d.EphemeralPublicKeyLength());
	SecByteBlock val1(d.AgreedValueLength()), val2(d.AgreedValueLength());

	d.GenerateStaticKeyPair(GlobalRNG(), spriv1, spub1);
	d.GenerateStaticKeyPair(GlobalRNG(), spriv2, spub2);
	d.GenerateEphemeralKeyPair(GlobalRNG(), epriv1, epub1);
	d.GenerateEphemeralKeyPair(GlobalRNG(), epriv2, epub2);

	memset(val1.begin(), 0x10, val1.size());
	memset(val2.begin(), 0x11, val2.size());

	if (!(d.Agree(val1, spriv1, epriv1, spub2, epub2) && d.Agree(val2, spriv2, epriv2, spub1, epub1)))
	{
		cout << "FAILED    authenticated key agreement failed" << endl;
		return false;
	}

	if (memcmp(val1.begin(), val2.begin(), d.AgreedValueLength()))
	{
		cout << "FAILED    authenticated agreed values not equal" << endl;
		return false;
	}

	cout << "passed    authenticated key agreement" << endl;
	return true;
}

bool ValidateRSA()
{
	cout << "\nRSA validation suite running...\n\n";

	byte out[100], outPlain[100];
	bool pass = true, fail;

	{
		const char *plain = "Everyone gets Friday off.";
		byte *signature = (byte *)
			"\x05\xfa\x6a\x81\x2f\xc7\xdf\x8b\xf4\xf2\x54\x25\x09\xe0\x3e\x84"
			"\x6e\x11\xb9\xc6\x20\xbe\x20\x09\xef\xb4\x40\xef\xbc\xc6\x69\x21"
			"\x69\x94\xac\x04\xf3\x41\xb5\x7d\x05\x20\x2d\x42\x8f\xb2\xa2\x7b"
			"\x5c\x77\xdf\xd9\xb1\x5b\xfc\x3d\x55\x93\x53\x50\x34\x10\xc1\xe1";

		FileSource keys("TestData/rsa512a.dat", true, new HexDecoder);
		Weak::RSASSA_PKCS1v15_MD2_Signer rsaPriv(keys);
		Weak::RSASSA_PKCS1v15_MD2_Verifier rsaPub(rsaPriv);

		size_t signatureLength = rsaPriv.SignMessage(GlobalRNG(), (byte *)plain, strlen(plain), out);
		fail = memcmp(signature, out, 64) != 0;
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "signature check against test vector\n";

		fail = !rsaPub.VerifyMessage((byte *)plain, strlen(plain), out, signatureLength);
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "verification check against test vector\n";

		out[10]++;
		fail = rsaPub.VerifyMessage((byte *)plain, strlen(plain), out, signatureLength);
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "invalid signature verification\n";
	}
	{
		FileSource keys("TestData/rsa1024.dat", true, new HexDecoder);
		RSAES_PKCS1v15_Decryptor rsaPriv(keys);
		RSAES_PKCS1v15_Encryptor rsaPub(rsaPriv);

		pass = CryptoSystemValidate(rsaPriv, rsaPub) && pass;
	}
	{
		RSAES<OAEP<SHA> >::Decryptor rsaPriv(GlobalRNG(), 512);
		RSAES<OAEP<SHA> >::Encryptor rsaPub(rsaPriv);

		pass = CryptoSystemValidate(rsaPriv, rsaPub) && pass;
	}
	{
		byte *plain = (byte *)
			"\x54\x85\x9b\x34\x2c\x49\xea\x2a";
		byte *encrypted = (byte *)
			"\x14\xbd\xdd\x28\xc9\x83\x35\x19\x23\x80\xe8\xe5\x49\xb1\x58\x2a"
			"\x8b\x40\xb4\x48\x6d\x03\xa6\xa5\x31\x1f\x1f\xd5\xf0\xa1\x80\xe4"
			"\x17\x53\x03\x29\xa9\x34\x90\x74\xb1\x52\x13\x54\x29\x08\x24\x52"
			"\x62\x51";
		byte *oaepSeed = (byte *)
			"\xaa\xfd\x12\xf6\x59\xca\xe6\x34\x89\xb4\x79\xe5\x07\x6d\xde\xc2"
			"\xf0\x6c\xb5\x8f";
		ByteQueue bq;
		bq.Put(oaepSeed, 20);
		FixedRNG rng(bq);

		FileSource privFile("TestData/rsa400pv.dat", true, new HexDecoder);
		FileSource pubFile("TestData/rsa400pb.dat", true, new HexDecoder);
		RSAES_OAEP_SHA_Decryptor rsaPriv;
		rsaPriv.AccessKey().BERDecodePrivateKey(privFile, false, 0);
		RSAES_OAEP_SHA_Encryptor rsaPub(pubFile);

		memset(out, 0, 50);
		memset(outPlain, 0, 8);
		rsaPub.Encrypt(rng, plain, 8, out);
		DecodingResult result = rsaPriv.FixedLengthDecrypt(GlobalRNG(), encrypted, outPlain);
		fail = !result.isValidCoding || (result.messageLength!=8) || memcmp(out, encrypted, 50) || memcmp(plain, outPlain, 8);
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "PKCS 2.0 encryption and decryption\n";
	}

	return pass;
}

bool ValidateDH()
{
	cout << "\nDH validation suite running...\n\n";

	FileSource f("TestData/dh1024.dat", true, new HexDecoder());
	DH dh(f);
	return SimpleKeyAgreementValidate(dh);
}

bool ValidateMQV()
{
	cout << "\nMQV validation suite running...\n\n";

	FileSource f("TestData/mqv1024.dat", true, new HexDecoder());
	MQV mqv(f);
	return AuthenticatedKeyAgreementValidate(mqv);
}

bool ValidateLUC_DH()
{
	cout << "\nLUC-DH validation suite running...\n\n";

	FileSource f("TestData/lucd512.dat", true, new HexDecoder());
	LUC_DH dh(f);
	return SimpleKeyAgreementValidate(dh);
}

bool ValidateXTR_DH()
{
	cout << "\nXTR-DH validation suite running...\n\n";

	FileSource f("TestData/xtrdh171.dat", true, new HexDecoder());
	XTR_DH dh(f);
	return SimpleKeyAgreementValidate(dh);
}

bool ValidateElGamal()
{
	cout << "\nElGamal validation suite running...\n\n";
	bool pass = true;
	{
		FileSource fc("TestData/elgc1024.dat", true, new HexDecoder);
		ElGamalDecryptor privC(fc);
		ElGamalEncryptor pubC(privC);
		privC.AccessKey().Precompute();
		ByteQueue queue;
		privC.AccessKey().SavePrecomputation(queue);
		privC.AccessKey().LoadPrecomputation(queue);

		pass = CryptoSystemValidate(privC, pubC) && pass;
	}
	return pass;
}

bool ValidateDLIES()
{
	cout << "\nDLIES validation suite running...\n\n";
	bool pass = true;
	{
		FileSource fc("TestData/dlie1024.dat", true, new HexDecoder);
		DLIES<>::Decryptor privC(fc);
		DLIES<>::Encryptor pubC(privC);
		pass = CryptoSystemValidate(privC, pubC) && pass;
	}
	{
		cout << "Generating new encryption key..." << endl;
		DLIES<>::GroupParameters gp;
		gp.GenerateRandomWithKeySize(GlobalRNG(), 128);
		DLIES<>::Decryptor decryptor;
		decryptor.AccessKey().GenerateRandom(GlobalRNG(), gp);
		DLIES<>::Encryptor encryptor(decryptor);

		pass = CryptoSystemValidate(decryptor, encryptor) && pass;
	}
	return pass;
}

bool ValidateNR()
{
	cout << "\nNR validation suite running...\n\n";
	bool pass = true;
	{
		FileSource f("TestData/nr2048.dat", true, new HexDecoder);
		NR<SHA>::Signer privS(f);
		privS.AccessKey().Precompute();
		NR<SHA>::Verifier pubS(privS);

		pass = SignatureValidate(privS, pubS) && pass;
	}
	{
		cout << "Generating new signature key..." << endl;
		NR<SHA>::Signer privS(GlobalRNG(), 256);
		NR<SHA>::Verifier pubS(privS);

		pass = SignatureValidate(privS, pubS) && pass;
	}
	return pass;
}

bool ValidateDSA(bool thorough)
{
	cout << "\nDSA validation suite running...\n\n";

	bool pass = true;
	FileSource fs1("TestData/dsa1024.dat", true, new HexDecoder());
	DSA::Signer priv(fs1);
	DSA::Verifier pub(priv);
	FileSource fs2("TestData/dsa1024b.dat", true, new HexDecoder());
	DSA::Verifier pub1(fs2);
	assert(pub.GetKey() == pub1.GetKey());
	pass = SignatureValidate(priv, pub, thorough) && pass;
	pass = RunTestDataFile("TestVectors/dsa.txt", g_nullNameValuePairs, thorough) && pass;
	return pass;
}

bool ValidateLUC()
{
	cout << "\nLUC validation suite running...\n\n";
	bool pass=true;

	{
		FileSource f("TestData/luc1024.dat", true, new HexDecoder);
		LUCSSA_PKCS1v15_SHA_Signer priv(f);
		LUCSSA_PKCS1v15_SHA_Verifier pub(priv);
		pass = SignatureValidate(priv, pub) && pass;
	}
	{
		LUCES_OAEP_SHA_Decryptor priv(GlobalRNG(), 512);
		LUCES_OAEP_SHA_Encryptor pub(priv);
		pass = CryptoSystemValidate(priv, pub) && pass;
	}
	return pass;
}

bool ValidateLUC_DL()
{
	cout << "\nLUC-HMP validation suite running...\n\n";

	FileSource f("TestData/lucs512.dat", true, new HexDecoder);
	LUC_HMP<SHA>::Signer privS(f);
	LUC_HMP<SHA>::Verifier pubS(privS);
	bool pass = SignatureValidate(privS, pubS);

	cout << "\nLUC-IES validation suite running...\n\n";

	FileSource fc("TestData/lucc512.dat", true, new HexDecoder);
	LUC_IES<>::Decryptor privC(fc);
	LUC_IES<>::Encryptor pubC(privC);
	pass = CryptoSystemValidate(privC, pubC) && pass;

	return pass;
}

bool ValidateRabin()
{
	cout << "\nRabin validation suite running...\n\n";
	bool pass=true;

	{
		FileSource f("TestData/rabi1024.dat", true, new HexDecoder);
		RabinSS<PSSR, SHA>::Signer priv(f);
		RabinSS<PSSR, SHA>::Verifier pub(priv);
		pass = SignatureValidate(priv, pub) && pass;
	}
	{
		RabinES<OAEP<SHA> >::Decryptor priv(GlobalRNG(), 512);
		RabinES<OAEP<SHA> >::Encryptor pub(priv);
		pass = CryptoSystemValidate(priv, pub) && pass;
	}
	return pass;
}

bool ValidateRW()
{
	cout << "\nRW validation suite running...\n\n";

	FileSource f("TestData/rw1024.dat", true, new HexDecoder);
	RWSS<PSSR, SHA>::Signer priv(f);
	RWSS<PSSR, SHA>::Verifier pub(priv);

	return SignatureValidate(priv, pub);
}

/*
bool ValidateBlumGoldwasser()
{
	cout << "\nBlumGoldwasser validation suite running...\n\n";

	FileSource f("TestData/blum512.dat", true, new HexDecoder);
	BlumGoldwasserPrivateKey priv(f);
	BlumGoldwasserPublicKey pub(priv);

	return CryptoSystemValidate(priv, pub);
}
*/

// Sanity check to ensure an OID maps to the expected curve.
template <class EC> struct EcExpectedParameters;

template<> struct EcExpectedParameters<ECP>
{
	OID oid;
	string name;
	string p, a, b;	
};

template<> struct EcExpectedParameters<EC2N>
{
	OID oid;
	string name;
	unsigned int c1, c2, c3, c4, c5;
	string a, b;
};

bool ValidateOIDtoECP()
{
	cout << "\nVerifying OID to ECP curve mappings...\n\n";

	bool pass = true;

	static EcExpectedParameters<ECP> exp[] = {
		{ ASN1::secp192r1(),
			"secp192r1",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
			"64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1" },
		{ ASN1::secp256r1(),
			"secp256r1",
			"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
			"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
			"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B" },
		{ ASN1::brainpoolP160r1(),
			"brainpoolP160r1",
			"E95E4A5F737059DC60DFC7AD95B3D8139515620F",
			"340E7BE2A280EB74E2BE61BADA745D97E8F7C300",
			"1E589A8595423412134FAA2DBDEC95C8D8675E58" },
		{ ASN1::brainpoolP192r1(),
			"brainpoolP192r1",
			"C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297",
			"6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF",
			"469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9" },
		{ ASN1::brainpoolP224r1(),
			"brainpoolP224r1",
			"D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
			"68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43",
			"2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B" },
		{  ASN1::brainpoolP256r1(),
			"brainpoolP256r1",
			"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
			"7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
			"26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6" },
		{ ASN1::brainpoolP320r1(),
			"brainpoolP320r1",
			"D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
			"3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",
			"520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6" },
		{  ASN1::brainpoolP384r1(),
			"brainpoolP384r1",
			"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
			"7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
			"04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11" },
		{  ASN1::brainpoolP512r1(),
			"brainpoolP512r1",
			"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
			"7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
			"3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723" },
		{ ASN1::secp112r1(),
			"secp112r1",
			"DB7C2ABF62E35E668076BEAD208B",
			"DB7C2ABF62E35E668076BEAD2088",
			"659EF8BA043916EEDE8911702B22" },
		{  ASN1::secp112r2(),
			"secp112r2",
			"DB7C2ABF62E35E668076BEAD208B",
			"6127C24C05F38A0AAAF65C0EF02C",
			"51DEF1815DB5ED74FCC34C85D709" },
		{  ASN1::secp160r1(),
			"secp160r1",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC",
			"1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45" },
		{  ASN1::secp160k1(),
			"secp160k1",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73",
			"0000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000007" },
		{ ASN1::secp256k1(),
			"secp256k1",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
			"0000000000000000000000000000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000000000000000000000000000007" },
		{ ASN1::secp128r1(),
			"secp128r1",
			"FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF",
			"FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC",
			"E87579C11079F43DD824993C2CEE5ED3" },
		{ ASN1::secp128r2(),
			"secp128r2",
			"FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF",
			"D6031998D1B3BBFEBF59CC9BBFF9AEE1",
			"5EEEFCA380D02919DC2C6558BB6D8A5D" },
		{  ASN1::secp160r2(),
			"secp160r2",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70",
			"B4E134D3FB59EB8BAB57274904664D5AF50388BA" },
		{  ASN1::secp192k1(),
			"secp192k1",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37",
			"000000000000000000000000000000000000000000000000",
			"000000000000000000000000000000000000000000000003" },
		{  ASN1::secp224k1(),
			"secp224k1",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D",
			"00000000000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000000000000000000000000000005" },
		{ ASN1::secp224r1(),
			"secp224r1",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
			"B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4" },
		{ ASN1::secp384r1(),
			"secp384r1",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
			"B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF" },
		{ ASN1::secp521r1(),
			"secp521r1",
			"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
			"0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00" },
		{ ASN1::wtls6(),
			"wtls6",
			"DB7C2ABF62E35E668076BEAD208B",
			"DB7C2ABF62E35E668076BEAD2088",
			"659EF8BA043916EEDE8911702B22" },
		{ ASN1::wtls7(),
			"wtls7",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC",
			"1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45" },
		{ ASN1::wtls8(),
			"wtls8",
			"FFFFFFFFFFFFFFFFFFFFFFFFFDE7",
			"0000000000000000000000000000",
			"0000000000000000000000000003" },
		{ ASN1::wtls9(),
			"wtls9",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC808F",
			"0000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000003" },
		{ ASN1::wtls10(),
			"wtls10",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC808F",
			"0000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000003" },
		{ ASN1::wtls12(),
			"wtls12",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
			"B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4" }
	};

#if 0
	GlobalRNG().Shuffle(&exp[0], &exp[0] + COUNTOF(exp));
#endif

	for(size_t i = 0; pass && i < COUNTOF(exp); i++)
	{
		StringSource ssP(exp[i].p, true, new HexDecoder);
		StringSource ssA(exp[i].a, true, new HexDecoder);
		StringSource ssB(exp[i].b, true, new HexDecoder);

		ECP::FieldElement p, a, b;
		p.Decode(ssP, (size_t)ssP.MaxRetrievable());
		a.Decode(ssA, (size_t)ssA.MaxRetrievable());
		b.Decode(ssB, (size_t)ssB.MaxRetrievable());

		const ECP::Field field(p);
		const DL_GroupParameters_EC<ECP> params(exp[i].oid);

		bool t1, t2, t3, t4;
		t1 = (field.GetModulus() == params.GetCurve().GetField().GetModulus());
		t2 = (a == params.GetCurve().GetA());
		t3 = (b == params.GetCurve().GetB());
		t4 = (t1 && t2 && t3);	

		cout << ( !(t4) ? "FAILED" : "passed") << "    OID " << exp[i].oid << " to " << exp[i].name << endl;
		pass &= t4;
	}

	return pass;
}

bool ValidateOIDtoEC2N()
{
	cout << "\nVerifying OID to EC2N curve mappings...\n\n";

	bool pass = true;

	static EcExpectedParameters<EC2N> exp[] = {

#ifdef CRYPTOPP_INCLUDE_X9_62_1998_CURVES
		{ ASN1::c2pnb163v1(),
			"c2pnb163v1",
			163, 8, 2, 1, 0,
			"072546B5435234A422E0789675F432C89435DE5242",
			"00C9517D06D5240D3CFF38C74B20B6CD4D6F9DD4D9" },
		{  ASN1::c2pnb163v2(),
			"c2pnb163v2",
			163, 8, 2, 1, 0,
			"0108B39E77C4B108BED981ED0E890E117C511CF072",
			"0667ACEB38AF4E488C407433FFAE4F1C811638DF20" },
		{ ASN1::c2pnb163v3(),
			"c2pnb163v3",
			163, 8, 2, 1, 0,
			"07A526C63D3E25A256A007699F5447E32AE456B50E",
			"03F7061798EB99E238FD6F1BF95B48FEEB4854252B" },
		{ ASN1::c2pnb176w1(),
			"c2pnb176w1",
			176, 43, 2, 1, 0,
			"E4E6DB2995065C407D9D39B8D0967B96704BA8E9C90B",
			"5DDA470ABE6414DE8EC133AE28E9BBD7FCEC0AE0FFF2" },
#endif
		{ ASN1::c2tnb191v1(),
			"c2tnb191v1",
			0, 0, 191, 9, 0,
			"2866537B676752636A68F56554E12640276B649EF7526267",
			"2E45EF571F00786F67B0081B9495A3D95462F5DE0AA185EC" },
		{ ASN1::c2tnb191v2(),
			"c2tnb191v2",
			0, 0, 191, 9, 0,
			"401028774D7777C7B7666D1366EA432071274F89FF01E718",
			"0620048D28BCBD03B6249C99182B7C8CD19700C362C46A01" },
		{ ASN1::c2tnb191v3(),
			"c2tnb191v3",
			0, 0, 191, 9, 0,
			"6C01074756099122221056911C77D77E77A777E7E7E77FCB",
			"71FE1AF926CF847989EFEF8DB459F66394D90F32AD3F15E8" },

#ifdef CRYPTOPP_INCLUDE_X9_62_1998_CURVES
		{ ASN1::c2pnb208w1(),
			"c2pnb208w1",
			208, 83, 2, 1, 0,
			"0000000000000000000000000000000000000000000000000000",
			"C8619ED45A62E6212E1160349E2BFA844439FAFC2A3FD1638F9E" },
#endif

		{ ASN1::c2tnb239v1(),
			"c2tnb239v1",
			0, 0, 239, 36, 0,
			"32010857077C5431123A46B808906756F543423E8D27877578125778AC76",
			"790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16" },
		{  ASN1::c2tnb239v2(),
			"c2tnb239v2",
			0, 0, 239, 36, 0,
			"4230017757A767FAE42398569B746325D45313AF0766266479B75654E65F",
			"5037EA654196CFF0CD82B2C14A2FCF2E3FF8775285B545722F03EACDB74B" },
		{  ASN1::c2tnb239v3(),
			"c2tnb239v3",
			0, 0, 239, 36, 0,
			"01238774666A67766D6676F778E676B66999176666E687666D8766C66A9F",
			"6A941977BA9F6A435199ACFC51067ED587F519C5ECB541B8E44111DE1D40" },

#ifdef CRYPTOPP_INCLUDE_X9_62_1998_CURVES
		{  ASN1::c2pnb272w1(),
			"c2pnb272w1",
			272, 56, 3, 1, 0,
			"91A091F03B5FBA4AB2CCF49C4EDD220FB028712D42BE752B2C40094DBACDB586FB20",
			"7167EFC92BB2E3CE7C8AAAFF34E12A9C557003D7C73A6FAF003F99F6CC8482E540F7" },
		{ ASN1::c2pnb304w1(),
			"c2pnb304w1",
			304, 11, 2, 1, 0,
			"FD0D693149A118F651E6DCE6802085377E5F882D1B510B44160074C1288078365A0396C8E681",
			"BDDB97E555A50A908E43B01C798EA5DAA6788F1EA2794EFCF57166B8C14039601E55827340BE" },
#endif

		{  ASN1::c2tnb359v1(),
			"c2tnb359v1",
			0, 0, 359, 68, 0,
			"5667676A654B20754F356EA92017D946567C46675556F19556A04616B567D223A5E05656FB549016A96656A557",
			"2472E2D0197C49363F1FE7F5B6DB075D52B6947D135D8CA445805D39BC345626089687742B6329E70680231988" },

#ifdef CRYPTOPP_INCLUDE_X9_62_1998_CURVES
		{ ASN1::c2pnb368w1(),
			"c2pnb368w1",
			368, 85, 2, 1, 0,
			"E0D2EE25095206F5E2A4F9ED229F1F256E79A0E2B455970D8D0D865BD94778C576D62F0AB7519CCD2A1A906AE30D",
			"FC1217D4320A90452C760A58EDCD30C8DD069B3C34453837A34ED50CB54917E1C2112D84D164F444F8F74786046A" },
#endif

		{ ASN1::c2tnb431r1(),
			"c2tnb431r1",
			0, 0, 431, 120, 0,
			"1A827EF00DD6FC0E234CAF046C6A5D8A85395B236CC4AD2CF32A0CADBDC9DDF620B0EB9906D0957F6C6FEACD615468DF104DE296CD8F",
			"10D9B4A3D9047D8B154359ABFB1B7F5485B04CEB868237DDC9DEDA982A679A5A919B626D4E50A8DD731B107A9962381FB5D807BF2618" },
		{ ASN1::sect163k1(),
			"sect163k1",
			163, 7, 6, 3, 0,
			"000000000000000000000000000000000000000001",
			"000000000000000000000000000000000000000001" },
		{ ASN1::sect163r1(),
			"sect163r1",
			163, 7, 6, 3, 0,
			"07B6882CAAEFA84F9554FF8428BD88E246D2782AE2",
			"0713612DCDDCB40AAB946BDA29CA91F73AF958AFD9" },
		{ ASN1::sect239k1(),
			"sect239k1",
			0, 0, 239, 158, 0,
			"000000000000000000000000000000000000000000000000000000000000",
			"000000000000000000000000000000000000000000000000000000000001" },
		{ ASN1::sect113r1(),
			"sect113r1",
			0, 0, 113, 9, 0,
			"003088250CA6E7C7FE649CE85820F7",
			"00E8BEE4D3E2260744188BE0E9C723" },
		{ ASN1::sect113r2(),
			"sect113r2",
			0, 0, 113, 9, 0,
			"00689918DBEC7E5A0DD6DFC0AA55C7",
			"0095E9A9EC9B297BD4BF36E059184F" },
		{ ASN1::sect163r2(),
			"sect163r2",
			163, 7, 6, 3, 0,
			"000000000000000000000000000000000000000001",
			"020A601907B8C953CA1481EB10512F78744A3205FD" },
		{ ASN1::sect283k1(),
			"sect283k1",
			283, 12, 7, 5, 0,
			"000000000000000000000000000000000000000000000000000000000000000000000000",
			"000000000000000000000000000000000000000000000000000000000000000000000001" },
		{ ASN1::sect283r1(),
			"sect283r1",
			283, 12, 7, 5, 0,
			"000000000000000000000000000000000000000000000000000000000000000000000001",
			"027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5" },
		{ ASN1::sect131r1(),
			"sect131r1",
			131, 8, 3, 2, 0,
			"07A11B09A76B562144418FF3FF8C2570B8",
			"0217C05610884B63B9C6C7291678F9D341" },
		{ ASN1::sect131r2(),
			"sect131r2",
			131, 8, 3, 2, 0,
			"03E5A88919D7CAFCBF415F07C2176573B2",
			"04B8266A46C55657AC734CE38F018F2192" },
		{ ASN1::sect193r1(),
			"sect193r1",
			0, 0, 193, 15, 0,
			"0017858FEB7A98975169E171F77B4087DE098AC8A911DF7B01",
			"00FDFB49BFE6C3A89FACADAA7A1E5BBC7CC1C2E5D831478814" },
		{ ASN1::sect193r2(),
			"sect193r2",
			0, 0, 193, 15, 0,
			"0163F35A5137C2CE3EA6ED8667190B0BC43ECD69977702709B",
			"00C9BB9E8927D4D64C377E2AB2856A5B16E3EFB7F61D4316AE" },
		{ ASN1::sect233k1(),
			"sect233k1",
			0, 0, 233, 74, 0,
			"000000000000000000000000000000000000000000000000000000000000",
			"000000000000000000000000000000000000000000000000000000000001" },
		{ ASN1::sect233r1(),
			"sect233r1",
			0, 0, 233, 74, 0,
			"000000000000000000000000000000000000000000000000000000000001",
			"0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD" },
		{ ASN1::sect409k1(),
			"sect409k1",
			0, 0, 409, 87, 0,
			"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001" },
		{ ASN1::sect571k1(),
			"sect571k1",
			571, 10, 5, 2, 0,
			"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001" },
		{ ASN1::sect571r1(),
			"sect571r1",
			571, 10, 5, 2, 0,
			"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
			"02F40E7E2221F295DE297117B7F3D62F5C6A97FFCB8CEFF1CD6BA8CE4A9A18AD84FFABBD8EFA59332BE7AD6756A66E294AFD185A78FF12AA520E4DE739BACA0C7FFEFF7F2955727A" },
		{ ASN1::wtls1(),
			"wtls1",
			0, 0, 113, 9, 0,
			"01",
			"01" },
		{ ASN1::wtls3(),
			"wtls3",
			163, 7, 6, 3, 0,
			"000000000000000000000000000000000000000001",
			"000000000000000000000000000000000000000001" },
		{ ASN1::wtls4(),
			"wtls4",
			0, 0, 113, 9, 0,
			"003088250CA6E7C7FE649CE85820F7",
			"00E8BEE4D3E2260744188BE0E9C723" },
		{ ASN1::wtls5(),
			"wtls5",
			163, 8, 2, 1, 0,
			"072546B5435234A422E0789675F432C89435DE5242",
			"00C9517D06D5240D3CFF38C74B20B6CD4D6F9DD4D9" },
		{ ASN1::wtls10(),
			"wtls10",
			0, 0, 233, 74, 0,
			"000000000000000000000000000000000000000000000000000000000000",
			"000000000000000000000000000000000000000000000000000000000001" },
		{ ASN1::wtls11(),
			"wtls11",
			0, 0, 233, 74, 0,
			"000000000000000000000000000000000000000000000000000000000001",
			"0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD" },
	};

#if 0
	GlobalRNG().Shuffle(&exp[0], &exp[0] + COUNTOF(exp));
#endif

	for(size_t i = 0; pass && i < COUNTOF(exp); i++)
	{
		StringSource ssA(exp[i].a, true, new HexDecoder);
		StringSource ssB(exp[i].b, true, new HexDecoder);

		EC2N::FieldElement a, b;
		a.Decode(ssA, (size_t)ssA.MaxRetrievable());
		b.Decode(ssB, (size_t)ssB.MaxRetrievable());

		unsigned int c1 = exp[i].c1, c2 = exp[i].c2, c3 = exp[i].c3, c4 = exp[i].c4, c5 = exp[i].c5;
		auto_ptr<EC2N::Field> field((c1 == 0) ?
			(EC2N::Field*)new GF2NT(c3, c4, c5) : (EC2N::Field*)new GF2NPP(c1, c2, c3, c4, c5));
		const DL_GroupParameters_EC<EC2N> params(exp[i].oid);

		bool t1, t2, t3, t4;
		t1 = (field->GetModulus() == params.GetCurve().GetField().GetModulus());
		t2 = (a == params.GetCurve().GetA());
		t3 = (b == params.GetCurve().GetB());
		t4 = (t1 && t2 && t3);	

		cout << ( !(t4) ? "FAILED" : "passed") << "    OID " << exp[i].oid << " to " << exp[i].name << endl;
		pass &= t4;
	}

	return pass;
}

bool ValidateECP()
{
	cout << "\nECP validation suite running...\n\n";

	ECIES<ECP>::Decryptor cpriv(GlobalRNG(), ASN1::secp192r1());
	ECIES<ECP>::Encryptor cpub(cpriv);
	ByteQueue bq;
	cpriv.GetKey().DEREncode(bq);
	cpub.AccessKey().AccessGroupParameters().SetEncodeAsOID(true);
	cpub.GetKey().DEREncode(bq);
	ECDSA<ECP, SHA>::Signer spriv(bq);
	ECDSA<ECP, SHA>::Verifier spub(bq);
	ECDH<ECP>::Domain ecdhc(ASN1::secp192r1());
	ECMQV<ECP>::Domain ecmqvc(ASN1::secp192r1());

	spriv.AccessKey().Precompute();
	ByteQueue queue;
	spriv.AccessKey().SavePrecomputation(queue);
	spriv.AccessKey().LoadPrecomputation(queue);

	bool pass = SignatureValidate(spriv, spub);
	cpub.AccessKey().Precompute();
	cpriv.AccessKey().Precompute();
	pass = CryptoSystemValidate(cpriv, cpub) && pass;
	pass = SimpleKeyAgreementValidate(ecdhc) && pass;
	pass = AuthenticatedKeyAgreementValidate(ecmqvc) && pass;

	cout << "Turning on point compression..." << endl;
	cpriv.AccessKey().AccessGroupParameters().SetPointCompression(true);
	cpub.AccessKey().AccessGroupParameters().SetPointCompression(true);
	ecdhc.AccessGroupParameters().SetPointCompression(true);
	ecmqvc.AccessGroupParameters().SetPointCompression(true);
	pass = CryptoSystemValidate(cpriv, cpub) && pass;
	pass = SimpleKeyAgreementValidate(ecdhc) && pass;
	pass = AuthenticatedKeyAgreementValidate(ecmqvc) && pass;

	cout << "Testing SEC 2, NIST, and Brainpool recommended curves..." << endl;
	OID oid;
	while (!(oid = DL_GroupParameters_EC<ECP>::GetNextRecommendedParametersOID(oid)).m_values.empty())
	{
		DL_GroupParameters_EC<ECP> params(oid);
		bool fail = !params.Validate(GlobalRNG(), 2);
		cout << (fail ? "FAILED" : "passed") << "    " << dec << params.GetCurve().GetField().MaxElementBitLength() << " bits" << endl;
		pass = pass && !fail;
	}

	return pass;
}

bool ValidateEC2N()
{
	cout << "\nEC2N validation suite running...\n\n";

	ECIES<EC2N>::Decryptor cpriv(GlobalRNG(), ASN1::sect193r1());
	ECIES<EC2N>::Encryptor cpub(cpriv);
	ByteQueue bq;
	cpriv.DEREncode(bq);
	cpub.AccessKey().AccessGroupParameters().SetEncodeAsOID(true);
	cpub.DEREncode(bq);
	ECDSA<EC2N, SHA>::Signer spriv(bq);
	ECDSA<EC2N, SHA>::Verifier spub(bq);
	ECDH<EC2N>::Domain ecdhc(ASN1::sect193r1());
	ECMQV<EC2N>::Domain ecmqvc(ASN1::sect193r1());

	spriv.AccessKey().Precompute();
	ByteQueue queue;
	spriv.AccessKey().SavePrecomputation(queue);
	spriv.AccessKey().LoadPrecomputation(queue);

	bool pass = SignatureValidate(spriv, spub);
	pass = CryptoSystemValidate(cpriv, cpub) && pass;
	pass = SimpleKeyAgreementValidate(ecdhc) && pass;
	pass = AuthenticatedKeyAgreementValidate(ecmqvc) && pass;

	cout << "Turning on point compression..." << endl;
	cpriv.AccessKey().AccessGroupParameters().SetPointCompression(true);
	cpub.AccessKey().AccessGroupParameters().SetPointCompression(true);
	ecdhc.AccessGroupParameters().SetPointCompression(true);
	ecmqvc.AccessGroupParameters().SetPointCompression(true);
	pass = CryptoSystemValidate(cpriv, cpub) && pass;
	pass = SimpleKeyAgreementValidate(ecdhc) && pass;
	pass = AuthenticatedKeyAgreementValidate(ecmqvc) && pass;

#if 0	// TODO: turn this back on when I make EC2N faster for pentanomial basis
	cout << "Testing SEC 2 recommended curves..." << endl;
	OID oid;
	while (!(oid = DL_GroupParameters_EC<EC2N>::GetNextRecommendedParametersOID(oid)).m_values.empty())
	{
		DL_GroupParameters_EC<EC2N> params(oid);
		bool fail = !params.Validate(GlobalRNG(), 2);
		cout << (fail ? "FAILED" : "passed") << "    " << params.GetCurve().GetField().MaxElementBitLength() << " bits" << endl;
		pass = pass && !fail;
	}
#endif

	return pass;
}

bool ValidateECDSA()
{
	cout << "\nECDSA validation suite running...\n\n";

	// from Sample Test Vectors for P1363
	GF2NT gf2n(191, 9, 0);
	byte a[]="\x28\x66\x53\x7B\x67\x67\x52\x63\x6A\x68\xF5\x65\x54\xE1\x26\x40\x27\x6B\x64\x9E\xF7\x52\x62\x67";
	byte b[]="\x2E\x45\xEF\x57\x1F\x00\x78\x6F\x67\xB0\x08\x1B\x94\x95\xA3\xD9\x54\x62\xF5\xDE\x0A\xA1\x85\xEC";
	EC2N ec(gf2n, PolynomialMod2(a,24), PolynomialMod2(b,24));

	EC2N::Point P;
	ec.DecodePoint(P, (byte *)"\x04\x36\xB3\xDA\xF8\xA2\x32\x06\xF9\xC4\xF2\x99\xD7\xB2\x1A\x9C\x36\x91\x37\xF2\xC8\x4A\xE1\xAA\x0D"
		"\x76\x5B\xE7\x34\x33\xB3\xF9\x5E\x33\x29\x32\xE7\x0E\xA2\x45\xCA\x24\x18\xEA\x0E\xF9\x80\x18\xFB", ec.EncodedPointSize());
	Integer n("40000000000000000000000004a20e90c39067c893bbb9a5H");
	Integer d("340562e1dda332f9d2aec168249b5696ee39d0ed4d03760fH");
	EC2N::Point Q(ec.Multiply(d, P));
	ECDSA<EC2N, SHA>::Signer priv(ec, P, n, d);
	ECDSA<EC2N, SHA>::Verifier pub(priv);

	Integer h("A9993E364706816ABA3E25717850C26C9CD0D89DH");
	Integer k("3eeace72b4919d991738d521879f787cb590aff8189d2b69H");
	byte sig[]="\x03\x8e\x5a\x11\xfb\x55\xe4\xc6\x54\x71\xdc\xd4\x99\x84\x52\xb1\xe0\x2d\x8a\xf7\x09\x9b\xb9\x30"
		"\x0c\x9a\x08\xc3\x44\x68\xc2\x44\xb4\xe5\xd6\xb2\x1b\x3c\x68\x36\x28\x07\x41\x60\x20\x32\x8b\x6e";
	Integer r(sig, 24);
	Integer s(sig+24, 24);

	Integer rOut, sOut;
	bool fail, pass=true;

	priv.RawSign(k, h, rOut, sOut);
	fail = (rOut != r) || (sOut != s);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "signature check against test vector\n";

	fail = !pub.VerifyMessage((byte *)"abc", 3, sig, sizeof(sig));
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "verification check against test vector\n";

	fail = pub.VerifyMessage((byte *)"xyz", 3, sig, sizeof(sig));
	pass = pass && !fail;

	pass = SignatureValidate(priv, pub) && pass;

	return pass;
}

bool ValidateESIGN()
{
	cout << "\nESIGN validation suite running...\n\n";

	bool pass = true, fail;

	const char *plain = "test";
	const byte *signature = (byte *)
		"\xA3\xE3\x20\x65\xDE\xDA\xE7\xEC\x05\xC1\xBF\xCD\x25\x79\x7D\x99\xCD\xD5\x73\x9D\x9D\xF3\xA4\xAA\x9A\xA4\x5A\xC8\x23\x3D\x0D\x37\xFE\xBC\x76\x3F\xF1\x84\xF6\x59"
		"\x14\x91\x4F\x0C\x34\x1B\xAE\x9A\x5C\x2E\x2E\x38\x08\x78\x77\xCB\xDC\x3C\x7E\xA0\x34\x44\x5B\x0F\x67\xD9\x35\x2A\x79\x47\x1A\x52\x37\x71\xDB\x12\x67\xC1\xB6\xC6"
		"\x66\x73\xB3\x40\x2E\xD6\xF2\x1A\x84\x0A\xB6\x7B\x0F\xEB\x8B\x88\xAB\x33\xDD\xE4\x83\x21\x90\x63\x2D\x51\x2A\xB1\x6F\xAB\xA7\x5C\xFD\x77\x99\xF2\xE1\xEF\x67\x1A"
		"\x74\x02\x37\x0E\xED\x0A\x06\xAD\xF4\x15\x65\xB8\xE1\xD1\x45\xAE\x39\x19\xB4\xFF\x5D\xF1\x45\x7B\xE0\xFE\x72\xED\x11\x92\x8F\x61\x41\x4F\x02\x00\xF2\x76\x6F\x7C"
		"\x79\xA2\xE5\x52\x20\x5D\x97\x5E\xFE\x39\xAE\x21\x10\xFB\x35\xF4\x80\x81\x41\x13\xDD\xE8\x5F\xCA\x1E\x4F\xF8\x9B\xB2\x68\xFB\x28";

	FileSource keys("TestData/esig1536.dat", true, new HexDecoder);
	ESIGN<SHA>::Signer signer(keys);
	ESIGN<SHA>::Verifier verifier(signer);

	fail = !SignatureValidate(signer, verifier);
	pass = pass && !fail;

	fail = !verifier.VerifyMessage((byte *)plain, strlen(plain), signature, verifier.SignatureLength());
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "verification check against test vector\n";

	cout << "Generating signature key from seed..." << endl;
	signer.AccessKey().GenerateRandom(GlobalRNG(), MakeParameters("Seed", ConstByteArrayParameter((const byte *)"test", 4))("KeySize", 3*512));
	verifier = signer;

	fail = !SignatureValidate(signer, verifier);
	pass = pass && !fail;

	return pass;
}
