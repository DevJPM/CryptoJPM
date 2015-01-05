// skein.cpp written and placed in the public domain by Jean-Pierre Muench

#include "pch.h"
#include "skein.h"
#include "Threefish.h"

NAMESPACE_BEGIN(CryptoPP)

Skein_Main_Provider::UBI::UBI(unsigned int Blocksize,TypeValues TypeValue,const byte* InitialState) :
m_TypeValue(TypeValue),m_Blocksize(Blocksize),m_State(InitialState,m_Blocksize),m_LowerCounter(0),m_UpperCounter(0)
{
	switch (m_Blocksize)
	{
	case 32:
		m_Threefish.reset(new Threefish_256::Encryption());
		break;
	case 64:
		m_Threefish.reset(new Threefish_512::Encryption());
		break;
	case 128:
		m_Threefish.reset(new Threefish_1024::Encryption());
		break;
	}
}

void Skein_Main_Provider::UBI::Update(const byte* input, size_t length)
{
	if(m_BufferForNextBlock.SizeInBytes() + length <= m_Blocksize)
	{
		if(m_BufferForNextBlock.SizeInBytes() + length <= m_BufferForNextBlock.SizeInBytes()) // counter buffer-/integeroverflows
			return;
		const size_t OldSize = m_BufferForNextBlock.SizeInBytes();
		m_BufferForNextBlock.CleanGrow(OldSize+length);
		memcpy(&m_BufferForNextBlock.BytePtr()[OldSize],input,length);

		return;
	}

	// process buffered data first
	SecByteBlock Buffer(m_Blocksize);
	memcpy(Buffer,m_BufferForNextBlock,m_BufferForNextBlock.SizeInBytes());
	const size_t ToCopy = m_Blocksize - m_BufferForNextBlock.SizeInBytes();
	memcpy(&Buffer.BytePtr()[m_BufferForNextBlock.SizeInBytes()],input,m_Blocksize - m_BufferForNextBlock.SizeInBytes());
	input += m_Blocksize - m_BufferForNextBlock.SizeInBytes();
	length -= m_Blocksize - m_BufferForNextBlock.SizeInBytes();

	word32 TweakFlags=0;
	TweakFlags |= word32(m_TypeValue) <<24; // msg flag
	if(m_LowerCounter==0&&m_UpperCounter==0)
		TweakFlags |= 1ui32 << 30; // first block flag

	IncrementCounters(m_Blocksize);
	FixedSizeSecBlock<byte,16> Tweak;
	memset_z(Tweak,0,16);
	memcpy(&Tweak.BytePtr()[0],(const byte*)&m_LowerCounter,sizeof(m_LowerCounter));
	memcpy(&Tweak.BytePtr()[8],(const byte*)&m_UpperCounter,sizeof(m_UpperCounter));
	memcpy(&Tweak.BytePtr()[12],(const byte*)&TweakFlags,sizeof(TweakFlags));
	/*ConditionalByteReverse(LITTLE_ENDIAN_ORDER,);
	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,);
	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,);*/

	m_Threefish->SetKey(m_State,m_Blocksize);
	m_Threefish->ProcessAndXorBlockWithTweak(Buffer,Buffer,m_State,Tweak,16);

	while(length > m_Blocksize)
	{
		word32 Flags=0;
		Flags |= word32(m_TypeValue) <<24; // msg flag

		IncrementCounters(m_Blocksize);
		FixedSizeSecBlock<byte,16> NewTweak;
		memset_z(NewTweak,0,16);
		memcpy(&NewTweak.BytePtr()[0],(const byte*)&m_LowerCounter,sizeof(m_LowerCounter));
		memcpy(&NewTweak.BytePtr()[8],(const byte*)&m_UpperCounter,sizeof(m_UpperCounter));
		memcpy(&NewTweak.BytePtr()[12],(const byte*)&Flags,sizeof(Flags));
		/*ConditionalByteReverse(LITTLE_ENDIAN_ORDER,&NewTweak.BytePtr()[0],(const byte*)&m_LowerCounter,sizeof(m_LowerCounter));
		ConditionalByteReverse(LITTLE_ENDIAN_ORDER,&NewTweak.BytePtr()[8],(const byte*)&m_UpperCounter,sizeof(m_UpperCounter));
		ConditionalByteReverse(LITTLE_ENDIAN_ORDER,&NewTweak.BytePtr()[12],(const byte*)&Flags,sizeof(Flags));*/

		m_Threefish->SetKey(m_State,m_Blocksize);
		m_Threefish->ProcessAndXorBlockWithTweak(input,input,m_State,NewTweak,16);

		input += m_Blocksize;
		length -= m_Blocksize;
	}

	m_BufferForNextBlock.CleanNew(length);
	memcpy(m_BufferForNextBlock,input,length);
}

void Skein_Main_Provider::UBI::TruncatedFinal(byte *hash, size_t size)
{
	ThrowIfInvalidTruncatedSize(size);

	SecByteBlock LastBlock(m_Blocksize);
	memset_z(LastBlock,0,m_Blocksize);
	memcpy_s(LastBlock,m_Blocksize,m_BufferForNextBlock,m_BufferForNextBlock.SizeInBytes());

	word32 TweakFlags=0;
	TweakFlags |= word32(m_TypeValue) <<24; // msg flag
	TweakFlags |= 1ui32 << 31; // last block flag
	if(m_LowerCounter==0&&m_UpperCounter==0)
		TweakFlags |= 1ui32 << 30; // first block flag

	IncrementCounters(m_BufferForNextBlock.SizeInBytes());
	m_BufferForNextBlock.CleanNew(0);

	FixedSizeSecBlock<byte,16> Tweak;
	memset_z(Tweak,0,16);
	memcpy(&Tweak.BytePtr()[0],(const byte*)&m_LowerCounter,sizeof(m_LowerCounter));
	memcpy(&Tweak.BytePtr()[8],(const byte*)&m_UpperCounter,sizeof(m_UpperCounter));
	memcpy(&Tweak.BytePtr()[12],(const byte*)&TweakFlags,sizeof(TweakFlags));

	m_Threefish->SetKey(m_State,m_Blocksize);
	m_Threefish->ProcessAndXorBlockWithTweak(LastBlock,LastBlock,m_State,Tweak,16);
	memcpy(hash,m_State,size);
	Restart();
}

void Skein_Main_Provider::UBI::OutTransformation(byte* OutReceiver,const size_t OutputSize,const byte* State)
{
	// output transformation now

	SecByteBlock LocalState(State,m_Blocksize);

	m_Threefish->SetKey(LocalState,m_Blocksize);
	word32 OutputTweakFlags=0;
	OutputTweakFlags |= 63ui32 <<24; // out flag
	OutputTweakFlags |= 1ui32 << 30; // first block flag
	OutputTweakFlags |= 1ui32 << 31; // last block flag
	FixedSizeSecBlock<byte,16> OutTweak;
	memset_z(OutTweak,0,16);
	
	SecByteBlock OutputBlock(m_Blocksize);
	word64 OutputCounter = 0;

	const word32 OutUBISize = sizeof(OutputCounter);
	memcpy(&OutTweak.BytePtr()[0],(const byte*)&OutUBISize,sizeof(OutUBISize));
	memcpy(&OutTweak.BytePtr()[12],(const byte*)&OutputTweakFlags,sizeof(OutputTweakFlags));

	for(word64 i=0;i<(OutputSize/m_Blocksize);++i)
	{
		memset_z(OutputBlock,0,m_Blocksize);
		ConditionalByteReverse(LITTLE_ENDIAN_ORDER,OutputBlock.BytePtr(),(const byte*)&OutputCounter,sizeof(OutputCounter));

		m_Threefish->ProcessAndXorBlockWithTweak(OutputBlock,NULL,OutReceiver + OutputCounter*m_Blocksize,OutTweak,16);
		++OutputCounter;
	}
	SecByteBlock LastDigestBlockBuffer(m_Blocksize);

	memset_z(OutputBlock,0,m_Blocksize);
	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,OutputBlock.BytePtr(),(const byte*)&OutputCounter,sizeof(OutputCounter));

	m_Threefish->ProcessAndXorBlockWithTweak(OutputBlock,NULL,LastDigestBlockBuffer,OutTweak,16);
	memcpy(OutReceiver + OutputCounter*m_Blocksize,LastDigestBlockBuffer,OutputSize-OutputCounter*m_Blocksize);
}

void Skein_Main_Provider::UBI::Restart()
{
	m_BufferForNextBlock.CleanNew(0);
	memset_z(m_State,0,m_State.size());

	m_LowerCounter=0;
	m_UpperCounter=0;
}

void Skein_Main_Provider::UBI::IncrementCounters(size_t n)
{
	const word64 OldLower = m_LowerCounter;
	const word32 OldUpper = m_UpperCounter;
	m_LowerCounter+=n;
	if(m_LowerCounter<OldLower)
		m_UpperCounter++;
	if(m_UpperCounter<OldUpper)
		throw(InvalidArgument("input string too long (longer than 96-bits)"));
}

void Skein_Main_Provider::Skein_Base::KeyUBI(const byte* Key,size_t Keylength)
{
	m_KeyedState.CleanNew(0);// delete
	m_KeyedState.CleanNew(m_BlockSize);

	UBI Keyer(m_BlockSize,UBI::KEY,m_KeyedState);
	Keyer.CalculateDigest(m_KeyedState,Key,Keylength);
}

void Skein_Main_Provider::Skein_Base::TruncatedFinalMsgUBI(byte *hash, size_t size)
{
	assert(size<=m_OutputLength);
	if(m_MsgUBI.get())
		m_MsgUBI->Final(m_State);
	UBI(m_BlockSize,UBI::OUT,m_State).OutTransformation(hash,size,m_State);
	ApplyAllSettings();
}

void Skein_Main_Provider::Skein_Base::RestartUBI()
{
	memset_z(m_State,0,m_State.SizeInBytes());
	if(m_MsgUBI.get())
		m_MsgUBI->Restart();
}

void Skein_Main_Provider::Skein_Base::ApplyAllSettings()
{
	RestartUBI();

	//key
	if(m_KeyedState.SizeInBytes()==m_BlockSize)
		memcpy_s(m_State,m_State.SizeInBytes(),m_KeyedState,m_KeyedState.SizeInBytes());

	//config
	word32 Literal = 0x33414853; // ="SHA3"
	word16 VersionNumber = 1;
	word64 DigestSize = 8 * m_OutputLength;
	FixedSizeSecBlock<byte,32> ConfigBlock;
	memset_z(ConfigBlock,0,ConfigBlock.SizeInBytes());
	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,ConfigBlock.BytePtr(),(const byte*)&Literal,sizeof(word32));
	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,&ConfigBlock.BytePtr()[4],(const byte*)&VersionNumber,sizeof(word16));
	ConditionalByteReverse(LITTLE_ENDIAN_ORDER,&ConfigBlock.BytePtr()[8],(const byte*)&DigestSize,sizeof(word64));

	UBI(m_BlockSize,UBI::CFG,m_State).CalculateDigest(m_State,ConfigBlock,ConfigBlock.SizeInBytes());
	
	// personalize
	if(m_PersonalizationString.SizeInBytes())
		UBI(m_BlockSize,UBI::PRS,m_State).CalculateDigest(m_State,m_PersonalizationString,m_PersonalizationString.SizeInBytes());

	// incorporate public key
	if(m_PersonalizationString.SizeInBytes())
		UBI(m_BlockSize,UBI::PK,m_State).CalculateDigest(m_State,m_PublicKey,m_PublicKey.SizeInBytes());

	// use key identifier
	if(m_KeyID.SizeInBytes())
		UBI(m_BlockSize,UBI::KDF,m_State).CalculateDigest(m_State,m_KeyID,m_KeyID.SizeInBytes());

	// set nonce
	if(m_Nonce.SizeInBytes())
		UBI(m_BlockSize,UBI::NON,m_State).CalculateDigest(m_State,m_Nonce,m_Nonce.SizeInBytes());

	// set up messsage UBI instance
	m_MsgUBI.reset(new UBI(m_BlockSize,UBI::MSG,m_State));
}

Skein_Main_Provider::Hash::Hash(const unsigned int DigestSize,unsigned int BlockSize) :
	m_DigestSize(DigestSize),m_Blocksize(BlockSize)
{
	if(m_Blocksize!=32 && m_Blocksize!=64 && m_Blocksize!=128)
		m_Blocksize=0;

	if(!m_Blocksize)
	{
		// use Threefish-256 only for Digests < 256 bits
		// use Threefish-512 for Digests d with 256 <= d <= 512
		// use Threefish-1024 for the rest
		if(m_DigestSize<32)
			m_Blocksize=32;
		else if(m_DigestSize<=64)
			m_Blocksize=64;
		else
			m_Blocksize=128;
	}

	ConfigUBI(m_DigestSize,m_Blocksize);

	ApplyAllSettings();
}

Skein_Main_Provider::MAC::MAC(const byte* Key,size_t keylength,const unsigned int DigestSize,unsigned int BlockSize ) :
	m_DigestSize(DigestSize),m_Blocksize(BlockSize)
{
	if(m_Blocksize!=32 && m_Blocksize!=64 && m_Blocksize!=128)
		m_Blocksize=0;

	if(!m_Blocksize)
	{
		// use Threefish-256 only for Digests < 256 bits
		// use Threefish-512 for Digests d with 256 <= d <= 512
		// use Threefish-1024 for the rest
		if(m_DigestSize<32)
			m_Blocksize=32;
		else if(m_DigestSize<=64)
			m_Blocksize=64;
		else
			m_Blocksize=128;
	}

	ConfigUBI(m_DigestSize,m_Blocksize);

	SetKey(Key,keylength);

	ApplyAllSettings();
}

Skein_Main_Provider::SignatureHash::SignatureHash(const byte* PublicKey,size_t Keylength,const unsigned int DigestSize,unsigned int BlockSize) :
	m_DigestSize(DigestSize),m_Blocksize(BlockSize)
{
	if(m_Blocksize!=32 && m_Blocksize!=64 && m_Blocksize!=128)
		m_Blocksize=0;

	if(!m_Blocksize)
	{
		// use Threefish-256 only for Digests < 256 bits
		// use Threefish-512 for Digests d with 256 <= d <= 512
		// use Threefish-1024 for the rest
		if(m_DigestSize<32)
			m_Blocksize=32;
		else if(m_DigestSize<=64)
			m_Blocksize=64;
		else
			m_Blocksize=128;
	}

	ConfigUBI(m_DigestSize,m_Blocksize);

	SetPublicKey(PublicKey,Keylength);

	ApplyAllSettings();
}

Skein_Main_Provider::KDF::KDF(const byte* Key,size_t keylength,const byte* KeyIdentifier,size_t IDsize,const unsigned int DerivedKeyLen,unsigned int BlockSize) :
	m_DerivedLength(DerivedKeyLen)
{
	if(m_Blocksize!=32 && m_Blocksize!=64 && m_Blocksize!=128)
		m_Blocksize=0;

	if(!m_Blocksize)
	{
		// use Threefish-256 only for Digests < 256 bits
		// use Threefish-512 for Digests d with 256 <= d <= 512
		// use Threefish-1024 for the rest
		if(m_DerivedLength<32)
			m_Blocksize=32;
		else if(m_DerivedLength<=64)
			m_Blocksize=64;
		else
			m_Blocksize=128;
	}

	ConfigUBI(m_DerivedLength,m_Blocksize);

	SetKey(Key,keylength);

	SetKeyIdentifier(KeyIdentifier,IDsize);

	ApplyAllSettings();
}



NAMESPACE_END