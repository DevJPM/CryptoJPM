// blake2b.cpp - written and placed in the public domain by Jean-Pierre Muench
// Thanks go to Zooko Wilcox-O'Hearn for providing the idea of implementing BLAKE2 in Crypto++/JPM
// Thanks go to Samuel Neves for the optimized C-implementation

#include "pch.h"
#include "blake2s.h"
#include "cpu.h"
#if CRYPTOPP_BOOL_CPP11_THREAD_SUPPORTED
#include <thread>
#endif

#define DISABLE_SSE_LOCALLY
// for testing purposes:
// NOTE: to get test-vector compliant results enable the  following:
//#define CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE 0

#define LOAD_MSG_0_1(buf) buf = _mm_set_epi32(m6,m4,m2,m0)
#define LOAD_MSG_0_2(buf) buf = _mm_set_epi32(m7,m5,m3,m1)
#define LOAD_MSG_0_3(buf) buf = _mm_set_epi32(m14,m12,m10,m8)
#define LOAD_MSG_0_4(buf) buf = _mm_set_epi32(m15,m13,m11,m9)
#define LOAD_MSG_1_1(buf) buf = _mm_set_epi32(m13,m9,m4,m14)
#define LOAD_MSG_1_2(buf) buf = _mm_set_epi32(m6,m15,m8,m10)
#define LOAD_MSG_1_3(buf) buf = _mm_set_epi32(m5,m11,m0,m1)
#define LOAD_MSG_1_4(buf) buf = _mm_set_epi32(m3,m7,m2,m12)
#define LOAD_MSG_2_1(buf) buf = _mm_set_epi32(m15,m5,m12,m11)
#define LOAD_MSG_2_2(buf) buf = _mm_set_epi32(m13,m2,m0,m8)
#define LOAD_MSG_2_3(buf) buf = _mm_set_epi32(m9,m7,m3,m10)
#define LOAD_MSG_2_4(buf) buf = _mm_set_epi32(m4,m1,m6,m14)
#define LOAD_MSG_3_1(buf) buf = _mm_set_epi32(m11,m13,m3,m7)
#define LOAD_MSG_3_2(buf) buf = _mm_set_epi32(m14,m12,m1,m9)
#define LOAD_MSG_3_3(buf) buf = _mm_set_epi32(m15,m4,m5,m2)
#define LOAD_MSG_3_4(buf) buf = _mm_set_epi32(m8,m0,m10,m6)
#define LOAD_MSG_4_1(buf) buf = _mm_set_epi32(m10,m2,m5,m9)
#define LOAD_MSG_4_2(buf) buf = _mm_set_epi32(m15,m4,m7,m0)
#define LOAD_MSG_4_3(buf) buf = _mm_set_epi32(m3,m6,m11,m14)
#define LOAD_MSG_4_4(buf) buf = _mm_set_epi32(m13,m8,m12,m1)
#define LOAD_MSG_5_1(buf) buf = _mm_set_epi32(m8,m0,m6,m2)
#define LOAD_MSG_5_2(buf) buf = _mm_set_epi32(m3,m11,m10,m12)
#define LOAD_MSG_5_3(buf) buf = _mm_set_epi32(m1,m15,m7,m4)
#define LOAD_MSG_5_4(buf) buf = _mm_set_epi32(m9,m14,m5,m13)
#define LOAD_MSG_6_1(buf) buf = _mm_set_epi32(m4,m14,m1,m12)
#define LOAD_MSG_6_2(buf) buf = _mm_set_epi32(m10,m13,m15,m5)
#define LOAD_MSG_6_3(buf) buf = _mm_set_epi32(m8,m9,m6,m0)
#define LOAD_MSG_6_4(buf) buf = _mm_set_epi32(m11,m2,m3,m7)
#define LOAD_MSG_7_1(buf) buf = _mm_set_epi32(m3,m12,m7,m13)
#define LOAD_MSG_7_2(buf) buf = _mm_set_epi32(m9,m1,m14,m11)
#define LOAD_MSG_7_3(buf) buf = _mm_set_epi32(m2,m8,m15,m5)
#define LOAD_MSG_7_4(buf) buf = _mm_set_epi32(m10,m6,m4,m0)
#define LOAD_MSG_8_1(buf) buf = _mm_set_epi32(m0,m11,m14,m6)
#define LOAD_MSG_8_2(buf) buf = _mm_set_epi32(m8,m3,m9,m15)
#define LOAD_MSG_8_3(buf) buf = _mm_set_epi32(m10,m1,m13,m12)
#define LOAD_MSG_8_4(buf) buf = _mm_set_epi32(m5,m4,m7,m2)
#define LOAD_MSG_9_1(buf) buf = _mm_set_epi32(m1,m7,m8,m10)
#define LOAD_MSG_9_2(buf) buf = _mm_set_epi32(m5,m6,m4,m2)
#define LOAD_MSG_9_3(buf) buf = _mm_set_epi32(m13,m3,m9,m15)
#define LOAD_MSG_9_4(buf) buf = _mm_set_epi32(m0,m12,m14,m11)

#define LOAD(p)  _mm_load_si128( (__m128i *)(p) )
#define STORE(p,r) _mm_store_si128((__m128i *)(p), r)

#define LOADU(p)  _mm_loadu_si128( (__m128i *)(p) )
#define STOREU(p,r) _mm_storeu_si128((__m128i *)(p), r)

#define _mm_roti_epi32(r, c) ( \
				(8==-(c)) ? _mm_shuffle_epi8(r,r8) \
			  : (16==-(c)) ? _mm_shuffle_epi8(r,r16) \
			  : _mm_xor_si128(_mm_srli_epi32( (r), -(c) ),_mm_slli_epi32( (r), 32-(-(c)) )) )

#define G1(row1,row2,row3,row4,buf) \
  row1 = _mm_add_epi32( _mm_add_epi32( row1, buf), row2 ); \
  row4 = _mm_xor_si128( row4, row1 ); \
  row4 = _mm_roti_epi32(row4, -16); \
  row3 = _mm_add_epi32( row3, row4 );   \
  row2 = _mm_xor_si128( row2, row3 ); \
  row2 = _mm_roti_epi32(row2, -12);

#define G2(row1,row2,row3,row4,buf) \
  row1 = _mm_add_epi32( _mm_add_epi32( row1, buf), row2 ); \
  row4 = _mm_xor_si128( row4, row1 ); \
  row4 = _mm_roti_epi32(row4, -8); \
  row3 = _mm_add_epi32( row3, row4 );   \
  row2 = _mm_xor_si128( row2, row3 ); \
  row2 = _mm_roti_epi32(row2, -7);

#define DIAGONALIZE(row1,row2,row3,row4) \
  row4 = _mm_shuffle_epi32( row4, _MM_SHUFFLE(2,1,0,3) ); \
  row3 = _mm_shuffle_epi32( row3, _MM_SHUFFLE(1,0,3,2) ); \
  row2 = _mm_shuffle_epi32( row2, _MM_SHUFFLE(0,3,2,1) );

#define UNDIAGONALIZE(row1,row2,row3,row4) \
  row4 = _mm_shuffle_epi32( row4, _MM_SHUFFLE(0,3,2,1) ); \
  row3 = _mm_shuffle_epi32( row3, _MM_SHUFFLE(1,0,3,2) ); \
  row2 = _mm_shuffle_epi32( row2, _MM_SHUFFLE(2,1,0,3) );

#define ROUND(r)  \
  LOAD_MSG_ ##r ##_1(buf1); \
  G1(row1,row2,row3,row4,buf1); \
  LOAD_MSG_ ##r ##_2(buf2); \
  G2(row1,row2,row3,row4,buf2); \
  DIAGONALIZE(row1,row2,row3,row4); \
  LOAD_MSG_ ##r ##_3(buf3); \
  G1(row1,row2,row3,row4,buf3); \
  LOAD_MSG_ ##r ##_4(buf4); \
  G2(row1,row2,row3,row4,buf4); \
  UNDIAGONALIZE(row1,row2,row3,row4); \


NAMESPACE_BEGIN(CryptoPP)

static const uint8_t blake2s_sigma[10][16] =
{
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
};

CRYPTOPP_ALIGN_DATA(64) static const uint32_t blake2s_IV[8] =
{
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

BLAKE2s::BLAKE2s(unsigned int Digestsize) :
	m_Digestsize(Digestsize)
{
	if(Digestsize>32 || !Digestsize)
		throw(InvalidArgument("invalid Digestsize!"));

	Restart();
}

void BLAKE2s::Restart()
{
	memset_z(m_h,0,m_h.SizeInBytes());
	memset_z(m_t,0,m_t.SizeInBytes());
	memset_z(m_f,0,m_f.SizeInBytes());
	memset_z(m_buf,0,m_buf.SizeInBytes());
	m_buflen=0;
	m_last_node=0;

	FixedSizeSecBlock<byte,MAX_DIGEST_SIZE> Params;
	memset_z(Params,0,MAX_DIGEST_SIZE);
	Params[0]=m_Digestsize;
	Params[2]=1;
	Params[3]=1;

	const byte* IVPtr = (const byte*) blake2s_IV;
	const byte* ParamsPtr = Params;

	for(int i=0;i<MAX_DIGEST_SIZE;++i)
		m_h.BytePtr()[i] = IVPtr[i] ^ ParamsPtr[i];
}

void BLAKE2s::Update(const byte *input, size_t length)
{
	while( length > 0 )
	{
		size_t left = m_buflen;
		size_t fill = 2 * BLOCKSIZE - left;

		if( length > fill )
		{
			memcpy( m_buf + left, input, fill ); // Fill buffer
			m_buflen += fill;
			IncrementCounter( BLOCKSIZE );
			Compress( m_buf ); // Compress
			memcpy( m_buf, m_buf + BLOCKSIZE, BLOCKSIZE ); // Shift buffer left
			m_buflen -= BLOCKSIZE;
			input += fill;
			length -= fill;
		}
		else // inlen <= fill
		{
			memcpy( m_buf + left, input, length );
			m_buflen += length; // Be lazy, do not compress
			input += length;
			length -= length;
		}
	}
}

void BLAKE2s::TruncatedFinal(byte *digest, size_t digestSize)
{
	ThrowIfInvalidTruncatedSize(digestSize);
	FixedSizeSecBlock<byte,BLOCKSIZE> buffer;

	if( m_buflen > BLOCKSIZE )
	{
		IncrementCounter(BLOCKSIZE );
		Compress(m_buf );
		m_buflen -= BLOCKSIZE;
		memcpy( m_buf, m_buf + BLOCKSIZE, m_buflen );
	}

	IncrementCounter( ( uint32_t )m_buflen );
	SetLastBlock();
	memset( m_buf + m_buflen, 0, 2 * BLOCKSIZE - m_buflen ); /* Padding */
	Compress( m_buf );

	for( int i = 0; i < 8; ++i ) /* Output full hash to temp buffer */
		*((word32*)(buffer + sizeof( m_h[i] ) * i))=ConditionalByteReverse<word32>(LITTLE_ENDIAN_ORDER, m_h[i] );

	memcpy( digest, buffer, digestSize );

	Restart();
}

void BLAKE2s::Compress(const byte* block)
{
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && !defined(DISABLE_SSE_LOCALLY)
if(HasSSSE3() && HasSSE2())
{
	__m128i row1, row2, row3, row4;
	__m128i buf1, buf2, buf3, buf4;
	__m128i ff0, ff1;
	const __m128i r8 = _mm_set_epi8( 12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1 );
	const __m128i r16 = _mm_set_epi8( 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2 );
	const word32  m0 = ( ( word32 * )block )[ 0];
	const word32  m1 = ( ( word32 * )block )[ 1];
	const word32  m2 = ( ( word32 * )block )[ 2];
	const word32  m3 = ( ( word32 * )block )[ 3];
	const word32  m4 = ( ( word32 * )block )[ 4];
	const word32  m5 = ( ( word32 * )block )[ 5];
	const word32  m6 = ( ( word32 * )block )[ 6];
	const word32  m7 = ( ( word32 * )block )[ 7];
	const word32  m8 = ( ( word32 * )block )[ 8];
	const word32  m9 = ( ( word32 * )block )[ 9];
	const word32 m10 = ( ( word32 * )block )[10];
	const word32 m11 = ( ( word32 * )block )[11];
	const word32 m12 = ( ( word32 * )block )[12];
	const word32 m13 = ( ( word32 * )block )[13];
	const word32 m14 = ( ( word32 * )block )[14];
	const word32 m15 = ( ( word32 * )block )[15];
	row1 = ff0 = LOADU( &m_h[0] );
	row2 = ff1 = LOADU( &m_h[4] );
	row3 = _mm_setr_epi32( 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A );
	row4 = _mm_xor_si128( _mm_setr_epi32( 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 ), LOADU( &m_t[0] ) );
	ROUND( 0 );
	ROUND( 1 );
	ROUND( 2 );
	ROUND( 3 );
	ROUND( 4 );
	ROUND( 5 );
	ROUND( 6 );
	ROUND( 7 );
	ROUND( 8 );
	ROUND( 9 );
	STOREU( &m_h[0], _mm_xor_si128( ff0, _mm_xor_si128( row1, row3 ) ) );
	STOREU( &m_h[4], _mm_xor_si128( ff1, _mm_xor_si128( row2, row4 ) ) );
}
else
{
#endif
  word32 m[16];
  word32 v[16];

  for( size_t i = 0; i < 16; ++i )
	  m[i] = ConditionalByteReverse<word32>(LITTLE_ENDIAN_ORDER,*((word32*)( block + i * sizeof( m[i] ) )));

  for( size_t i = 0; i < 8; ++i )
	v[i] = m_h[i];

  v[ 8] = blake2s_IV[0];
  v[ 9] = blake2s_IV[1];
  v[10] = blake2s_IV[2];
  v[11] = blake2s_IV[3];
  v[12] = m_t[0] ^ blake2s_IV[4];
  v[13] = m_t[1] ^ blake2s_IV[5];
  v[14] = m_f[0] ^ blake2s_IV[6];
  v[15] = m_f[1] ^ blake2s_IV[7];
#define GREF(r,i,a,b,c,d) \
  do { \
	a = a + b + m[blake2s_sigma[r][2*i+0]]; \
	d = rotrFixed<word32>(d ^ a, 16); \
	c = c + d; \
	b = rotrFixed<word32>(b ^ c, 12); \
	a = a + b + m[blake2s_sigma[r][2*i+1]]; \
	d = rotrFixed<word32>(d ^ a, 8); \
	c = c + d; \
	b = rotrFixed<word32>(b ^ c, 7); \
  } while(0)
#define ROUNDREF(r)  \
  do { \
	GREF(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
	GREF(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
	GREF(r,2,v[ 2],v[ 6],v[10],v[14]); \
	GREF(r,3,v[ 3],v[ 7],v[11],v[15]); \
	GREF(r,4,v[ 0],v[ 5],v[10],v[15]); \
	GREF(r,5,v[ 1],v[ 6],v[11],v[12]); \
	GREF(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
	GREF(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
  } while(0)
  ROUNDREF( 0 );
  ROUNDREF( 1 );
  ROUNDREF( 2 );
  ROUNDREF( 3 );
  ROUNDREF( 4 );
  ROUNDREF( 5 );
  ROUNDREF( 6 );
  ROUNDREF( 7 );
  ROUNDREF( 8 );
  ROUNDREF( 9 );

  for( size_t i = 0; i < 8; ++i )
	m_h[i] = m_h[i] ^ v[i] ^ v[i + 8];

#undef GREF
#undef ROUNDREF
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && !defined(DISABLE_SSE_LOCALLY)
}
#endif
}

BLAKE2sMAC::BLAKE2sMAC(unsigned int Digestsize,const byte* Key,unsigned int Keylength) :
	m_Digestsize(Digestsize)
{
	if(Digestsize>32 || !Digestsize)
		throw(InvalidArgument("invalid Digestsize!"));

	ThrowIfInvalidKeyLength(Keylength);

	SetKey(Key,Keylength);

	Restart();
}

void BLAKE2sMAC::Restart()
{
	memset_z(m_h,0,m_h.SizeInBytes());
	memset_z(m_t,0,m_t.SizeInBytes());
	memset_z(m_f,0,m_f.SizeInBytes());
	memset_z(m_buf,0,m_buf.SizeInBytes());
	m_buflen=0;
	m_last_node=0;

	FixedSizeSecBlock<byte,MAX_DIGEST_SIZE> Params;
	memset_z(Params,0,MAX_DIGEST_SIZE);
	Params.BytePtr()[0]=m_Digestsize;
	Params.BytePtr()[1]=m_Keylen;
	Params.BytePtr()[2]=(byte)1;
	Params.BytePtr()[3]=(byte)1;

	const byte* IVPtr = (const byte*) blake2s_IV;
	const byte* ParamsPtr = Params;

	for(int i=0;i<MAX_DIGEST_SIZE;++i)
		m_h.BytePtr()[i] = IVPtr[i] ^ ParamsPtr[i];

	Update(m_Key,BLOCKSIZE);
}

void BLAKE2sMAC::Update(const byte *input, size_t length)
{
	while( length > 0 )
	{
		size_t left = m_buflen;
		size_t fill = 2 * BLOCKSIZE - left;

		if( length > fill )
		{
			memcpy( m_buf + left, input, fill ); // Fill buffer
			m_buflen += fill;
			IncrementCounter( BLOCKSIZE );
			Compress( m_buf ); // Compress
			memcpy( m_buf, m_buf + BLOCKSIZE, BLOCKSIZE ); // Shift buffer left
			m_buflen -= BLOCKSIZE;
			input += fill;
			length -= fill;
		}
		else // inlen <= fill
		{
			memcpy( m_buf + left, input, length );
			m_buflen += length; // Be lazy, do not compress
			input += length;
			length -= length;
		}
	}
}

void BLAKE2sMAC::TruncatedFinal(byte *digest, size_t digestSize)
{
	ThrowIfInvalidTruncatedSize(digestSize);
	FixedSizeSecBlock<byte,MAX_DIGEST_SIZE> buffer;

	if( m_buflen > BLOCKSIZE )
	{
		IncrementCounter(BLOCKSIZE );
		Compress(m_buf );
		m_buflen -= BLOCKSIZE;
		memcpy( m_buf, m_buf + BLOCKSIZE, m_buflen );
	}

	IncrementCounter( ( uint32_t )m_buflen );
	SetLastBlock();
	memset_z( m_buf.BytePtr() + m_buflen, 0, 2 * BLOCKSIZE - m_buflen ); /* Padding */
	Compress( m_buf );

	for( int i = 0; i < 8; ++i ) /* Output full hash to temp buffer */
		*((word32*)(buffer + sizeof( m_h[i] ) * i))=ConditionalByteReverse<word32>(LITTLE_ENDIAN_ORDER, m_h[i] );

	memcpy( digest, buffer, digestSize );

	Restart();
}

void BLAKE2sMAC::Compress(const byte* block)
{
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && !defined(DISABLE_SSE_LOCALLY)
if(HasSSSE3() && HasSSE2())
{
	__m128i row1, row2, row3, row4;
	__m128i buf1, buf2, buf3, buf4;
	__m128i ff0, ff1;
	const __m128i r8 = _mm_set_epi8( 12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1 );
	const __m128i r16 = _mm_set_epi8( 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2 );
	const word32  m0 = ( ( word32 * )block )[ 0];
	const word32  m1 = ( ( word32 * )block )[ 1];
	const word32  m2 = ( ( word32 * )block )[ 2];
	const word32  m3 = ( ( word32 * )block )[ 3];
	const word32  m4 = ( ( word32 * )block )[ 4];
	const word32  m5 = ( ( word32 * )block )[ 5];
	const word32  m6 = ( ( word32 * )block )[ 6];
	const word32  m7 = ( ( word32 * )block )[ 7];
	const word32  m8 = ( ( word32 * )block )[ 8];
	const word32  m9 = ( ( word32 * )block )[ 9];
	const word32 m10 = ( ( word32 * )block )[10];
	const word32 m11 = ( ( word32 * )block )[11];
	const word32 m12 = ( ( word32 * )block )[12];
	const word32 m13 = ( ( word32 * )block )[13];
	const word32 m14 = ( ( word32 * )block )[14];
	const word32 m15 = ( ( word32 * )block )[15];
	row1 = ff0 = LOADU( &m_h[0] );
	row2 = ff1 = LOADU( &m_h[4] );
	row3 = _mm_setr_epi32( 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A );
	row4 = _mm_xor_si128( _mm_setr_epi32( 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 ), LOADU( &m_t[0] ) );
	ROUND( 0 );
	ROUND( 1 );
	ROUND( 2 );
	ROUND( 3 );
	ROUND( 4 );
	ROUND( 5 );
	ROUND( 6 );
	ROUND( 7 );
	ROUND( 8 );
	ROUND( 9 );
	STOREU( &m_h[0], _mm_xor_si128( ff0, _mm_xor_si128( row1, row3 ) ) );
	STOREU( &m_h[4], _mm_xor_si128( ff1, _mm_xor_si128( row2, row4 ) ) );
}
else
{
#endif
  word32 m[16];
  word32 v[16];

  for( size_t i = 0; i < 16; ++i )
	  m[i] = ConditionalByteReverse<word32>(LITTLE_ENDIAN_ORDER,*((word32*)( block + i * sizeof( m[i] ) )));

  for( size_t i = 0; i < 8; ++i )
	v[i] = m_h[i];

  v[ 8] = blake2s_IV[0];
  v[ 9] = blake2s_IV[1];
  v[10] = blake2s_IV[2];
  v[11] = blake2s_IV[3];
  v[12] = m_t[0] ^ blake2s_IV[4];
  v[13] = m_t[1] ^ blake2s_IV[5];
  v[14] = m_f[0] ^ blake2s_IV[6];
  v[15] = m_f[1] ^ blake2s_IV[7];
#define GREF(r,i,a,b,c,d) \
  do { \
	a = a + b + m[blake2s_sigma[r][2*i+0]]; \
	d = rotrFixed<word32>(d ^ a, 16); \
	c = c + d; \
	b = rotrFixed<word32>(b ^ c, 12); \
	a = a + b + m[blake2s_sigma[r][2*i+1]]; \
	d = rotrFixed<word32>(d ^ a, 8); \
	c = c + d; \
	b = rotrFixed<word32>(b ^ c, 7); \
  } while(0)
#define ROUNDREF(r)  \
  do { \
	GREF(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
	GREF(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
	GREF(r,2,v[ 2],v[ 6],v[10],v[14]); \
	GREF(r,3,v[ 3],v[ 7],v[11],v[15]); \
	GREF(r,4,v[ 0],v[ 5],v[10],v[15]); \
	GREF(r,5,v[ 1],v[ 6],v[11],v[12]); \
	GREF(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
	GREF(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
  } while(0)
  ROUNDREF( 0 );
  ROUNDREF( 1 );
  ROUNDREF( 2 );
  ROUNDREF( 3 );
  ROUNDREF( 4 );
  ROUNDREF( 5 );
  ROUNDREF( 6 );
  ROUNDREF( 7 );
  ROUNDREF( 8 );
  ROUNDREF( 9 );

  for( size_t i = 0; i < 8; ++i )
	m_h[i] = m_h[i] ^ v[i] ^ v[i + 8];

#undef GREF
#undef ROUNDREF
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && !defined(DISABLE_SSE_LOCALLY)
}
#endif
}

BLAKE2sp::BLAKE2sRoot::BLAKE2sRoot(unsigned int DigestSize) :
	BLAKE2s(DigestSize)
{
}

void BLAKE2sp::BLAKE2sRoot::Restart()
{
	memset_z(m_h,0,m_h.SizeInBytes());
	memset_z(m_t,0,m_t.SizeInBytes());
	memset_z(m_f,0,m_f.SizeInBytes());
	memset_z(m_buf,0,m_buf.SizeInBytes());
	m_buflen=0;
	m_last_node=1;

	FixedSizeSecBlock<byte,MAX_DIGEST_SIZE> Params;
	memset_z(Params,0,MAX_DIGEST_SIZE);
	Params[0]=m_Digestsize;
	Params[2]=PARALLELISM_DEGREE; //fanout
	Params[3]=2; //depth
	Params[16]=1; // node_depth
	Params[17]=MAX_DIGEST_SIZE; // inner length

	const byte* IVPtr = (const byte*) blake2s_IV;
	const byte* ParamsPtr = Params;

	for(int i=0;i<MAX_DIGEST_SIZE;++i)
		m_h.BytePtr()[i] = IVPtr[i] ^ ParamsPtr[i];
}

BLAKE2sp::BLAKE2sLeaf::BLAKE2sLeaf(unsigned int DigestSize,bool IsLastNode,word64 Offset) :
	BLAKE2s(DigestSize),m_IsLastNode(IsLastNode),m_Offset(Offset)
{
}

void BLAKE2sp::BLAKE2sLeaf::Restart()
{
	memset_z(m_h,0,m_h.SizeInBytes());
	memset_z(m_t,0,m_t.SizeInBytes());
	memset_z(m_f,0,m_f.SizeInBytes());
	memset_z(m_buf,0,m_buf.SizeInBytes());
	m_buflen=0;
	m_last_node=0;

	if(m_IsLastNode)
		m_last_node=1;

	FixedSizeSecBlock<byte,MAX_DIGEST_SIZE> Params;
	memset_z(Params,0,MAX_DIGEST_SIZE);
	Params[0]=m_Digestsize;
	Params[2]=PARALLELISM_DEGREE; //fanout
	Params[3]=2; //depth
	*((word64*)(&Params[8]))=m_Offset; // node_depth
	Params[17]=MAX_DIGEST_SIZE; // inner length

	const byte* IVPtr = (const byte*) blake2s_IV;
	const byte* ParamsPtr = Params;

	for(int i=0;i<MAX_DIGEST_SIZE;++i)
		m_h.BytePtr()[i] = IVPtr[i] ^ ParamsPtr[i];
}

BLAKE2sp::BLAKE2sp(unsigned int Digestsize):
	m_Root(Digestsize),m_Digestsize(Digestsize),m_buflen(0)
{
	if(Digestsize>32 || !Digestsize)
		throw(InvalidArgument("invalid Digestsize!"));

	for(unsigned int i=0;i<PARALLELISM_DEGREE;++i)
		m_Leaves.push_back(BLAKE2sLeaf(Digestsize,i==(PARALLELISM_DEGREE-1),i));
}

void BLAKE2sp::Restart()
{
	m_Root.Restart();
	for(unsigned int i=0;i<PARALLELISM_DEGREE;++i)
		m_Leaves.at(i).Restart();
}

void BLAKE2sp::Update(const byte *input, size_t length)
{
	size_t left = m_buflen;
	size_t fill = m_buf.SizeInBytes() - left;

	if( left && length >= fill )
	{
		memcpy( m_buf + left, input, fill );

		for( size_t i = 0; i < PARALLELISM_DEGREE; ++i )
			m_Leaves.at(i).Update( m_buf + i * BLOCKSIZE, BLOCKSIZE );

		input += fill;
		length -= fill;
		left = 0;
	}

#if CRYPTOPP_BOOL_CPP11_THREAD_SUPPORTED
	std::vector<std::thread> ThreadVector(PARALLELISM_DEGREE);
	for(unsigned int i=0;i<PARALLELISM_DEGREE;++i)
		ThreadVector.at(i)=std::thread(&BLAKE2sp::ThreadUpdate,this,i,input,length);
	for(std::vector<std::thread>::iterator it=ThreadVector.begin();it!=ThreadVector.end();++it)
		it->join();
#else
	for(unsigned int i=0;i<PARALLELISM_DEGREE;++i)
		ThreadUpdate(i,input,length);
#endif

	input += length - length % ( PARALLELISM_DEGREE * BLOCKSIZE );
	length %= PARALLELISM_DEGREE * BLOCKSIZE;

	if( length > 0 )
		memcpy( m_buf + left, input, length );

	m_buflen = left + length;
}

void BLAKE2sp::TruncatedFinal(byte *digest, size_t digestSize)
{
	FixedSizeSecBlock<byte,MAX_DIGEST_SIZE> hash[PARALLELISM_DEGREE];

	for( size_t i = 0; i < PARALLELISM_DEGREE; ++i )
	{
		if( m_buflen > i * BLOCKSIZE )
		{
			size_t left = m_buflen - i * BLOCKSIZE;

			if( left > BLOCKSIZE )
				left = BLOCKSIZE;

			m_Leaves.at(i).Update(  m_buf + i * BLOCKSIZE, left );
		}

		m_Leaves.at(i).Final( hash[i] );
	}

	for( size_t i = 0; i < PARALLELISM_DEGREE; ++i )
		m_Root.Update(hash[i],MAX_DIGEST_SIZE);

	m_Root.TruncatedFinal(digest,digestSize);

	Restart();
}

void BLAKE2sp::ThreadUpdate(unsigned int ID,const byte* input, size_t length)
{
	uint64_t inlen__ = length;
	const uint8_t *in__ = ( const uint8_t * )input;
	in__ += ID * BLOCKSIZE;

	while( inlen__ >= PARALLELISM_DEGREE * BLOCKSIZE )
	{
		m_Leaves.at(ID).Update( in__, BLOCKSIZE );
		in__ += PARALLELISM_DEGREE * BLOCKSIZE;
		inlen__ -= PARALLELISM_DEGREE * BLOCKSIZE;
	}
}

BLAKE2spMAC::BLAKE2sMACRoot::BLAKE2sMACRoot(unsigned int DigestSize,unsigned int keylen) :
	BLAKE2s(DigestSize),m_Keylen(keylen)
{
	Restart();
}

void BLAKE2spMAC::BLAKE2sMACRoot::Restart()
{
	memset_z(m_h,0,m_h.SizeInBytes());
	memset_z(m_t,0,m_t.SizeInBytes());
	memset_z(m_f,0,m_f.SizeInBytes());
	memset_z(m_buf,0,m_buf.SizeInBytes());
	m_buflen=0;
	m_last_node=1;

	FixedSizeSecBlock<byte,MAX_DIGEST_SIZE> Params;
	memset_z(Params,0,MAX_DIGEST_SIZE);
	Params[0]=m_Digestsize;
	Params[1]=m_Keylen;
	Params[2]=PARALLELISM_DEGREE; //fanout
	Params[3]=2; //depth
	Params[14]=1; // node_depth
	Params[15]=MAX_DIGEST_SIZE; // inner length

	const byte* IVPtr = (const byte*) blake2s_IV;
	const byte* ParamsPtr = Params;

	for(int i=0;i<MAX_DIGEST_SIZE;++i)
		m_h.BytePtr()[i] = IVPtr[i] ^ ParamsPtr[i];
}

BLAKE2spMAC::BLAKE2sMACLeaf::BLAKE2sMACLeaf(unsigned int DigestSize,const byte* Key,unsigned int keylen,bool IsLastNode,word32 Offset) :
	BLAKE2sMAC(DigestSize,Key,keylen),m_IsLastNode(IsLastNode),m_Offset(Offset)
{
	Restart();
}

void BLAKE2spMAC::BLAKE2sMACLeaf::Restart()
{
	memset_z(m_h,0,m_h.SizeInBytes());
	memset_z(m_t,0,m_t.SizeInBytes());
	memset_z(m_f,0,m_f.SizeInBytes());
	memset_z(m_buf,0,m_buf.SizeInBytes());
	m_buflen=0;
	m_last_node=0;

	if(m_IsLastNode)
		m_last_node=1;

	FixedSizeSecBlock<byte,MAX_DIGEST_SIZE> Params;
	memset_z(Params,0,MAX_DIGEST_SIZE);
	Params[0]=m_Digestsize;
	Params[1]=m_Keylen;
	Params[2]=PARALLELISM_DEGREE; //fanout
	Params[3]=2; //depth
	*((word32*)(&Params[8]))=m_Offset; // offset
	Params[14]=0; // node_depth: 0 for leaf and 1 for root 
	Params[15]=MAX_DIGEST_SIZE; // inner length

	const byte* IVPtr = (const byte*) blake2s_IV;
	const byte* ParamsPtr = Params;

	for(int i=0;i<MAX_DIGEST_SIZE;++i)
		m_h.BytePtr()[i] = IVPtr[i] ^ ParamsPtr[i];

	Update(m_Key,BLOCKSIZE);
}

BLAKE2spMAC::BLAKE2spMAC(unsigned int Digestsize,const byte* Key,unsigned int Keylength):
	m_Root(Digestsize,Keylength),m_Digestsize(Digestsize),m_buflen(0)
{
	if(Digestsize>32 || !Digestsize)
		throw(InvalidArgument("invalid Digestsize!"));

	for(unsigned int i=0;i<PARALLELISM_DEGREE;++i)
		m_Leaves.push_back(BLAKE2sMACLeaf(Digestsize,Key,Keylength,i==(PARALLELISM_DEGREE-1),i));

	Restart();
}

void BLAKE2spMAC::Restart()
{
	m_Root.Restart();
	for(unsigned int i=0;i<PARALLELISM_DEGREE;++i)
		m_Leaves.at(i).Restart();
}

void BLAKE2spMAC::Update(const byte *input, size_t length)
{
	size_t left = m_buflen;
	size_t fill = m_buf.SizeInBytes() - left;

	if( left && length >= fill )
	{
		memcpy( m_buf + left, input, fill );

		for( size_t i = 0; i < PARALLELISM_DEGREE; ++i )
			m_Leaves.at(i).Update( m_buf + i * BLOCKSIZE, BLOCKSIZE );

		input += fill;
		length -= fill;
		left = 0;
	}

#if CRYPTOPP_BOOL_CPP11_THREAD_SUPPORTED
	std::vector<std::thread> ThreadVector(PARALLELISM_DEGREE);
	for(unsigned int i=0;i<PARALLELISM_DEGREE;++i)
		ThreadVector.at(i)=std::thread(&BLAKE2spMAC::ThreadUpdate,this,i,input,length);
	for(std::vector<std::thread>::iterator it=ThreadVector.begin();it!=ThreadVector.end();++it)
		it->join();
#else
	for(unsigned int i=0;i<PARALLELISM_DEGREE;++i)
		ThreadUpdate(i,input,length);
#endif

	input += length - length % ( PARALLELISM_DEGREE * BLOCKSIZE );
	length %= PARALLELISM_DEGREE * BLOCKSIZE;

	if( length > 0 )
		memcpy( m_buf + left, input, length );

	m_buflen = left + length;
}

void BLAKE2spMAC::TruncatedFinal(byte *digest, size_t digestSize)
{
	FixedSizeSecBlock<byte,MAX_DIGEST_SIZE> hash[PARALLELISM_DEGREE];

	for( size_t i = 0; i < PARALLELISM_DEGREE; ++i )
	{
		if( m_buflen > i * BLOCKSIZE )
		{
			size_t left = m_buflen - i * BLOCKSIZE;

			if( left > BLOCKSIZE )
				left = BLOCKSIZE;

			m_Leaves.at(i).Update(  m_buf + i * BLOCKSIZE, left );
		}

		m_Leaves.at(i).Final( hash[i] );
	}

	for( size_t i = 0; i < PARALLELISM_DEGREE; ++i )
		m_Root.Update(hash[i],MAX_DIGEST_SIZE);

	m_Root.TruncatedFinal(digest,digestSize);

	Restart();
}

void BLAKE2spMAC::ThreadUpdate(unsigned int ID,const byte* input, size_t length)
{
	uint64_t inlen__ = length;
	const uint8_t *in__ = ( const uint8_t * )input;
	in__ += ID * BLOCKSIZE;

	while( inlen__ >= PARALLELISM_DEGREE * BLOCKSIZE )
	{
		m_Leaves.at(ID).Update( in__, BLOCKSIZE );
		in__ += PARALLELISM_DEGREE * BLOCKSIZE;
		inlen__ -= PARALLELISM_DEGREE * BLOCKSIZE;
	}
}


NAMESPACE_END