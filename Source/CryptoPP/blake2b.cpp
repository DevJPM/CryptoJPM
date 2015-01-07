// blake2b.cpp - written and placed in the public domain by Jean-Pierre Muench
// Thanks go to Zooko Wilcox-O'Hearn for providing the idea of implementing BLAKE2 in Crypto++/JPM
// Thanks go to Samuel Neves for the optimized C-implementation

#include "pch.h"
#include "blake2b.h"
#include "cpu.h"

#define LOAD_MSG_0_1(b0, b1) b0 = _mm_set_epi64x(m2, m0); b1 = _mm_set_epi64x(m6, m4)
#define LOAD_MSG_0_2(b0, b1) b0 = _mm_set_epi64x(m3, m1); b1 = _mm_set_epi64x(m7, m5)
#define LOAD_MSG_0_3(b0, b1) b0 = _mm_set_epi64x(m10, m8); b1 = _mm_set_epi64x(m14, m12)
#define LOAD_MSG_0_4(b0, b1) b0 = _mm_set_epi64x(m11, m9); b1 = _mm_set_epi64x(m15, m13)
#define LOAD_MSG_1_1(b0, b1) b0 = _mm_set_epi64x(m4, m14); b1 = _mm_set_epi64x(m13, m9)
#define LOAD_MSG_1_2(b0, b1) b0 = _mm_set_epi64x(m8, m10); b1 = _mm_set_epi64x(m6, m15)
#define LOAD_MSG_1_3(b0, b1) b0 = _mm_set_epi64x(m0, m1); b1 = _mm_set_epi64x(m5, m11)
#define LOAD_MSG_1_4(b0, b1) b0 = _mm_set_epi64x(m2, m12); b1 = _mm_set_epi64x(m3, m7)
#define LOAD_MSG_2_1(b0, b1) b0 = _mm_set_epi64x(m12, m11); b1 = _mm_set_epi64x(m15, m5)
#define LOAD_MSG_2_2(b0, b1) b0 = _mm_set_epi64x(m0, m8); b1 = _mm_set_epi64x(m13, m2)
#define LOAD_MSG_2_3(b0, b1) b0 = _mm_set_epi64x(m3, m10); b1 = _mm_set_epi64x(m9, m7)
#define LOAD_MSG_2_4(b0, b1) b0 = _mm_set_epi64x(m6, m14); b1 = _mm_set_epi64x(m4, m1)
#define LOAD_MSG_3_1(b0, b1) b0 = _mm_set_epi64x(m3, m7); b1 = _mm_set_epi64x(m11, m13)
#define LOAD_MSG_3_2(b0, b1) b0 = _mm_set_epi64x(m1, m9); b1 = _mm_set_epi64x(m14, m12)
#define LOAD_MSG_3_3(b0, b1) b0 = _mm_set_epi64x(m5, m2); b1 = _mm_set_epi64x(m15, m4)
#define LOAD_MSG_3_4(b0, b1) b0 = _mm_set_epi64x(m10, m6); b1 = _mm_set_epi64x(m8, m0)
#define LOAD_MSG_4_1(b0, b1) b0 = _mm_set_epi64x(m5, m9); b1 = _mm_set_epi64x(m10, m2)
#define LOAD_MSG_4_2(b0, b1) b0 = _mm_set_epi64x(m7, m0); b1 = _mm_set_epi64x(m15, m4)
#define LOAD_MSG_4_3(b0, b1) b0 = _mm_set_epi64x(m11, m14); b1 = _mm_set_epi64x(m3, m6)
#define LOAD_MSG_4_4(b0, b1) b0 = _mm_set_epi64x(m12, m1); b1 = _mm_set_epi64x(m13, m8)
#define LOAD_MSG_5_1(b0, b1) b0 = _mm_set_epi64x(m6, m2); b1 = _mm_set_epi64x(m8, m0)
#define LOAD_MSG_5_2(b0, b1) b0 = _mm_set_epi64x(m10, m12); b1 = _mm_set_epi64x(m3, m11)
#define LOAD_MSG_5_3(b0, b1) b0 = _mm_set_epi64x(m7, m4); b1 = _mm_set_epi64x(m1, m15)
#define LOAD_MSG_5_4(b0, b1) b0 = _mm_set_epi64x(m5, m13); b1 = _mm_set_epi64x(m9, m14)
#define LOAD_MSG_6_1(b0, b1) b0 = _mm_set_epi64x(m1, m12); b1 = _mm_set_epi64x(m4, m14)
#define LOAD_MSG_6_2(b0, b1) b0 = _mm_set_epi64x(m15, m5); b1 = _mm_set_epi64x(m10, m13)
#define LOAD_MSG_6_3(b0, b1) b0 = _mm_set_epi64x(m6, m0); b1 = _mm_set_epi64x(m8, m9)
#define LOAD_MSG_6_4(b0, b1) b0 = _mm_set_epi64x(m3, m7); b1 = _mm_set_epi64x(m11, m2)
#define LOAD_MSG_7_1(b0, b1) b0 = _mm_set_epi64x(m7, m13); b1 = _mm_set_epi64x(m3, m12)
#define LOAD_MSG_7_2(b0, b1) b0 = _mm_set_epi64x(m14, m11); b1 = _mm_set_epi64x(m9, m1)
#define LOAD_MSG_7_3(b0, b1) b0 = _mm_set_epi64x(m15, m5); b1 = _mm_set_epi64x(m2, m8)
#define LOAD_MSG_7_4(b0, b1) b0 = _mm_set_epi64x(m4, m0); b1 = _mm_set_epi64x(m10, m6)
#define LOAD_MSG_8_1(b0, b1) b0 = _mm_set_epi64x(m14, m6); b1 = _mm_set_epi64x(m0, m11)
#define LOAD_MSG_8_2(b0, b1) b0 = _mm_set_epi64x(m9, m15); b1 = _mm_set_epi64x(m8, m3)
#define LOAD_MSG_8_3(b0, b1) b0 = _mm_set_epi64x(m13, m12); b1 = _mm_set_epi64x(m10, m1)
#define LOAD_MSG_8_4(b0, b1) b0 = _mm_set_epi64x(m7, m2); b1 = _mm_set_epi64x(m5, m4)
#define LOAD_MSG_9_1(b0, b1) b0 = _mm_set_epi64x(m8, m10); b1 = _mm_set_epi64x(m1, m7)
#define LOAD_MSG_9_2(b0, b1) b0 = _mm_set_epi64x(m4, m2); b1 = _mm_set_epi64x(m5, m6)
#define LOAD_MSG_9_3(b0, b1) b0 = _mm_set_epi64x(m9, m15); b1 = _mm_set_epi64x(m13, m3)
#define LOAD_MSG_9_4(b0, b1) b0 = _mm_set_epi64x(m14, m11); b1 = _mm_set_epi64x(m0, m12)
#define LOAD_MSG_10_1(b0, b1) b0 = _mm_set_epi64x(m2, m0); b1 = _mm_set_epi64x(m6, m4)
#define LOAD_MSG_10_2(b0, b1) b0 = _mm_set_epi64x(m3, m1); b1 = _mm_set_epi64x(m7, m5)
#define LOAD_MSG_10_3(b0, b1) b0 = _mm_set_epi64x(m10, m8); b1 = _mm_set_epi64x(m14, m12)
#define LOAD_MSG_10_4(b0, b1) b0 = _mm_set_epi64x(m11, m9); b1 = _mm_set_epi64x(m15, m13)
#define LOAD_MSG_11_1(b0, b1) b0 = _mm_set_epi64x(m4, m14); b1 = _mm_set_epi64x(m13, m9)
#define LOAD_MSG_11_2(b0, b1) b0 = _mm_set_epi64x(m8, m10); b1 = _mm_set_epi64x(m6, m15)
#define LOAD_MSG_11_3(b0, b1) b0 = _mm_set_epi64x(m0, m1); b1 = _mm_set_epi64x(m5, m11)
#define LOAD_MSG_11_4(b0, b1) b0 = _mm_set_epi64x(m2, m12); b1 = _mm_set_epi64x(m3, m7)

#define LOAD(p)  _mm_load_si128( (__m128i *)(p) )
#define STORE(p,r) _mm_store_si128((__m128i *)(p), r)

#define LOADU(p)  _mm_loadu_si128( (__m128i *)(p) )
#define STOREU(p,r) _mm_storeu_si128((__m128i *)(p), r)

#define TOF(reg) _mm_castsi128_ps((reg))
#define TOI(reg) _mm_castps_si128((reg))

#define LIKELY(x) __builtin_expect((x),1)

#define _mm_roti_epi64(x, c) \
	(-(c) == 32) ? _mm_shuffle_epi32((x), _MM_SHUFFLE(2,3,0,1))  \
	: (-(c) == 24) ? _mm_shuffle_epi8((x), r24) \
	: (-(c) == 16) ? _mm_shuffle_epi8((x), r16) \
	: (-(c) == 63) ? _mm_xor_si128(_mm_srli_epi64((x), -(c)), _mm_add_epi64((x), (x)))  \
	: _mm_xor_si128(_mm_srli_epi64((x), -(c)), _mm_slli_epi64((x), 64-(-(c))))

#define DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
  t0 = _mm_alignr_epi8(row2h, row2l, 8); \
  t1 = _mm_alignr_epi8(row2l, row2h, 8); \
  row2l = t0; \
  row2h = t1; \
  \
  t0 = row3l; \
  row3l = row3h; \
  row3h = t0;    \
  \
  t0 = _mm_alignr_epi8(row4h, row4l, 8); \
  t1 = _mm_alignr_epi8(row4l, row4h, 8); \
  row4l = t1; \
  row4h = t0;

#define UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
  t0 = _mm_alignr_epi8(row2l, row2h, 8); \
  t1 = _mm_alignr_epi8(row2h, row2l, 8); \
  row2l = t0; \
  row2h = t1; \
  \
  t0 = row3l; \
  row3l = row3h; \
  row3h = t0; \
  \
  t0 = _mm_alignr_epi8(row4l, row4h, 8); \
  t1 = _mm_alignr_epi8(row4h, row4l, 8); \
  row4l = t1; \
  row4h = t0;

#define G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l); \
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h); \
  \
  row4l = _mm_xor_si128(row4l, row1l); \
  row4h = _mm_xor_si128(row4h, row1h); \
  \
  row4l = _mm_roti_epi64(row4l, -32); \
  row4h = _mm_roti_epi64(row4h, -32); \
  \
  row3l = _mm_add_epi64(row3l, row4l); \
  row3h = _mm_add_epi64(row3h, row4h); \
  \
  row2l = _mm_xor_si128(row2l, row3l); \
  row2h = _mm_xor_si128(row2h, row3h); \
  \
  row2l = _mm_roti_epi64(row2l, -24); \
  row2h = _mm_roti_epi64(row2h, -24); \
 
#define G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l); \
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h); \
  \
  row4l = _mm_xor_si128(row4l, row1l); \
  row4h = _mm_xor_si128(row4h, row1h); \
  \
  row4l = _mm_roti_epi64(row4l, -16); \
  row4h = _mm_roti_epi64(row4h, -16); \
  \
  row3l = _mm_add_epi64(row3l, row4l); \
  row3h = _mm_add_epi64(row3h, row4h); \
  \
  row2l = _mm_xor_si128(row2l, row3l); \
  row2h = _mm_xor_si128(row2h, row3h); \
  \
  row2l = _mm_roti_epi64(row2l, -63); \
  row2h = _mm_roti_epi64(row2h, -63); \

#define ROUND(r) \
  LOAD_MSG_ ##r ##_1(b0, b1); \
  G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
  LOAD_MSG_ ##r ##_2(b0, b1); \
  G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
  DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
  LOAD_MSG_ ##r ##_3(b0, b1); \
  G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
  LOAD_MSG_ ##r ##_4(b0, b1); \
  G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
  UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h);

NAMESPACE_BEGIN(CryptoPP)

CRYPTOPP_ALIGN_DATA( 64 ) static const word64 blake2b_IV[8] =
{
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const byte blake2b_sigma[12][16] =
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
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

BLAKE2b::BLAKE2b(unsigned int Digestsize) :
	m_Digestsize(Digestsize)
{
	if(Digestsize>64 || !Digestsize)
		throw(InvalidArgument("invalid Digestsize!"));

	Restart();
}

void BLAKE2b::Restart()
{
	memset_z(m_h,0,m_h.SizeInBytes());
	memset_z(m_t,0,m_t.SizeInBytes());
	memset_z(m_f,0,m_f.SizeInBytes());
	memset_z(m_buf,0,m_buf.SizeInBytes());
	m_buflen=0;
	m_last_node=0;

	FixedSizeSecBlock<byte,BLOCKSIZE> Params;
	memset_z(Params,0,BLOCKSIZE);
	Params[0]=m_Digestsize;
	Params[2]=1;
	Params[3]=1;

	const byte* IVPtr = (const byte*) blake2b_IV;
	const byte* ParamsPtr = Params;

	for(int i=0;i<BLOCKSIZE;++i)
		m_h[i] = IVPtr[i] ^ ParamsPtr[i];
}

void BLAKE2b::TruncatedFinal(byte *digest, size_t digestSize)
{
	if( m_buflen > BLOCKSIZE )
	{
		IncrementCounter( BLOCKSIZE );
		Compress( m_buf.BytePtr() );
		m_buflen -= BLOCKSIZE;
		memcpy( m_buf, m_buf + BLOCKSIZE, m_buflen );
	}

	IncrementCounter( m_buflen );
	SetLastBlock();
	memset_z( m_buf.BytePtr() + m_buflen, 0, 2 * BLOCKSIZE - m_buflen ); /* Padding */
	Compress( m_buf.BytePtr() );
	memcpy( digest, &m_h[0], digestSize );
}

void BLAKE2b::Compress(const byte* block)
{
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
if(HasSSSE3() && HasSSE2())
{
  __m128i row1l, row1h;
  __m128i row2l, row2h;
  __m128i row3l, row3h;
  __m128i row4l, row4h;
  __m128i b0, b1;
  __m128i t0, t1;
  const __m128i r16 = _mm_setr_epi8( 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9 );
  const __m128i r24 = _mm_setr_epi8( 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10 );

  const word64  m0 = ( ( word64 * )block )[ 0];
  const word64  m1 = ( ( word64 * )block )[ 1];
  const word64  m2 = ( ( word64 * )block )[ 2];
  const word64  m3 = ( ( word64 * )block )[ 3];
  const word64  m4 = ( ( word64 * )block )[ 4];
  const word64  m5 = ( ( word64 * )block )[ 5];
  const word64  m6 = ( ( word64 * )block )[ 6];
  const word64  m7 = ( ( word64 * )block )[ 7];
  const word64  m8 = ( ( word64 * )block )[ 8];
  const word64  m9 = ( ( word64 * )block )[ 9];
  const word64 m10 = ( ( word64 * )block )[10];
  const word64 m11 = ( ( word64 * )block )[11];
  const word64 m12 = ( ( word64 * )block )[12];
  const word64 m13 = ( ( word64 * )block )[13];
  const word64 m14 = ( ( word64 * )block )[14];
  const word64 m15 = ( ( word64 * )block )[15];

  row1l = LOADU( &m_h[0] );
  row1h = LOADU( &m_h[2] );
  row2l = LOADU( &m_h[4] );
  row2h = LOADU( &m_h[6] );
  row3l = LOADU( &blake2b_IV[0] );
  row3h = LOADU( &blake2b_IV[2] );
  row4l = _mm_xor_si128( LOADU( &blake2b_IV[4] ), LOADU( &m_t[0] ) );
  row4h = _mm_xor_si128( LOADU( &blake2b_IV[6] ), LOADU( &m_f[0] ) );
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
  ROUND( 10 );
  ROUND( 11 );
  row1l = _mm_xor_si128( row3l, row1l );
  row1h = _mm_xor_si128( row3h, row1h );
  STOREU( &m_h[0], _mm_xor_si128( LOADU( &m_h[0] ), row1l ) );
  STOREU( &m_h[2], _mm_xor_si128( LOADU( &m_h[2] ), row1h ) );
  row2l = _mm_xor_si128( row4l, row2l );
  row2h = _mm_xor_si128( row4h, row2h );
  STOREU( &m_h[4], _mm_xor_si128( LOADU( &m_h[4] ), row2l ) );
  STOREU( &m_h[6], _mm_xor_si128( LOADU( &m_h[6] ), row2h ) );
}
else
{
#endif
  uint64_t m[16];
  uint64_t v[16];
  int i;

  for( i = 0; i < 16; ++i )
	  m[i] = ConditionalByteReverse(LITTLE_ENDIAN_ORDER,*((word64*) (block + i * sizeof( m[i] ))) );

  for( i = 0; i < 8; ++i )
	v[i] = m_h[i];

  v[ 8] = blake2b_IV[0];
  v[ 9] = blake2b_IV[1];
  v[10] = blake2b_IV[2];
  v[11] = blake2b_IV[3];
  v[12] = m_t[0] ^ blake2b_IV[4];
  v[13] = m_t[1] ^ blake2b_IV[5];
  v[14] = m_f[0] ^ blake2b_IV[6];
  v[15] = m_f[1] ^ blake2b_IV[7];
#define GREF(r,i,a,b,c,d) \
  do { \
	a = a + b + m[blake2b_sigma[r][2*i+0]]; \
	d = rotrFixed<word64>(d ^ a, 32); \
	c = c + d; \
	b = rotrFixed<word64>(b ^ c, 24); \
	a = a + b + m[blake2b_sigma[r][2*i+1]]; \
	d = rotrFixed<word64>(d ^ a, 16); \
	c = c + d; \
	b = rotrFixed<word64>(b ^ c, 63); \
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
  ROUNDREF( 10 );
  ROUNDREF( 11 );

  for( i = 0; i < 8; ++i )
	m_h[i] = m_h[i] ^ v[i] ^ v[i + 8];

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
}
#endif
}

void BLAKE2b::Update(const byte *input, size_t length)
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
			Compress( m_buf.BytePtr() ); // Compress
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

BLAKE2bMAC::BLAKE2bMAC(unsigned int Digestsize,const byte* Key,unsigned int Keylength) :
	m_Digestsize(Digestsize)
{
	if(Digestsize>64 || !Digestsize)
		throw(InvalidArgument("invalid Digestsize!"));

	ThrowIfInvalidKeyLength(Keylength);

	SetKey(Key,Keylength);

	Restart();
}

void BLAKE2bMAC::Restart()
{
	memset_z(m_h,0,m_h.SizeInBytes());
	memset_z(m_t,0,m_t.SizeInBytes());
	memset_z(m_f,0,m_f.SizeInBytes());
	memset_z(m_buf,0,m_buf.SizeInBytes());
	m_buflen=0;
	m_last_node=0;

	FixedSizeSecBlock<byte,BLOCKSIZE> Params;
	memset_z(Params,0,BLOCKSIZE);
	Params[0]=m_Digestsize;
	Params[2]=1;
	Params[3]=1;

	const byte* IVPtr = (const byte*) blake2b_IV;
	const byte* ParamsPtr = Params;

	for(int i=0;i<BLOCKSIZE;++i)
		m_h[i] = IVPtr[i] ^ ParamsPtr[i];

	Update(m_Key,BLOCKSIZE);
}

void BLAKE2bMAC::TruncatedFinal(byte *digest, size_t digestSize)
{
	if( m_buflen > BLOCKSIZE )
	{
		IncrementCounter( BLOCKSIZE );
		Compress( m_buf.BytePtr() );
		m_buflen -= BLOCKSIZE;
		memcpy( m_buf, m_buf + BLOCKSIZE, m_buflen );
	}

	IncrementCounter( m_buflen );
	SetLastBlock();
	memset_z( m_buf.BytePtr() + m_buflen, 0, 2 * BLOCKSIZE - m_buflen ); /* Padding */
	Compress( m_buf.BytePtr() );
	memcpy( digest, &m_h[0], digestSize );
}

void BLAKE2bMAC::Compress(const byte* block)
{
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
if(HasSSSE3() && HasSSE2())
{
  __m128i row1l, row1h;
  __m128i row2l, row2h;
  __m128i row3l, row3h;
  __m128i row4l, row4h;
  __m128i b0, b1;
  __m128i t0, t1;
  const __m128i r16 = _mm_setr_epi8( 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9 );
  const __m128i r24 = _mm_setr_epi8( 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10 );

  const word64  m0 = ( ( word64 * )block )[ 0];
  const word64  m1 = ( ( word64 * )block )[ 1];
  const word64  m2 = ( ( word64 * )block )[ 2];
  const word64  m3 = ( ( word64 * )block )[ 3];
  const word64  m4 = ( ( word64 * )block )[ 4];
  const word64  m5 = ( ( word64 * )block )[ 5];
  const word64  m6 = ( ( word64 * )block )[ 6];
  const word64  m7 = ( ( word64 * )block )[ 7];
  const word64  m8 = ( ( word64 * )block )[ 8];
  const word64  m9 = ( ( word64 * )block )[ 9];
  const word64 m10 = ( ( word64 * )block )[10];
  const word64 m11 = ( ( word64 * )block )[11];
  const word64 m12 = ( ( word64 * )block )[12];
  const word64 m13 = ( ( word64 * )block )[13];
  const word64 m14 = ( ( word64 * )block )[14];
  const word64 m15 = ( ( word64 * )block )[15];

  row1l = LOADU( &m_h[0] );
  row1h = LOADU( &m_h[2] );
  row2l = LOADU( &m_h[4] );
  row2h = LOADU( &m_h[6] );
  row3l = LOADU( &blake2b_IV[0] );
  row3h = LOADU( &blake2b_IV[2] );
  row4l = _mm_xor_si128( LOADU( &blake2b_IV[4] ), LOADU( &m_t[0] ) );
  row4h = _mm_xor_si128( LOADU( &blake2b_IV[6] ), LOADU( &m_f[0] ) );
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
  ROUND( 10 );
  ROUND( 11 );
  row1l = _mm_xor_si128( row3l, row1l );
  row1h = _mm_xor_si128( row3h, row1h );
  STOREU( &m_h[0], _mm_xor_si128( LOADU( &m_h[0] ), row1l ) );
  STOREU( &m_h[2], _mm_xor_si128( LOADU( &m_h[2] ), row1h ) );
  row2l = _mm_xor_si128( row4l, row2l );
  row2h = _mm_xor_si128( row4h, row2h );
  STOREU( &m_h[4], _mm_xor_si128( LOADU( &m_h[4] ), row2l ) );
  STOREU( &m_h[6], _mm_xor_si128( LOADU( &m_h[6] ), row2h ) );
}
else
{
#endif
  uint64_t m[16];
  uint64_t v[16];
  int i;

  for( i = 0; i < 16; ++i )
	  m[i] = ConditionalByteReverse(LITTLE_ENDIAN_ORDER,*((word64*) (block + i * sizeof( m[i] ))) );

  for( i = 0; i < 8; ++i )
	v[i] = m_h[i];

  v[ 8] = blake2b_IV[0];
  v[ 9] = blake2b_IV[1];
  v[10] = blake2b_IV[2];
  v[11] = blake2b_IV[3];
  v[12] = m_t[0] ^ blake2b_IV[4];
  v[13] = m_t[1] ^ blake2b_IV[5];
  v[14] = m_f[0] ^ blake2b_IV[6];
  v[15] = m_f[1] ^ blake2b_IV[7];
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
  ROUNDREF( 10 );
  ROUNDREF( 11 );

  for( i = 0; i < 8; ++i )
	m_h[i] = m_h[i] ^ v[i] ^ v[i + 8];

#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
}
#endif
}

void BLAKE2bMAC::Update(const byte *input, size_t length)
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
			Compress( m_buf.BytePtr() ); // Compress
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

NAMESPACE_END