// scrypt.cpp written and placed in the publc domain by Jean-Pierre Muench
// (non-sse) salsa20/8 core from Daniel J. Bernstein who placed in the public domain
#include "pch.h"
#include "scrypt.h"
#include "cpu.h"

#define DISABLE_SSE_LOCALLY

NAMESPACE_BEGIN(CryptoPP)

size_t scrypt_Base::MaxDerivedKeyLength() const
{
#if CRYPTOPP_BOOL_X64 == 1
	return 0xffffffffUI64 * GetHash().DigestSize();
#else
	return 0xffffffffU;// should multiply by T::DIGESTSIZE, but gets overflow that way
#endif
}

word64 scrypt_Base::MaxTCost() const
{
	const word64 Result = (0xffffffffUI64 >> (Log2R + 7)) * GetHash().DigestSize();
	if(Result > word64((size_t(0)-1))) // prevent integer overflow
		return word64(0)-1;
	else
		return Result;
}

size_t scrypt_Base::MaxMemoryUsage(word64 mCost) const
{
	// needs 128*N*r bits of memory, r=8 --> 1024*N --> 1<<(mCost + 10)
	if(mCost >= MaxMCost())
		return size_t(0)-1;
	else
		return 1ui64 << (mCost+Log2R+7);
}

word64 scrypt_Base::GetMCostFromPeakNumberBytes(size_t PeakNumberBytes) const
{
	if(PeakNumberBytes<(1ui64 << (Log2R+7)))
		return 1; // minmal valid mCost
	
	word32 NumberShifts=0;
	PeakNumberBytes>>=Log2R+7; // reduction to only measure log_2(N) and not 128rN
	while(PeakNumberBytes!=1)
	{
		PeakNumberBytes>>=1;
		NumberShifts++;
	}
	return NumberShifts;
}

word64 scrypt_Base::Integerify(const byte* State,word64 R,word64 N) const
{
	/*uint32_t * X = (word32 *)((uintptr_t)(State) + (2 * R - 1) * 64);

	word64 Index = (((uint64_t)(X[1]) << 32) + X[0]);

	return Index & (N-1);*/
	const size_t AccessIndex = (R<<7)-64;
	word64 Index = ConditionalByteReverse(LITTLE_ENDIAN_ORDER,*((word64*)(&State[AccessIndex]))) & ConditionalByteReverse(LITTLE_ENDIAN_ORDER,N-1);
	return ConditionalByteReverse(LITTLE_ENDIAN_ORDER,Index); // revert if it was big-endian, so we get a proper access
}

void scrypt_Base::BlockMix(byte* Out,const byte* In,word64 R) const
{
	FixedSizeSecBlock<byte,64> BlockMixState;
	memcpy_s(BlockMixState,64,&In[(R<<7)-64],64);
	for(word64 j=0;j<(R<<1);j+=2) // perform double-rounds
	{
		// round 1:
		xorbuf(BlockMixState,&In[j<<6],64);
		OptimizedSalsa208Core((word32*)BlockMixState.BytePtr());
		memcpy_s(&Out[j<<5],64,BlockMixState,64);

		// round 2:
		xorbuf(BlockMixState,&In[(j|1)<<6],64);
		OptimizedSalsa208Core((word32*)BlockMixState.BytePtr());
		memcpy_s(&Out[(j<<5)+(R<<6)],64,BlockMixState,64);
	}
}

void scrypt_Base::SMix(byte* Data,size_t Offset,word64 Log2N,word64 R)const
{
	const size_t LocalDataLength = R << 7;
	const word64 Modulus = ConditionalByteReverse(LITTLE_ENDIAN_ORDER,(1ui64<<Log2N)-1);

	SecByteBlock LookupTable((1ui64<<(Log2N+7))*R);
	SecByteBlock PrimaryState(&Data[Offset],LocalDataLength);
	SecByteBlock SecondaryState(LocalDataLength);

	for(word64 i=0;i<(1ui64<<Log2N);i+=2)
	{
		memcpy(&LookupTable.BytePtr()[i*LocalDataLength],PrimaryState,LocalDataLength);
		BlockMix(SecondaryState,PrimaryState,R);

		memcpy(&LookupTable.BytePtr()[(i|1)*LocalDataLength],SecondaryState,LocalDataLength);
		BlockMix(PrimaryState,SecondaryState,R);
	}
	for(word64 i=0;i<(1ui64<<Log2N);i+=2)
	{
		xorbuf(PrimaryState,&LookupTable.BytePtr()[Integerify(PrimaryState,R,1ui64<<Log2N)*LocalDataLength],LocalDataLength);
		BlockMix(SecondaryState,PrimaryState,R);

		xorbuf(SecondaryState,&LookupTable.BytePtr()[Integerify(SecondaryState,R,1ui64<<Log2N)*LocalDataLength],LocalDataLength);
		BlockMix(PrimaryState,SecondaryState,R);
	}
	memcpy(&Data[Offset],PrimaryState,LocalDataLength);
}

// the content of the following function has been placed in the public domain by Colin Percival
// upon request of Jean-Pierre Muench
void Salsa208SSE(__m128i B[4])
{
	__m128i X0, X1, X2, X3;
	__m128i T;
	size_t i;

	X0 = B[0];
	X1 = B[1];
	X2 = B[2];
	X3 = B[3];

	for (i = 0; i < 8; i += 2) {
		/* Operate on "columns". */
		T = _mm_add_epi32(X0, X3);
		X1 = _mm_xor_si128(X1, _mm_slli_epi32(T, 7));
		X1 = _mm_xor_si128(X1, _mm_srli_epi32(T, 25));
		T = _mm_add_epi32(X1, X0);
		X2 = _mm_xor_si128(X2, _mm_slli_epi32(T, 9));
		X2 = _mm_xor_si128(X2, _mm_srli_epi32(T, 23));
		T = _mm_add_epi32(X2, X1);
		X3 = _mm_xor_si128(X3, _mm_slli_epi32(T, 13));
		X3 = _mm_xor_si128(X3, _mm_srli_epi32(T, 19));
		T = _mm_add_epi32(X3, X2);
		X0 = _mm_xor_si128(X0, _mm_slli_epi32(T, 18));
		X0 = _mm_xor_si128(X0, _mm_srli_epi32(T, 14));

		/* Rearrange data. */
		X1 = _mm_shuffle_epi32(X1, 0x93);
		X2 = _mm_shuffle_epi32(X2, 0x4E);
		X3 = _mm_shuffle_epi32(X3, 0x39);

		/* Operate on "rows". */
		T = _mm_add_epi32(X0, X1);
		X3 = _mm_xor_si128(X3, _mm_slli_epi32(T, 7));
		X3 = _mm_xor_si128(X3, _mm_srli_epi32(T, 25));
		T = _mm_add_epi32(X3, X0);
		X2 = _mm_xor_si128(X2, _mm_slli_epi32(T, 9));
		X2 = _mm_xor_si128(X2, _mm_srli_epi32(T, 23));
		T = _mm_add_epi32(X2, X3);
		X1 = _mm_xor_si128(X1, _mm_slli_epi32(T, 13));
		X1 = _mm_xor_si128(X1, _mm_srli_epi32(T, 19));
		T = _mm_add_epi32(X1, X2);
		X0 = _mm_xor_si128(X0, _mm_slli_epi32(T, 18));
		X0 = _mm_xor_si128(X0, _mm_srli_epi32(T, 14));

		/* Rearrange data. */
		X1 = _mm_shuffle_epi32(X1, 0x39);
		X2 = _mm_shuffle_epi32(X2, 0x4E);
		X3 = _mm_shuffle_epi32(X3, 0x93);
	}

	B[0] = _mm_add_epi32(B[0], X0);
	B[1] = _mm_add_epi32(B[1], X1);
	B[2] = _mm_add_epi32(B[2], X2);
	B[3] = _mm_add_epi32(B[3], X3);
}

void Salsa208REF(word32* InOut)
{
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
   int i;
   word32 x[16];
   for (i = 0;i < 16;++i)
	   x[i] = InOut[i];
   for (i = 8;i > 0;i -= 2) {
	 x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
	 x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
	 x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
	 x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
	 x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
	 x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
	 x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
	 x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
	 x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
	 x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
	 x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
	 x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
	 x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
	 x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
	 x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
	 x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
   }
   for (i = 0;i < 16;++i)
	   InOut[i] += x[i];
}

void scrypt_Base::OptimizedSalsa208Core(word32* InOut) const
{
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && !defined(DISABLE_SSE_LOCALLY)
	if(HasSSE2())
	{
		Salsa208SSE((__m128i*)InOut);
	}
	else
	{
#endif
		Salsa208REF(InOut);
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE && !defined(DISABLE_SSE_LOCALLY)
	}
#endif
}

/*void scrypt_Base::OptimizedSalsa208Core(word32* InOut) const
{
#define CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE 1
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
	if(HasSSE2())
	{*/
		// the following function is mainly authored by Colin Percival
		// He has placed this function in the public domain after request by Jean-Pierre Muench
/*#define COPY_TO_SSE(k) \
	__m128i I##k;\
	I##k.m128i_u32[0]=X##k.m128i_u32[0]=InOut[(k)*4]; \
	I##k.m128i_u32[1]=X##k.m128i_u32[1]=InOut[(k)*4+1]; \
	I##k.m128i_u32[2]=X##k.m128i_u32[2]=InOut[(k)*4+2]; \
	I##k.m128i_u32[3]=X##k.m128i_u32[3]=InOut[(k)*4+3];
	

	COPY_TO_SSE(0)
	COPY_TO_SSE(1)
	COPY_TO_SSE(2)
	COPY_TO_SSE(3)


#undef COPY_TO_SSE*/
	/*__m128i* X = (__m128i*) InOut;
	__m128i X0, X1, X2, X3;
	__m128i T;
	size_t i;*/
	
	/*X0=*((__m128i*)(&InOut[(0)*4]));
	X1=*((__m128i*)(&InOut[(1)*4]));
	X2=*((__m128i*)(&InOut[(2)*4]));
	X3=*((__m128i*)(&InOut[(3)*4]));*/
	/*X0=X[0];
	X1=X[1];
	X2=X[2];
	X3=X[3];

	for (i = 0; i < 8; i += 2) {*/
		/* Operate on "columns". */
		/*T = _mm_add_epi32(X0, X3);
		X1 = _mm_xor_si128(X1, _mm_slli_epi32(T, 7));
		X1 = _mm_xor_si128(X1, _mm_srli_epi32(T, 25));
		T = _mm_add_epi32(X1, X0);
		X2 = _mm_xor_si128(X2, _mm_slli_epi32(T, 9));
		X2 = _mm_xor_si128(X2, _mm_srli_epi32(T, 23));
		T = _mm_add_epi32(X2, X1);
		X3 = _mm_xor_si128(X3, _mm_slli_epi32(T, 13));
		X3 = _mm_xor_si128(X3, _mm_srli_epi32(T, 19));
		T = _mm_add_epi32(X3, X2);
		X0 = _mm_xor_si128(X0, _mm_slli_epi32(T, 18));
		X0 = _mm_xor_si128(X0, _mm_srli_epi32(T, 14));*/

		/* Rearrange data. */
		/*X1 = _mm_shuffle_epi32(X1, 0x93);
		X2 = _mm_shuffle_epi32(X2, 0x4E);
		X3 = _mm_shuffle_epi32(X3, 0x39);*/

		/* Operate on "rows". */
		/*T = _mm_add_epi32(X0, X1);
		X3 = _mm_xor_si128(X3, _mm_slli_epi32(T, 7));
		X3 = _mm_xor_si128(X3, _mm_srli_epi32(T, 25));
		T = _mm_add_epi32(X3, X0);
		X2 = _mm_xor_si128(X2, _mm_slli_epi32(T, 9));
		X2 = _mm_xor_si128(X2, _mm_srli_epi32(T, 23));
		T = _mm_add_epi32(X2, X3);
		X1 = _mm_xor_si128(X1, _mm_slli_epi32(T, 13));
		X1 = _mm_xor_si128(X1, _mm_srli_epi32(T, 19));
		T = _mm_add_epi32(X1, X2);
		X0 = _mm_xor_si128(X0, _mm_slli_epi32(T, 18));
		X0 = _mm_xor_si128(X0, _mm_srli_epi32(T, 14));*/

		/* Rearrange data. */
		/*X1 = _mm_shuffle_epi32(X1, 0x39);
		X2 = _mm_shuffle_epi32(X2, 0x4E);
		X3 = _mm_shuffle_epi32(X3, 0x93);
	}*/

	/**((__m128i*)(&InOut[(0)*4])) = _mm_add_epi32(*((__m128i*)(&InOut[(0)*4])), X0);
	*((__m128i*)(&InOut[(1)*4])) = _mm_add_epi32(*((__m128i*)(&InOut[(1)*4])), X1);
	*((__m128i*)(&InOut[(2)*4])) = _mm_add_epi32(*((__m128i*)(&InOut[(2)*4])), X2);
	*((__m128i*)(&InOut[(3)*4])) = _mm_add_epi32(*((__m128i*)(&InOut[(3)*4])), X3);
	X[0]=_mm_add_epi32(X[0], X0);
	X[1]=_mm_add_epi32(X[1], X1);
	X[2]=_mm_add_epi32(X[2], X2);
	X[3]=_mm_add_epi32(X[3], X3);*/

/*#define GET_FROM_SSE(k) \
	InOut[(k)*4]=I##k.m128i_u32[0];\
	InOut[(k)*4+1]=I##k.m128i_u32[1];\
	InOut[(k)*4+2]=I##k.m128i_u32[2];\
	InOut[(k)*4+3]=I##k.m128i_u32[3];

	GET_FROM_SSE(0)
	GET_FROM_SSE(1)
	GET_FROM_SSE(2)
	GET_FROM_SSE(3)
#undef GET_FROM_SSE*/
	/*}
	else
	{
#endif
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
	   int i;
	   word32 x[16];
	   for (i = 0;i < 16;++i)
		   x[i] = InOut[i];
	   for (i = 8;i > 0;i -= 2) {
		 x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
		 x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
		 x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
		 x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
		 x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
		 x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
		 x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
		 x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
		 x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
		 x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
		 x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
		 x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
		 x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
		 x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
		 x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
		 x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
	   }
	   for (i = 0;i < 16;++i)
		   InOut[i] += x[i];
#undef R
#if CRYPTOPP_BOOL_SSE2_INTRINSICS_AVAILABLE
	} // ! HasSSE2()
#endif
}*/

NAMESPACE_END