#ifndef CRYPTOPP_DHASH_H
#define CRYPTOPP_DHASH_H


NAMESPACE_BEGIN(CryptoPP)

template<class BASE>
class CRYPTOPP_DLL DoubledHash: public BASE
{
public:
	static const char * CRYPTOPP_API StaticAlgorithmName() { return BASE::StaticAlgorithmName(); }

	void TruncatedFinal(byte *digest, size_t digestSize)
  {
    unsigned char firstDigest[BASE::DIGESTSIZE] = {0};
    m_hash.Final(firstDigest);
    m_hash.Restart();
    m_hash.Update(firstDigest, BASE::DIGESTSIZE);
    m_hash.TruncatedFinal(digest, digestSize);
  }

	unsigned int DigestSize() const { return BASE::DIGESTSIZE; }
	void Update(const byte *input, size_t length) { m_hash.Update(input, length); }

private:
	BASE m_hash;
};


NAMESPACE_END

#endif // CRYPTOPP_DHASH_H
