#ifndef RSA_BN_H
#define RSA_BN_H

#include <openssl/bn.h>

struct BNInt
{
    BNInt()
    {
        v = BN_new();
    }

    ~BNInt()
    {
        BN_clear_free(v);
    }

    template<size_t BitSize>
    BNInt(RSAInt<BitSize> src)
    {
        v = BN_new();
        set_from_words(src.words, src.WORD_COUNT);
    }
    
    void set_from_words(const RSAIntBase::word_t* src, size_t words)
    {
        BN_clear(v);
        size_t bitsCnt = 0;
        for (size_t wordsCnt = 0; wordsCnt < words; wordsCnt++)
        for (RSAIntBase::word_t bitsMask = 1; bitsMask != 0; bitsMask <<=1, bitsCnt++)
          if (src[wordsCnt] & bitsMask) BN_set_bit(v, bitsCnt);
    }

    template<size_t BitSize>
    operator RSAInt<BitSize>() const
    {
        RSAInt<BitSize> ret;
        get_to_words(ret.words, ret.WORD_COUNT);
        return ret;
    }

    void get_to_words(RSAIntBase::word_t* dst, size_t words) const
    {
        size_t bitsCnt = 0;
        size_t const bitsInWord = sizeof(*dst) << 3;
        for (size_t wordsCnt = 0; wordsCnt < words; wordsCnt++) {
          dst[wordsCnt] = 0;
          for (size_t bitInWord = 0; bitInWord < bitsInWord; bitInWord++, bitsCnt++)
            dst[wordsCnt] |= RSAIntBase::word_t(BN_is_bit_set(v, bitsCnt)) << bitInWord;
        }
    }

    operator BIGNUM*() const
    {
        return v;
    }

    BIGNUM* v;
};

std::ostream& operator<<(std::ostream& out, const BNInt& v)
{
    return out << BN_bn2hex(v);
}

#endif
