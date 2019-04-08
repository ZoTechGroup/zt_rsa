#ifndef RSA_GMP_H
#define RSA_GMP_H

#include <cstddef>
#include <gmp.h>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <iostream>
#include "rsa.h"

struct GMPInt
{
    GMPInt()
    {
        mpz_init(v);
    }
    explicit
    GMPInt(int src)
    {
        mpz_init_set_si(v, src);
    }
    explicit
    GMPInt(uint32_t src)
    {
        mpz_init_set_ui(v, src);
    }
    explicit
    GMPInt(uint64_t src)
    {
        mpz_init_set_ui(v, src>>32);
        mpz_mul_2exp(v, v, 32);
        mpz_add_ui(v, v, uint32_t(src));
    }
    GMPInt(const GMPInt& src)
    {
        mpz_init_set(v, src.v);
    }
    /*
    GMPInt(GMPInt&& src)
        : v{src.v[0]}
    {
        src.v[0] = __mpz_struct{};
    }
    */
    GMPInt(const RSAIntBase::word_t* src, size_t word_count)
        : v()
    {
        set_from_words(src, word_count);
    }
    template<int W>
    GMPInt(const ap_uint<W>& src)
    {
        size_t k = W/32;
        mpz_init_set_ui(v, uint32_t(src>>k*32));
        while ( k ) {
            --k;
            mpz_mul_2exp(v, v, 32);
            mpz_add_ui(v, v, uint32_t(src>>k*32));
        }
    }
    ~GMPInt()
    {
        mpz_clear(v);
    }

    GMPInt& operator=(const GMPInt& src)
    {
        if ( this != &src ) {
            mpz_set(v, src.v);
        }
        return *this;
    }
    /*
    GMPInt& operator=(GMPInt&& src)
    {
        v[0] = src.v[0];
        src.v[0] = __mpz_struct();
        return *this;
    }
    */

    template<size_t BitSize>
    GMPInt(RSAInt<BitSize> src)
	    : v()
    {
        set_from_words(src.words, src.WORD_COUNT);
    }

    size_t get_bit_size() const
    {
        return mpz_sizeinbase(v, 2);
    }
    size_t get_word_count() const
    {
        return (get_bit_size()-1)/RSAIntBase::WORD_BITS+1;
    }
    uint64_t get_low_word() const
    {
        return mpz_getlimbn(v, 0);
    }
    
    void set_from_words(const RSAIntBase::word_t* src, size_t word_count);
    void get_to_words(RSAIntBase::word_t* dst, size_t word_count) const;
    
    template<size_t BitSize>
    operator RSAInt<BitSize>() const
    {
        RSAInt<BitSize> ret;
        get_to_words(ret.words, ret.WORD_COUNT);
        return ret;
    }

    bool operator==(const GMPInt& b) const
    {
        return mpz_cmp(v, b) == 0;
    }
    bool operator!=(const GMPInt& b) const
    {
        return mpz_cmp(v, b) != 0;
    }
    bool operator<(const GMPInt& b) const
    {
        return mpz_cmp(v, b) < 0;
    }
    bool operator>(const GMPInt& b) const
    {
        return mpz_cmp(v, b) > 0;
    }
    bool operator<=(const GMPInt& b) const
    {
        return mpz_cmp(v, b) <= 0;
    }
    bool operator>=(const GMPInt& b) const
    {
        return mpz_cmp(v, b) >= 0;
    }

    operator mpz_srcptr() const
    {
        return v;
    }
    operator mpz_ptr()
    {
        return v;
    }

    bool is_negative() const
    {
        return mpz_sgn(v) < 0;
    }
    
    GMPInt& operator+=(const GMPInt& b)
    {
        mpz_add(*this, *this, b);
        return *this;
    }

    GMPInt& operator-=(const GMPInt& b)
    {
        mpz_sub(*this, *this, b);
        return *this;
    }

    std::string to_hex_string() const
    {
        char* str = mpz_get_str(0, -16, v);
        std::string ret(str);
        void (*freefunc)(void *, size_t);
        mp_get_memory_functions(0, 0, &freefunc);
        freefunc(str, ret.size()+1);
        return ret;
    }

    mpz_t v;
};

inline
bool is_negative(const GMPInt& a)
{
    return a.is_negative();
}

inline
GMPInt operator+(const GMPInt& a, const GMPInt& b)
{
    GMPInt ret;
    mpz_add(ret, a, b);
    return ret;
}

inline
GMPInt operator-(const GMPInt& a, const GMPInt& b)
{
    GMPInt ret;
    mpz_sub(ret, a, b);
    return ret;
}

inline
GMPInt operator*(const GMPInt& a, const GMPInt& b)
{
    GMPInt ret;
    mpz_mul(ret, a, b);
    return ret;
}

inline
GMPInt operator/(const GMPInt& a, const GMPInt& b)
{
    GMPInt ret;
    mpz_div(ret, a, b);
    return ret;
}

inline
GMPInt operator%(const GMPInt& a, const GMPInt& b)
{
    GMPInt ret;
    mpz_mod(ret, a, b);
    return ret;
}

inline
GMPInt operator<<(const GMPInt& a, unsigned shift)
{
    GMPInt ret;
    mpz_mul_2exp(ret, a, shift);
    return ret;
}

inline
GMPInt operator>>(const GMPInt& a, unsigned shift)
{
    GMPInt ret;
    mpz_div_2exp(ret, a, shift);
    return ret;
}

inline
GMPInt mulm(const GMPInt& a, const GMPInt& b, const GMPInt& m)
{
    return a*b%m;
}

inline
GMPInt subm(const GMPInt& a, const GMPInt& b, const GMPInt& m)
{
    GMPInt ret = a - b;
    if ( ret.is_negative() )
        ret += m;
    return ret;
}

inline
GMPInt subm2(const GMPInt& a, const GMPInt& b, const GMPInt& m)
{
    GMPInt ret = subm(a, b, m);
    if ( ret.is_negative() )
        ret += m;
    return ret;
}

inline
GMPInt powm_sec(const GMPInt& a, const GMPInt& e, const GMPInt& m)
{
    GMPInt ret;
    mpz_powm/*_sec*/(ret, a, e, m);
    return ret;
}

inline
GMPInt powm(const GMPInt& a, const GMPInt& e, const GMPInt& m)
{
    GMPInt ret;
    mpz_powm(ret, a, e, m);
    return ret;
}

std::ostream& operator<<(std::ostream& out, const GMPInt& v);

#endif
