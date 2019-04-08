#include <stddef.h>
#include "rsa_gmp.h"

void GMPInt::set_from_words(const RSAIntBase::word_t* src, size_t word_count)
{
    size_t word_bytes = sizeof(*src);
    size_t nails = CHAR_BIT*word_bytes-RSAIntBase::WORD_BITS;
    mpz_import(v, word_count, -1, word_bytes, 0, nails, src);
}


void GMPInt::get_to_words(RSAIntBase::word_t* dst, size_t word_count) const
{
    size_t value_word_count = (get_bit_size()-1)/RSAIntBase::WORD_BITS+1;
    if ( value_word_count > word_count )
        throw std::runtime_error("number doesn't fit into RSAInt<>");
    size_t word_bytes = sizeof(*dst);
    size_t nails = CHAR_BIT*word_bytes-RSAIntBase::WORD_BITS;
    mpz_export(dst, &value_word_count, -1, word_bytes, 0, nails, v);
    std::fill(dst+value_word_count, dst+word_count, 0);
}

std::ostream& operator<<(std::ostream& out, const GMPInt& v)
{
    return out << v.to_hex_string();
}
