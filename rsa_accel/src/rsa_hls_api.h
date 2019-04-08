#ifndef RSA_HLS_API_H
#define RSA_HLS_API_H

#include <stddef.h>
#include <stdint.h>

// input/output word type and its size in bits
typedef uint64_t rsa_word_t;
const size_t RSA_WORD_BITS = 64;

inline
size_t rsa_bits_to_words(size_t bits)
{
    return (bits+RSA_WORD_BITS-1)/RSA_WORD_BITS;
}

// exponentiation mode - fast, or fixed time (secure against timing side attack)
enum PowerMode {
    fast_power,
    secure_power
};

// Montgomery exponentiation kernel entry function
extern "C"
void rsaMontgPowNKernelEntry64(uint16_t req_count,
                               const rsa_word_t* args, // ARG64_WORDS
                               rsa_word_t* results); // RESULT64_WORDS

// Montgomery exponentiation kernel parameters
// it can be obtained by calling kernel entry function with req_count==0
struct RSAMontgInfo {
    static const rsa_word_t kMagic = 0x7a6f74656368;
    rsa_word_t info_size; // total number of bytes in the info structure
    rsa_word_t magic; // kMagic
    rsa_word_t flags;
    rsa_word_t max_mod_bits;
    rsa_word_t max_req_count;
    rsa_word_t montg_word_bits;
    rsa_word_t request_words;
    rsa_word_t result_words;
    
    inline size_t get_mod_word_count() const
    {
        return rsa_bits_to_words(max_mod_bits);
    }
    inline size_t get_arg_word_count() const
    {
        return 1+4*get_mod_word_count(); // sizes word, then (mod, exp, r2, data)
    }
    inline size_t get_result_word_count() const
    {
        return get_mod_word_count(); // just one value
    }
};

// calculate word count for modulus in montgomery multiplication algorithm
// needs two zero bits to avoid overflow
// the argument is number of bits in modulus
#define GET_MONTG_WORD_COUNT2(mod_bits, word_bits) (((mod_bits)+1)/(word_bits)+1) // =41 for RSA-2048

// R2 is the value required by Montgomery multiplication algorithm that's
// cheaper to calculate on CPU. Its value is (2^R2_BIT % MOD).
// The GET_MONTG_R2_BIT macro gives the R2_BIT value.
#define GET_MONTG_R2_BIT2(mod_bits, word_bits) (2*(word_bits)*(GET_MONTG_WORD_COUNT2(mod_bits, word_bits)+1))

// Default Montgomery multiplication word size in bits (montg_word_bits field in RSAMontgInfo)
#define DEFAULT_MONTG_WORD_BITS 51

#define GET_MONTG_WORD_COUNT(mod_bits) GET_MONTG_WORD_COUNT2(mod_bits, DEFAULT_MONTG_WORD_BITS)
#define GET_MONTG_R2_BIT(mod_bits) GET_MONTG_R2_BIT2(mod_bits, DEFAULT_MONTG_WORD_BITS)

#endif//RSA_HLS_API_H
