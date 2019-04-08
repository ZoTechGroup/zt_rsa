#ifndef RSA_SEQ_IMPL_H
#define RSA_SEQ_IMPL_H

#include "rsa_seq_def.h"
#include "rsa_hls_api.h"

const size_t MAX_RSA_WORDS = (MAX_RSA_BITS-1)/RSA_WORD_BITS+1; // =32 for RSA-2048

struct MontgPowParams
{
    // sizes and mode
    size_t mod_bits, exp_bits;
    size_t n; // montg word count
    PowerMode mode;

    // parameters
    uint64_t mod64[MAX_RSA_WORDS]; // in 64-bit words
    uint64_t exp[MAX_RSA_WORDS]; // in 64-bit words
    
    // calculated values
    uint64_t r264[MAX_RSA_WORDS]; // in 64-bit words
};

#endif//RSA_SEQ_IMPL_H
