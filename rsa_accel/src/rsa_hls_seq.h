#ifndef RSA_HLS_SEQ_H
#define RSA_HLS_SEQ_H

#define __gmp_const const
#include "rsa_hls_def.h"
#include <ap_int.h>

const size_t MONTG_WORD_MUL_COUNT = MONTG_SUBWORD_COUNT;

// chip capabilities
const size_t CHIP_SUM_BITS = 41;
const size_t CHIP_MUL1_BITS = MONTG_SUBWORD_BITS;
const size_t CHIP_MUL2_BITS = 26;
const size_t CHIP_SUMMATOR_JOIN = 2;

struct SParamCheck {
    static const size_t MONTG_WORD_BITS = CHIP_MUL1_BITS*MONTG_WORD_MUL_COUNT;
    //static_assert(MONTG_WORD_BITS == ::MONTG_WORD_BITS, "MONTG_WORD_BITS discrepancy");
};

// calculate number of multiplications during exponentiation
// first argument is number of bits in exponent
// second argument is number of 1 bits in exponent
// in secure mode second argument must be the same as the first
#define GET_MONTG_MUL_STEPS(exp_bits, exp_ones) ((exp_bits)+(exp_ones))
// calculate number of multiplications during exponentiation in secure mode
// the argument is number of bits in exponent
#define GET_SEC_MONTG_MUL_STEPS(exp_bits) GET_MONTG_MUL_STEPS(exp_bits, exp_bits)

// calculate number of montgomery steps
// first argument is number of bits in modulus
// second argument is number of bits in exponent
// third argument is number of 1 bits in exponent
// in secure mode third argument must be the same as the second
#define GET_MONTG_POW_STEPS(mod_bits, exp_bits, exp_ones) \
    ((GET_MONTG_WORD_COUNT(mod_bits, MONTG_WORD_BITS)+2)*GET_MONTG_MUL_STEPS(exp_bits, exp_ones)+2)

// calculate number of montgomery steps in secure mode
// first argument is number of bits in modulus
// second argument is number of bits in exponent
#define GET_SEC_MONTG_POW_STEPS(mod_bits, exp_bits) \
    ((GET_MONTG_WORD_COUNT(mod_bits, MONTG_WORD_BITS)+2)*GET_SEC_MONTG_MUL_STEPS(exp_bits)+2)

const size_t EXP_WORD_BITS = RSA_WORD_BITS;
const size_t EXP_WORD_COUNT = (MAX_RSA_BITS-1)/EXP_WORD_BITS+1;

typedef ap_uint<MONTG_WORD_BITS> main_word_t;
#if MAX_RSA_BITS <= 2048
typedef ap_uint<6> montg_n_t; // must fit MAX_MONTG_WORD_COUNT+1
typedef ap_uint<12> mod_bits_t; // must fit MAX_RSA_BITS
#else
typedef ap_uint<7> montg_n_t; // must fit MAX_MONTG_WORD_COUNT+1
typedef ap_uint<13> mod_bits_t; // must fit MAX_RSA_BITS
#endif

// Packet with 51-bit words, pre- and post- processed on CPU
// input:
//   sizes(1), exp(I), mmm0(M), data(M), r2(M+1)
// sizes:
//   bits[15..0] = modulus bits
//   bits[31..16] = exponent bits
//   bits[39..32] = n
//   bit[40] = const time
// output:
//   data(M)
const size_t ARG_SIZES_POS  = 0;
const size_t ARG_SIZES_SIZE = 1;
const size_t ARG_EXP_POS    = ARG_SIZES_POS + ARG_SIZES_SIZE;
const size_t ARG_EXP_SIZE   = RSA_INPUT_WORDS;
const size_t ARG_MMM0_POS   = ARG_EXP_POS + ARG_EXP_SIZE;
const size_t ARG_MMM0_SIZE  = MAX_MONTG_WORD_COUNT + 1; // 1 extra zero word
const size_t ARG_BASE_POS   = ARG_MMM0_POS + ARG_MMM0_SIZE;
const size_t ARG_BASE_SIZE  = MAX_MONTG_WORD_COUNT + 1; // 1 extra zero word
const size_t ARG_R2_POS     = ARG_BASE_POS + ARG_BASE_SIZE;
const size_t ARG_R2_SIZE    = MAX_MONTG_WORD_COUNT + 2; // 2 extra zero words
const size_t ARG_WORDS      = ARG_R2_POS + ARG_R2_SIZE; // =160 for RSA-2048

const size_t RESULT_WORDS   = MAX_MONTG_AB_WORD_COUNT; // =42 for RSA-2048

// Raw packet with all 64-bit words, pre- and post- processed in kernel
// input:
//   sizes(1), exp(I), mod(I), data(I), r2(I)
// sizes:
//   bits[15..0] = modulus bits
//   bits[31..16] = exponent bits
//   bits[39..32] = n
//   bit[40] = const time
// output:
//   data(I)
const size_t ARG64_SIZES_POS  = 0;
const size_t ARG64_SIZES_SIZE = 1;
const size_t ARG64_EXP_POS    = ARG64_SIZES_POS + ARG64_SIZES_SIZE;
const size_t ARG64_EXP_SIZE   = RSA_INPUT_WORDS;
const size_t ARG64_MOD_POS    = ARG64_EXP_POS + ARG64_EXP_SIZE;
const size_t ARG64_MOD_SIZE   = RSA_INPUT_WORDS;
const size_t ARG64_BASE_POS   = ARG64_MOD_POS + ARG64_MOD_SIZE;
const size_t ARG64_BASE_SIZE  = RSA_INPUT_WORDS;
const size_t ARG64_R2_POS     = ARG64_BASE_POS + ARG64_BASE_SIZE;
const size_t ARG64_R2_SIZE    = RSA_INPUT_WORDS;
const size_t ARG64_WORDS      = ARG64_R2_POS + ARG64_R2_SIZE; // =129 for RSA-2048

const size_t RESULT64_WORDS   = RSA_OUTPUT_WORDS; // =32 for RSA-2048

#endif
