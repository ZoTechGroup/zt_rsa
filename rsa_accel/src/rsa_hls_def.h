#ifndef RSA_HLS_DEF_H
#define RSA_HLS_DEF_H

#include "rsa_hls_api.h"

#define UNIT_COUNT 500

// max number of bits in RSA modulus
// this variable must be defined on a Makefile level
#ifndef MAX_RSA_BITS
# define MAX_RSA_BITS 4096
#endif

#ifndef NO_CONST_TIME
# define NO_CONST_TIME
#endif

const size_t RSA_INPUT_BITS = MAX_RSA_BITS;
const size_t RSA_OUTPUT_BITS = MAX_RSA_BITS; // (MAX_MONTG_WORD_COUNT+1)*MONTG_WORD_BITS-1;
const size_t RSA_INPUT_WORDS = (RSA_INPUT_BITS-1)/RSA_WORD_BITS+1; // =32 for RSA-2048
const size_t RSA_OUTPUT_WORDS = (RSA_OUTPUT_BITS-1)/RSA_WORD_BITS+1; // =32 for RSA-2048
const size_t RSA_DATA_WORDS = RSA_OUTPUT_WORDS; // = max(RSA_INPUT_WORDS, RSA_OUTPUT_WORDS)

/////////////////////////////////////////////////////////////////////////////
// internal Montgomery multuplication sizes

// Montgomery word size in bits
const size_t MONTG_SUBWORD_BITS = 17;
const size_t MONTG_SUBWORD_COUNT = 3;
const size_t MONTG_WORD_BITS = MONTG_SUBWORD_BITS*MONTG_SUBWORD_COUNT;

// max Montgomery word count
// it's a number of words to fit modulus with 2 high bits zeros
const size_t MAX_MONTG_WORD_COUNT = GET_MONTG_WORD_COUNT2(MAX_RSA_BITS, MONTG_WORD_BITS);
// montgomery mul needs one extra word for operands and result
const size_t MAX_MONTG_AB_WORD_COUNT = MAX_MONTG_WORD_COUNT+1;
// internal accumultator needs even one more word = MAX_MONTG_WORD_COUNT+2
const size_t MAX_MONTG_P_WORD_COUNT = MAX_MONTG_WORD_COUNT+2;


#endif // RSA_HLS_DEF_H
