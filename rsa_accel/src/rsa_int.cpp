#include "rsa_int.h"
#include <cstring>
#include <iostream>
#include <fstream>
#include <stdexcept>

using namespace std;

inline uint8_t hex2val(char c)
{
    if ( c >= '0' && c <= '9' ) return c-'0';
    if ( c >= 'A' && c <= 'F' ) return c-'A'+10;
    if ( c >= 'a' && c <= 'f' ) return c-'a'+10;
    throw runtime_error("Bad hex char");
}

inline char val2hex(uint8_t v, RSAIntBase::CharCase char_case)
{
    if ( char_case == RSAIntBase::upcase ) {
        return "0123456789ABCDEF"[v];
    }
    else {
        return "0123456789abcdef"[v];
    }
}

void RSAIntBase::set_byte(word_t* dst, size_t dst_size, size_t i, uint8_t byte)
{
    size_t dst_i = i*8/WORD_BITS;
    size_t dst_off = i*8%WORD_BITS;
    word_t v = byte;
    if ( dst_i >= dst_size )
        throw runtime_error("Too long src");
    dst[dst_i] |= v << dst_off;
    if ( WORD_BITS%8 && dst_off+8 > WORD_BITS ) {
        dst[dst_i] &= WORD_MASK;
        if ( dst_i+1 >= dst_size )
            throw runtime_error("Too long src");
        dst[dst_i+1] |= v >> (WORD_BITS - dst_off);
    }
}

void RSAIntBase::hex2words(word_t* dst, size_t dst_size, const char* src)
{
    size_t src_size = strlen(src);
    while ( src_size > 1 && *src == '0' ) {
        ++src;
        --src_size;
    }
    while ( src_size*4 > dst_size*WORD_BITS ) {
        if ( *src == '0' ) {
            ++src;
            --src_size;
        }
        else {
            throw runtime_error("Too long src");
        }
    }
    fill_n(dst, dst_size, 0);
    for ( size_t i = 0; i < src_size; ++i ) {
        size_t dst_i = i*4/WORD_BITS;
        size_t dst_off = i*4%WORD_BITS;
        word_t v = hex2val(src[src_size-1-i]);
        dst[dst_i] |= v << dst_off;
        if ( WORD_BITS%4 && dst_off+4 > WORD_BITS ) {
            dst[dst_i] &= WORD_MASK;
            dst[dst_i+1] |= v >> (WORD_BITS - dst_off);
        }
    }
}

string RSAIntBase::words2hex(const word_t* src, size_t src_size, CharCase char_case)
{
    size_t bits = src_size*WORD_BITS;
    size_t dst_size = (bits+3)/4;
    char buf[dst_size];
    memset(buf, 0, sizeof(buf));
    for ( size_t i = 0; i < dst_size; ++i ) {
        size_t src_i = i*4/WORD_BITS;
        size_t src_off = i*4%WORD_BITS;
        word_t v = src[src_i]>>src_off;
        if ( WORD_BITS%4 && src_i+1 < src_size && src_off+4 > WORD_BITS ) {
            v |= src[src_i+1]<<(WORD_BITS - src_off);
        }
        v &= 15;
        buf[dst_size-1-i] = val2hex(v, char_case);
    }
    char* dst = buf;
    char* dst_end = buf+dst_size;
    while ( dst+1 < dst_end && *dst == '0' ) {
        ++dst;
    }
    return string(dst, dst_end);
}
