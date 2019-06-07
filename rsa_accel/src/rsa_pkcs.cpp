/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

//This OpenSSL header is needed in case native cryptographically strong pseudo-random RAND_bytes() function is used.
//#include <openssl/rand.h>

#include "rsa.h"
#include "rsa_gmp.h"
#include "rsa_pkcs.h"

//these RSA limits are taken from $OPENSSL_DIR/include/openssl/rsa.h
# ifndef RSA_SMALL_MODULUS_BITS
#  define RSA_SMALL_MODULUS_BITS 3072
# endif

# ifndef RSA_MAX_PUBEXP_BITS
/* exponent limit enforced for "large" modulus only */
#  define RSA_MAX_PUBEXP_BITS    64
# endif


RSAMessage ref_powmod_simple     (RSAMessage const&, RSAFullInt    const&, RSAModulus const&);
RSAMessage ref_powmod_complex_sec(RSAMessage const&, RSAPrivateKey const&, bool = false);


inline unsigned int constant_time_msb(unsigned int a)
{
    return 0 - (a >> (sizeof(a) * 8 - 1));
}

// adding inline declaration for some functions to use them outside
unsigned int constant_time_is_zero(unsigned int a)
{   // the same as:
    // return a==0 ? ~0 : 0;
    return constant_time_msb(~a & (a - 1));
}
inline unsigned int constant_time_is_zero(unsigned int);

unsigned int constant_time_eq(unsigned int a, unsigned int b)
{
    return constant_time_is_zero(a ^ b);
}
inline unsigned int constant_time_eq(unsigned int, unsigned int);

inline unsigned int constant_time_select(unsigned int mask, unsigned int a, unsigned int b)
{
    return (mask & a) | (~mask & b);
}

int constant_time_select_int(unsigned int mask, int a, int b)
{
    return (int)constant_time_select(mask, (unsigned)(a), (unsigned)(b));
}
inline int constant_time_select_int(unsigned int, int, int);

unsigned int constant_time_lt(unsigned int a, unsigned int b)
{
    return constant_time_msb(a ^ ((a ^ b) | ((a - b) ^ b)));
}
inline unsigned int constant_time_lt(unsigned int, unsigned int);

unsigned int constant_time_ge(unsigned int a, unsigned int b)
{
    return ~constant_time_lt(a, b);
}
inline unsigned int constant_time_ge(unsigned int, unsigned int);

unsigned char constant_time_select_8(unsigned char mask, unsigned char a, unsigned char b)
{
    return (unsigned char)constant_time_select(mask, a, b);
}
inline unsigned char constant_time_select_8(unsigned char, unsigned char, unsigned char);

inline unsigned int constant_time_eq_int(int a, int b)
{
    return constant_time_eq((unsigned)(a), (unsigned)(b));
}


//Errors state definitions, taken from $OPENSSL_DIR/include/openssl/err.h
# define ERR_FLAG_CLEAR  0x02
# define ERR_NUM_ERRORS  16
typedef struct err_state_st {
    int err_flags[ERR_NUM_ERRORS];
    unsigned long err_buffer[ERR_NUM_ERRORS];
    char *err_data[ERR_NUM_ERRORS];
    int err_data_flags[ERR_NUM_ERRORS];
    const char *err_file[ERR_NUM_ERRORS];
    int err_line[ERR_NUM_ERRORS];
    int top, bottom;
} ERR_STATE;


void err_clear_last_constant_time(int clear)
{
    ERR_STATE *es;
    int top;

    // In ERR_STATE structure err_flags are just updates but never used,
    // thus removing real functioning
    es = NULL; //ERR_get_state();
    if (es == NULL)
        return;

    top = es->top;

    /*
     * Flag error as cleared but remove it elsewhere to avoid two errors
     * accessing the same error stack location, revealing timing information.
     */
    clear = constant_time_select_int(constant_time_eq_int(clear, 0),
                                     0, ERR_FLAG_CLEAR);
    es->err_flags[top] |= clear;
}


int RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen, int flen)
{
    if (flen > (tlen - RSA_PKCS1_PADDING_SIZE)) return 0;

    to += flen;

    *(to++) = '\0';
    // pad out with 0xff data
    int j = tlen - 3 - flen;
    memset(to, 0xff, j);
    to += j;

    *(to++) = 1;
    *(to++) = 0;  // Private Key BT (Block Type)

    return 1;
}

int RSA_padding_check_PKCS1_type_1(int const tlen,
                                   unsigned char *from, int flen,
                                   int const num)
{
    /*
     * The format is
     * 00 || 01 || PS || 00 || D
     * PS - padding string, at least 8 bytes of FF
     * D  - data.
     */

    if (num < RSA_PKCS1_PADDING_SIZE) return -1;
    from += (flen-1);

    /* Accept inputs with and without the leading 0-byte. */
    if (num == flen) {
        if ((*from--) != 0x00) return -1;
        flen--;
    }

    if ((num != (flen + 1)) || (*(from--) != 0x01)) return -1;
    from[1] = 0; // clearing leading padding byte

    /* scan over padding data */
    int j = flen - 1;               /* one for type. */
    int i;
    for (i = 0; i < j; i++) {
        if (*from != 0xff) {       /* should decrypt to 0xff */
            if (*from == 0) {
                from--;
                break;
            } else return -1;
        }
        from[0] = 0; // clearing padding
        from--;
    }

    if (i == j) return -1;

    if (i < 8) return -1;
    i++;                        /* Skip over the '\0' */
    j -= i;
    if (j > tlen) return -1;

    return j;
}

int RAND_bytes(unsigned char *buf, int num)
{
    for (int cnt = 0; cnt < num; cnt++)
        buf[cnt] = rand();
    return 1;
}

int RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen, int flen)
{
    if (flen > (tlen - RSA_PKCS1_PADDING_SIZE)) return 0;

    to += flen;

    *(to++) = '\0';
    // pad out with non-zero random data
    int j = tlen - 3 - flen;

    if (RAND_bytes(to, j) <= 0) return 0;
    for (int i = 0; i < j; i++) {
        if (*to == '\0')
            do {
                if (RAND_bytes(to, 1) <= 0) return 0;
            } while (*to == '\0');
        to++;
    }

    *(to++) = 2;
    *(to++) = 0;  // Public Key BT (Block Type)

    return 1;
}

int RSA_padding_check_PKCS1_type_2(uint8_t* from, int flen, int num)
{
    //RSA_PKCS1_PADDING_SIZE = 11 is not used in this function

    if (flen <= 0) return -1;

    /*
     * PKCS#1 v1.5 decryption. See "PKCS #1 v2.2: RSA Cryptography Standard",
     * section 7.2.2.
     */

    if (flen > num || num < 11) return -1;

    // |em| is the encoded message, zero-padded to exactly |num| bytes */
    //uint8_t* em = OPENSSL_malloc(num);
    uint8_t* em  = new uint8_t[2*num]{};
    if (em == NULL) return -1;
    uint8_t* em_ini = em;
    /*
     * Caller is encouraged to pass zero-padded message created with
     * BN_bn2binpad. Trouble is that since we can't read out of |from|'s
     * bounds, it's impossible to have an invariant memory access pattern
     * in case |from| was not zero-padded in advance.
     */
    uint8_t* to = from; // saving initial pointer and length
    int tlen = flen;
    // std::cout << " flen: " << flen << std::endl;
    unsigned int mask;
    int i;
    for (from--, em--, i = 0; i < num; i++) {
        mask = ~constant_time_is_zero(flen);
        flen -= 1 & mask;
        from += 1 & mask;
        *++em = *from & mask;
        *from = 0;
    }

    unsigned int good = constant_time_is_zero(em[0]);
    good &= constant_time_eq(em[-1], 2);

    /* scan over padding data */
    unsigned int found_zero_byte = 0;
    int zero_index = 0;
    for (i = 2; i < num; i++) {
        unsigned int equals0 = constant_time_is_zero(em[-i]);

        zero_index = constant_time_select_int(~found_zero_byte & equals0,
                                              i, zero_index);
        found_zero_byte |= equals0;
    }

    /*
     * PS must be at least 8 bytes long, and it starts two bytes into |em|.
     * If we never found a 0-byte, then |zero_index| is 0 and the check
     * also fails.
     */
    good &= constant_time_ge(zero_index, 2 + 8);

    /*
     * Skip the zero byte. This is incorrect if we never found a zero-byte
     * but in this case we also do not copy the message out.
     */
    int msg_index = zero_index + 1;
    int mlen = num - msg_index;

    /*
     * For good measure, do this check in constant time as well.
     */
    good &= constant_time_ge(tlen, mlen);

    /*
     * Move the result in-place by |num|-11-|mlen| bytes to the left.
     * Then if |good| move |mlen| bytes from |em|+11 to |to|.
     * Otherwise leave |to| unchanged.
     * Copy the memory back in a way that does not reveal the size of
     * the data being copied via a timing side channel. This requires copying
     * parts of the buffer multiple times based on the bits set in the real
     * length. Clear bits do a non-copy with identical access pattern.
     * The loop below has overall complexity of O(N*log(N)).
     */
    tlen = constant_time_select_int(constant_time_lt(num - 11, tlen),
                                    num - 11, tlen);
    for (msg_index = 1; msg_index < num - 11; msg_index <<= 1) {
        mask = ~constant_time_eq(msg_index & (num - 11 - mlen), 0);
        for (i = 11; i < num - msg_index; i++)
            em[-i] = constant_time_select_8(mask, em[-i - msg_index], em[-i]);
    }
    // std::cout << " mlen: " << mlen << std::endl;
    // std::cout << " tlen: " << tlen << std::endl;

    em -= mlen-1;
    for (i = 0; i < tlen; i++) {
        mask = good & constant_time_lt(i, mlen);
        to[i] = constant_time_select_8(mask, em[i - 11], 0);
        // std::cout << std::hex << " i: " << i << " mask: " << mask << " to[i]: " << (int)to[i] << std::endl;
    }

    // OPENSSL_clear_free(em, num);
    std::memset(em_ini , 0, 2*num);
    delete[] em_ini;
    err_clear_last_constant_time(1 & good);

    return constant_time_select_int(good, mlen, -1);
}


int RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
                                      const unsigned char *from, int flen,
                                      int num, const unsigned char *param,
                                      int plen, const EVP_MD *md = NULL,
                                      const EVP_MD *mgf1md = NULL)
{
    std::cout << "Sorry, RSA_PKCS1_OAEP_PADDING is not supported." << std::endl;
    return -1;
}

int RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
                                    const unsigned char *from, int flen,
                                    const unsigned char *param, int plen,
                                    const EVP_MD *md = NULL, const EVP_MD *mgf1md = NULL)
{
    std::cout << "Sorry, RSA_PKCS1_OAEP_PADDING is not supported." << std::endl;
    return -1;
}

int RSA_padding_add_SSLv23(unsigned char *to, int tlen,
                           const unsigned char *from, int flen)
{
    std::cout << "Sorry, RSA_SSLV23_PADDING is not supported." << std::endl;
    return -1;
}

int RSA_padding_check_SSLv23(unsigned char *to, int tlen,
                             const unsigned char *from, int flen, int num)
{
    std::cout << "Sorry, RSA_SSLV23_PADDING is not supported." << std::endl;
    return -1;
}

int RSA_padding_add_X931(unsigned char *to, int tlen,
                         const unsigned char *from, int flen)
{
    std::cout << "Sorry, RSA_X931_PADDING is not supported." << std::endl;
    return -1;
}

int RSA_padding_check_X931(unsigned char *to, int tlen,
                           const unsigned char *from, int flen, int num)
{
    std::cout << "Sorry, RSA_X931_PADDING is not supported." << std::endl;
    return -1;
}


int rsa_pkcs_public_encrypt(RSAMessage f, RSAMessage& ret, const RSAPrivateKey& key, int padding)
{
    if (key.modulus.get_actual_bit_size() > MAX_RSA_BITS)  return -1;
    if (GMPInt(key.modulus) <= GMPInt(key.publicExponent)) return -1;
    /* for large moduli, enforce exponent limit */
    if (key.modulus.get_actual_bit_size() > RSA_SMALL_MODULUS_BITS &&
        key.publicExponent.get_actual_bit_size() > RSA_MAX_PUBEXP_BITS) return -1;

    if (padding == RSA_PKCS1_PADDING) {
      int const num = (key.modulus.get_actual_bit_size()+7)/8;
      // int const flen = num - (padding == RSA_PKCS1_PADDING      ? RSA_PKCS1_PADDING_SIZE:
      //                         padding == RSA_PKCS1_OAEP_PADDING ? 42:0); // requirement for message length by PKCS
      int const flen = (f.get_actual_bit_size()+7)/8;

      uint8_t* buf = reinterpret_cast<uint8_t*>(f.words);
  
      if (RSA_padding_add_PKCS1_type_2(buf, num, flen) <= 0) return -1;
  
      // usually the padding functions would catch this
      if (GMPInt(f) >= GMPInt(key.modulus)) return -1;
    }
    else if (padding != RSA_NO_PADDING) {
      int const num = (key.modulus.get_actual_bit_size()+7)/8;
      // int const flen = num - (padding == RSA_PKCS1_PADDING      ? RSA_PKCS1_PADDING_SIZE:
      //                         padding == RSA_PKCS1_OAEP_PADDING ? 42:0); // requirement for message length by PKCS
      int const flen = (f.get_actual_bit_size()+7)/8;
      uint8_t* buf  = new uint8_t[num];
      uint8_t* from = new uint8_t[flen];
  
      f.get_bigend_to_bytes(from, flen);
  
      switch (padding) {
      case RSA_PKCS1_OAEP_PADDING:
          if (RSA_padding_add_PKCS1_OAEP_mgf1(buf, num, from, flen, NULL, 0) <= 0) return -1;
          break;
      case RSA_SSLV23_PADDING:
          if (RSA_padding_add_SSLv23(buf, num, from, flen) <= 0) return -1;
          break;
      default: return -1;
      }
  
      f.set_bigend_from_bytes(buf, num);
      // usually the padding functions would catch this
      if (GMPInt(f) >= GMPInt(key.modulus)) return -1;
      std::memset(from, 0, flen);
      std::memset(buf , 0, num);
      delete[] from;
      delete[] buf;
    }

    ret = ref_powmod_simple(f, key.publicExponent, key.modulus);
    size_t const r = (ret.get_actual_bit_size()+7)/8;
    
    return r;
}


BN_BLINDING* RSA_setup_blinding(const RSAPrivateKey& key, BN_CTX *in_ctx)
{
    BIGNUM *e;
    BN_CTX *ctx;
    BN_BLINDING *ret = NULL;

    if (in_ctx == NULL) {
        if ((ctx = BN_CTX_new()) == NULL)
            return 0;
    } else {
        ctx = in_ctx;
    }

    BN_CTX_start(ctx);
    e = BN_CTX_get(ctx);
    if (e == NULL) return 0;

    e = key.publicExponent;

    {
        BIGNUM *n = BN_new();

        if (n == NULL) return 0;
        BN_with_flags(n, key.modulus, BN_FLG_CONSTTIME);

        ret = BN_BLINDING_create_param(NULL, e, n, ctx, NULL, NULL);
        /* We MUST free n before any further use of rsa->n */
        BN_free(n);
    }
    if (ret == NULL) return 0;

    BN_BLINDING_set_current_thread(ret);

    if (0) {
      // Discovering and printing got blinding factors
      unsigned long blindFlags = BN_BLINDING_get_flags(ret);
      std::cout << "Blinding flags: " << BN_BLINDING_get_flags(ret) << std::endl;
      BN_BLINDING_set_flags(ret, BN_BLINDING_NO_RECREATE | BN_BLINDING_NO_UPDATE); //switching-off updating of blinding factors
      std::cout << "Switching off blinding update: " << BN_BLINDING_get_flags(ret) << std::endl;
  
      BIGNUM* A  = BN_new();
      BIGNUM* Ai = BN_new();
      BN_one(A);
      BN_BLINDING_convert_ex(A, Ai, ret, ctx);
      std::cout << "Blinding   factor A : " << BN_bn2hex(A)  << std::endl;
      std::cout << "Unblinding factor Ai: " << BN_bn2hex(Ai) << std::endl;
      BN_free(Ai);
      BN_free(A);
  
      BN_BLINDING_set_flags(ret, blindFlags); // restoring back the flags
      std::cout << "Restoring blinding flags: " << BN_BLINDING_get_flags(ret) << std::endl;
    }

    BN_CTX_end(ctx);
    if (ctx != in_ctx)
        BN_CTX_free(ctx);
    if (e != key.publicExponent)
        BN_free(e);

    return ret;
}


// signing
int rsa_pkcs_private_encrypt(RSAMessage f, RSAMessage& ret, const RSAPrivateKey& key, int padding, bool const blindOff)
{
    if (padding == RSA_PKCS1_PADDING) {
      int const num = (key.modulus.get_actual_bit_size()+7)/8;
      int const flen = (f.get_actual_bit_size()+7)/8;

      uint8_t* buf = reinterpret_cast<uint8_t*>(f.words);
  
      if (RSA_padding_add_PKCS1_type_1(buf, num, flen) <= 0) return -1;
  
      if (GMPInt(f) >= GMPInt(key.modulus)) return -1;
    }
    else if (padding != RSA_NO_PADDING) {
      int const num = (key.modulus.get_actual_bit_size()+7)/8;
      int const flen = (f.get_actual_bit_size()+7)/8;
      uint8_t* buf  = new uint8_t[num];
      uint8_t* from = new uint8_t[flen];
  
      f.get_bigend_to_bytes(from, flen);
  
      switch (padding) {
      case RSA_X931_PADDING:
          if (RSA_padding_add_X931(buf, num, from, flen) <= 0) return -1;
          break;
      case RSA_SSLV23_PADDING:
      default: return -1;
      }
  
      f.set_bigend_from_bytes(buf, num);
      // usually the padding functions would catch this
      if (GMPInt(f) >= GMPInt(key.modulus)) return -1;
      std::memset(from, 0, flen);
      std::memset(buf , 0, num);
      delete[] from;
      delete[] buf;
    }

    // ---------- Blinding -----------
    // A non-NULL unblind instructs BN_BLINDING_convert_ex() and BN_BLINDING_invert_ex()
    // to store the unblinding factor outside the blinding structure.
    BN_BLINDING *blinding = NULL;
    BIGNUM *unblind = NULL;
    BN_CTX *ctx = NULL;
    if (!blindOff) {
      if ((ctx = BN_CTX_new()) == NULL) return -1;
      BN_CTX_start(ctx);
      blinding = RSA_setup_blinding(key, ctx);
      if (blinding) {
        BIGNUM* bn_f(f);
        if (!BN_BLINDING_convert_ex(bn_f, unblind, blinding, ctx)) return -1;
        f = bn_f;
        BN_clear_free(bn_f);
      }
    }

    RSAPrimeInt const ZeroRSAInt; // constant initialized to zero
    if ( true || (
         key.prime1      != ZeroRSAInt && // if the key contains CRT components
         key.prime2      != ZeroRSAInt &&
         key.exponent1   != ZeroRSAInt &&
         key.exponent2   != ZeroRSAInt &&
         key.coefficient != ZeroRSAInt ))
         ret = ref_powmod_complex_sec(f, key); // using CRT reduction
    else ret = ref_powmod_simple     (f, key.privateExponent, key.modulus);

    // ---------- Unblinding -----------
    if (!blindOff) {
      if (blinding) {
        BIGNUM* bn_ret(ret);
        if (!BN_BLINDING_invert_ex(bn_ret, unblind, blinding, ctx)) return -1;
        ret = bn_ret;
        BN_clear_free(bn_ret);
      }
      BN_CTX_end(ctx);
      BN_CTX_free(ctx);
    }

    size_t const r = (ret.get_actual_bit_size()+7)/8;
    return r;
}

int rsa_pkcs_private_decrypt(RSAMessage f, RSAMessage& ret, const RSAPrivateKey& key, int padding, bool const blindOff)
{
    if (GMPInt(f) >= GMPInt(key.modulus)) return -1;

    // ---------- Blinding -----------
    // A non-NULL unblind instructs BN_BLINDING_convert_ex() and BN_BLINDING_invert_ex()
    // to store the unblinding factor outside the blinding structure.
    BN_BLINDING *blinding = NULL;
    BIGNUM *unblind = NULL;
    BN_CTX *ctx = NULL;
    if (!blindOff) {
      if ((ctx = BN_CTX_new()) == NULL) return -1;
      BN_CTX_start(ctx);
      blinding = RSA_setup_blinding(key, ctx);
      if (blinding) {
        BIGNUM* bn_f(f);
        if (!BN_BLINDING_convert_ex(bn_f, unblind, blinding, ctx)) return -1;
        f = bn_f;
        BN_clear_free(bn_f);
      }
    }

    // do the decrypt
    RSAPrimeInt const ZeroRSAInt; // constant initialized to zero
    if ( true || (
         key.prime1      != ZeroRSAInt && // if the key contains CRT components
         key.prime2      != ZeroRSAInt &&
         key.exponent1   != ZeroRSAInt &&
         key.exponent2   != ZeroRSAInt &&
         key.coefficient != ZeroRSAInt ))
         ret = ref_powmod_complex_sec(f, key); // using CRT reduction
    else ret = ref_powmod_simple     (f, key.privateExponent, key.modulus);

    // ---------- Unblinding -----------
    if (!blindOff) {
      if (blinding) {
        BIGNUM* bn_ret(ret);
        if (!BN_BLINDING_invert_ex(bn_ret, unblind, blinding, ctx)) return -1;
        ret = bn_ret;
        BN_clear_free(bn_ret);
      }
      BN_CTX_end(ctx);
      BN_CTX_free(ctx);
    }

    int r = (ret.get_actual_bit_size()+7)/8;

    if (padding == RSA_PKCS1_PADDING) {
      int const num = (key.modulus.get_actual_bit_size()+7)/8;
  
      //int const flen = num;
      int const flen = (ret.get_actual_bit_size()+7)/8;
  
      r = RSA_padding_check_PKCS1_type_2(reinterpret_cast<uint8_t*>(ret.words), flen, num);
  
    }
    else if (padding != RSA_NO_PADDING) {
      int const num = (key.modulus.get_actual_bit_size()+7)/8;
      int const tlen = num - RSA_PKCS1_PADDING_SIZE;
  
      uint8_t* buf = new uint8_t[num];
      uint8_t* to  = new uint8_t[tlen]{};
  
      //int const j = num;
      int const j = (ret.get_actual_bit_size()+7)/8;
      ret.get_bigend_to_bytes(buf, j);
  
      switch (padding) {
      case RSA_PKCS1_OAEP_PADDING:
          r = RSA_padding_check_PKCS1_OAEP_mgf1(to, tlen, buf, j, num, NULL, 0);
          break;
      case RSA_SSLV23_PADDING:
          r = RSA_padding_check_SSLv23(to, tlen, buf, j, num);
          break;
      default: return -1;
      }
  
      ret.set_bigend_from_bytes(to, r);
  
      std::memset(to , 0, tlen);
      std::memset(buf, 0, num);
      delete[] to;
      delete[] buf;
    }

    return r;
}

/* signature verification */
int rsa_pkcs_public_decrypt(const RSAMessage& f, RSAMessage& ret, const RSAPrivateKey& key, int padding)
{
    if (key.modulus.get_actual_bit_size() > MAX_RSA_BITS)  return -1;
    if (GMPInt(key.modulus) <= GMPInt(key.publicExponent)) return -1;
    /* for large moduli, enforce exponent limit */
    if (key.modulus.get_actual_bit_size() > RSA_SMALL_MODULUS_BITS &&
        key.publicExponent.get_actual_bit_size() > RSA_MAX_PUBEXP_BITS) return -1;

    if (GMPInt(f) >= GMPInt(key.modulus)) return -1;

    ret = ref_powmod_simple(f, key.publicExponent, key.modulus);

    int r = (ret.get_actual_bit_size()+7)/8;

    if (padding == RSA_PKCS1_PADDING) {
      int const num = (key.modulus.get_actual_bit_size()+7)/8;
      int const tlen = num - RSA_PKCS1_PADDING_SIZE;
      //int const flen = num;
      int const flen = (ret.get_actual_bit_size()+7)/8;

      r = RSA_padding_check_PKCS1_type_1(tlen, reinterpret_cast<uint8_t*>(ret.words), flen, num);
    }
    else if (padding != RSA_NO_PADDING) {
      int const num = (key.modulus.get_actual_bit_size()+7)/8;
      int const tlen = num - RSA_PKCS1_PADDING_SIZE;
  
      uint8_t* buf = new uint8_t[num];
      uint8_t* to  = new uint8_t[tlen];
  
      //int const i = num;
      int const i = (ret.get_actual_bit_size()+7)/8;
      ret.get_bigend_to_bytes(buf, i);
  
      switch (padding) {
      case RSA_X931_PADDING:
          r = RSA_padding_check_X931(to, tlen, buf, i, num);
          break;
      default: return -1;
      }

      ret.set_bigend_from_bytes(to, r);
  
      std::memset(to , 0, tlen);
      std::memset(buf, 0, num);
      delete[] to;
      delete[] buf;
    }

    return r;
}
