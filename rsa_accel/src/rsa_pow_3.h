#include "rsa_seq.h"
#include "rsa_gmp.h"
#include <cassert>
#include <cstdlib>
#include <iomanip>

extern bool benchmarking;

struct HLSMontgomery
{
    HLSMontgomery(const RSAIntBase::word_t* mod, size_t m_bit_size);

    static
    void pow_4(uint8_t count,
               RSAIntBase::word_t* dst_out[],
               const size_t m_bit_size[],
               const RSAIntBase::word_t* base_in[],
               const RSAIntBase::word_t* exp_in[],
               const RSAIntBase::word_t* mod_in[],
               const PowerMode mode[]);
    
    static
    void pow_multi(size_t count,
                   RSAIntBase::word_t* dst_out[],
                   const size_t m_bit_size[],
                   const RSAIntBase::word_t* base_in[],
                   const RSAIntBase::word_t* exp_in[],
                   const RSAIntBase::word_t* mod_in[],
                   const PowerMode mode[]);
    
    static
    void pow(RSAIntBase::word_t* dst_out,
             const size_t bit_size_in,
             const RSAIntBase::word_t* base_in,
             const RSAIntBase::word_t* exp_in,
             const RSAIntBase::word_t* mod_in);
    static
    void pow_sec(RSAIntBase::word_t* dst_out,
                 const size_t bit_size_in,
                 const RSAIntBase::word_t* base_in,
                 const RSAIntBase::word_t* exp_in,
                 const RSAIntBase::word_t* mod_in);
    static
    void pow_pair(RSAIntBase::word_t* dst_out[2],
                  const size_t bit_size_in[2],
                  const RSAIntBase::word_t* base_in[2],
                  const RSAIntBase::word_t* exp_in[2],
                  const RSAIntBase::word_t* mod_in[2]);
    static
    void pow_sec_pair(RSAIntBase::word_t* dst_out[2],
                      const size_t bit_size_in[2],
                      const RSAIntBase::word_t* base_in[2],
                      const RSAIntBase::word_t* exp_in[2],
                      const RSAIntBase::word_t* mod_in[2]);
};

template<size_t BITS>
struct MPNInt
{
    static const size_t WORD_BITS = sizeof(mp_limb_t)*8;
    static const size_t WORD_COUNT = (BITS-1)/WORD_BITS+1;
    static const size_t TOTAL_BITS = WORD_BITS*WORD_COUNT;
    typedef mp_limb_t word_t;
    
    static size_t get_word_count(size_t bits)
    {
        return (bits-1)/WORD_BITS+1;
    }
    
    word_t words[WORD_COUNT];
    
    MPNInt()
    {
    }
    MPNInt(Zero)
    {
        std::fill(words, words+WORD_COUNT, 0);
    }
    MPNInt(const RSAIntBase::word_t* src, size_t bit_count)
    {
        assert(bit_count <= TOTAL_BITS);
        assert(RSAIntBase::WORD_BITS == WORD_BITS);
        std::fill(std::copy(src, src+get_word_count(bit_count), words), words+WORD_COUNT, 0);
    }

    void set_bit(size_t bit)
    {
        assert(bit < TOTAL_BITS);
        words[bit/WORD_BITS] |= word_t(1)<<bit%WORD_BITS;
    }
};


HLSMontgomery::HLSMontgomery(const RSAIntBase::word_t* src, size_t m_bit_size)
{
}


static inline uint64_t start_m1(uint64_t m0)
{
    return -((((m0+2)&4)<<1)+m0) & 0xf; // correct to 4 bits
}

static inline uint64_t expand_m1(uint64_t x0, uint64_t m0)
{
    return (m0*x0+2)*x0; // doubles number of correct bits in x0
}

static inline uint64_t expand_m1_high_64(uint64_t x0, uint64_t m0, uint64_t m1)
{
    // faster version to caclculate only high 64 bits
    uint64_t prod_hi;
#if defined(__SIZEOF_INT128__)
    prod_hi = uint64_t(__uint128_t(m0)*x0 >> 64);
#else
    prod_hi = (ap_uint<64>(m0)*ap_uint<64>(x0))(127,64);
#endif
    return (prod_hi+m1*x0+1)*x0;
}

static inline void calc_m1(uint64_t* dst, size_t word_count, const uint64_t* words)
{
    uint64_t x0 = 0;
    uint64_t x1 = 0;
    if ( word_count != 0 ) {
        uint64_t m0 = words[0];
        uint64_t m1 = word_count > 1? words[1]: 0;
        
        x0 = start_m1(m0); // 4 bits valid
        x0 = expand_m1(x0, m0); // 8 bits valid
        x0 = expand_m1(x0, m0); // 16 bits valid
        x0 = expand_m1(x0, m0); // 32 bits valid
        x0 = expand_m1(x0, m0); // 64 bits valid
        x1 = expand_m1_high_64(x0, m0, m1); // 128 bits valid
    }
    dst[0] = x0;
    dst[1] = x1;
}

void HLSMontgomery::pow_multi(size_t count,
                              RSAIntBase::word_t* dst_out[],
                              const size_t m_bit_size[],
                              const RSAIntBase::word_t* base_in[],
                              const RSAIntBase::word_t* exp_in[],
                              const RSAIntBase::word_t* mod_in[],
                              const PowerMode mode[])
{
    while ( count ) {
        size_t c = std::min(count, size_t(4));
        pow_4(c, dst_out, m_bit_size, base_in, exp_in, mod_in, mode);
        count -= c;
        dst_out += c;
        m_bit_size += c;
        base_in += c;
        exp_in += c;
        mod_in += c;
        mode += c;
    }
}

void HLSMontgomery::pow_4(uint8_t count, RSAIntBase::word_t* dst_out[], const size_t m_bit_size[], const RSAIntBase::word_t* base_in[], const RSAIntBase::word_t* exp_in[], const RSAIntBase::word_t* mod_in[], const PowerMode mode[])
{
    static const size_t RSA_INPUT_BITS = 2048;
    bool fit = true;

    for ( size_t i = 0; fit && i < count; ++i ) 
      {
        fit = m_bit_size[i] <= RSA_INPUT_BITS;
      }

    if ( !fit ) 
      {
        for ( size_t i = 0; i < count; ++i ) 
          {
            size_t m_word_count = (m_bit_size[i]-1)/RSAIntBase::WORD_BITS+1;
            GMPInt base(base_in[i], m_word_count);
            GMPInt exp(exp_in[i], m_word_count);
            GMPInt mod(mod_in[i], m_word_count);
            GMPInt result;

            if ( mode[i] == fast_power ) 
              {
                result = powm(base, exp, mod);
              }
            else 
              {
                result = powm_sec(base, exp, mod);
              }

            result.get_to_words(dst_out[i], m_word_count);
        }

        return;
    }

    MontgPowParams* params[4];

    for ( int i = 0; i < count; ++i ) 
      {
        params[i] = rsa_montg_alloc_init_params(rsa_montg_trim_bits(m_bit_size[i], mod_in[i]),
                                        rsa_montg_trim_bits(m_bit_size[i], exp_in[i]),
                                        mode[i]);
    }

    if ( !benchmarking ) {
        std::cout << "calling rsa_montg_pow_N({";
        for ( int i = 0; i < count; ++i ) {
            if ( i ) std::cout << ", ";
            std::cout<<"fs"[mode[i]];
        }
        std::cout << "})" << std::endl;
    }
    rsa_montg_pow_N(count, params, base_in, dst_out);
    if ( !benchmarking ) {
        std::cout << "returned" << std::endl;
    }
    for ( int i = 0; i < count; ++i ) {
        rsa_montg_free_params(params[i]);
    }

}

inline
void HLSMontgomery::pow(RSAIntBase::word_t* dst,
                        const size_t bit_size,
                        const RSAIntBase::word_t* base,
                        const RSAIntBase::word_t* exp,
                        const RSAIntBase::word_t* mod)
{
    PowerMode mode = fast_power;
    pow_multi(1, &dst, &bit_size, &base, &exp, &mod, &mode);
}

inline
void HLSMontgomery::pow_sec(RSAIntBase::word_t* dst,
                            const size_t bit_size,
                            const RSAIntBase::word_t* base,
                            const RSAIntBase::word_t* exp,
                            const RSAIntBase::word_t* mod)
{
    PowerMode mode = secure_power;
    pow_multi(1, &dst, &bit_size, &base, &exp, &mod, &mode);
}

inline
void HLSMontgomery::pow_pair(RSAIntBase::word_t* dst[2],
                             const size_t bit_size[2],
                             const RSAIntBase::word_t* base[2],
                             const RSAIntBase::word_t* exp[2],
                             const RSAIntBase::word_t* mod[2])
{
    PowerMode mode[2] = { fast_power, fast_power };
    pow_multi(2, dst, bit_size, base, exp, mod, mode);
}

inline
void HLSMontgomery::pow_sec_pair(RSAIntBase::word_t* dst[2],
                                 const size_t bit_size[2],
                                 const RSAIntBase::word_t* base[2],
                                 const RSAIntBase::word_t* exp[2],
                                 const RSAIntBase::word_t* mod[2])
{
    PowerMode mode[2] = { secure_power, secure_power };
    pow_multi(2, dst, bit_size, base, exp, mod, mode);
}
