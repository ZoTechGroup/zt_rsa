#ifndef RSA_INT_H
#define RSA_INT_H

#define __gmp_const const
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <algorithm>
#include <cassert>
#include <ap_int.h>

template<size_t Bit32Count> struct RSABit32Type;
template<> struct RSABit32Type<1> {
    typedef uint32_t type;
};
template<> struct RSABit32Type<2> {
    typedef uint64_t type;
};
template<> struct RSABit32Type<3> {
    typedef ap_uint<96> type;
};
template<> struct RSABit32Type<4> {
    typedef ap_uint<128> type;
};
template<> struct RSABit32Type<5> {
    typedef ap_uint<160> type;
};
template<size_t BitCount> struct RSABitType : RSABit32Type<(BitCount-1)/32+1> {};

template<class V> struct BitSize;
template<> struct BitSize<uint64_t> {
    static const size_t value = 64;
};
template<int W> struct BitSize< ap_uint<W> > {
    static const size_t value = W;
};

struct RSAIntBase
{
    static const size_t WORD_BITS = 64;
    typedef RSABitType<WORD_BITS>::type word_t;
    typedef RSABitType<WORD_BITS+3>::type add_word_t;
    typedef RSABitType<WORD_BITS*2>::type wide_word_t;
    static const word_t WORD_MASK = (((word_t(1)<<(WORD_BITS-1))-1)<<1)+1;

    static void set_byte(word_t* dst, size_t dst_size, size_t index, uint8_t byte);
    static void hex2words(word_t* dst, size_t dst_size, const char* src);
    enum CharCase {
        upcase,
        locase
    };
    static std::string words2hex(const word_t* src, size_t src_size, CharCase char_case = upcase);

};

enum Zero {
    zero
};
enum Pow2 {
    pow2
};

template<size_t WordCount, class WordType>
struct IntArray {
    typedef WordType word_t;
    static const size_t WORD_COUNT = WordCount;
    static const size_t WORD_BITS = word_t::width;
    static const size_t TOTAL_BITS = WORD_COUNT*WORD_BITS;

    void pragmas() const
    {
#pragma HLS INLINE
#pragma HLS ARRAY_PARTITION variable=words
    }

    IntArray()
    {
#pragma HLS INLINE
        pragmas();
    }
    explicit
    IntArray(Zero)
    {
#pragma HLS INLINE
        pragmas();
        clear();
    }
    explicit
    IntArray(WordType w0)
    {
#pragma HLS INLINE
        pragmas();
        clear();
        words[0] = w0;
    }
    IntArray(Pow2, size_t bit)
    {
#pragma HLS INLINE
        pragmas();
        clear();
        assert(bit < TOTAL_BITS);
        words[bit/WORD_BITS][bit%WORD_BITS] = 1;
    }
    IntArray(const IntArray<WordCount, WordType>& s)
    {
#pragma HLS INLINE
        pragmas();
        *this = s;
    }
    IntArray(const IntArray<WordCount-1, WordType>& s)
    {
#pragma HLS INLINE
        pragmas();
        *this = s;
    }
    template<class W>
    IntArray(size_t s_word_count, const W* s_words, size_t s_word_bits)
    {
#pragma HLS INLINE
        pragmas();
        set_from_words(s_word_count, s_words, s_word_bits);
    }

    IntArray<WordCount, WordType>& operator=(const IntArray<WordCount, WordType>& s)
    {
#pragma HLS INLINE
        pragmas();
        s.pragmas();
        for ( size_t i = 0; i < WORD_COUNT; ++i ) {
#pragma HLS UNROLL
            words[i] = s.words[i];
        }
        return *this;
    }
    IntArray<WordCount, WordType>& operator=(const IntArray<WordCount-1, WordType>& s)
    {
#pragma HLS INLINE
        pragmas();
        s.pragmas();
        for ( size_t i = 0; i < WORD_COUNT; ++i ) {
#pragma HLS UNROLL
            words[i] = s.get(i);
        }
        return *this;
    }

    size_t get_actual_bit_size() const
    {
    	size_t ret = 0;
    	for ( size_t i = 0; i < WORD_COUNT; ++i ) {
#pragma HLS UNROLL
    		if ( ap_uint<WORD_BITS> w = words[i] ) {
    			ret = (i+1)*WORD_BITS - w.countLeadingZeros();
    		}
    	}
    	return ret;
    }

    IntArray<WORD_COUNT-1, word_t> trim_low_word() const
    {
#pragma HLS INLINE
        IntArray<WORD_COUNT-1, word_t> ret;
        for ( size_t i = 0; i < WORD_COUNT-1; ++i ) {
#pragma HLS UNROLL
            ret.words[i] = words[i+1];
        }
        return ret;
    }
    IntArray<WORD_COUNT-1, word_t> trim_high_word(bool allow_non_zero = false) const
    {
#pragma HLS INLINE
        assert(allow_non_zero || words[WORD_COUNT-1] == 0);
        IntArray<WORD_COUNT-1, word_t> ret;
        for ( size_t i = 0; i < WORD_COUNT-1; ++i ) {
#pragma HLS UNROLL
            ret.words[i] = words[i];
        }
        return ret;
    }

    IntArray<WORD_COUNT+1, word_t> add_low_word(const word_t& w = 0) const
    {
#pragma HLS INLINE
        IntArray<WORD_COUNT+1, word_t> ret;
        ret.words[0] = w;
        for ( size_t i = 1; i < WORD_COUNT+1; ++i ) {
#pragma HLS UNROLL
            ret.words[i] = words[i-1];
        }
        return ret;
    }

    IntArray mask_words(size_t keep) const
    {
#pragma HLS INLINE
        IntArray r(zero);
        for ( size_t i = 0; i < WORD_COUNT; ++i ) {
#pragma HLS UNROLL
            if ( i < keep )
                r[i] = words[i];
        }
        return r;
    }

    template<class W>
    void set_from_words(size_t src_word_count, const W* src_words, size_t src_word_bits)
    {
        clear();
        for ( size_t i = 0; i < src_word_count; ++i ) {
            W w = src_words[i];
            size_t dst_pos = i*src_word_bits;
            size_t w_bits = src_word_bits;
            while ( w_bits > 0 ) {
                size_t dst_off = dst_pos%WORD_BITS;
                size_t add_bits = std::min<size_t>(WORD_BITS-dst_off, w_bits);
                size_t dst_i = dst_pos/WORD_BITS;
                if ( dst_i >= WORD_COUNT ) {
                    assert(w == 0);
                    break;
                }
                words[dst_i] |= word_t(w) << dst_off;
                dst_pos += add_bits;
                w_bits -= add_bits;
                w >>= add_bits;
            }
        }
    }
    void get_to_words(size_t dst_word_count, RSAIntBase::word_t* dst_words, size_t dst_word_bits) const
    {
        for ( size_t i = 0; i < dst_word_count; ++i ) {
#pragma HLS UNROLL
            RSAIntBase::word_t w;
            if ( dst_word_bits <= 32 ) {
                ap_uint<32> t;
                get_bits(t, i*dst_word_bits);
                w = t & RSAIntBase::WORD_MASK;
            }
            else {
                assert(dst_word_bits <= 64);
                ap_uint<64> t;
                get_bits(t, i*dst_word_bits);
                w = t & RSAIntBase::WORD_MASK;
            }
            dst_words[i] = w;
        }
    }

    bool operator==(const IntArray& b) const
    {
        return std::equal(words, words+WORD_COUNT, b.words);
    }
    
    word_t get_high_word() const
    {
#pragma HLS INLINE
        return words[WORD_COUNT-1];
    }
    ap_uint<1> get_high_bit() const
    {
#pragma HLS INLINE
        return get_high_word()[WORD_BITS-1];
    }
    static size_t popcount(word_t w)
    {
        size_t c = 0;
        for ( int i = 0; i < w.width; ++i ) {
            c += w[i];
        }
        return c;
    }
    size_t countPopulation() const
    {
        size_t c = 0;
        for ( size_t i = 0; i < WORD_COUNT; ++i ) {
            c += popcount(words[i]);
        }
        return c;
    }
    word_t operator[](size_t i) const
    {
#pragma HLS INLINE
        assert(i < WORD_COUNT);
        return words[i];
    }
    word_t& operator[](size_t i)
    {
#pragma HLS INLINE
        assert(i < WORD_COUNT);
        return words[i];
    }
    word_t get(size_t i) const
    {
#pragma HLS INLINE
        if ( i < WORD_COUNT ) {
            return words[i];
        }
        else {
            return 0;
        }
    }
    void set(size_t i, word_t v, word_t overflow = 0)
    {
#pragma HLS INLINE
        if ( i < WORD_COUNT ) {
            words[i] = v;
        }
        else {
            assert(v == overflow);
        }
    }

    template<int W>
    void get_bits(ap_uint<W>& r, ssize_t spos) const
    {
#pragma HLS INLINE
        r = 0;
        size_t rpos, pos;
        if ( spos < 0 ) {
            rpos = -spos;
            pos = 0;
        }
        else {
            rpos = 0;
            pos = spos;
        }
        for ( ; rpos < W; ) {
#pragma HLS UNROLL
            if ( pos >= TOTAL_BITS ) {
                break;
            }
            else {
                size_t wi = pos%WORD_BITS;
                size_t wr = WORD_BITS-wi;
                r |= ap_uint<W>(words[pos/WORD_BITS] >> wi) << rpos;
                rpos += wr;
                pos += wr;
            }
        }
    }

    std::string to_hex_string() const
    {
        size_t B = WORD_COUNT*word_t::width;
        size_t S = (B+3)/4;
        char buf[S];
        for ( size_t i = 0; i < S; ++i ) {
            ap_uint<4> d;
            get_bits(d, i*4);
            buf[S-1-i] = "0123456789ABCDEF"[d];
        }
        const char* s = buf;
        const char* e = buf+S;
        while ( s+1 < e && *s == '0' )
            ++s;
        return std::string(s, e);
    }

    void clear()
    {
#pragma HLS INLINE
        for ( size_t i = 0; i < WORD_COUNT; ++i ) {
#pragma HLS UNROLL
            words[i] = 0;
        }
    }

    IntArray<WORD_COUNT+1, word_t> operator<<(size_t shift) const
    {
#pragma HLS INLINE
        IntArray<WORD_COUNT+1, word_t> r;
        assert(shift <= size_t(word_t::width));
        for ( size_t i = 0; i < r.WORD_COUNT; ++i ) {
#pragma HLS UNROLL
            r.words[i] = ap_uint<word_t::width*2>((get(i),get(i-1))) >> (word_t::width-shift);
        }
        return r;
    }
    
    word_t words[WORD_COUNT];
};

template<size_t C, class W>
std::ostream& operator<<(std::ostream& out, const IntArray<C, W>& v)
{
    return out << v.to_hex_string();
}


template<size_t BitSize>
struct RSAInt : RSAIntBase
{
    static const size_t BIT_SIZE = BitSize;
    static const size_t WORD_COUNT = (BIT_SIZE-1)/WORD_BITS+1;

    void pragmas() const
    {
#pragma HLS ARRAY_PARTITION variable=words
    }
    
    RSAInt()
    {
        pragmas();
        std::fill(words, words+WORD_COUNT, 0);
    }
    enum ENoInit {
        NoInit
    };
    RSAInt(ENoInit)
    {
        pragmas();
        //std::fill(words, words+WORD_COUNT, 0);
    }
    explicit
    RSAInt(const char* hex_str)
    {
        pragmas();
        from_hex_string(hex_str);
    }
    RSAInt(const word_t* src, size_t src_size)
    {
        pragmas();
        set_from_words(src, src_size);
    }

    void set_from_words(const word_t* src, size_t src_size)
    {
        assert(src_size <= WORD_COUNT);
        std::copy(src, src+src_size, words);
        std::fill(words+src_size, words+WORD_COUNT, 0);
    }

    size_t get_actual_bit_size() const
    {
        size_t word_count = WORD_COUNT;
        while ( word_count > 0 && !words[word_count-1] ) {
            word_count -= 1;
        }
        size_t bit_size = word_count*WORD_BITS;
        if ( word_count ) {
            bit_size -= __builtin_clzll(words[word_count-1]);
        }
        return bit_size;
    }

    void trim_bits(size_t bit_count)
    {
        size_t w = bit_count/WORD_BITS;
        size_t b = bit_count%WORD_BITS;
        for ( size_t i = w+1; i < WORD_COUNT; ++i )
            words[i] = 0;
        words[w] &= (word_t(1)<<b)-1;
    }

    word_t operator[](size_t i) const
    {
#pragma HLS INLINE
        assert(i < WORD_COUNT);
        return words[i];
    }
    word_t& operator[](size_t i)
    {
#pragma HLS INLINE
        assert(i < WORD_COUNT);
        return words[i];
    }
    
    ap_uint<1> get_bit(size_t pos) const
    {
#pragma HLS INLINE
        size_t i = pos/WORD_BITS;
        if ( i < WORD_COUNT ) {
            return (words[i]>>(pos%WORD_BITS))&1;
        }
        else {
            return 0;
        }
    }

    template<int W>
    void get_bits(ap_uint<W>& r, size_t pos) const
    {
#pragma HLS INLINE
        for ( size_t i = 0; i < W; ++i ) {
#pragma HLS UNROLL
            r[i] = get_bit(pos+i);
        }
    }

    void set_byte(size_t index, uint8_t byte)
    {
        RSAIntBase::set_byte(words, WORD_COUNT, index, byte);
    }
    
    void from_hex_string(const char* hex_str)
    {
        hex2words(words, WORD_COUNT, hex_str);
    }

    std::string to_hex_string() const
    {
        return words2hex(words, WORD_COUNT);
    }

    bool operator==(const RSAInt<BitSize>& b) const
    {
        return std::equal(words, words+WORD_COUNT, b.words);
    }
    
    bool operator!=(const RSAInt<BitSize>& b) const
    {
        return !(*this == b);
    }
    
    word_t words[WORD_COUNT]; // least-significant first
};

template<size_t BitSize>
std::ostream& operator<<(std::ostream& out, const RSAInt<BitSize>& v)
{
    return out << v.to_hex_string();
}


template<size_t BITS, class Carry>
struct RSAIntCarry
{
    typedef RSAInt<BITS> main_t;
    typedef Carry carry_t;

    static const size_t WORD_COUNT = main_t::WORD_COUNT;
    static const size_t WORD_BITS = main_t::WORD_BITS;
    static const size_t TOTAL_BITS = main_t::TOTAL_BITS;
    
    void pragmas() const
    {
#pragma HLS ARRAY_PARTITION variable=carry
    }
    
    RSAIntCarry()
        : main(main_t::NoInit)
    {
        pragmas();
    }
    RSAIntCarry(size_t word_count, const typename main_t::word_t* src)
        : main(src, word_count)
    {
        pragmas();
        std::fill(carry, carry+WORD_COUNT, 0);
        assert(word_count <= WORD_COUNT);
    }
    RSAIntCarry(size_t word_count, const typename main_t::word_t* src, const carry_t* src_carry)
        : main(src, word_count)
    {
        pragmas();
        assert(word_count <= WORD_COUNT);
        std::copy(src_carry, src_carry+word_count, carry);
        std::fill(carry+word_count, carry+WORD_COUNT, 0);
    }

    void operator=(const main_t& src)
    {
        main = src;
        std::fill(carry, carry+WORD_COUNT, 0);
    }

    main_t main;
    carry_t carry[WORD_COUNT];

    main_t get_carry_int() const
    {
        main_t ret(main_t::NoInit);
        std::copy(carry, carry+WORD_COUNT, ret.words);
        return ret;
    }

    main_t propagate_carry() const
    {
        bool is_ff[WORD_COUNT];
        bool is_fe[WORD_COUNT];
        for ( unsigned i = 0; i < WORD_COUNT; ++i ) {
            is_fe[i] = main[i] == (main_t(-2)&main_t::WORD_MASK);
            is_ff[i] = main[i] == (main_t(-1)&main_t::WORD_MASK);
        }
        bool cx[WORD_COUNT];
        cx[0] = 0;
        for ( unsigned i = 0; i < WORD_COUNT-1; ++i ) {
            cx[i+1] = (is_ff[i]&(carry[i]|cx[i])) | (is_fe[i]&carry[i]&cx[i]);
        }
        main_t r;
        for ( unsigned i = 0; i < WORD_COUNT; ++i ) {
            r[i] = main[i] + (carry[i]+cx[i]);
        }
        return r;
    }
};

template<size_t BIT_SIZE, class Carry>
std::ostream& operator<<(std::ostream& out, RSAIntCarry<BIT_SIZE, Carry> v)
{
    return out << v.propagate_carry();
}


template<size_t C, class Word, class Carry = ap_uint<1> >
struct IntWithCarry
{
    typedef Word main_word_t;
    typedef Carry carry_word_t;
    static const size_t WORD_COUNT = C;
    static const size_t WORD_BITS = main_word_t::width;
    
    typedef IntArray<WORD_COUNT, main_word_t> main_t;
    typedef IntArray<WORD_COUNT, carry_word_t> carry_t;
    typedef std::pair<main_t, carry_t> pair_t;
    
    typedef IntWithCarry<WORD_COUNT, main_word_t, carry_word_t> this_t;
    typedef IntArray<WORD_COUNT-1, main_word_t> shorter_main_t;
    typedef IntWithCarry<WORD_COUNT-1, main_word_t, carry_word_t> shorter_this_t;
    typedef IntWithCarry<WORD_COUNT+1, main_word_t, carry_word_t> longer_this_t;
    
    main_t first;
    carry_t second;
    
    void pragmas() const
    {
#pragma HLS INLINE
        first.pragmas();
        second.pragmas();
    }

    IntWithCarry()
    {
    }
    explicit
    IntWithCarry(Zero)
        : first(zero),
          second(zero)
    {
    }
    explicit
    IntWithCarry(main_word_t w0)
        : first(w0),
          second(zero)
    {
    }
    IntWithCarry(Pow2, size_t bit)
        : first(pow2, bit),
          second(zero)
    {
    }
    IntWithCarry(const main_t& main, const carry_t& carry)
        : first(main),
          second(carry)
    {
    }
    IntWithCarry(const main_t& s)
        : first(s),
          second(zero)
    {
    }
    IntWithCarry(const shorter_main_t& s)
        : first(s),
          second(zero)
    {
    }
    IntWithCarry(const this_t& s)
        : first(s.first),
          second(s.second)
    {
    }
    IntWithCarry(const shorter_this_t& s)
        : first(s.first),
          second(s.second)
    {
    }
    IntWithCarry(size_t s_word_count, const RSAIntBase::word_t* s_words, size_t s_word_bits)
        : first(s_word_count, s_words, s_word_bits),
          second(zero)
    {
    }
    
    void clear()
    {
#pragma HLS INLINE
        first.clear();
        second.clear();
    }

    shorter_this_t trim_low_word() const
    {
#pragma HLS INLINE
        shorter_this_t ret;
        ret.first = first.trim_low_word();
        ret.second = second.trim_low_word();
        return ret;
    }
    void extract_low_word_full(shorter_this_t& high, ap_uint<WORD_BITS+1>& low) const
    {
#pragma HLS INLINE
        low = get_low_word_full();
        high.first = first.trim_low_word();
        high.second = second.trim_low_word();
    }
    shorter_this_t trim_high_word(bool allow_overflow = false) const
    {
#pragma HLS INLINE
        assert(allow_overflow || propagate_carry().get_high_word() == 0);
        return shorter_this_t(first.trim_high_word(1), second.trim_high_word(1));
    }

    longer_this_t add_low_word(const main_word_t& w = 0) const
    {
#pragma HLS INLINE
        return longer_this_t(first.add_low_word(w), second.add_low_word());
    }
    
    this_t mask_words(size_t keep) const
    {
#pragma HLS INLINE
        return this_t(first.mask_words(keep), second.mask_words(keep));
    }
    
    main_word_t get_low_word() const
    {
#pragma HLS INLINE
        assert(this->second[0] == 0);
        return this->first[0];
    }
    ap_uint<WORD_BITS+1> get_low_word_full() const
    {
#pragma HLS INLINE
        return first[0]+second[0];
    }

    main_t get_carry_int() const
    {
#pragma HLS INLINE
        main_t ret;
        for ( unsigned i = 0; i < WORD_COUNT; ++i ) {
#pragma HLS UNROLL
            ret[i] = second[i];
        }
        return ret;
    }

    main_t propagate_carry() const
    {
        ap_uint<WORD_COUNT> is_ff;
        ap_uint<WORD_COUNT> is_fe;
        for ( unsigned i = 0; i < WORD_COUNT; ++i ) {
#pragma HLS UNROLL
            is_fe[i] = first[i] == main_word_t(-2);
            is_ff[i] = first[i] == main_word_t(-1);
        }
        ap_uint<WORD_COUNT> cx;
        cx[0] = 0;
        for ( unsigned i = 0; i < WORD_COUNT-1; ++i ) {
#pragma HLS UNROLL
            cx[i+1] = (is_ff[i]&(second[i]|cx[i])) | (is_fe[i]&second[i]&cx[i]);
        }
        IntArray<C, main_word_t> r;
        for ( unsigned i = 0; i < WORD_COUNT; ++i ) {
#pragma HLS UNROLL
            r[i] = first[i] + (second[i]+cx[i]);
        }
        return r;
    }

    IntWithCarry<WORD_COUNT, main_word_t, ap_uint<Carry::width+2> >
    mul_by_4(bool allow_overflow = false) const
    {
        IntWithCarry<WORD_COUNT, main_word_t, ap_uint<Carry::width+2> > r;
        r.first = (first << 2).trim_high_word(allow_overflow);
        for ( unsigned i = 0; i < C; ++i ) {
#pragma HLS UNROLL
            r.second[i] = second[i]*4;
        }
        return r;
    }
};


template<size_t C, class Word, class Carry>
std::ostream& operator<<(std::ostream& out, IntWithCarry<C, Word, Carry> v)
{
    return out << v.propagate_carry();
}


void base_mulm(RSAIntBase::word_t* dst,
               size_t bit_size,
               const RSAIntBase::word_t* a,
               const RSAIntBase::word_t* b,
               const RSAIntBase::word_t* mod);

void base_powm      (RSAIntBase::word_t* dst, size_t bit_size, const RSAIntBase::word_t* base, const RSAIntBase::word_t* exp, const RSAIntBase::word_t* mod);
int  base_powm_queue(RSAIntBase::word_t* dst, size_t bit_size, const RSAIntBase::word_t* base, const RSAIntBase::word_t* exp, const RSAIntBase::word_t* mod);

void base_powm_sec      (RSAIntBase::word_t* dst, size_t bit_size, const RSAIntBase::word_t* base, const RSAIntBase::word_t* exp, const RSAIntBase::word_t* mod);
int  base_powm_sec_queue(RSAIntBase::word_t* dst, size_t bit_size, const RSAIntBase::word_t* base, const RSAIntBase::word_t* exp, const RSAIntBase::word_t* mod);

void base_powm_pair(RSAIntBase::word_t* dst[2],
                    const size_t bit_size[2],
                    const RSAIntBase::word_t* base[2],
                    const RSAIntBase::word_t* exp[2],
                    const RSAIntBase::word_t* mod[2]);

void base_powm_sec_pair(RSAIntBase::word_t* dst[2],
                        const size_t bit_size[2],
                        const RSAIntBase::word_t* base[2],
                        const RSAIntBase::word_t* exp[2],
                        const RSAIntBase::word_t* mod[2]);

template<size_t BitSize>
inline
RSAInt<BitSize> mulm(const RSAInt<BitSize>& a,
                     const RSAInt<BitSize>& b,
                     const RSAInt<BitSize>& mod)
{
    RSAInt<BitSize> ret;
    base_mulm(ret.words, mod.get_actual_bit_size(), a.words, b.words, mod.words);
    return ret;
}

template<size_t BitSize> inline RSAInt<BitSize> powm(const RSAInt<BitSize>& base, const RSAInt<BitSize>& exp, const RSAInt<BitSize>& mod)
{
    RSAInt<BitSize> ret;
    base_powm(ret.words, mod.get_actual_bit_size(), base.words, exp.words, mod.words);
    return ret;
}

template<size_t BitSize> inline int powm_queue(const RSAInt<BitSize>& base, const RSAInt<BitSize>& exp, const RSAInt<BitSize>& mod, RSAInt<BitSize>& ret)
{
  return base_powm_queue(ret.words, mod.get_actual_bit_size(), base.words, exp.words, mod.words);
}






template<size_t BitSize> inline RSAInt<BitSize> powm_sec(const RSAInt<BitSize>& base, const RSAInt<BitSize>& exp, const RSAInt<BitSize>& mod)
{
    RSAInt<BitSize> ret;
    base_powm_sec(ret.words, mod.get_actual_bit_size(), base.words, exp.words, mod.words);
    return ret;
}


template<size_t BitSize> inline int powm_sec_queue(const RSAInt<BitSize>& base, const RSAInt<BitSize>& exp, const RSAInt<BitSize>& mod, RSAInt<BitSize>& ret) 
{
  return base_powm_sec_queue(ret.words, mod.get_actual_bit_size(), base.words, exp.words, mod.words);
}












template<size_t BitSize>
inline
void powm_pair(RSAInt<BitSize> ret[2],
               const RSAInt<BitSize> base[2],
               const RSAInt<BitSize> exp[2],
               const RSAInt<BitSize> mod[2])
{
    RSAIntBase::word_t* ret_ptr[2];
    size_t bit_size[2];
    const RSAIntBase::word_t* base_ptr[2];
    const RSAIntBase::word_t* exp_ptr[2];
    const RSAIntBase::word_t* mod_ptr[2];
    for ( int i = 0; i < 2; ++i ) {
        bit_size[i] = mod[i].get_actual_bit_size();
        ret_ptr[i] = ret[i].words;
        bit_size[i] = BitSize;
        base_ptr[i] = base[i].words;
        exp_ptr[i] = exp[i].words;
        mod_ptr[i] = mod[i].words;
    }
    base_powm_pair(ret_ptr, bit_size, base_ptr, exp_ptr, mod_ptr);
}

template<size_t BitSize>
inline
void powm_sec_pair(RSAInt<BitSize> ret[2],
                   const RSAInt<BitSize> base[2],
                   const RSAInt<BitSize> exp[2],
                   const RSAInt<BitSize> mod[2])
{
    RSAIntBase::word_t* ret_ptr[2];
    size_t bit_size[2];
    const RSAIntBase::word_t* base_ptr[2];
    const RSAIntBase::word_t* exp_ptr[2];
    const RSAIntBase::word_t* mod_ptr[2];
    for ( int i = 0; i < 2; ++i ) {
        bit_size[i] = mod[i].get_actual_bit_size();
        ret_ptr[i] = ret[i].words;
        base_ptr[i] = base[i].words;
        exp_ptr[i] = exp[i].words;
        mod_ptr[i] = mod[i].words;
    }
    base_powm_sec_pair(ret_ptr, bit_size, base_ptr, exp_ptr, mod_ptr);
}

#endif
