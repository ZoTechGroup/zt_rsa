#ifndef RSA_SEQ_H
#define RSA_SEQ_H

#include <iostream>
#include "rsa_hls_api.h"

struct MontgPowParams;

struct rsa_montg_number_t {
    explicit
    rsa_montg_number_t(size_t word_count = 0, const rsa_word_t* words_ptr = 0)
        : word_count(word_count), words_ptr(words_ptr)
    {
    }
    
    operator const void*() const
    {
        return words_ptr;
    }

    size_t get_actual_bit_size() const;
    
    size_t size() const { return word_count; }
    bool empty() const { return word_count == 0; }
    const rsa_word_t* begin() const { return words_ptr; }
    const rsa_word_t* end() const { return words_ptr+word_count; }
    rsa_word_t front() const { return words_ptr[0]; }
    rsa_word_t back() const { return words_ptr[word_count-1]; }

    static size_t trimmed_size(size_t size, const rsa_word_t* words)
    {
        while ( size && !words[size-1] ) {
            --size;
        }
        return size;
    }
    size_t trimmed_size() const
    {
        return trimmed_size(size(), begin());
    }

    size_t word_count;
    const rsa_word_t* words_ptr;
};
std::ostream& operator<<(std::ostream& out, rsa_montg_number_t v);

inline
rsa_montg_number_t rsa_montg_trim(size_t word_count, const rsa_word_t* words_ptr)
{
    return rsa_montg_number_t(rsa_montg_number_t::trimmed_size(word_count, words_ptr), words_ptr);
}

inline
rsa_montg_number_t rsa_montg_trim_bits(size_t bit_count, const rsa_word_t* words_ptr)
{
    return rsa_montg_trim(rsa_bits_to_words(bit_count), words_ptr);
}


MontgPowParams* rsa_montg_alloc_params();
void rsa_montg_free_params(MontgPowParams* params);

bool rsa_montg_init_params(MontgPowParams* params,
                           rsa_montg_number_t mod,
                           rsa_montg_number_t exp,
                           PowerMode mode);
MontgPowParams* rsa_montg_alloc_init_params(rsa_montg_number_t mod,
                                            rsa_montg_number_t exp,
                                            PowerMode mode);


rsa_word_t* rsa_montg_alloc_input();
void rsa_montg_free_input(rsa_word_t* ptr);

void rsa_montg_init_public_input(rsa_word_t* input,
                                 rsa_montg_number_t data,
                                 rsa_montg_number_t mod);
rsa_word_t* rsa_montg_alloc_init_public_input(rsa_montg_number_t data,
                                              rsa_montg_number_t mod);

void rsa_montg_init_private_input(rsa_word_t* input,
                                  rsa_montg_number_t data,
                                  rsa_montg_number_t mod);
rsa_word_t* rsa_montg_alloc_init_private_input(rsa_montg_number_t data,
                                               rsa_montg_number_t mod);

rsa_word_t* rsa_montg_alloc_output();
void rsa_montg_free_output(rsa_word_t* ptr);

void rsa_montg_combine_private_outputs(rsa_word_t* output,
                                       const rsa_word_t* output1,
                                       const rsa_word_t* output2,
                                       rsa_montg_number_t mod1,
                                       rsa_montg_number_t mod2,
                                       rsa_montg_number_t coeff);
rsa_word_t* rsa_montg_alloc_combine_private_outputs(const rsa_word_t* output1,
                                                    const rsa_word_t* output2,
                                                    rsa_montg_number_t mod1,
                                                    rsa_montg_number_t mod2,
                                                    rsa_montg_number_t coeff);

// single exponentiation, part of kernel
void rsa_montg_pow_1(const MontgPowParams* params,
                     const rsa_word_t* input,
                     rsa_word_t* output);

// block exponentiation of up to UNIT_COUNT requests, part of kernel
void rsa_montg_pow_N(size_t count,
                     const MontgPowParams* const params[],
                     const rsa_word_t* const input[],
                     rsa_word_t* const output[]);

// low level interface
namespace KernelNS {
    uint16_t get_max_mod_bits();
    inline size_t get_max_mod_words()
    {
        return rsa_bits_to_words(get_max_mod_bits());
    }
    uint16_t get_max_req_count();
    uint16_t get_montg_word_bits();

    struct Args;
    struct Results;

    Args* alloc_args();
    void free_args(Args* args);
    rsa_word_t* get_req_args(Args* args, uint16_t index);
    const rsa_word_t* get_req_args(const Args* args, uint16_t index);

    Results* alloc_results();
    void free_results(Results* results);
    rsa_word_t* get_req_results(Results* results, uint16_t index);
    const rsa_word_t* get_req_results(const Results* results, uint16_t index);

    bool init_req(Args* args,
                  uint16_t index,
                  const MontgPowParams& params,
                  rsa_montg_number_t data);
    bool init_req(Args* args,
                  uint16_t index,
                  const MontgPowParams& params,
                  const rsa_word_t* data);
    bool init_public_req(Args* args,
                         uint16_t index,
                         rsa_montg_number_t mod,
                         rsa_montg_number_t exp,
                         PowerMode mode,
                         rsa_montg_number_t data);
    void get_public_output(rsa_word_t* output,
                           const Results* results,
                           uint16_t index);
    bool init_private_req(Args* args,
                          uint16_t index,
                          rsa_montg_number_t mod,
                          rsa_montg_number_t exp,
                          PowerMode mode,
                          rsa_montg_number_t data);
    void combine_private_outputs(rsa_word_t* output,
                                 const Results* results,
                                 uint16_t index1,
                                 uint16_t index2,
                                 rsa_montg_number_t mod1,
                                 rsa_montg_number_t mod2,
                                 rsa_montg_number_t coeff);

    void send_kernel_args(uint16_t req_count, const Args* args);
    void receive_kernel_results(uint16_t req_count, Results* results);
    void start_kernel_call(uint16_t req_count, const Args* args, Results* results);
    void wait_kernel_call(Results* results);
    void do_kernel_call(uint16_t req_count, const Args* args, Results* results);
    void kernel_call(uint16_t req_count, const Args* args, Results* results);
    const RSAMontgInfo& get_kernel_info();
    RSAMontgInfo read_kernel_info();
}

inline
size_t rsa_montg_max_mod_bits()
{
    return KernelNS::get_max_mod_bits();
}

inline
size_t rsa_montg_max_mod_words()
{
    return rsa_bits_to_words(rsa_montg_max_mod_bits());
}

// OpenCL initialization, not part of kernel
void rsa_montg_init(const char* ps_dev_name, const char* ps_kernel_fname);
void rsa_montg_cleanup();

#endif//RSA_SEQ_H
