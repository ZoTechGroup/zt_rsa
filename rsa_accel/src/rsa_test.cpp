#include <stddef.h>
#include "rsa_seq.h"
#include "rsa.h"
#include "rsa_gmp.h"
#include "rsa_pkcs.h"
#include <openssl/pem.h>
#include <iostream>
#include <cassert>
#include <vector>
#include "timer.h"
using namespace std;

// OpenCL wrapper control
extern bool benchmarking;
extern int bench_packet;
extern bool bench_clock;
extern bool skip_opencl_call;
extern int kernel_call_count;

void opencl_cleanup();
void opencl_init(const char* ps_dev_name, const char* ps_kernel_fname);

inline
rsa_montg_number_t num(const RSAFullInt& v)
{
    return rsa_montg_trim(v.WORD_COUNT, v.words);
}

inline
RSAMessage from_output(const rsa_word_t* v, size_t word_count)
{
    RSAMessage ret;
    assert(ret.WORD_COUNT >= word_count);
    copy(v, v+word_count, ret.words);
    fill(ret.words+word_count, ret.words+ret.WORD_COUNT, 0);
    return ret;
}

inline
RSAMessage from_output(const rsa_word_t* v, const RSAFullInt& mod)
{
    return from_output(v, num(mod).size());
}

inline
RSAMessage ref_powmod_simple_sec(const RSAMessage& msg, const RSAFullInt& exponent, const RSAModulus& modulus)
{
#if 1
    MontgPowParams* params =
        rsa_montg_alloc_init_params(num(modulus), num(exponent), secure_power);
    assert(params);
    rsa_word_t* input =
        rsa_montg_alloc_init_public_input(num(msg), num(modulus));
    assert(input);
    rsa_word_t* output = rsa_montg_alloc_output();
    rsa_montg_pow_N(1, &params, &input, &output);
    rsa_montg_free_params(params);
    rsa_montg_free_input(input);
    RSAMessage ret = from_output(output, modulus);
    rsa_montg_free_output(output);
    return ret;
#else
    return powm_sec((msg), exponent, modulus);
#endif
}

inline int ref_powmod_simple_sec_queue(const RSAMessage& msg_inp, const RSAFullInt& exponent, const RSAModulus& modulus, RSAMessage& msg_out)
{
  return powm_sec_queue((msg_inp), exponent, modulus, msg_out);
}

inline
RSAMessage ref_powmod_simple(const RSAMessage& msg, const RSAFullInt& exponent, const RSAModulus& modulus)
{
#if 1
    MontgPowParams* params =
        rsa_montg_alloc_init_params(num(modulus), num(exponent), fast_power);
    assert(params);
    rsa_word_t* input =
        rsa_montg_alloc_init_public_input(num(msg), num(modulus));
    assert(input);
    rsa_word_t* output = rsa_montg_alloc_output();
    rsa_montg_pow_N(1, &params, &input, &output);
    rsa_montg_free_params(params);
    rsa_montg_free_input(input);
    RSAMessage ret = from_output(output, modulus);
    rsa_montg_free_output(output);
    return ret;
#else
    return powm((msg), exponent, modulus);
#endif
}

inline int ref_powmod_simple_queue(const RSAMessage& msg_inp, const RSAFullInt& exponent, const RSAModulus& modulus, RSAMessage& msg_out)
{
  return powm_queue(msg_inp, exponent, modulus, msg_out);
}

/*
RSA private key operation as implemented in openssl RSA_eay_mod_exp()

RSA_eay_mod_exp(r0 out, I in, rsa, ctx);

p : prime1
q : prime2
dmp1 : exponent1
dmq1 : exponent2
iqmp : coefficient

m1 = (I % prime1)^exponent1 % prime1; // CONSTTIME
m2 = (I % prime2)^exponent2 % prime2; // CONSTTIME

// d = (m1 - m2) % prime1
d = m1 - m2;
if ( d < 0 ) d += prime1;
if ( d < 0 ) d += prime1; // may be necessary only if prime1 < prime2

t = (d*coefficient) % prime1; // CONSTTIME
ret = m2 + t * prime2;

// if we have public exponent then verify if public operation is congruent to the input mod n
if ( public_exponent && n ) {
  vrfy = (ret ^ public_exponent % n - I) % n;
  if ( vrfy < 0 ) vrfy += n;
  if ( vrfy != 0 ) {
    // slow operation in case of failed verification
    ret = I ^ private_exponent % n;
  }
}

return ret;

 */

RSAMessage ref_powmod_complex_sec(const RSAMessage& msg, const RSAPrivateKey& key, bool as_queue = false)
{
  if (!as_queue) {
    MontgPowParams* params[2];
    params[0] =
        rsa_montg_alloc_init_params(num(key.prime1), num(key.exponent1), fast_power);
    assert(params[0]);
    params[1] =
        rsa_montg_alloc_init_params(num(key.prime2), num(key.exponent2), fast_power);
    assert(params[1]);
    rsa_word_t* input[2];
    input[0] =
        rsa_montg_alloc_init_private_input(num(msg), num(key.prime1));
    assert(input[0]);
    input[1] =
        rsa_montg_alloc_init_private_input(num(msg), num(key.prime2));
    assert(input[1]);
    rsa_word_t* output[2];
    output[0] = rsa_montg_alloc_output();
    output[1] = rsa_montg_alloc_output();
    rsa_montg_pow_N(2, params, input, output);
    rsa_montg_free_params(params[0]);
    rsa_montg_free_params(params[1]);
    rsa_montg_free_input(input[0]);
    rsa_montg_free_input(input[1]);
    
    rsa_word_t* result =
        rsa_montg_alloc_combine_private_outputs(output[0], output[1],
                                                num(key.prime1),
                                                num(key.prime2),
                                                num(key.coefficient));
    rsa_montg_free_input(output[0]);
    rsa_montg_free_input(output[1]);
    
    RSAMessage ret = from_output(result, key.modulus);
    rsa_montg_free_output(result);
    return ret;
  } else {
    // copy multiply used numbers
    GMPInt c = msg;
    GMPInt prime1 = key.prime1;
    GMPInt prime2 = key.prime2;

    GMPInt c1 = c % prime1;
    GMPInt c2 = c % prime2;
    
    RSAPrimeInt rr[2];
    RSAPrimeInt cc[2] = { c1, c2 };
    RSAPrimeInt ee[2] = { key.exponent1, key.exponent2 };
    RSAPrimeInt mm[2] = { key.prime1, key.prime2 };
    // cout << "input: "<<c<<endl;
    // cout << "mod[0]: "<<mm[0]<<endl;
    // cout << "input[0]: "<<cc[0]<<endl;
    // cout << "input[1]: "<<cc[1]<<endl;
    powm_sec_pair(rr, cc, ee, mm);
    GMPInt m1 = rr[0];
    GMPInt m2 = rr[1];
    // cout << "output[0]: "<<rr[0]<<endl;
    // cout << "output[1]: "<<rr[1]<<endl;
    
    if ( 0 ) {
        cout << c2 << endl;
        cout << key.exponent2 << endl;
        cout << key.prime2 << endl;
        cout << m2 << endl;
    }
    GMPInt ret = m2 + mulm(subm2(m1, m2, key.prime1), key.coefficient, key.prime1)*key.prime2;
    // cout << "ret: "<<ret<<endl;
    return ret;
  }
}

/*
int ref_powmod_complex_sec_queue(const RSAMessage& msg, const RSAPrivateKey& key, RSAMessage& msg_out)
{
    // copy multiply used numbers
    GMPInt c = msg;
    GMPInt prime1 = key.prime1;
    GMPInt prime2 = key.prime2;

    GMPInt c1 = c % prime1;
    GMPInt c2 = c % prime2;
    
    RSAPrimeInt rr[2];
    RSAPrimeInt cc[2] = { c1, c2 };
    RSAPrimeInt ee[2] = { key.exponent1, key.exponent2 };
    RSAPrimeInt mm[2] = { key.prime1, key.prime2 };

    return powm_sec_pair_queue(rr, cc, ee, mm);
    
//S    GMPInt m1 = rr[0];
//S    GMPInt m2 = rr[1];
//S    
//S    if ( 0 ) 
//S    {
//S        cout << c2 << endl;
//S        cout << key.exponent2 << endl;
//S        cout << key.prime2 << endl;
//S        cout << m2 << endl;
//S    }
//S    
//S    GMPInt ret = m2 + mulm(subm2(m1, m2, key.prime1), key.coefficient, key.prime1)*key.prime2;
//S    
//S    return ret;
}

int ref_powmod_complex_sec_queue_after(const RSAMessage& msg, const RSAPrivateKey& key, RSAMessage& msg_out)
{
    // copy multiply used numbers
    GMPInt c = msg;
    GMPInt prime1 = key.prime1;
    GMPInt prime2 = key.prime2;

    GMPInt c1 = c % prime1;
    GMPInt c2 = c % prime2;
    
    RSAPrimeInt rr[2];
    RSAPrimeInt cc[2] = { c1, c2 };
    RSAPrimeInt ee[2] = { key.exponent1, key.exponent2 };
    RSAPrimeInt mm[2] = { key.prime1, key.prime2 };

    powm_sec_pair(rr, cc, ee, mm);
    
    GMPInt m1 = rr[0];
    GMPInt m2 = rr[1];
    
    if ( 0 ) 
    {
        cout << c2 << endl;
        cout << key.exponent2 << endl;
        cout << key.prime2 << endl;
        cout << m2 << endl;
    }
    
    GMPInt ret = m2 + mulm(subm2(m1, m2, key.prime1), key.coefficient, key.prime1)*key.prime2;
    
    return ret;
}
*/

RSAMessage reference_public(const RSAMessage& msg, const RSAPrivateKey& key, bool as_public = true, bool GMPuse = false)
{
  //return ref_powmod_simple(msg, key.publicExponent, key.modulus);
  if (GMPuse) {
    GMPInt ret;
    mpz_powm(ret, GMPInt(msg), GMPInt(as_public ? key.publicExponent : key.privateExponent), GMPInt(key.modulus));
    return ret;
  }
  else {
    BIGNUM* ret = BN_new();
    // BN_CTX* ctx = BN_CTX_new();
    BN_CTX* ctx = BN_CTX_secure_new();
    BN_mod_exp(ret, msg, as_public ? key.publicExponent : key.privateExponent, key.modulus, ctx);
    BN_CTX_free(ctx);
    return ret;
  }
}

inline
RSAMessage RSAEP_ref(const RSAMessage& msg, const RSAPublicKey& key)
{
    return ref_powmod_simple(msg, key.publicExponent, key.modulus);
}

inline int RSAEP_ref_queue(const RSAMessage& msg, const RSAPublicKey& key, RSAMessage& msg_out)
{
    return ref_powmod_simple_queue(msg, key.publicExponent, key.modulus, msg_out);
}

inline
RSAMessage RSAEP_ref(const RSAMessage& msg, const RSAPrivateKey& key)
{
    return ref_powmod_simple(msg, key.publicExponent, key.modulus);
}

inline int RSAEP_ref_queue(const RSAMessage& msg_inp, const RSAPrivateKey& key, RSAMessage& msg_out)
{
    // cout << "key.publicExponent  = " << key.publicExponent << endl;
    // cout << "key.modulus         = " << key.modulus        << endl;
  
    return ref_powmod_simple_queue(msg_inp, key.publicExponent, key.modulus, msg_out);
}

inline
RSAMessage RSADP_ref(const RSAMessage& msg, const RSAPrivateKey& key, bool as_public = false)
{
    if ( as_public ) {
        return ref_powmod_simple_sec(msg, key.privateExponent, key.modulus);
    }
    else {
        return ref_powmod_complex_sec(msg, key);
    }
}

inline int RSADP_ref_queue(const RSAMessage& msg_inp, const RSAPrivateKey& key, RSAMessage& msg_out, bool as_public = false)
{
    if ( as_public ) 
      {
        return ref_powmod_simple_sec_queue(msg_inp, key.privateExponent, key.modulus, msg_out);
      }
    else 
      {
        msg_out = ref_powmod_complex_sec(msg_inp, key, true);
        return -1;
      }
}

/*
inline int RSADP_ref_queue_after(const RSAMessage& msg_inp, const RSAPrivateKey& key, RSAMessage& msg_out, bool as_public = false)
{
    if ( as_public ) 
      {
        return -1; //ref_powmod_simple_sec_queue(msg_inp, key.privateExponent, key.modulus, msg_out);
      }
    else 
      {
        return ref_powmod_complex_sec_queue_after(msg_inp, key, msg_out);
      }
}
*/

const char* const ref_data[][3] = {
    {
        "../../data/test_key1.private",
        "4320323092034713910341084108410861286401892640189264018296481264180640182abcdef64018926312312312311234320323092034713910341084108410861286401892640189264018296481264180640182abcdef64018926312312312311234320323092034713910341084108410861286401892640189264018296481264180640182abcdef64018926312312312311234320323092034713910341084108410861286401892640189264018296481264180640182abcdef6401892631231231231",
        "40C104E0BD48F0ABC84568A7C2B06005694C77B802D659A03942F3A12BECCB862CB8783B9BE04DF990377CE4F62DD6A8E9945C5402100DD72086C856CD26BE2816E163056ED1D893F84898B1375613220D9348E36BF5ED8E74DCA3770DD1A5BA47D18C4FA29A0FAE5D7EF1C89F8E287AEF7B5FB24F446F36A7C097C9FDD85DBFDE350F612147B55B9BFF67705F015B22E647D1703A31EF8A9AEAA262A9600E2FB6C4AF130144DC484C153858E9F0EFC1E26022B1972B1BAC507CDB1A50254593F78550072D740B263A2F8894A88E6DC7A518A3B8171E6C6F7CE950927240290FD1F95BCB817D0C76FEC558D6FB30F0979FB70B9C6FF1C705AC66F75A3A8DCA16"
    },
    {
        "../../data/test_key1.private",
        "4320323092034713910341084108410861286401892640189264018296481264180640182abcdef64018926312312312311234320323092034713910341084108410861286401892640189264018296481264180640182abcdef64018926312312312311234320323092034713910341084108410861286401892640189264018296481264180640182abcdef64018926312312312311234320323092034713910341084108410861286401892640189264018296481264180640182abcdef6401892631231231231000000000000000000000000000000000000000000000000000000000000",
        "B548E95D80476EC151CB53922245847559AC9D89D9CB9411394CE1AF5A09D6F0F044163B3D3964420956FEBB02830FC1E1E106F5834DF5CF497151DF5C2AD88908B77ECFB8B75A4878F11954B606AF95C418E564C7E7AA0DEEAA81601A308A1DB3C6985D1B4B2E588454766A8FBAD1C16255003D0AB3C6C2AFC05B1EB1AA02E8C991A028061D3ABFB44B36DACF321D60C08E58B2922B102F416D34518BA8BBE737517077F06A58F4BAE8F5FA48FB5AE0352071E163A353329670908907F41895B31F73B1D46669011410A1EC18577E30AA6D8725AE0A29B02208D6F573373A48A7ADC4AB05BDF1898469E5B749A1F28F4204EC84B8D74A18656E9970B3DD3CBF"
    },
};

void help()
{
    cout << "Parameters:\n"
         << "  -host [sw_emu|hw_emu|hw]   OpenCL host/emulation type (XCL_EMULATION_MODE=...)\n"
         << "  -d <device>         OpenCL device\n"
         << "  -k <file>           OpenCL kernel file (RSA_KERNEL_BIN=...)\n"
         << "  -key <file>         RSA key file\n"
         << "  -msg <hexstring>    message to encrypt\n"
         << "  -queue              run requests in queue mode\n"
         << "  -pkcs               run RSA PKCS conformance test\n"
         << "  -pkcs-nopadd        disabling padding for PKCS-compliant test\n"
         << "  -pkcs-noblind       disabling blinding for PKCS-compliant test\n"
         << "  -bench-count <n>    run speed test <n> times\n"
         << "  -bench-public-init  run speed test for public key preparation\n"
         << "  -bench-private-init run speed test for private key preparation\n"
         << "  -bench-private-data-init   run speed test for private data preparation\n"
         << "  -bench-private-data-merge  run speed test for private data post-processing\n"
         << "  -bench-public       run speed test for public key encryption\n"
         << "  -bench-private      run speed test for private key encryption\n"
         << "  -bench-packet <n>   limit number of requests in one packet\n"
         << "  -exp-ones <n>       force exponent to be n ones\n"
         << "  -bench-CPU          run speed test for whole CPU overhead\n"
         << "  -bench-OCL          run speed test for whole OpenCL overhead\n"
         << "  -kernel-calls <n>   call kernel n times\n"
         << "  -bench-parallel     run encryption speed test in parallel\n"
         << "  -bench-sequential   run encryption speed test sequentially\n"
         << "  -bench-clock        collect and print time spent in different code\n"
         << "  -low-level          use low-level kernel interface\n"
         << "  -low-level2         use 2-way low-level kernel interface\n"
         << "  -trace-init         printout results of Montgomery initialization\n"
         << "  -no-trace-init      turn off printout results of Montgomery initialization\n"
         << "  -trace-steps        printout output for different iterations\n"
         << flush;
    exit(1);
}

RSAMessage get_msg(const RSAMessage& msg, size_t i, const RSAPrivateKey& key)
{
    RSAMessage ret = msg;
    i %= key.modulus.get_actual_bit_size()-1;
    ret.words[i/RSA_WORD_BITS] ^= rsa_word_t(1)<<(i%RSA_WORD_BITS);
    return ret;
}

namespace LowLevel {
    struct Sign {
        size_t get_number_of_requests() const
        {
            return 2;
        }
        void prepare_args(KernelNS::Args* args, size_t index,
                          const RSAPrivateKey& key, const RSAMessage& data)
        {
            KernelNS::init_private_req(args, index,
                                       num(key.prime1), num(key.exponent1),
                                       fast_power, num(data));
            KernelNS::init_private_req(args, index+1,
                                       num(key.prime2), num(key.exponent2),
                                       fast_power, num(data));
        }
        void prepare_results(const KernelNS::Results* results, size_t index,
                             const RSAPrivateKey& key, RSAMessage& result)
        {
            KernelNS::combine_private_outputs(result.words,
                                              results, index, index+1,
                                              num(key.prime1),
                                              num(key.prime2),
                                              num(key.coefficient));
        }
    };
    struct Verify {
        size_t get_number_of_requests() const
        {
            return 1;
        }
        void prepare_args(KernelNS::Args* args, size_t index,
                          const RSAPrivateKey& key, const RSAMessage& data)
        {
            KernelNS::init_public_req(args, index,
                                      num(key.modulus), num(key.publicExponent),
                                      fast_power, num(data));
        }
        void prepare_results(const KernelNS::Results* results, size_t index,
                             const RSAPrivateKey& key, RSAMessage& result)
        {
            KernelNS::get_public_output(result.words,
                                        results, index);
        }
    };

    void prepare_encrypt_args(size_t req_count,
                              const RSAPrivateKey* const* keys,
                              const RSAMessage* inp_msgs,
                              KernelNS::Args* args)
    {
        for ( size_t i = 0; i < req_count; ++i ) {
            const RSAPrivateKey& key = *keys[i];
            const RSAMessage& data = inp_msgs[i];
            KernelNS::init_private_req(args, i*2,
                                       num(key.prime1), num(key.exponent1),
                                       fast_power, num(data));
            KernelNS::init_private_req(args, i*2+1,
                                       num(key.prime2), num(key.exponent2),
                                       fast_power, num(data));
        }
    }
    void prepare_encrypt_results(size_t req_count,
                                 const RSAPrivateKey* const* keys,
                                 const KernelNS::Results* results,
                                 RSAMessage* enc_msgs)
    {
        for ( size_t i = 0; i < req_count; ++i ) {
            const RSAPrivateKey& key = *keys[i];
            KernelNS::combine_private_outputs(enc_msgs[i].words,
                                              results, i*2, i*2+1,
                                              num(key.prime1),
                                              num(key.prime2),
                                              num(key.coefficient));
        }
    }
    
    void prepare_decrypt_args(size_t req_count,
                              const RSAPrivateKey* const* keys,
                              const RSAMessage* inp_msgs,
                              KernelNS::Args* args)
    {
        for ( size_t i = 0; i < req_count; ++i ) {
            const RSAPrivateKey& key = *keys[i];
            const RSAMessage& data = inp_msgs[i];
            KernelNS::init_public_req(args, i,
                                      num(key.modulus), num(key.publicExponent),
                                      fast_power, num(data));
        }
    }
    void prepare_decrypt_results(size_t req_count,
                                 const RSAPrivateKey* const* keys,
                                 const KernelNS::Results* results,
                                 RSAMessage* enc_msgs)
    {
        for ( size_t i = 0; i < req_count; ++i ) {
            KernelNS::get_public_output(enc_msgs[i].words,
                                        results, i);
        }
    }

    void encrypt(const vector<const RSAPrivateKey*>& keys,
                 const vector<RSAMessage>& inp_msgs,
                 vector<RSAMessage>& enc_msgs)
    {
        size_t COUNT = keys.size();
        size_t MAX_REQ_COUNT = KernelNS::get_max_req_count()/2;
        KernelNS::Args* args = KernelNS::alloc_args();
        KernelNS::Results* results = KernelNS::alloc_results();
        for ( size_t req_pos = 0, req_count = 0; req_pos < COUNT; req_pos += req_count ) {
            req_count = min(COUNT-req_pos, MAX_REQ_COUNT);
            prepare_encrypt_args(req_count, &keys[req_pos], &inp_msgs[req_pos], args);
            KernelNS::kernel_call(req_count*2, args, results);
            prepare_encrypt_results(req_count, &keys[req_pos], results, &enc_msgs[req_pos]);
        }
        KernelNS::free_args(args);
        KernelNS::free_results(results);
    }
    void decrypt(const vector<const RSAPrivateKey*>& keys,
                 const vector<RSAMessage>& inp_msgs,
                 vector<RSAMessage>& enc_msgs)
    {
        size_t COUNT = keys.size();
        size_t MAX_REQ_COUNT = KernelNS::get_max_req_count();
        KernelNS::Args* args = KernelNS::alloc_args();
        KernelNS::Results* results = KernelNS::alloc_results();
        for ( size_t req_pos = 0, req_count = 0; req_pos < COUNT; req_pos += req_count ) {
            req_count = min(COUNT-req_pos, MAX_REQ_COUNT);
            prepare_decrypt_args(req_count, &keys[req_pos], &inp_msgs[req_pos], args);
            KernelNS::kernel_call(req_count, args, results);
            prepare_decrypt_results(req_count, &keys[req_pos], results, &enc_msgs[req_pos]);
        }
        KernelNS::free_args(args);
        KernelNS::free_results(results);
    }

    struct KernelCall {
        KernelCall()
            : req_pos(0),
              req_count(0),
              args(KernelNS::alloc_args()),
              results(KernelNS::alloc_results())
        {
        }
        void reset()
        {
            assert(!req_count);
            KernelNS::free_args(args);
            KernelNS::free_results(results);
        }
        size_t req_pos;
        size_t req_count;
        KernelNS::Args* args;
        KernelNS::Results* results;
    };

    void start_encrypt2(KernelCall& call,
                        size_t req_pos,
                        size_t req_count,
                        const vector<const RSAPrivateKey*>& keys,
                        const vector<RSAMessage>& inp_msgs)
    {
        assert(!call.req_count);
        call.req_pos = req_pos;
        call.req_count = req_count;
        prepare_encrypt_args(req_count, &keys[req_pos], &inp_msgs[req_pos], call.args);
        KernelNS::send_kernel_args(req_count*2, call.args);
        KernelNS::start_kernel_call(req_count*2, call.args, call.results);
    }
    void finish_encrypt2(KernelCall& call,
                         const vector<const RSAPrivateKey*>& keys,
                         vector<RSAMessage>& enc_msgs)
    {
        if ( !call.req_count )
            return;

        KernelNS::wait_kernel_call(call.results);
        KernelNS::receive_kernel_results(call.req_count*2, call.results);
        prepare_encrypt_results(call.req_count, &keys[call.req_pos], call.results, &enc_msgs[call.req_pos]);
        call.req_count = 0;
    }

    void start_decrypt2(KernelCall& call,
                        size_t req_pos,
                        size_t req_count,
                        const vector<const RSAPrivateKey*>& keys,
                        const vector<RSAMessage>& inp_msgs)
    {
        assert(!call.req_count);
        call.req_pos = req_pos;
        call.req_count = req_count;
        prepare_decrypt_args(req_count, &keys[req_pos], &inp_msgs[req_pos], call.args);
        KernelNS::send_kernel_args(req_count, call.args);
        KernelNS::start_kernel_call(req_count, call.args, call.results);
    }
    void finish_decrypt2(KernelCall& call,
                         const vector<const RSAPrivateKey*>& keys,
                         vector<RSAMessage>& enc_msgs)
    {
        if ( !call.req_count )
            return;

        KernelNS::wait_kernel_call(call.results);
        KernelNS::receive_kernel_results(call.req_count, call.results);
        prepare_decrypt_results(call.req_count, &keys[call.req_pos], call.results, &enc_msgs[call.req_pos]);
        call.req_count = 0;
    }

    void encrypt2(const vector<const RSAPrivateKey*>& keys,
                  const vector<RSAMessage>& inp_msgs,
                  vector<RSAMessage>& enc_msgs)
    {
        size_t COUNT = keys.size();
        size_t MAX_REQ_COUNT = KernelNS::get_max_req_count()/2;
        KernelCall call0, call1;
        for ( size_t req_pos = 0, req_count = 0; req_pos < COUNT; req_pos += req_count ) {
            req_count = min(COUNT-req_pos, MAX_REQ_COUNT);
            finish_encrypt2(call0, keys, enc_msgs);
            start_encrypt2(call0, req_pos, req_count, keys, inp_msgs);
            swap(call0, call1);
        }
        finish_encrypt2(call0, keys, enc_msgs);
        finish_encrypt2(call1, keys, enc_msgs);
        call0.reset();
        call1.reset();
    }
    void decrypt2(const vector<const RSAPrivateKey*>& keys,
                  const vector<RSAMessage>& inp_msgs,
                  vector<RSAMessage>& enc_msgs)
    {
        size_t COUNT = keys.size();
        size_t MAX_REQ_COUNT = KernelNS::get_max_req_count();
        KernelCall call0, call1;
        for ( size_t req_pos = 0, req_count = 0; req_pos < COUNT; req_pos += req_count ) {
            req_count = min(COUNT-req_pos, MAX_REQ_COUNT);
            finish_decrypt2(call0, keys, enc_msgs);
            start_decrypt2(call0, req_pos, req_count, keys, inp_msgs);
            swap(call0, call1);
        }
        finish_decrypt2(call0, keys, enc_msgs);
        finish_decrypt2(call1, keys, enc_msgs);
        call0.reset();
        call1.reset();
    }
}

int main(int argc, char *argv[])
{
    const char* host_type = 0;
    bool sw_emulation = false;
    bool hw_emulation = false;
    const char* device = 0;
    const char* kernel_file = 0;
    string key_file;
    string inp_msg;
    bool queue_mode  = false;
    bool pkcs_mode   = false;
    bool pkcs_nopadd = false;
    bool pkcs_noblind = false;
    int bench_count = 0;
    bool bench_public_init = false;
    bool bench_private_init = false;
    bool bench_private_data_init = false;
    bool bench_private_data_merge = false;
    bool bench_public = false;
    bool bench_private = false;
    int exp_ones = 0;
    bool bench_CPU = false;
    bool bench_OCL = false;
    bool bench_parallel = true;
    bool trace_init = false;
    bool trace_steps = false;
    bool low_level = false;
    bool low_level2 = false;

    vector<string> args;
    for ( int i = 1; i < argc; ++i ) {
        args.push_back(argv[i]);
    }
    if ( args.empty() ) {
        string args_file_name = getenv("HOME")+string("/rsa_test.args");
        ifstream args_in(args_file_name.c_str());
        if ( args_in ) {
            string s;
            while ( args_in >> s ) {
                args.push_back(s);
            }
        }
        if ( !args.empty() ) {
            cout << "Used args from file:";
            for ( size_t i = 0; i < args.size(); ++i )
                cout << ' ' << args[i];
            cout << endl;
        }
    }
    for ( size_t i = 0; i < args.size(); ++i ) {
        if ( args[i] == "-h" ) {
            help();
        }
        if ( args[i] == "-host" && i+1 < args.size() ) {
            host_type = args[++i].c_str();
            continue;
        }
        if ( args[i] == "-d" && i+1 < args.size() ) {
            device = args[++i].c_str();
            continue;
        }
        if ( args[i] == "-k" && i+1 < args.size() ) {
            kernel_file = args[++i].c_str();
            continue;
        }
        if ( args[i] == "-key" && i+1 < args.size() ) {
            key_file = args[++i];
            continue;
        }
        if ( args[i] == "-msg" && i+1 < args.size() ) {
            inp_msg = args[++i];
            continue;
        }
        if ( args[i] == "-queue" ) {
            queue_mode = true;
            continue;
        }
        if ( args[i] == "-pkcs" ) {
            pkcs_mode = true;
            continue;
        }
        if ( args[i] == "-pkcs-nopadd" ) {
            pkcs_nopadd = true;
            continue;
        }
        if ( args[i] == "-pkcs-noblind" ) {
            pkcs_noblind = true;
            continue;
        }
        if ( args[i] == "-bench-count" && i+1 < args.size() &&
             (bench_count = atoi(args[i+1].c_str())) ) {
            ++i;
            continue;
        }
        if ( args[i] == "-bench-public-init" ) {
            bench_public_init = true;
            continue;
        }
        if ( args[i] == "-bench-private-init" ) {
            bench_private_init = true;
            continue;
        }
        if ( args[i] == "-bench-private-data-init" ) {
            bench_private_data_init = true;
            continue;
        }
        if ( args[i] == "-bench-private-data-merge" ) {
            bench_private_data_merge = true;
            continue;
        }
        if ( args[i] == "-bench-public" ) {
            bench_public = true;
            continue;
        }
        if ( args[i] == "-bench-private" ) {
            bench_private = true;
            continue;
        }
        if ( args[i] == "-bench-packet" && i+1 < args.size() &&
             (bench_packet = atoi(args[i+1].c_str())) ) {
            ++i;
            continue;
        }
        if ( args[i] == "-exp-ones" && i+1 < args.size() &&
             (exp_ones = atoi(args[i+1].c_str())) ) {
            ++i;
            continue;
        }
        if ( args[i] == "-bench-CPU" ) {
            bench_CPU = true;
            continue;
        }
        if ( args[i] == "-bench-OCL" ) {
            bench_OCL = true;
            kernel_call_count = 0;
            continue;
        }
        if ( args[i] == "-kernel-calls" && i+1 < args.size() &&
             (kernel_call_count = atoi(args[i+1].c_str())) ) {
            ++i;
            continue;
        }
        if ( args[i] == "-bench-parallel" ) {
            bench_parallel = true;
            continue;
        }
        if ( args[i] == "-bench-sequential" ) {
            bench_parallel = false;
            continue;
        }
        if ( args[i] == "-low-level" ) {
            low_level = true;
            continue;
        }
        if ( args[i] == "-low-level2" ) {
            low_level = true;
            low_level2 = true;
            continue;
        }
        if ( args[i] == "-bench-clock" ) {
            bench_clock = true;
            continue;
        }
        if ( args[i] == "-trace-init" ) {
            trace_init = true;
            continue;
        }
        if ( args[i] == "-no-trace-init" ) {
            trace_init = false;
            continue;
        }
        if ( args[i] == "-trace-steps" ) {
            trace_steps = true;
            continue;
        }
        if ( args[i] == "1" ) {
            continue;
        }
        cout << "Unknown parameter: " << args[i] << endl << endl;
        help();
    }

    if ( 0 && args.empty() ) {
        // make multiple requests
        bench_count = 5;
        bench_parallel = true;
        bench_public = true;
        low_level = true;
        low_level2 = true;
        bench_clock = true;
    }

    if ( !host_type ) {
        host_type = getenv("XCL_EMULATION_MODE");
    }
    if ( host_type ) {
        hw_emulation = strcasecmp(host_type, "hw_emu") == 0;
        sw_emulation = strcasecmp(host_type, "sw_emu") == 0;
    }
    // if ( hw_emulation || sw_emulation ) {
    //     putenv(strdup("XCL_EMULATION_MODE=true"));
    // }
    // else {
    //     //putenv(strdup("XCL_EMULATION_MODE=false"));
    // }

    std::string const plPath = getenv("AWS_PLATFORM");
    std::size_t const plFirstChar = plPath.rfind("/")+1;
    std::size_t const plLastChar  = plPath.rfind(".xpfm");
    std::string const plName = plPath.substr(plFirstChar, plLastChar - plFirstChar);
    bool const plAWS = (plPath.rfind("xilinx_aws") != std::string::npos); // is platform really AWS-based
    std::string const kernelName = hw_emulation ? ("./xclbin/rsa_hls_krnl.hw_emu." + plName + ".xclbin") :
                                   sw_emulation ? ("./xclbin/rsa_hls_krnl.sw_emu." + plName + ".xclbin") :
                                   plAWS ?        (       "./rsa_hls_krnl.hw."     + plName + ".awsxclbin") :
                                                  ("./xclbin/rsa_hls_krnl.hw."     + plName + ".xclbin");

    if ( !device ) {
        device = plName.c_str();
    }

    if ( 1 || host_type ) {
        if ( !kernel_file ) {
            kernel_file = getenv("RSA_KERNEL_BIN");
        }
        if ( !kernel_file ) {
            kernel_file = kernelName.c_str();
        }
    }
    else {
        device = 0;
        kernel_file = 0;
    }

    if ( device && *device )
        opencl_init(device, kernel_file);
    
    if ( key_file.empty() && KernelNS::get_max_mod_bits() < 512 ) {
        key_file = "../../data/test_key_rsa256.private";
        if ( inp_msg.empty() )
            inp_msg = "123304958302985ab4203947834ecfffffffffffff000000000000";
    }
    if ( key_file.empty() && KernelNS::get_max_mod_bits() < 1024 ) {
        key_file = "../../data/test_key_rsa512.private";
        if ( inp_msg.empty() )
            inp_msg = "123304958302985abfffffffffffffffffff2234203947834ec000000000000fffffffffffff000000000000";
    }
    if ( key_file.empty() && KernelNS::get_max_mod_bits() < 2048 ) {
        key_file = "../../data/test_key_rsa1024.private";
        if ( inp_msg.empty() )
            inp_msg = "123304958302985abf4444444444444444444444ffffffffffffffffff2234203947834ec000000000000fffffffffffff00000000000000000000000000000000000000000";
    }
    if ( key_file.empty() ) {
        key_file = "../../data/test_key1.private";
    }
    if ( inp_msg.empty() ) {
        inp_msg = "4320323092034713910341084108410861286401892640189264018296481264180640182abcdef64018926312312312311234320323092034713910341084108410861286401892640189264018296481264180640182abcdef64018926312312312311234320323092034713910341084108410861286401892640189264018296481264180640182abcdef64018926312312312311234320323092034713910341084108410861286401892640189264018296481264180640182abcdef6401892631231231231000000000000000000000000000000000000000000000000000000000000";
    }
    
    try {
        RSAPrivateKey key(key_file, RSAKeyParser::base64);
        
        cout << endl << "RSA Key components:" << endl;
        cout << "modulus         (mod)  = " << key.modulus         << endl << endl;
        cout << "publicExponent  (e)    = " << key.publicExponent  << endl << endl;
        cout << "privateExponent (d)    = " << key.privateExponent << endl << endl;
        cout << "prime1          (p)    = " << key.prime1          << endl << endl;
        cout << "prime2          (q)    = " << key.prime2          << endl << endl;
        cout << "exponent1       (dP)   = " << key.exponent1       << endl << endl;
        cout << "exponent2       (dQ)   = " << key.exponent2       << endl << endl;
        cout << "coefficient     (qInv) = " << key.coefficient     << endl << endl;

        // creating OpenSSl complient RSA key
        FILE* keyFp = fopen(key_file.c_str(), "rb");
        RSA* sslKey = RSA_new();
        sslKey = PEM_read_RSAPrivateKey(keyFp, &sslKey, NULL, NULL);
        if (!keyFp || !sslKey) {
          cout << "ERROR: Cannot read and/or parse key file: " << key_file << endl;
          return -1;
        }
        if (pkcs_noblind) RSA_blinding_off(sslKey); // Blinding is enabled by default
        // RSA_clear_flags(sslKey, RSA_FLAG_CACHE_PUBLIC);

        const BIGNUM* sslKey_n;
        const BIGNUM* sslKey_e;
        const BIGNUM* sslKey_d;
        const BIGNUM* sslKey_p;
        const BIGNUM* sslKey_q;
        const BIGNUM* sslKey_dmp1;
        const BIGNUM* sslKey_dmq1;
        const BIGNUM* sslKey_iqmp;

        RSA_get0_key       (sslKey, &sslKey_n, &sslKey_e, &sslKey_d);
        RSA_get0_factors   (sslKey, &sslKey_p, &sslKey_q);
        RSA_get0_crt_params(sslKey, &sslKey_dmp1, &sslKey_dmq1, &sslKey_iqmp);

        cout << endl << "OpenSSL RSA Key components:" << endl;
        cout << "Key size               = " << RSA_size (sslKey)*8    << endl;      
        cout << "modulus         (mod)  = " << BN_bn2hex(sslKey_n)    << endl << endl;
        cout << "publicExponent  (e)    = " << BN_bn2hex(sslKey_e)    << endl << endl;
        cout << "privateExponent (d)    = " << BN_bn2hex(sslKey_d)    << endl << endl;
        cout << "prime1          (p)    = " << BN_bn2hex(sslKey_p)    << endl << endl;
        cout << "prime2          (q)    = " << BN_bn2hex(sslKey_q)    << endl << endl;
        cout << "exponent1       (dP)   = " << BN_bn2hex(sslKey_dmp1) << endl << endl;
        cout << "exponent2       (dQ)   = " << BN_bn2hex(sslKey_dmq1) << endl << endl;
        cout << "coefficient     (qInv) = " << BN_bn2hex(sslKey_iqmp) << endl << endl;
        cout << "default flags: " << hex << RSA_flags     (sslKey)     << endl;
        cout << "current flags: " << hex << RSA_test_flags(sslKey, ~0) << endl << endl;
        cout << dec;

        bool const blindOff = RSA_test_flags(sslKey, RSA_FLAG_NO_BLINDING);
        cout << "RSA Padding  Off: " << pkcs_nopadd << endl;
        cout << "RSA Blinding Off: " << blindOff    << endl;


        if ( queue_mode ) {
          cout << "### Montgomery modular exponentiation queue test ###" << endl;
          size_t MAX_REQ_COUNT = KernelNS::get_max_req_count();

          RSAMessage msg[MAX_REQ_COUNT];
  
          for(int k = 0; k < MAX_REQ_COUNT; k++)
            msg[k].from_hex_string(inp_msg.c_str ());
          
          // RSAMessage enc_msg = RSAEP_ref(msg[0], key);
          // RSAMessage dec_msg = RSADP_ref(enc_msg, key);
  
          // if ( dec_msg != msg[0] ) 
          // {
          //     cout << "### Results are incorrect" << endl;
  
          //     cout << " Source msg: " << (msg[0]).to_hex_string() << endl;
          //     cout << "Encoded msg: " << enc_msg.to_hex_string() << endl;
          //     cout << "Decoded msg: " << dec_msg.to_hex_string() << endl;
          //     return 1;
          // }
          // cout << "Results are correct" << endl;
  
          cout << "\n\nTest Multirquest (" << MAX_REQ_COUNT << ")\n\n" << endl;
  
          RSAMessage enc_msg_arr[MAX_REQ_COUNT];
          RSAMessage dec_msg_arr[MAX_REQ_COUNT];
  
          int enc_id[MAX_REQ_COUNT];
          int dec_id[MAX_REQ_COUNT];
  
          for(int i =  0; i < MAX_REQ_COUNT; i++)
            {
              msg[i][0] = msg[i][1] = i;
            }
  
            {
              for(int i = 0; i < MAX_REQ_COUNT; i++)
                {
                  enc_id[i] = RSAEP_ref_queue(msg[i], key, enc_msg_arr[i]);
                }
            }
  
          cout << "\n\nRSAEP complete\n\n" << endl;
  
          for(int i =  0; i < MAX_REQ_COUNT; i++)
            dec_id[i] = RSADP_ref_queue(enc_msg_arr[i], key, dec_msg_arr[i]);
  
          for(int i =  0; i < MAX_REQ_COUNT; i++)
            {
              msg[i][0] = msg[i][1] = i;
  
              if ( dec_msg_arr[i] != msg[i] ) 
                {
                  cout << "### Results are incorrect" << endl;
   
                  cout << " Source msg: " << msg[i].to_hex_string() << endl;
                  cout << "Encoded msg: " << enc_msg_arr[i].to_hex_string() << endl;
                  cout << "Decoded msg: " << dec_msg_arr[i].to_hex_string() << endl;
                  return 1;
              }
            }
          
          cout << "Results are correct" << endl;

        } else if (pkcs_mode && !bench_count) {
           cout << "### RSA PKCS conformance single test ###" << endl;

           {
            cout << endl << "Encrypt/decrypt test" << endl;
            RSAMessage msg(inp_msg.c_str());
            // int padding = pkcs_nopadd ? RSA_NO_PADDING : RSA_PKCS1_OAEP_PADDING;
            int padding = pkcs_nopadd ? RSA_NO_PADDING : RSA_PKCS1_PADDING;
            int msgMaxSize = RSA_size(sslKey) - (padding == RSA_PKCS1_PADDING      ? RSA_PKCS1_PADDING_SIZE:
                                                 padding == RSA_PKCS1_OAEP_PADDING ? 42:0); // requirement for message length by PKCS
            if ( ((msg.get_actual_bit_size()+7)/8) > msgMaxSize ) {
                cout << "Message is trimmed to satisfy PKCS" << endl;
                // normalize msg to fit modulus
                msg.trim_bits(msgMaxSize * 8);
                if ( GMPInt(msg) >= GMPInt(key.modulus) ) {
                    msg.trim_bits(msgMaxSize * 8 - 1);
                }
                assert(GMPInt(msg) < GMPInt(key.modulus));
            }

            cout << "Single public key encryption" << endl;
            srand(time(NULL)); //making further pseudo-random values non-deterministic

            RSAMessage enc_msg;
            int encSize = rsa_pkcs_public_encrypt(msg, enc_msg, key, padding);

            int msgSize = pkcs_nopadd ? RSA_size(sslKey) : (msg.get_actual_bit_size()+7)/8;
            uint8_t* msgBigEnd = new uint8_t[msgMaxSize]{}; //initializing with zeros
            msg.get_bigend_to_bytes(msgBigEnd, msgSize);

            uint8_t* msgBigEndEncRef = new uint8_t[RSA_size(sslKey)];
            int refSize = RSA_public_encrypt(msgSize, msgBigEnd, msgBigEndEncRef, sslKey, padding);
            RSAMessage ref_enc_msg(msgBigEndEncRef, refSize, true);

            if (encSize < 0 || refSize < 0) {
              cout << "Unsuccessful encryption:" << endl;
              cout << " Source msg: " << msg        .to_hex_string() << ", size: " << msgSize << endl;
              cout << "Encoded msg: " << enc_msg    .to_hex_string() << ", size: " << encSize << endl;
              cout << "Ref Enc msg: " << ref_enc_msg.to_hex_string() << ", size: " << refSize << endl;
              return 1;
            }

            RSAMessage mod_exp_msg = reference_public(msg, key);
            if ( pkcs_nopadd ) {
              cout << "Verification of encrypted data (no padding): ";
              if (enc_msg != ref_enc_msg || enc_msg != mod_exp_msg) {
                cout << "encryption mismatch:" << endl;
                cout << " Source msg: " << msg        .to_hex_string() << ", size: " << msgSize << endl;
                cout << "Encoded msg: " << enc_msg    .to_hex_string() << ", size: " << encSize << endl;
                cout << "Ref Enc msg: " << ref_enc_msg.to_hex_string() << ", size: " << refSize << endl;
                cout << "Mod Exp msg: " << mod_exp_msg.to_hex_string() << endl;
                return 1;
              }
              else cout << "OK" << endl;
            }

            cout << "Single private key decryption" << endl;

            RSAMessage dec_msg;
            int decSize = rsa_pkcs_private_decrypt(enc_msg, dec_msg, key, padding, blindOff);

            uint8_t* msgBigEndDecRef = new uint8_t[msgMaxSize];
            refSize = RSA_private_decrypt(refSize, msgBigEndEncRef, msgBigEndDecRef, sslKey, padding);
            RSAMessage ref_dec_msg(msgBigEndDecRef, refSize, true);

            if (decSize < 0 || refSize < 0) {
              cout << "Unsuccessful decryption:" << endl;
              cout << "Encoded msg: " << enc_msg    .to_hex_string() << ", size: " << encSize << endl;
              cout << "Decoded msg: " << dec_msg    .to_hex_string() << ", size: " << decSize << endl;
              cout << "Ref Dec msg: " << ref_dec_msg.to_hex_string() << ", size: " << refSize << endl;
              return 1;
            }

            mod_exp_msg = reference_public(enc_msg, key, false);
            cout << "Verification of decrypted data: ";
            if (dec_msg != ref_dec_msg || dec_msg != msg || (pkcs_nopadd && dec_msg != mod_exp_msg)) {
              cout << "decryption mismatch:" << endl;
              cout << " Source msg: " << msg        .to_hex_string() << ", size: " << msgSize << endl;
              cout << "Encoded msg: " << enc_msg    .to_hex_string() << ", size: " << encSize << endl;
              cout << "Decoded msg: " << dec_msg    .to_hex_string() << ", size: " << decSize << endl;
              cout << "Ref Dec msg: " << ref_dec_msg.to_hex_string() << ", size: " << refSize << endl;
              cout << "Mod Exp msg: " << mod_exp_msg.to_hex_string() << endl;
              return 1;
            }
            else cout << "OK" << endl;

            delete[] msgBigEnd;
            delete[] msgBigEndEncRef;
            delete[] msgBigEndDecRef;
           }

           {
            cout << endl << "Sign/verify test" << endl;
            RSAMessage msg(inp_msg.c_str());
            int padding = pkcs_nopadd ? RSA_NO_PADDING : RSA_PKCS1_PADDING;
            int msgMaxSize = RSA_size(sslKey) - (padding == RSA_PKCS1_PADDING ? RSA_PKCS1_PADDING_SIZE:0); // requirement for message length by PKCS
            if ( ((msg.get_actual_bit_size()+7)/8) > msgMaxSize ) {
                cout << "Message is trimmed to satisfy PKCS" << endl;
                // normalize msg to fit modulus
                msg.trim_bits(msgMaxSize * 8);
                if ( GMPInt(msg) >= GMPInt(key.modulus) ) {
                    msg.trim_bits(msgMaxSize * 8 - 1);
                }
                assert(GMPInt(msg) < GMPInt(key.modulus));
            }

            cout << "Single private key encryption (sign)" << endl;

            RSAMessage enc_msg;
            int encSize = rsa_pkcs_private_encrypt(msg, enc_msg, key, padding, blindOff);

            int msgSize = pkcs_nopadd ? RSA_size(sslKey) : (msg.get_actual_bit_size()+7)/8;
            uint8_t* msgBigEnd = new uint8_t[msgMaxSize]{}; //initializing with zeros
            msg.get_bigend_to_bytes(msgBigEnd, msgSize);

            uint8_t* msgBigEndEncRef = new uint8_t[RSA_size(sslKey)];
            int refSize = RSA_private_encrypt(msgSize, msgBigEnd, msgBigEndEncRef, sslKey, padding);
            RSAMessage ref_enc_msg(msgBigEndEncRef, refSize, true);

            if (encSize < 0 || refSize < 0) {
              cout << "Unsuccessful sign:" << endl;
              cout << " Source msg: " << msg        .to_hex_string() << ", size: " << msgSize << endl;
              cout << "Encoded msg: " << enc_msg    .to_hex_string() << ", size: " << encSize << endl;
              cout << "Ref Enc msg: " << ref_enc_msg.to_hex_string() << ", size: " << refSize << endl;
              return 1;
            }

            RSAMessage mod_exp_msg = reference_public(msg, key, false);
            cout << "Verification of encrypted data: ";
            if (enc_msg != ref_enc_msg || (pkcs_nopadd && enc_msg != mod_exp_msg)) {
              cout << "encryption mismatch:" << endl;
              cout << " Source msg: " << msg        .to_hex_string() << ", size: " << msgSize << endl;
              cout << "Encoded msg: " << enc_msg    .to_hex_string() << ", size: " << encSize << endl;
              cout << "Ref Enc msg: " << ref_enc_msg.to_hex_string() << ", size: " << refSize << endl;
              cout << "Mod Exp msg: " << mod_exp_msg.to_hex_string() << endl;
              return 1;
            }
            else cout << "OK" << endl;

            cout << "Single public key decryption (verify)" << endl;

            RSAMessage dec_msg;
            int decSize = rsa_pkcs_public_decrypt(enc_msg, dec_msg, key, padding);

            uint8_t* msgBigEndDecRef = new uint8_t[msgMaxSize];
            refSize = RSA_public_decrypt(refSize, msgBigEndEncRef, msgBigEndDecRef, sslKey, padding);
            RSAMessage ref_dec_msg(msgBigEndDecRef, refSize, true);

            if (decSize < 0 || refSize < 0) {
              cout << "Unsuccessful decryption:" << endl;
              cout << "Encoded msg: " << enc_msg    .to_hex_string() << ", size: " << encSize << endl;
              cout << "Decoded msg: " << dec_msg    .to_hex_string() << ", size: " << decSize << endl;
              cout << "Ref Dec msg: " << ref_dec_msg.to_hex_string() << ", size: " << refSize << endl;
              return 1;
            }

            mod_exp_msg = reference_public(enc_msg, key);
            cout << "Verification of decrypted data: ";
            if (dec_msg != ref_dec_msg || dec_msg != msg || (pkcs_nopadd && dec_msg != mod_exp_msg)) {
              cout << "decryption mismatch:" << endl;
              cout << " Source msg: " << msg        .to_hex_string() << ", size: " << msgSize << endl;
              cout << "Encoded msg: " << enc_msg    .to_hex_string() << ", size: " << encSize << endl;
              cout << "Decoded msg: " << dec_msg    .to_hex_string() << ", size: " << decSize << endl;
              cout << "Ref Dec msg: " << ref_dec_msg.to_hex_string() << ", size: " << refSize << endl;
              cout << "Mod Exp msg: " << mod_exp_msg.to_hex_string() << endl;
              return 1;
            }
            else cout << "OK" << endl;

            delete[] msgBigEnd;
            delete[] msgBigEndEncRef;
            delete[] msgBigEndDecRef;
           }
        }


        RSAMessage msg(inp_msg.c_str());
        if ( msg.get_actual_bit_size() >= key.modulus.get_actual_bit_size() ) {
            // normalize msg to fit modulus
            msg.trim_bits(key.modulus.get_actual_bit_size());
            if ( GMPInt(msg) >= GMPInt(key.modulus) ) {
                msg.trim_bits(key.modulus.get_actual_bit_size()-1);
            }
            assert(GMPInt(msg) < GMPInt(key.modulus));
            inp_msg = msg.to_hex_string();
        }

        RSAMessage enc_msg;
        if ( !queue_mode && !pkcs_mode && !bench_count && !bench_CPU && !bench_OCL && !bench_clock &&
             !trace_init && !trace_steps ) {
            cout << "### Montgomery modular exponentiation single test ###" << endl;
            cout << "Single public key encryption"<<endl;
            enc_msg = RSAEP_ref(msg, key);
            //cout << "Encoded msg: "<<enc_msg.to_hex_string()<<endl;
            if (0)
            for ( size_t i = 0; i < sizeof(ref_data)/sizeof(ref_data[0]); ++i ) {
                string ref_key_file = ref_data[i][0];
                string ref_inp_msg = ref_data[i][1];
                string ref_enc_msg = ref_data[i][2];
                if ( key_file == ref_key_file && inp_msg == ref_inp_msg ) {
                    if ( enc_msg.to_hex_string() != ref_enc_msg ) {
                        cout << "enc: " << enc_msg << endl;
                        cout << "exp: " << ref_enc_msg << endl;
                        return 1;
                    }
                }
            }
            cout << "Verification of encrypted data: ";
            RSAMessage ref_enc_msg = reference_public(msg, key);
            if ( ref_enc_msg != enc_msg ) {
                cout << "encryption mismatch:" << endl;
                cout << " Source msg: "<<msg.to_hex_string()<<endl;
                cout << "Encoded msg: "<<enc_msg.to_hex_string()<<endl;
                cout << "Ref Enc msg: "<<ref_enc_msg.to_hex_string()<<endl;
                return 1;
            }
            else cout << "OK" << endl;

            cout << "Single private key decryption"<<endl;
            RSAMessage dec_msg = RSADP_ref(enc_msg, key);
            RSAMessage ref_dec_msg = reference_public(enc_msg, key, false);
            cout << "Verification of decrypted data: ";
            if ( dec_msg != msg || dec_msg != ref_dec_msg) {
                cout << "decryption mismatch:" << endl;
                cout << " Source msg: "<<msg.to_hex_string()<<endl;
                cout << "Encoded msg: "<<enc_msg.to_hex_string()<<endl;
                cout << "Decoded msg: "<<dec_msg.to_hex_string()<<endl;
                cout << "Ref Dec msg: "<<ref_dec_msg.to_hex_string()<<endl;
                return 1;
            }
            else cout << "OK" << endl;
        }

        if ( exp_ones ) {
            GMPInt exp = (GMPInt(1)<<exp_ones)-GMPInt(1);
            key.publicExponent = exp;
            key.exponent1 = exp;
            key.exponent2 = exp;
            cout << "Forcing exponent to "<<key.publicExponent<<endl;
        }

        if ( bench_count && bench_public_init ) {
            benchmarking = true;
            const int COUNT = bench_count;
            cout << "Running public init benchmark " << COUNT << endl;
            double t0 = get_time();
            vector<MontgPowParams*> params(COUNT);
            for ( int i = 0; i < COUNT; ++i ) {
                params[i] =
                    rsa_montg_alloc_init_params(num(key.modulus),
                                                num(key.publicExponent),
                                                fast_power);
                assert(params[i]);
            }
            for ( int i = 0; i < COUNT; ++i ) {
                rsa_montg_free_params(params[i]);
            }
            double t1 = get_time();
            cout << "Public key init time: "<<(t1-t0)/COUNT*1e6<<" uS"<<endl;
            benchmarking = false;
        }
        if ( bench_count && bench_private_init ) {
            benchmarking = true;
            const int COUNT = bench_count;
            cout << "Running private init benchmark " << COUNT << endl;
            double t0 = get_time();
            vector<MontgPowParams*> params(COUNT*2);
            for ( int i = 0; i < COUNT; ++i ) {
                params[i*2+0] =
                    rsa_montg_alloc_init_params(num(key.prime1),
                                                num(key.exponent1),
                                                fast_power);
                assert(params[i*2+0]);
                params[i*2+1] =
                    rsa_montg_alloc_init_params(num(key.prime2),
                                                num(key.exponent2),
                                                fast_power);
                assert(params[i*2+1]);
            }
            for ( int i = 0; i < COUNT*2; ++i ) {
                rsa_montg_free_params(params[i]);
            }
            double t1 = get_time();
            cout << "Private key init time: "<<(t1-t0)/COUNT*1e6<<" uS"<<endl;
            benchmarking = false;
        }
        if ( bench_count && bench_private_data_init ) {
            benchmarking = true;
            const int COUNT = bench_count;
            cout << "Running private data init benchmark " << COUNT << endl;
            MontgPowParams* params1 = 
                rsa_montg_alloc_init_params(num(key.prime1),
                                            num(key.exponent1),
                                            fast_power);
            assert(params1);
            MontgPowParams* params2 = 
                rsa_montg_alloc_init_params(num(key.prime2),
                                            num(key.exponent2),
                                            fast_power);
            assert(params2);
            double t0 = get_time();
            vector<rsa_word_t*> input(COUNT*2);
            for ( int i = 0; i < COUNT; ++i ) {
                input[i*2+0] =
                    rsa_montg_alloc_init_private_input(num(msg), num(key.prime1));
                assert(input[i*2+0]);
                input[i*2+1] =
                    rsa_montg_alloc_init_private_input(num(msg), num(key.prime2));
                assert(input[i*2+1]);
            }
            for ( int i = 0; i < COUNT*2; ++i ) {
                rsa_montg_free_input(input[i]);
            }
            double t1 = get_time();
            rsa_montg_free_params(params1);
            rsa_montg_free_params(params2);
            cout << "Private data init time: "<<(t1-t0)/COUNT*1e6<<" uS"<<endl;
            benchmarking = false;
        }
        if ( bench_count && bench_private_data_merge ) {
            benchmarking = true;
            const int COUNT = bench_count;
            cout << "Running private data merge benchmark " << COUNT << endl;
            rsa_word_t* output1 = rsa_montg_alloc_output();
            rsa_word_t* output2 = rsa_montg_alloc_output();
            double t0 = get_time();
            vector<rsa_word_t*> output(COUNT);
            for ( int i = 0; i < COUNT; ++i ) {
                output[i] =
                    rsa_montg_alloc_combine_private_outputs(output1, output2,
                                                            num(key.prime1),
                                                            num(key.prime2),
                                                            num(key.coefficient));
            }
            for ( int i = 0; i < COUNT; ++i ) {
                rsa_montg_free_output(output[i]);
            }
            double t1 = get_time();
            rsa_montg_free_output(output1);
            rsa_montg_free_output(output2);
            cout << "Private data init time: "<<(t1-t0)/COUNT*1e6<<" uS"<<endl;
            benchmarking = false;
            
        }
        if ( bench_count && bench_public && !bench_parallel ) {
            benchmarking = true;
            const int COUNT = bench_count;
            vector<RSAMessage> output(COUNT);
            cout << "Running sequential public encryption benchmark " << COUNT << endl;
            double t0 = get_time();
            for ( int i = 0; i < COUNT; ++i ) {
                output[i] = RSAEP_ref(msg, key);
            }
            double t1 = get_time();
            cout << "Public simple time: "<<(t1-t0)/COUNT*1e6<<" uS"<<endl;
            benchmarking = false;
            cout << "Verification" << endl;
            size_t error_count = 0;
            RSAMessage ref = reference_public(msg, key);
            for ( int i = 0; i < COUNT; ++i ) {
                if ( output[i] != ref ) {
                    cerr << "Failed encoding "<<i<<":\n";
                    cerr << "inp: "<<msg<<'\n';
                    cerr << "enc: "<<output[i]<<'\n';
                    cerr << "exp: "<<ref<<endl;
                    ++error_count;
                }
            }
            if ( error_count ) {
                return 1;
            }
        }
        if ( bench_count && bench_private && !bench_parallel ) {
            benchmarking = true;
            const int COUNT = bench_count;
            vector<RSAMessage> output(COUNT);
            int padding = pkcs_nopadd ? RSA_NO_PADDING : RSA_PKCS1_PADDING;
            cout << "Running sequential private encryption benchmark " << COUNT << endl;
            double t0 = get_time();
            if (!pkcs_mode)
              for ( int i = 0; i < COUNT; ++i )
                output[i] = RSADP_ref(msg, key);
            else
              for ( int i = 0; i < COUNT; ++i )
                rsa_pkcs_private_encrypt(msg, output[i], key, padding, blindOff);
            double t1 = get_time();
            cout << "Private fast time: "<<(t1-t0)/COUNT*1e6<<" uS"<<endl;
            benchmarking = false;
            if ( exp_ones ) {
                cout << "Skipping verification due to modified key" << endl;
            }
            else {
                cout << "Verification" << endl;
                size_t error_count = 0;
                for ( int i = 0; i < COUNT; ++i ) {
                    if (!pkcs_mode) {
                      RSAMessage dec = reference_public(output[i], key);
                      if ( dec != msg ) {
                          cerr << "Failed decoding "<<i<<":\n";
                          cerr << "inp: "<<msg<<'\n';
                          cerr << "enc: "<<output[i]<<'\n';
                          cerr << "dec: "<<dec<<endl;
                          ++error_count;
                      }
                    }
                    else {
                      int msgSize = pkcs_nopadd ? RSA_size(sslKey) : (msg.get_actual_bit_size()+7)/8;
                      uint8_t* msgBigEnd = new uint8_t[msgSize];
                      msg.get_bigend_to_bytes(msgBigEnd, msgSize);
                      uint8_t* msgBigEndEncRef = new uint8_t[RSA_size(sslKey)];
                      int refSize = RSA_private_encrypt(msgSize, msgBigEnd, msgBigEndEncRef, sslKey, padding);
                      RSAMessage ref_enc_msg(msgBigEndEncRef, refSize, true);
                      delete[] msgBigEnd;
                      delete[] msgBigEndEncRef;
                      if ( ref_enc_msg != output[i] ) {
                          cerr << "Failed encoding "<<i<<":\n";
                          cerr << "inp: "<<msg<<'\n';
                          cerr << "enc: "<<output[i]<<'\n';
                          cerr << "ref_enc: "<<ref_enc_msg<<endl;
                          ++error_count;
                      }
                    }
                }
                if ( error_count ) {
                    return 1;
                }
            }
        }
        if ( bench_count && bench_public && bench_parallel ) {
            benchmarking = true;
            skip_opencl_call = bench_CPU;
            const int COUNT = bench_count;
            cout << "Running parallel public encryption benchmark " << COUNT << endl;
            vector<const RSAPrivateKey*> keys(COUNT);
            vector<RSAMessage> inp_msgs(COUNT);
            vector<RSAMessage> enc_msgs(COUNT);
            vector<RSAMessage> dec_msgs(COUNT);
            for ( int i = 0; i < COUNT; ++i ) {
                keys[i] = &key;
                inp_msgs[i] = get_msg(msg, i, *keys[i]);
            }
            double t0 = get_time();
            {
                TIMER_N("bench_public", COUNT);
                if ( low_level ) {
                    if ( low_level2 )
                        LowLevel::decrypt2(keys, inp_msgs, enc_msgs);
                    else
                        LowLevel::decrypt(keys, inp_msgs, enc_msgs);
                }
                else {
                    vector<MontgPowParams*> params(COUNT);
                    vector<rsa_word_t*> input(COUNT);
                    vector<rsa_word_t*> output(COUNT);
                    for ( int i = 0; i < COUNT; ++i ) {
                        const RSAPrivateKey& key = *keys[i];
                        const RSAMessage& data = inp_msgs[i];
                        params[i] =
                            rsa_montg_alloc_init_params(num(key.modulus), num(key.publicExponent), fast_power);
                        assert(params[i]);
                        input[i] =
                            rsa_montg_alloc_init_public_input(num(data), num(key.modulus));
                        assert(input[i]);
                        output[i] = rsa_montg_alloc_output();
                    }
                    rsa_montg_pow_N(COUNT, params.data(), input.data(), output.data());
                    for ( int i = 0; i < COUNT; ++i ) {
                        const RSAPrivateKey& key = *keys[i];
                        enc_msgs[i] = from_output(output[i], key.modulus);
                        rsa_montg_free_params(params[i]);
                        rsa_montg_free_input(input[i]);
                        rsa_montg_free_output(output[i]);
                    }
                }
            }
            double t1 = get_time();
            cout << "Public parallel time: "<<(t1-t0)/COUNT*1e6<<" uS"<<endl;
            benchmarking = false;
            skip_opencl_call = false;
            cout << "Verification" << endl;
            size_t error_count = 0;
            for ( int i = 0; i < COUNT; ++i ) {
                RSAMessage ref = reference_public(inp_msgs[i], *keys[i]);
                if ( ref != enc_msgs[i] ) {
                    cerr << "Failed encoding "<<i<<":\n";
                    cerr << "inp: "<<inp_msgs[i]<<'\n';
                    cerr << "enc: "<<enc_msgs[i]<<'\n';
                    cerr << "ref: "<<ref<<endl;
                    ++error_count;
                }
            }
            if ( error_count ) {
                return 1;
            }
        }
        if ( bench_count && bench_private && bench_parallel ) {
            benchmarking = true;
            skip_opencl_call = bench_CPU;
            int COUNT = bench_count;
            cout << "Running parallel private encryption benchmark " << COUNT << endl;
            vector<const RSAPrivateKey*> keys(COUNT);
            vector<RSAMessage> inp_msgs(COUNT);
            vector<RSAMessage> enc_msgs(COUNT);
            for ( int i = 0; i < COUNT; ++i ) {
                keys[i] = &key;
                inp_msgs[i] = get_msg(msg, i, *keys[i]);
            }
            double t0 = get_time();
            {
                TIMER_N("bench_private", COUNT);
                if ( low_level ) {
                    if ( low_level2 )
                        LowLevel::encrypt2(keys, inp_msgs, enc_msgs);
                    else
                        LowLevel::encrypt(keys, inp_msgs, enc_msgs);
                }
                else {
                    vector<MontgPowParams*> params(COUNT*2);
                    vector<rsa_word_t*> input(COUNT*2);
                    vector<rsa_word_t*> output(COUNT*2);
                    for ( int i = 0; i < COUNT; ++i ) {
                        const RSAPrivateKey& key = *keys[i];
                        const RSAMessage& data = inp_msgs[i];
                        params[i*2+0] =
                            rsa_montg_alloc_init_params(num(key.prime1), num(key.exponent1), fast_power);
                        assert(params[i*2+0]);
                        params[i*2+1] =
                            rsa_montg_alloc_init_params(num(key.prime2), num(key.exponent2), fast_power);
                        assert(params[i*2+1]);
                        input[i*2+0] =
                            rsa_montg_alloc_init_private_input(num(data), num(key.prime1));
                        assert(input[i*2+0]);
                        input[i*2+1] =
                            rsa_montg_alloc_init_private_input(num(data), num(key.prime2));
                        assert(input[i*2+1]);
                        output[i*2+0] = rsa_montg_alloc_output();
                        output[i*2+1] = rsa_montg_alloc_output();
                    }
                    rsa_montg_pow_N(COUNT*2, params.data(), input.data(), output.data());
                    for ( int i = 0; i < COUNT*2; ++i ) {
                        rsa_montg_free_params(params[i]);
                        rsa_montg_free_input(input[i]);
                    }
                    params.clear();
                    input.clear();
                
                    // post-processing
                    for ( int i = 0; i < COUNT; ++i ) {
                        rsa_montg_combine_private_outputs(enc_msgs[i].words,
                                                          output[i*2+0], output[i*2+1],
                                                          num(key.prime1),
                                                          num(key.prime2),
                                                          num(key.coefficient));
                    }
                    for ( int i = 0; i < 2*COUNT; ++i ) {
                        rsa_montg_free_output(output[i]);
                    }
                    output.clear();
                }
            }
            double t1 = get_time();
            cout << "Private parallel time: "<<(t1-t0)/COUNT*1e6<<" uS"<<endl;
            
            if ( exp_ones ) {
                cout << "Skipping verification due to modified key" << endl;
            }
            else if ( bench_clock ) {
                cout << "Skipping verification due to benchmarking" << endl;
            }
            else {
                // verification
                cout << "Verifying "<<COUNT<<" results..."<<endl;
                size_t error_count = 0;
#if 1
                for ( int i = 0; i < COUNT; ++i ) {
                    RSAMessage dec = reference_public(enc_msgs[i], *keys[i]);
                    if ( dec != inp_msgs[i] ) {
                        cerr << "Failed encoding "<<i<<":\n";
                        cerr << "inp: "<<inp_msgs[i]<<'\n';
                        cerr << "enc: "<<enc_msgs[i]<<'\n';
                        cerr << "dec: "<<dec<<endl;
                        ++error_count;
                    }
                }
#else
                vector<MontgPowParams*> params(COUNT);
                vector<rsa_word_t*> input(COUNT);
                vector<rsa_word_t*> output(COUNT);
                for ( int i = 0; i < COUNT; ++i ) {
                    const RSAPrivateKey& key = *keys[i];
                    const RSAMessage& data = enc_msgs[i];
                    params[i] =
                        rsa_montg_alloc_init_params(num(key.modulus), num(key.publicExponent), fast_power);
                    assert(params[i]);
                    input[i] =
                        rsa_montg_alloc_init_public_input(num(data), num(key.modulus));
                    assert(input[i]);
                    output[i] = rsa_montg_alloc_output();
                }
                rsa_montg_pow_N(COUNT, params.data(), input.data(), output.data());
                for ( int i = 0; i < COUNT; ++i ) {
                    rsa_montg_free_params(params[i]);
                    rsa_montg_free_input(input[i]);
                    // check
                    if ( !skip_opencl_call && kernel_call_count > 0 ) {
                        const RSAPrivateKey& key = *keys[i];
                        const RSAMessage& exp = inp_msgs[i];
                        RSAMessage dec = from_output(output[i], key.modulus);
                        if ( exp != dec ) {
                            cerr << "Failed encoding "<<i<<":\n";
                            cerr << "inp: "<<inp_msgs[i]<<'\n';
                            cerr << "enc: "<<enc_msgs[i]<<'\n';
                            cerr << "dec: "<<dec<<endl;
                            ++error_count;
                        }
                    }
                    rsa_montg_free_output(output[i]);
                }
#endif
                if ( error_count ) {
                    return 1;
                }
            }
            benchmarking = false;
            skip_opencl_call = false;
        }

        RSA_free(sslKey);
    }
    catch (exception& exc) {
        cerr << "Exception: "<<exc.what()<<endl;
        return 1;
    }
    opencl_cleanup();
}

void __assert_fail(const char *expr, const char *file, unsigned int line, const char* func)
{
    cout.flush();
    fflush(0);
    fprintf(stderr, "%s:%d: %s: assertion failed: %s\n", file, line, func, expr);
    abort();
}
extern "C" void __assert_func(const char *file, int line, const char* func, const char *expr)
{
    cout.flush();
    fflush(0);
    fprintf(stderr, "%s:%d: %s: assertion failed: %s\n", file, line, func, expr);
    abort();
}
