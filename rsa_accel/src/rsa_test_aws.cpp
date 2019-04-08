#include <stddef.h>
#include "rsa_seq_impl.h"
#include "rsa.h"
#include "rsa_gmp.h"
#include <iostream>
#include <sys/time.h>
#include <cassert>

static const size_t DEFAULT_RSA_BITS = 2048;
static const size_t DEFAULT_UNIT_COUNT = 400;
static const size_t DEFAULT_KERNEL_ARG_WORDS = 1+4*MAX_RSA_WORDS;
static const size_t DEFAULT_KERNEL_RESULT_WORDS = MAX_RSA_WORDS;

#define UNIT_COUNT DEFAULT_UNIT_COUNT
#define KERNEL_ARG_WORDS DEFAULT_KERNEL_ARG_WORDS
#define KERNEL_RESULT_WORDS DEFAULT_KERNEL_RESULT_WORDS

using namespace std;

void opencl_cleanup();
void opencl_init(const char* ps_dev_name, const char* ps_kernel_fname);


double get_time()
{
  timeval tv;
  
  gettimeofday(&tv, 0);
  
  return tv.tv_sec+tv.tv_usec*1e-6;
}

inline RSAMessage ref_powmod_simple_sec(const RSAMessage& msg, const RSAFullInt& exponent, const RSAModulus& modulus)
{
  return powm_sec((msg), exponent, modulus);
}

inline int ref_powmod_simple_sec_queue(const RSAMessage& msg_inp, const RSAFullInt& exponent, const RSAModulus& modulus, RSAMessage& msg_out)
{
  return powm_sec_queue((msg_inp), exponent, modulus, msg_out);
}




inline RSAMessage ref_powmod_simple(const RSAMessage& msg, const RSAFullInt& exponent, const RSAModulus& modulus)
{
  return powm((msg), exponent, modulus);
}

inline int ref_powmod_simple_queue(const RSAMessage& msg_inp, const RSAFullInt& exponent, const RSAModulus& modulus, RSAMessage& msg_out)
{
  return powm_queue(msg_inp, exponent, modulus, msg_out);
}




RSAMessage ref_powmod_complex_sec(const RSAMessage& msg, const RSAPrivateKey& key)
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
    
    if ( 0 ) {
        cout << c2 << endl;
        cout << key.exponent2 << endl;
        cout << key.prime2 << endl;
        cout << m2 << endl;
    }
    GMPInt ret = m2 + mulm(subm2(m1, m2, key.prime1), key.coefficient, key.prime1)*key.prime2;
    return ret;
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

inline RSAMessage RSAEP_ref(const RSAMessage& msg, const RSAPublicKey& key)
{
    return ref_powmod_simple(msg, key.publicExponent, key.modulus);
}

inline int RSAEP_ref_queue(const RSAMessage& msg, const RSAPublicKey& key, RSAMessage& msg_out)
{
    return ref_powmod_simple_queue(msg, key.publicExponent, key.modulus, msg_out);
}






inline RSAMessage RSAEP_ref(const RSAMessage& msg, const RSAPrivateKey& key)
{
    return ref_powmod_simple(msg, key.publicExponent, key.modulus);
}

inline int RSAEP_ref_queue(const RSAMessage& msg_inp, const RSAPrivateKey& key, RSAMessage& msg_out)
{
  cout << key.publicExponent << endl;
  cout << key.modulus        << endl;
  
  
    return ref_powmod_simple_queue(msg_inp, key.publicExponent, key.modulus, msg_out);
}




inline RSAMessage RSADP_ref(const RSAMessage& msg, const RSAPrivateKey& key, bool as_public = false)
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
        msg_out = ref_powmod_complex_sec(msg_inp, key);
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




int main(int argc, char *argv[])
{
    printf("Start\n");
    cout << "Start_1"  << endl;
    
    bool hw_emulation = false;
    bool sw_emulation = false;
    bool hw_aws_exec  = false;
    
    if ( const char* env = getenv("XCL_EMULATION_MODE") ) 
      {
        hw_emulation = strcasecmp(env, "hw_emu") == 0;
        sw_emulation = strcasecmp(env, "sw_emu") == 0;
        hw_aws_exec  = strcasecmp(env, "hw_aws") == 0;
      }

    std::string const plPath = getenv("AWS_PLATFORM");
    std::size_t const plFirstChar = plPath.rfind("/")+1;
    std::size_t const plLastChar  = plPath.rfind(".xpfm");
    std::string const plName = plPath.substr(plFirstChar, plLastChar - plFirstChar);

    std::string kernel_file;
    if ( hw_emulation ) 
      {
        kernel_file = "./xclbin/rsa_hls_krnl.hw_emu." + plName + ".xclbin";
      }
    else if ( sw_emulation ) 
      {
        kernel_file = "./xclbin/rsa_hls_krnl.sw_emu." + plName + ".xclbin";
      }
    else if ( hw_aws_exec )
      {
        kernel_file = "./rsa_hls_krnl.hw." + plName + ".awsxclbin";
      }
    else
      {
        kernel_file = "./xclbin/rsa_hls_krnl.hw." + plName + ".xclbin";
      }

    opencl_init(plName.c_str(), kernel_file.c_str());

    try 
      {
        #if ( MAX_RSA_BITS == 2048 )
            string key_file_name = "../../data/test_key4.private";
            string inp_msg = "4320323092034713910341084108410861286401892640189264018296481264180640182abcdef64018926312312312311234320323092034713910341084108410861286401892640189264018296481264180640182abcdef64018926312312312311234320323092034713910341084108410861286401892640189264018296481264180640182abcdef64018926312312312311234320323092034713910341084108410861286401892640189264018296481264180640182abcdef6401892631231231231000000000000000000000000000000000000000000000000000000000000";
        #elif ( MAX_RSA_BITS == 1024 )
            string key_file_name = "../../data/test_key_rsa1024.private";
            string inp_msg = "123304958302985abf4444444444444444444444ffffffffffffffffff2234203947834ec000000000000fffffffffffff00000000000000000000000000000000000000000";
        #elif ( MAX_RSA_BITS == 512 )
            string key_file_name = "../../data/test_key_rsa512.private";
            string inp_msg = "123304958302985abfffffffffffffffffff2234203947834ec000000000000fffffffffffff000000000000";
        #elif ( MAX_RSA_BITS == 256 )
            string key_file_name = "../../data/test_key_rsa256.private";
            string inp_msg = "123304958302985ab4203947834ecfffffffffffff000000000000";
        #else
            #error "WRONG MAX_RSA_BITS value"
        #endif
        RSAPrivateKey key(key_file_name, RSAKeyParser::base64);
        
        cout << "key.exponent1       = " << key.exponent1 << endl << endl;
        cout << "key.exponent2       = " << key.exponent2 << endl << endl;
        cout << "key.modulus         = " << key.modulus   << endl << endl;
        cout << "key.prime1          = " << key.prime1    << endl << endl;
        cout << "key.prime2          = " << key.prime2    << endl << endl;
        cout << "key.privateExponent = " << key.privateExponent << endl << endl;
        cout << "key.publicExponent  = " << key.publicExponent  << endl << endl;

        RSAMessage msg[UNIT_COUNT];

        for(int k = 0; k < UNIT_COUNT; k++)
          msg[k].from_hex_string(inp_msg.c_str ());


        
//        RSAMessage enc_msg = RSAEP_ref(msg[0], key);
//        RSAMessage dec_msg = RSADP_ref(enc_msg, key);

//        if ( dec_msg != msg[0] ) 
//          {
//            cout << "### Results are incorrect" << endl;
//
//            cout << " Source msg: " << (msg[0]).to_hex_string() << endl;
//            cout << "Encoded msg: " << enc_msg.to_hex_string() << endl;
//            cout << "Decoded msg: " << dec_msg.to_hex_string() << endl;
//            return 1;
//        }

//        cout << "Results are correct" << endl;

        cout << "\n\nTest Multirquest (" << UNIT_COUNT << ")\n\n" << endl;

        RSAMessage enc_msg_arr[UNIT_COUNT];
        RSAMessage dec_msg_arr[UNIT_COUNT];

        int enc_id[UNIT_COUNT];
        int dec_id[UNIT_COUNT];

        for(int i =  0; i < UNIT_COUNT; i++)
          {
            msg[i][0] = msg[i][1] = i;
          }

//#        for(int k = 0; k < 28*100000/UNIT_COUNT; k++)
          {
            for(int i = 0; i < UNIT_COUNT; i++)
              {
                enc_id[i] = RSAEP_ref_queue(msg[i], key, enc_msg_arr[i]);
              }
          }

        cout << "\n\nRSAEP complete\n\n" << endl;

//         while( 1 )
//           {
//             for(int i =  0; i < UNIT_COUNT; i++)
//               ;
//           }


        for(int i =  0; i < UNIT_COUNT; i++)
          dec_id[i] = RSADP_ref_queue(enc_msg_arr[i], key, dec_msg_arr[i]);

//         while( 1 )
//           {
//             for(int i =  0; i < UNIT_COUNT; i++)
//               ;
//           }

        for(int i =  0; i < UNIT_COUNT; i++)
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
        
//        if ( dec_msg != msg ) 
//          {
//            cout << "### Results are incorrect" << endl;
//
//            cout << " Source msg: " << msg.to_hex_string() << endl;
//            cout << "Encoded msg: " << enc_msg.to_hex_string() << endl;
//            cout << "Decoded msg: " << dec_msg.to_hex_string() << endl;
//            return 1;
//        }

        cout << "Results are correct" << endl;
    }
    catch (exception& exc) 
      {
        cerr << "Exception: " << exc.what() << endl;
        return 1;
    }

    opencl_cleanup();
}

void __assert_fail(const char *expr, const char *file, int line, const char* func)
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
