#include "rsa_gmp.h"
#include <cassert>
#include <pthread.h>

//#define TRACE 1
//#define COLLECT_SIZES

# include "rsa_pow_3.h"
# define Montgomery HLSMontgomery

using namespace std;

#ifndef UNIT_COUNT
# define UNIT_COUNT 400
#endif

RSAIntBase::word_t* dst_arr  [UNIT_COUNT];
size_t              bsz_arr  [UNIT_COUNT];
RSAIntBase::word_t* base_arr [UNIT_COUNT];
RSAIntBase::word_t* exp_arr  [UNIT_COUNT];
RSAIntBase::word_t* mod_arr  [UNIT_COUNT];
int                 stat_arr [UNIT_COUNT];
PowerMode           pmode_arr[UNIT_COUNT];

int rqst_idx = 0;
int resp_qnt = 0;



void base_mulm(RSAIntBase::word_t* dst,
               size_t bit_size,
               const RSAIntBase::word_t* a,
               const RSAIntBase::word_t* b,
               const RSAIntBase::word_t* mod)
{
    size_t word_size = (bit_size-1)/RSAIntBase::WORD_BITS+1;
    mulm(GMPInt(a, word_size), GMPInt(b, word_size), GMPInt(mod, word_size)).get_to_words(dst, word_size);
}

inline
RSAIntBase::word_t get_bit(const RSAIntBase::word_t* exp, size_t b)
{
    return exp[b/RSAIntBase::WORD_BITS] & (RSAIntBase::word_t(1)<<(b%RSAIntBase::WORD_BITS));
}

void base_powm(RSAIntBase::word_t* dst,
               size_t bit_size,
               const RSAIntBase::word_t* base,
               const RSAIntBase::word_t* exp,
               const RSAIntBase::word_t* mod)
{
    Montgomery::pow(dst, bit_size, base, exp, mod);
    /*
    Montgomery montg(mod, bit_size);
    montg.to_result(dst, montg.pow(montg.from_arg(base), montg.from_exp(exp)));
    */
}




pthread_mutex_t FPGA_Lock; 
pthread_mutex_t FPGA_Queue_Lock; 


void FPGA_Init(void)
{
  if(pthread_mutex_init(&FPGA_Lock, NULL) != 0) 
     { 
         printf("\n Mutex FPGA_Lock init has failed\n"); 
         exit(0); 
     }   

  if(pthread_mutex_init(&FPGA_Queue_Lock, NULL) != 0) 
     { 
         printf("\n Mutex FPGA_Lock init has failed\n"); 
         exit(0); 
     }   
}

void FPGA_Finish(void)
{
  pthread_mutex_destroy( &FPGA_Lock );
  
  pthread_mutex_destroy( &FPGA_Queue_Lock );
}


int base_powm_queue(RSAIntBase::word_t* dst, size_t bit_size, const RSAIntBase::word_t* base, const RSAIntBase::word_t* exp, const RSAIntBase::word_t* mod)
{
  pthread_mutex_lock(&FPGA_Queue_Lock);
  //{
      int cur_rqst = rqst_idx;
      
      if(cur_rqst == -1)
        {
          pthread_mutex_unlock(&FPGA_Queue_Lock);
          return( cur_rqst );
        }

      if(rqst_idx < UNIT_COUNT)
        {
          dst_arr [rqst_idx] = dst;
          bsz_arr [rqst_idx] = bit_size;

          base_arr[rqst_idx] = (RSAIntBase::word_t*) base;
          exp_arr [rqst_idx] = (RSAIntBase::word_t*) exp;
          mod_arr [rqst_idx] = (RSAIntBase::word_t*) mod;

          stat_arr[rqst_idx] = 0;
          
          pmode_arr[rqst_idx] = fast_power;

          rqst_idx++;
        }

      if(rqst_idx < UNIT_COUNT)
        {
          pthread_mutex_unlock(&FPGA_Queue_Lock);
          return( cur_rqst );
        }

      pthread_mutex_lock(&FPGA_Lock);
      //{
          Montgomery::pow_multi(UNIT_COUNT, dst_arr, bsz_arr, (const RSAIntBase::word_t**)base_arr, (const RSAIntBase::word_t**)exp_arr, (const RSAIntBase::word_t**)mod_arr, pmode_arr);
      //}
      pthread_mutex_unlock(&FPGA_Lock);
      
      for(int i = 0; i < UNIT_COUNT; i++)
        stat_arr[i] = 1;
        
      resp_qnt = 0;

      rqst_idx = -1;
  //}
  pthread_mutex_unlock(&FPGA_Queue_Lock);
  
  return( cur_rqst );
}


int Get_Rqst_Stat(int rqst_id)
{
  if( rqst_id < 0 || rqst_id >= UNIT_COUNT )
    return( -1 );
  
  pthread_mutex_lock(&FPGA_Queue_Lock);
  //{
      int stat = stat_arr[rqst_id];
      
      if( stat == 1 )
        {
          stat_arr[rqst_id] = -1;
          resp_qnt++;
        }
      
      if(resp_qnt == UNIT_COUNT)
        {
          rqst_idx = 0;
        }
  //}
  pthread_mutex_unlock(&FPGA_Queue_Lock);
  
  return( stat );
}


void base_powm_sec(RSAIntBase::word_t* dst, size_t bit_size, const RSAIntBase::word_t* base, const RSAIntBase::word_t* exp, const RSAIntBase::word_t* mod) 
{
    Montgomery::pow_sec(dst, bit_size, base, exp, mod);
}

int base_powm_sec_queue(RSAIntBase::word_t* dst, size_t bit_size, const RSAIntBase::word_t* base, const RSAIntBase::word_t* exp, const RSAIntBase::word_t* mod) 
{
  int cur_rqst = rqst_idx;

  if(rqst_idx < UNIT_COUNT)
    {
      dst_arr [rqst_idx] = dst;
      bsz_arr [rqst_idx] = bit_size;

      base_arr[rqst_idx] = (RSAIntBase::word_t*) base;
      exp_arr [rqst_idx] = (RSAIntBase::word_t*) exp;
      mod_arr [rqst_idx] = (RSAIntBase::word_t*) mod;

      stat_arr[rqst_idx] = 0;
      
      pmode_arr[rqst_idx] = secure_power;

      rqst_idx++;
    }

  if(rqst_idx < UNIT_COUNT)
    return( cur_rqst );

    Montgomery::pow_multi(UNIT_COUNT, dst_arr, bsz_arr, (const RSAIntBase::word_t**)base_arr, (const RSAIntBase::word_t**)exp_arr, (const RSAIntBase::word_t**)mod_arr, pmode_arr);

  rqst_idx = 0;

  return( cur_rqst );
}


void base_powm_pair(RSAIntBase::word_t* dst[2],
                    const size_t bit_size[2],
                    const RSAIntBase::word_t* base[2],
                    const RSAIntBase::word_t* exp[2],
                    const RSAIntBase::word_t* mod[2])
{
    Montgomery::pow_pair(dst, bit_size, base, exp, mod);
}

void base_powm_sec_pair(RSAIntBase::word_t* dst[2],
                        const size_t bit_size[2],
                        const RSAIntBase::word_t* base[2],
                        const RSAIntBase::word_t* exp[2],
                        const RSAIntBase::word_t* mod[2])
{
    Montgomery::pow_sec_pair(dst, bit_size, base, exp, mod);
}
