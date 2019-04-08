#include <time.h>
#include <iostream>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/crypto/rsa/rsa_locl.h>
#include <openssl/rsa.h>
#include <openssl/async.h>
#include <openssl/engine.h>

#include "RSA_Sign_Demo.h"

//====================================================================================================//

pthread_barrier_t Barrier;

//====================================================================================================//
//==
//==
//==
//====================================================================================================//

int main(int argc, char** argv)
{
  ENGINE *e = NULL;

  OpenSSL_add_all_algorithms();

  if( argc != 2 || (strcmp(argv[1], "-hw") && strcmp(argv[1], "-sw")) )
    {
      printf("RSA_Sign_Demo -sw|hw\n\n  -sw : use original OpenSSL SW methods for sign\n  -hw : use FPGA accelerator for sign\n");
      return( 1 );
    }

  bool use_engine = strcmp(argv[1], "-hw") == 0;

  if( use_engine )
    {
      ENGINE_load_builtin_engines();

      //---------------------------------------------------------------------------
      //-- Get special OpenSSL engine to dynamically load custom engines
      //---------------------------------------------------------------------------

      e = ENGINE_by_id("dynamic");                            

      if( ! e )
        {
          printf("Error: OpenSSL Engine initialization failed\n");
          return( 2 );
        }

      //---------------------------------------------------------------------------
      //-- Load Zotech's RSA Engine from shared library
      //---------------------------------------------------------------------------

      const char *engine_path = "../../rsa_engine/build/ZoTech_AWS_RSA_Engine.so";

      int r;

      r  = ENGINE_ctrl_cmd_string(e, "SO_PATH", engine_path            , 0);
      r &= ENGINE_ctrl_cmd_string(e, "ID"     , "zotech_aws_rsa_kernel", 0);
      r &= ENGINE_ctrl_cmd_string(e, "LOAD"   , NULL                   , 0);

      if( ! r )
        {
          ENGINE_free(e);

          printf("Error: Zotech's RSA engine loading failed\n");
          return( 3 );
        }

      if( ! ENGINE_init(e) )
        {
          ENGINE_free(e);

          printf("Error: Zotech's RSA engine initialization failed\n");
          return( 4 );
        }  


      if( ! ENGINE_set_default_RSA(e) )
        {
          ENGINE_finish(e);
          ENGINE_free  (e);

          printf("Error: Zotech's RSA engine is not set as default RSA engine\n");
          return( 5 );
        }
    }

  // Quantity of: treads, jobs, cycles
  Run_Sign(         6   , 200 ,  250  );

  if( use_engine )
    {
      double p;

      printf("\nEngine statistic:\n\n");

      if( ENGINE_ctrl(e, ZTE_CMD_TOTAL_MULT_QNT, sizeof(double), &p, NULL) )  printf("Total multiplication performed      : %d\n"       ,  (int)p       );
      if( ENGINE_ctrl(e, ZTE_CMD_TOTAL_TIME    , sizeof(double), &p, NULL) )  printf("Total time spent by FPGA            : %3.2f sec\n",       p       );
      if( ENGINE_ctrl(e, ZTE_CMD_AVERAGE_TIME  , sizeof(double), &p, NULL) )  printf("Average time per one multiplication : %3.2f us\n" ,       p       );
      if( ENGINE_ctrl(e, ZTE_CMD_AVERAGE_LOAD  , sizeof(double), &p, NULL) )  printf("Average FPGA load                   : %3.1f %%\n" ,       p*100.0 );

      ENGINE_finish(e);
      ENGINE_free  (e);
    }

  timespec tm_s, tm_e;

  clock_gettime(CLOCK_REALTIME, &tm_s);
  clock_gettime(CLOCK_REALTIME, &tm_e);

  printf("\nTime resolution : %g us\n\n\n", ( (double)(tm_e.tv_sec - tm_s.tv_sec) + (double)(tm_e.tv_nsec - tm_s.tv_nsec)/1000000000.0 )*1000000.0 );

  return 0;
}

//====================================================================================================//
//==
//==
//==
//====================================================================================================//

void Run_Sign( int thread_qnt, int job_qnt, int cycle_qnt )
{
  bool all_th_ok = true;


  printf("\n\n-------------- RSA Sign --------------\n\n");

  //---------------------------------------------------------------------------
  //-- Check parameters
  //---------------------------------------------------------------------------

  if( thread_qnt < 1 || job_qnt < 1 || cycle_qnt < 1)
    {
      printf("Nothing to do\n");
      return;
    }

  //---------------------------------------------------------------------------
  //-- Allocate memory
  //---------------------------------------------------------------------------

  BIGNUM *bn  = BN_new();
  RSA    *key = RSA_new();

  pthread_attr_t *th_attr = new pthread_attr_t[ thread_qnt ];
  pthread_t      *th_id   = new pthread_t     [ thread_qnt ];
  void *         *th_ret  = new void *        [ thread_qnt ];
  bool           *th_ok   = new bool          [ thread_qnt ];
  thread_arg     *th_arg  = new thread_arg    [ thread_qnt ];

  if( ! key || ! bn )
    {
      printf("Error: memory allocation for key failed\n");

      goto ret;
    }

  if( ! th_attr || ! th_id || ! th_ret || ! th_ok || ! th_arg)
    {
      printf("Error: Insufficient amount of memory for threads\n");

      goto ret;
    }

  //---------------------------------------------------------------------------
  //-- Generate RSA private key
  //---------------------------------------------------------------------------


  if( BN_set_word(bn, RSA_F4) != 1 || RSA_generate_key_ex(key, 2048, bn, NULL) != 1)
    {
      printf("Error: Key generation failed\n");
      goto ret;
    }

  //---------------------------------------------------------------------------
  //-- Initialize barrier to synchronize beginning of useful work
  //---------------------------------------------------------------------------

  if( pthread_barrier_init(&Barrier, NULL, thread_qnt+1) != 0 )
    {
      printf("Error: Barrier initialization failed\n");

      goto ret;
    }

  //---------------------------------------------------------------------------
  //-- Launch treads
  //---------------------------------------------------------------------------

  for(int i = 0; i < thread_qnt; i++)
    {
      th_ok[i] = true;

      th_arg[i].id        = i;
      th_arg[i].job_qnt   = job_qnt;
      th_arg[i].cycle_qnt = cycle_qnt;
      th_arg[i].key       = RSAPrivateKey_dup(key);

      if( pthread_attr_init(&th_attr[i]) != 0 || th_arg[i].key == NULL ) 
        { 
          if( th_arg[i].key == NULL )
            printf("Error: Thread #%d key duplication failed\n", i); 

          printf("Error: Thread #%d initialization failed\n", i); 

          th_ok[i] = false;

          all_th_ok = false;

          continue;
        }

      th_arg[i].key->e = NULL;

      if( pthread_create(&th_id[i], &th_attr[i], Sign_Thread, (void *)&th_arg[i]) != 0) 
        { 
          printf("Error: Thread #%d creation failed\n", i); 

          th_ok[i] = false;

          all_th_ok = false;
        }
    }

  //---------------------------------------------------------------------------
  //-- Wait all threads complete initialization
  //---------------------------------------------------------------------------

  if( all_th_ok )
    pthread_barrier_wait( &Barrier );

  //---------------------------------------------------------------------------
  //-- Save time of start
  //---------------------------------------------------------------------------

  timespec tm_s; 

  clock_gettime(CLOCK_REALTIME, &tm_s); 

  printf("\n  Running ... \n");

  //---------------------------------------------------------------------------
  //-- Wait all threads finish
  //---------------------------------------------------------------------------

  for(int i = 0; i < thread_qnt; i++)
    {
      th_ret[i] = NULL;

      if(th_ok[i])
        pthread_join(th_id[i], &th_ret[i]);
      else
        all_th_ok = false;
    }


  printf("\n--------- Signing complete -----------\n");

  //---------------------------------------------------------------------------
  //-- Compute performance only if all threads was successful
  //---------------------------------------------------------------------------

  if(all_th_ok)
    {
      timespec tm_e; 

      clock_gettime(CLOCK_REALTIME, &tm_e);

      double total_time = ( (double)(tm_e.tv_sec - tm_s.tv_sec) + (double)(tm_e.tv_nsec - tm_s.tv_nsec)/1000000000.0 );

      double averg_time = total_time / double(cycle_qnt) / (double)(thread_qnt) / (double)(job_qnt);

      printf("\nOveral statistic:\n\n", total_time );

      printf("Total time              : %3.2f sec\n", total_time );

      if( averg_time > 0.0000001 )       // impossible that average time is less than 100 ns
        {
          printf("Average time per sign   : %3.2f us\n", averg_time * 1000000.0);

          printf("Average sign per second : %d\n", (int)(1.0 / averg_time ));
        }
      else
        {
          printf("\nError: Something goes wrong and result is incorrect\n");
        }
    }

  //---------------------------------------------------------------------------
  //-- Release resources
  //---------------------------------------------------------------------------

  pthread_barrier_destroy( &Barrier );

ret:

  if( key )
    RSA_free( key );

  if(bn)
    BN_free(bn);

  if( th_attr ) delete [] th_attr;
  if( th_id   ) delete [] th_id  ;
  if( th_ret  ) delete [] th_ret ;
  if( th_ok   ) delete [] th_ok  ;
  if( th_arg  ) delete [] th_arg ;
}

//====================================================================================================//

int Sign_Job(void *arg)
{
  sign_job_arg *a = (sign_job_arg *)arg;

  unsigned int sign_len = KEY_BYTE_SIZE;

  RSA_sign(NID_sha256, a->hash, SHA256_DIGEST_LENGTH, a->sign,  &sign_len, a->key);

  return 1;
}

//====================================================================================================//

void * Sign_Thread(void *arg)
{
  if(arg == NULL)
    {
      pthread_barrier_wait( &Barrier );

      return NULL;
    }

  RSA * key = NULL;

  thread_arg *th_arg = (thread_arg *)arg;

  unsigned char ptext[KEY_BYTE_SIZE];

  int *retvalue = new int[th_arg->job_qnt];

  ASYNC_JOB* *job = new ASYNC_JOB* [th_arg->job_qnt];

  ASYNC_WAIT_CTX *wctx;

  sign_job_arg* job_arg = new sign_job_arg [th_arg->job_qnt];

  int *job_stat = new int[th_arg->job_qnt];

  if(! retvalue || ! job || ! job_arg || ! job_stat)
    {
      printf("Error: Insufficient amount of memory\nSigning failed\n");

      goto ret;
    }


  ASYNC_init_thread(th_arg->job_qnt, th_arg->job_qnt);

  //---------------------------------------------------------------------------
  //-- Prepare data for jobs
  //---------------------------------------------------------------------------

  printf("  Prepare jobs in thread #%d\n", th_arg->id);

  for(int k = 0; k < th_arg->job_qnt; k++)
    {
      job_arg[k].key = th_arg->key;

      for(int n = 0; n < KEY_BYTE_SIZE; n++)
        ptext[n] = rand();

      SHA256(ptext, KEY_BYTE_SIZE, job_arg[k].hash);
    }

  //---------------------------------------------------------------------------
  //-- Launch jobs
  //---------------------------------------------------------------------------

  wctx = ASYNC_WAIT_CTX_new();

  pthread_barrier_wait( &Barrier );

  for(int s = 0; s < th_arg->cycle_qnt; s++)
    {
      //-----------------------------------------------------------------------
      //-- Reset jobs
      //-----------------------------------------------------------------------

      for(int k = 0; k < th_arg->job_qnt; k++)
        {
          job[k] = NULL;

          job_arg[k].id = k;

          for(int n = 0; n < KEY_BYTE_SIZE; n++)
            job_arg[k].sign[n] = 0;

          job_stat[k] = ASYNC_NO_JOBS;
        }

      //-----------------------------------------------------------------------
      //-- Run jobs
      //-----------------------------------------------------------------------

      while(1)
        {
          int nj = 0;

          for(int k = 0; k < th_arg->job_qnt; k++)
            {
              if( job_stat[k] == ASYNC_FINISH )
                { nj++; continue; }

              job_stat[k] = ASYNC_start_job(&job[k], wctx, &retvalue[k], Sign_Job, (void *)&job_arg[k], sizeof(sign_job_arg));

              if(job_stat[k] == ASYNC_PAUSE ) 
                ;
              else if( job_stat[k] == ASYNC_FINISH )
                ; 
              else
                printf("# job_stat[k] = %d", job_stat[k]);
            }

          if( nj == th_arg->job_qnt )
            break;
        }

    }

  ASYNC_WAIT_CTX_free(wctx);

ret:

  if( retvalue ) delete [] retvalue;
  if( job      ) delete [] job     ;
  if( job_arg  ) delete [] job_arg ;
  if( job_stat ) delete [] job_stat; 

  return( NULL );
}

//====================================================================================================//
