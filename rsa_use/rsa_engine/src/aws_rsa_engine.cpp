#define _CRT_SECURE_NO_WARNINGS

#include <time.h>

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "aws_rsa_engine.h"
#include "aws_rsa_fpga.h"

//#include <openssl/crypto/rsa/rsa_locl.h>
//#include <openssl/include/internal/cryptlib.h>
//#include <openssl/crypto/include/internal/bn_int.h>
//#include <openssl/crypto/bn/bn_lcl.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/async.h>
#include <openssl/bn.h>

#define OSSL_ERROR (0)
#define OSSL_OK    (1)

static const char *AWS_RSA_Engine_ID   = "zotech_aws_rsa_kernel";
static const char *AWS_RSA_Engine_Name = "Zotech AWS FPGA Montgmery multiplier acelerator";

static ENGINE *AWS_RSA_Engine = NULL;

static RSA_METHOD *AWS_RSA_Method = NULL;

int Multiplication_Counter = 0;
int Krnl_Run_Qnt = 0;


static bool FPGA_Ready        = false;
static bool FPGA_Kernel_Ready = false;

static ClDevice *FPGA = NULL;

pthread_mutex_t FPGA_Krnl_Lock; 
pthread_mutex_t FPGA_Rqst_Lock; 
pthread_mutex_t FPGA_Resp_Lock; 

static FPGA_thread_info FPGA_TI;


extern "C" int   aws_bn_mod_exp (BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
           int (*def_bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
           
void * FPGA_thread(void * arg);

double Delta_Time(timespec dt)
{
  return( (double)(dt.tv_sec) + (double)(dt.tv_nsec)/1000000000.0);
}

//====================================================================================================//

static const ENGINE_CMD_DEFN AWS_RSA_Cmd_Def[] = { {ZTE_CMD_TOTAL_MULT_QNT, "TOTAL_MULT_QNT", "Return total quantity of performed multiplications", ENGINE_CMD_FLAG_NO_INPUT},
	                                                 {ZTE_CMD_TOTAL_TIME    , "TOTAL_TIME"    , "Return total time spend by RSA FPGA kernel"        , ENGINE_CMD_FLAG_NO_INPUT},
                                                   {ZTE_CMD_AVERAGE_TIME  , "AVERAGE_TIME"  , "Return average time for one multiplication"        , ENGINE_CMD_FLAG_NO_INPUT},
                                                   {ZTE_CMD_AVERAGE_LOAD  , "AVERAGE_LOAD"  , "Return average load of RSA FPGA kernel in percent" , ENGINE_CMD_FLAG_NO_INPUT},
                                                   {     0     ,     NULL ,                          NULL                                         ,              0          }
                                                 };

//====================================================================================================//

extern "C" int AWS_RSA_Bind(ENGINE *e, const char *id)
{
  Debug_Message("AWS_RSA_Bind() enter\n");
  Debug_Message_1("AWS_RSA_Bind - ID = %s\n", id);
  
  //---------------- Create set of RSA methods ----------------//
  
  AWS_RSA_Method = RSA_meth_dup( RSA_PKCS1_OpenSSL() );        // duplicate default RSA 
    
  if( AWS_RSA_Method == NULL )
     {
       Err_Message("### Error: AWS_RSA_Bind - Creation of AWS_RSA_Method failed\n");
       return( OSSL_ERROR );
     }
    
  if( ! RSA_meth_set1_name(AWS_RSA_Method, "AWS RSA method") )
     {
       Err_Message("### Error: AWS_RSA_Bind - RSA_meth_set1_name() failed\n");
       return( OSSL_ERROR );
     }

  //---------------- Setup engine's callbacks ----------------//

  if( ! ENGINE_set_id              (e, AWS_RSA_Engine_ID  ) ) { Err_Message("### Error: AWS_RSA_Bind - ENGINE_set_id() failed\n"              ); goto error; }
  if( ! ENGINE_set_name            (e, AWS_RSA_Engine_Name) ) { Err_Message("### Error: AWS_RSA_Bind - ENGINE_set_name() failed\n"            ); goto error; }
  if( ! ENGINE_set_init_function   (e, AWS_RSA_Init       ) ) { Err_Message("### Error: AWS_RSA_Bind - ENGINE_set_init_function() failed\n"   ); goto error; }
  if( ! ENGINE_set_finish_function (e, AWS_RSA_Finish     ) ) { Err_Message("### Error: AWS_RSA_Bind - ENGINE_set_finish_function() failed\n" ); goto error; }
  if( ! ENGINE_set_destroy_function(e, AWS_RSA_Destroy    ) ) { Err_Message("### Error: AWS_RSA_Bind - ENGINE_set_destroy_function() failed\n"); goto error; }
  if( ! ENGINE_set_ctrl_function   (e, AWS_RSA_Ctrl       ) ) { Err_Message("### Error: AWS_RSA_Bind - ENGINE_set_ctrl_function() failed\n"   ); goto error; }
  if( ! ENGINE_set_cmd_defns       (e, AWS_RSA_Cmd_Def    ) ) { Err_Message("### Error: AWS_RSA_Bind - ENGINE_set_cmd_defns() failed\n"       ); goto error; }

  //---------------- Setup engine's RSA methods ----------------//
  
  if( ! ENGINE_set_RSA(e, AWS_RSA_Method) )      // Use default RSA methods set - methods replacement to FPGA accelerated will be do later
    {                                            // during initialization in AWS_RSA_Init() after FPGA will be ready
      Err_Message("### Error: AWS_RSA_Bind - ENGINE_set_RSA() failed\n"); goto error; 
    }

  Debug_Message("AWS_RSA_Bind() exit\n");

  return( OSSL_OK );
 
error:
 
  Debug_Message("### AWS_RSA_Bind() exit\n");

  return( OSSL_ERROR );
}

//====================================================================================================//

extern "C"
{
  IMPLEMENT_DYNAMIC_BIND_FN (AWS_RSA_Bind)
  IMPLEMENT_DYNAMIC_CHECK_FN()
}

//====================================================================================================//

#define FPGA_RUN_MODE_HW 0
#define FPGA_RUN_MODE_HW_EMU 1
#define FPGA_RUN_MODE_SW_EMU 2
#define FPGA_RUN_MODE_HW_AWS 3

extern void FPGA_Init(void);

extern "C" int AWS_RSA_Init(ENGINE *e)
{
  Debug_Message("AWS_RSA_Init() enter\n");

  std::string const plPath = getenv("AWS_PLATFORM");
  std::size_t const plFirstChar = plPath.rfind("/")+1;
  std::size_t const plLastChar  = plPath.rfind(".xpfm");
  std::string const plName = plPath.substr(plFirstChar, plLastChar - plFirstChar);
  bool const plAWS = (plPath.rfind("xilinx_aws") != std::string::npos); // is platform really AWS-based
  std::string kernel_file;

  int run_mode = plAWS ? FPGA_RUN_MODE_HW_AWS : FPGA_RUN_MODE_HW;
  
  pthread_attr_t attr;

  int ret = OSSL_OK;

  if( ! AWS_RSA_Method )
    goto error;

  def_bn_mod_exp = RSA_meth_get_bn_mod_exp( RSA_PKCS1_OpenSSL() );

  if( ! RSA_meth_set_bn_mod_exp(AWS_RSA_Method, aws_bn_mod_exp) ) { Err_Message("### Error: AWS_RSA_Init - RSA_meth_set_bn_mod_exp() failed\n"); goto error; }

  if( pthread_mutex_init(&FPGA_Krnl_Lock, NULL) != 0 ) { Err_Message("### Error: AWS_RSA_Init - Initialization of mutex FPGA_Krnl_Lock failed\n"); goto error; }
  if( pthread_mutex_init(&FPGA_Rqst_Lock, NULL) != 0 ) { Err_Message("### Error: AWS_RSA_Init - Initialization of mutex FPGA_Rqst_Lock failed\n"); goto error; }
  if( pthread_mutex_init(&FPGA_Resp_Lock, NULL) != 0 ) { Err_Message("### Error: AWS_RSA_Init - Initialization of mutex FPGA_Resp_Lock failed\n"); goto error; }
  
  //-------------- Load FPGA kernel ----------------//

  if( const char* env = getenv("XCL_EMULATION_MODE") ) 
    {
      run_mode = strcasecmp(env, "hw_emu") == 0 ? FPGA_RUN_MODE_HW_EMU : run_mode;
      run_mode = strcasecmp(env, "sw_emu") == 0 ? FPGA_RUN_MODE_SW_EMU : run_mode;
    }

  switch( run_mode )
    {
      case FPGA_RUN_MODE_HW     : kernel_file = "../../../rsa_accel/build/SDx/xclbin/rsa_hls_krnl.hw."     + plName + ".xclbin"; break;
      case FPGA_RUN_MODE_HW_EMU : kernel_file = "../../../rsa_accel/build/SDx/xclbin/rsa_hls_krnl.hw_emu." + plName + ".xclbin"; break;
      case FPGA_RUN_MODE_SW_EMU : kernel_file = "../../../rsa_accel/build/SDx/xclbin/rsa_hls_krnl.sw_emu." + plName + ".xclbin"; break;
      case FPGA_RUN_MODE_HW_AWS : kernel_file = "../../../rsa_accel/build/SDx/rsa_hls_krnl.hw."            + plName + ".awsxclbin"; break;
    
      default: goto error; 
    }

  FPGA = new ClDevice;
  
  if( FPGA == NULL )
    goto error;

  if( ! FPGA->Open_Device(plName) )
    goto error;

  if( ! FPGA->Open_Kernel(kernel_file, "rsaMontgPowNKernelEntry64") )            //rsa_montg_pow_N_kernel_entry_to_stream
    goto error;
    
    FPGA->Eng_Total_Time.tv_sec = 0;      FPGA->Eng_Total_Time.tv_sec = 0;
    FPGA->Eng_Time .tv_sec = 0;           FPGA->Eng_Time .tv_nsec = 0;
    FPGA->Rqst_Time.tv_sec = 0;           FPGA->Rqst_Time.tv_nsec = 0;
    FPGA->Resp_Time.tv_sec = 0;           FPGA->Resp_Time.tv_nsec = 0;
    FPGA->DPut_Time.tv_sec = 0;           FPGA->DPut_Time.tv_nsec = 0;
    FPGA->DGet_Time.tv_sec = 0;           FPGA->DGet_Time.tv_nsec = 0;
    FPGA->Krnl_Time.tv_sec = 0;           FPGA->Krnl_Time.tv_nsec = 0;

//      FPGA->Close_Kernel();
//      FPGA->Close_Device();
    
//      delete(FPGA);

  //-------------- Create thread for FPGA ----------------//

  FPGA_TI.FPGA = FPGA;

  if( pthread_mutex_init(&FPGA_TI.FPGA_Thrd_Lock, NULL) != 0 ) { Err_Message("### Error: AWS_RSA_Init - Initialization of mutex FPGA_TI.FPGA_Thrd_Lock failed\n"); goto error; }
  
  pthread_mutex_lock(&FPGA_TI.FPGA_Thrd_Lock);

  if( pthread_attr_init(&attr) != 0 ) { Err_Message("### Error: AWS_RSA_Init - pthread_attr_init() failed\n"); goto error; }

  if( pthread_create(&FPGA_TI.thread_id, &attr, FPGA_thread, &FPGA_TI) != 0) { Err_Message("### Error: AWS_RSA_Init - pthread_create() failed\n"); goto error; }


  Debug_Message("AWS_RSA_Init() exit\n");
  
  return( OSSL_OK );

error:  //..................................//

  Debug_Message("### AWS_RSA_Init() exit\n");
  
  return( OSSL_ERROR );
}

//====================================================================================================//

extern "C" int AWS_RSA_Finish(ENGINE *e)
{
  Debug_Message("AWS_RSA_Finish() enter\n");
  
  Debug_Message_1("AWS_RSA_Finish - Encription_Counter = %d\n", Multiplication_Counter);
  
//  printf("Eng_Total_Time = %g\n", Delta_Time(FPGA->Eng_Total_Time) );
//  
//  printf("Eng_Time = %g\n", Delta_Time(FPGA->Eng_Time) );
//  
//  printf("Rqst_Time = %g\n", Delta_Time(FPGA->Rqst_Time) );
//  printf("DPut_Time = %g\n", Delta_Time(FPGA->DPut_Time) );
//  printf("Krnl_Time = %g\n", Delta_Time(FPGA->Krnl_Time) );
//  printf("DGet_Time = %g\n", Delta_Time(FPGA->DGet_Time) );
//  printf("Resp_Time = %g\n", Delta_Time(FPGA->Resp_Time) );
  
  
  void *result;
  int i;
  
  pthread_mutex_unlock(&FPGA_TI.FPGA_Thrd_Lock);
  
  for(i = 0; i < 100 && pthread_tryjoin_np(FPGA_TI.thread_id, &result) == EBUSY; i++)
    usleep(10000);
    
  if( i == 100 )
    goto error;
  
  pthread_mutex_destroy( &FPGA_TI.FPGA_Thrd_Lock );
  
  if(FPGA)
    {
      FPGA->Close_Kernel();
      FPGA->Close_Device();
      
      delete(FPGA);
      
      FPGA = NULL;
    }
  
  pthread_mutex_destroy( &FPGA_Krnl_Lock );
  pthread_mutex_destroy( &FPGA_Rqst_Lock );
  pthread_mutex_destroy( &FPGA_Resp_Lock );
  
  FPGA_Ready        = false;
  FPGA_Kernel_Ready = false;

  Debug_Message("AWS_RSA_Finish() exit\n");

  return( OSSL_OK );

error:

  Debug_Message("### AWS_RSA_Finish() exit\n");
  
  return( OSSL_ERROR );
}

//====================================================================================================//

extern "C" int AWS_RSA_Destroy(ENGINE *e)
{
  Debug_Message("AWS_RSA_Destroy() enter\n");

  RSA_meth_free(AWS_RSA_Method);
  AWS_RSA_Method = NULL;

  Debug_Message("AWS_RSA_Destroy() exit\n");

  return( OSSL_OK );

error:

  Debug_Message("### AWS_RSA_Destroy() exit\n");
  
  return( OSSL_ERROR );
}

//====================================================================================================//

extern "C" int AWS_RSA_Ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
  if( p == NULL || i != sizeof(double) )  
    return( 0 );

  double *resp = (double *)p;

  if(FPGA == NULL)
    {
      *resp = -1.0;

      return( 0 );
    }

	switch(cmd) 
    {
	    case ZTE_CMD_TOTAL_MULT_QNT : *resp = (double)Multiplication_Counter;  
                                    
                                    return( 1 );
	    
      case ZTE_CMD_TOTAL_TIME     : *resp  = (FPGA->Krnl_Time.tv_sec  + FPGA->DPut_Time.tv_sec  + FPGA->DGet_Time.tv_sec );
                                    *resp += (FPGA->Krnl_Time.tv_nsec + FPGA->DPut_Time.tv_nsec + FPGA->DGet_Time.tv_nsec) / 1000000000.0;  
                                    
                                    return( 1 );
	    
      case ZTE_CMD_AVERAGE_TIME   : if( Multiplication_Counter < 1)
                                      {
                                        *resp = -2.0;

                                        return( 0 );
                                      }
                                    
                                    *resp  = (FPGA->Krnl_Time.tv_sec  + FPGA->DPut_Time.tv_sec  + FPGA->DGet_Time.tv_sec ) * 1000000.0;
                                    *resp += (FPGA->Krnl_Time.tv_nsec + FPGA->DPut_Time.tv_nsec + FPGA->DGet_Time.tv_nsec) / 1000.0;  
                                    
                                    *resp /= (double)Multiplication_Counter;
                                    
                                    return( 1 );
	    
      case ZTE_CMD_AVERAGE_LOAD   : if( Krnl_Run_Qnt < 1)
                                      {
                                        *resp = 0.0;

                                        return( 0 );
                                      }
                                    
                                    *resp  = (double)(Multiplication_Counter / Krnl_Run_Qnt) / (double)FPGA->Get_Unit_Qnt();  
                                    
                                    return( 1 );

      default:  return( 0 );
	  }

	return 0;
}

//====================================================================================================//

#include "rsa_int.h"
#include "rsa.h"

#include <openssl/crypto/rsa/rsa_locl.h>
#include <openssl/include/internal/cryptlib.h>
#include <openssl/crypto/include/internal/bn_int.h>
#include <openssl/crypto/bn/bn_lcl.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/async.h>

extern int Get_Rqst_Stat(int rqst_id);

#define BIGNUM_DMAX ( 2048 / ( 8 * sizeof(BN_ULONG) ) )

extern "C" int aws_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
//  Debug_Message(".");
  
  int ret = OSSL_ERROR;
  int id = -1;
  ClDevice::rr_state state;

  timespec tm_s, tm_e;


//  if( m->top*BN_BYTES*8 == 2048)
    {
      BIGNUM r_krnl;

      BN_ULONG r_krnl_d[BIGNUM_DMAX];

      int i;

      r_krnl.dmax  = BIGNUM_DMAX;
      r_krnl.flags = 0;
      r_krnl.neg   = 0;
      r_krnl.top   = 0;

      r_krnl.d = r_krnl_d;
      
      for( i = 0; i < BIGNUM_DMAX; i++) 
        r_krnl.d[i] = 0; 

      while( (state = FPGA->Add_Request(id, a, p, m)) != ClDevice::RR_SLOT_READY)
        {
          if( state == ClDevice::RR_SLOT_ERROR)
            return(0);
          
          ASYNC_pause_job();
        }
      
//      printf("Request - thread: %d, ID: %d\n", (unsigned int)pthread_self(), id);

      do
        {
          if( state == ClDevice::RR_SLOT_ERROR)
            return(0);

          ASYNC_pause_job();
        }
      while( (state = FPGA->Get_Response(id, &r_krnl)) != ClDevice::RR_SLOT_READY);    

//      ret = def_bn_mod_exp(r, a, p, m, ctx, m_ctx);                                                           //#Debug

//      if(r_krnl.top != r->top)
//        printf("#Error - thread: %d, ID: %d - r_krnl.top != r->top\n", (unsigned int)pthread_self(), id);     //#Debug

//      for( i = 0; i < r->top; i++)                                                                            //#Debug
//        if( r_krnl.d[i] != r->d[i] )                                                                          //#Debug
//          {      
//            printf("#Error - thread: %d, ID: %d\n", (unsigned int)pthread_self(), id);                        //#Debug
//            break;                                                                                            //#Debug
//          }

//      if(i == r->top)                                                                                         //#Debug
//        printf("Ok - thread: %d, ID: %d\n", (unsigned int)pthread_self(), id);                                //#Debug

      BN_copy(r, &r_krnl);

      ret = 1;

//      clock_gettime(CLOCK_REALTIME, &tm_e);

//      FPGA->Eng_Time.tv_sec  += tm_e.tv_sec  - tm_s.tv_sec;
//      FPGA->Eng_Time.tv_nsec += tm_e.tv_nsec - tm_s.tv_nsec;

//      if(FPGA->Eng_Time.tv_nsec >  1000000000) {FPGA->Eng_Time.tv_sec++; FPGA->Eng_Time.tv_nsec-=1000000000;}
//      if(FPGA->Eng_Time.tv_nsec < -1000000000) {FPGA->Eng_Time.tv_sec--; FPGA->Eng_Time.tv_nsec+=1000000000;}

      return(ret);   //#Debug

      //#Debug return( 1 );
    }

  clock_gettime(CLOCK_REALTIME, &tm_s);
  
  if( def_bn_mod_exp )
    {
      ret = def_bn_mod_exp(r, a, p, m, ctx, m_ctx);
    }

  clock_gettime(CLOCK_REALTIME, &tm_e);

  FPGA->Eng_Time.tv_sec  += tm_e.tv_sec  - tm_s.tv_sec;
  FPGA->Eng_Time.tv_nsec += tm_e.tv_nsec - tm_s.tv_nsec;

  if(FPGA->Eng_Time.tv_nsec >  1000000000) {FPGA->Eng_Time.tv_sec++; FPGA->Eng_Time.tv_nsec-=1000000000;}
  if(FPGA->Eng_Time.tv_nsec < -1000000000) {FPGA->Eng_Time.tv_sec--; FPGA->Eng_Time.tv_nsec+=1000000000;}

  return( ret );
}



void * FPGA_thread(void * arg)
{
  FPGA_thread_info *ti = (FPGA_thread_info *)arg;
  
  if( ti == NULL )
    return( NULL );
    
  int m;
  
  while( (m = pthread_mutex_trylock(&ti->FPGA_Thrd_Lock)) == EBUSY )
    {
      usleep(200);
      FPGA->Compute();
    }
  
  if( m == 0 )
    pthread_mutex_unlock(&ti->FPGA_Thrd_Lock);
    
  return( NULL );
}













/*
int main()
{
  return AWS_RSA_Bind(NULL, NULL);
}
*/