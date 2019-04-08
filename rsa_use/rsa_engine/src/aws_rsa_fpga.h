#include <stdio.h>
#include <string.h>
#include <iostream>

#include <sys/cdefs.h>

#include <pthread.h>

#include <CL/opencl.h>

#include "rsa_hls_seq.h"
// #include "rsa_hls_def.h"
#include "rsa_seq_impl.h"
#include "rsa_gmp.h"


typedef __uint128_t rsa_dword_t;

static const uint64_t MONTG_WORD_MASK = (uint64_t(1)<<MONTG_WORD_BITS)-1;

static const size_t KERNEL_ARG_WORDS    = ARG64_WORDS;
static const size_t KERNEL_RESULT_WORDS = RESULT64_WORDS;


using namespace std;

class ClDevice
{
  public:
    ClDevice() : Platform_ID(0), Device_ID(0), Context(0), Command_Queue(0), Program(0), Kernel(0)
      {
        if( pthread_mutex_init(&Rqst_Lock    , NULL) != 0 ) { Err_Message("ClDevice - Initialization of mutex Rqst_Lock failed\n"); }
        if( pthread_mutex_init(&Rqst_Rdy_Lock, NULL) != 0 ) { Err_Message("ClDevice - Initialization of mutex Rqst_Rdy_Lock failed\n"); }
        if( pthread_mutex_init(&Krnl_Lock    , NULL) != 0 ) { Err_Message("ClDevice - Initialization of mutex Krnl_Lock failed\n"); }
        if( pthread_mutex_init(&Resp_Lock    , NULL) != 0 ) { Err_Message("ClDevice - Initialization of mutex Resp_Lock failed\n"); }
      }

    ~ClDevice();

  public:

    typedef enum
      {
        RR_SLOT_EMPTY =  0,
        RR_SLOT_FULL  =  1,
        RR_SLOT_BUSY  =  2,
        RR_SLOT_READY =  3,
        RR_SLOT_ERROR = -3
      }
      rr_state;


  private:

    struct zt_aux_data     // Auxilary data from request needed to make response from CL response buffer
      {
        MontgPowParams prm;

        rr_state stat;
        
        int id;
      };

    cl_platform_id   Platform_ID;
    cl_device_id     Device_ID;
    cl_context       Context;
    cl_command_queue Command_Queue;
    cl_program       Program;
    cl_kernel        Kernel;

public:
    timespec Eng_Total_Time;
    timespec Eng_Time;
    timespec Rqst_Time;
    timespec Resp_Time;
    timespec DPut_Time;
    timespec DGet_Time;
    timespec Krnl_Time;

private:
    //-------------- Request related --------------//

    pthread_mutex_t Rqst_Lock, Rqst_Rdy_Lock;

    int             Rqst_Qnt, Rqst_Rdy_Qnt;
    rsa_word_t      Rqst_Buffer[ UNIT_COUNT * KERNEL_ARG_WORDS ];
    zt_aux_data     Rqst_Aux   [ UNIT_COUNT ];

    //-------------- Kernel related --------------//

    pthread_mutex_t Krnl_Lock;

    cl_ushort       Krnl_Qnt;
    cl_mem       CL_Rqst_Buffer;
    cl_mem       CL_Resp_Buffer;
    zt_aux_data     Krnl_Aux[ UNIT_COUNT ];

    //-------------- Response related --------------//

    pthread_mutex_t Resp_Lock;

    int             Resp_Qnt;
    rsa_word_t      Resp_Buffer[ UNIT_COUNT * KERNEL_RESULT_WORDS ];
    zt_aux_data     Resp_Aux   [ UNIT_COUNT ];

    uint32_t GID_Counter;

    bool Init_Kernel_Interface();
    bool Find_Platform();
    bool Find_Device( const string& target_device_name );

    void Make_Response(const MontgPowParams& params,       rsa_word_t* data, const rsa_word_t* args);
    void Make_Request (const MontgPowParams& params, const rsa_word_t* data,       rsa_word_t* args);

  public:

    bool Device_is_Opened() const { return Command_Queue; }
    bool Kernel_is_Opened() const { return Kernel; }

    bool Open_Device(const string& target_device_name);
    void Close_Device();
    bool Open_Kernel(const string& kernel_name, const string& program_name);
    void Close_Kernel();

    int Get_Unit_Qnt() { return( UNIT_COUNT ); }

    void Compute();

    rr_state Add_Request(int &id, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m);

    rr_state Get_Response(int id, BIGNUM *r);
};
