#ifndef __AWS_RSA_ENGINE_H__
//{
    #define __AWS_RSA_ENGINE_H__

    #include <stdio.h>

    #include <pthread.h>

    #include <openssl/engine.h>
    
//    #define AWS_RSA_DIAGNOSTIC_MESSAGE 1

    enum aws_rsa_engine_cmd
      {
        ZTE_CMD_TOTAL_MULT_QNT = ENGINE_CMD_BASE,
        ZTE_CMD_TOTAL_TIME,
        ZTE_CMD_AVERAGE_TIME,
        ZTE_CMD_AVERAGE_LOAD
      };

    //====================================================================================================//

    extern "C" int AWS_RSA_Init   (ENGINE *e);
    extern "C" int AWS_RSA_Finish (ENGINE *e);
    extern "C" int AWS_RSA_Destroy(ENGINE *e);
    extern "C" int AWS_RSA_Ctrl   (ENGINE *e, int cmd, long i, void *p, void (*f) (void));
    
    #if AWS_RSA_DIAGNOSTIC_MESSAGE == 1
    //{
        #define Debug_Message(msg)          printf(msg)
        #define Debug_Message_1(msg, a1)    printf(msg, a1)
        #define Debug_Message_2(msg,a1,a2)  printf(msg, a1, a2)
    //}
    #else
    //{
        #define Debug_Message(msg)
        #define Debug_Message_1(msg, a1)
        #define Debug_Message_2(msg,a1,a2)
    //}
    #endif

    #define Err_Message(msg)            printf(msg)
    #define Err_Message_1(msg,a1)       printf(msg, a1)
    #define Err_Message_2(msg,a1,a2)    printf(msg, a1, a2)
    
    class ClDevice;
    
    struct FPGA_thread_info 
      {
        ClDevice *FPGA;

        pthread_t       thread_id;        // ID returned by pthread_create()
        
        pthread_mutex_t FPGA_Thrd_Lock;  // while locked, FPGA thread still perform working cycles. 
                                          // When released, then FPGA thread should finish current computation cycle and exit
      };
    
//}
#endif