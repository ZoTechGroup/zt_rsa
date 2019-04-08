//====================================================================================================//

#define KEY_BIT_SIZE   (2048)

#define KEY_BYTE_SIZE  (KEY_BIT_SIZE/8)

//====================================================================================================//

enum aws_rsa_engine_cmd
  {
    ZTE_CMD_TOTAL_MULT_QNT = ENGINE_CMD_BASE,
    ZTE_CMD_TOTAL_TIME,
    ZTE_CMD_AVERAGE_TIME,
    ZTE_CMD_AVERAGE_LOAD
  };

//====================================================================================================//

struct thread_arg
{
  int id;
  int job_qnt, cycle_qnt;

  RSA *key;
};

struct sign_job_arg
{
  int id;

  unsigned char hash[ SHA256_DIGEST_LENGTH ];

  unsigned char sign[ KEY_BYTE_SIZE ];

  RSA *key;
};

//====================================================================================================//

void Run_Sign( int thread_qnt, int job_qnt, int cycles_qnt );

int Sign_Job(void *arg);

void * Sign_Thread(void *arg);

//====================================================================================================//