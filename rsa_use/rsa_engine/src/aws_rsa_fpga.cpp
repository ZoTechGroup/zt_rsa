#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <assert.h>

#include "aws_rsa_engine.h"
#include "aws_rsa_fpga.h"

#include <openssl/crypto/rsa/rsa_locl.h>
#include <openssl/include/internal/cryptlib.h>
#include <openssl/crypto/include/internal/bn_int.h>
#include <openssl/crypto/bn/bn_lcl.h>


using namespace std;


#define INIT_ARRAY(name) memset(&name, 99, sizeof(name))
#define INIT_PTR_ARRAY(ptr, size) memset(ptr, 99, sizeof(*ptr)*(size))

extern int Multiplication_Counter;
          
extern int Krnl_Run_Qnt;


//====================================================================================================//

ClDevice::~ClDevice()
{
  Debug_Message("ClDevice destructor\n");

  pthread_mutex_destroy(&Rqst_Lock    );
  pthread_mutex_destroy(&Rqst_Rdy_Lock);
  pthread_mutex_destroy(&Krnl_Lock    );
  pthread_mutex_destroy(&Resp_Lock    );

//  Close_Kernel();
//  Close_Device();

  Debug_Message("ClDevice closed\n");
}

//====================================================================================================//

void ClDevice::Close_Kernel()
{
  if ( CL_Rqst_Buffer )
    {
      clReleaseMemObject(CL_Rqst_Buffer);
      CL_Rqst_Buffer = 0;
    }

  if ( CL_Resp_Buffer )
    {
      clReleaseMemObject(CL_Resp_Buffer);
      CL_Resp_Buffer = 0;
    }

  if( Kernel )
    {
      Debug_Message("Closing kernel\n");
//      clReleaseKernel(Kernel);                         //? crash engine  //ToDo find out why
      Kernel = 0;
    }

  if( Program )
    {
      Debug_Message("Closing program\n");
      clReleaseProgram(Program);
      Program = 0;
    }
}

//====================================================================================================//

void ClDevice::Close_Device()
{
  if ( Command_Queue )
    {
      Debug_Message("Closing command queue\n");
      clReleaseCommandQueue(Command_Queue);
      Command_Queue = 0;
    }

  if ( Context )
    {
      Debug_Message("Closing context\n");
      clReleaseContext(Context);
      Context = 0;
    }

  if ( Device_ID )
    {
      Debug_Message("Closing device\n");
      clReleaseDevice(Device_ID);
      Device_ID = 0;
    }
}

//====================================================================================================//

bool ClDevice::Open_Device(const string& target_device_name)
{
  if( Device_is_Opened() )
    {
      Debug_Message("ClDevice::Open_Device - Device_is_Opened\n");

      Close_Kernel();
      Close_Device();
    }

  Debug_Message_1("ClDevice::Open_Device - Build for target device: %s\n", target_device_name.c_str());

  cl_int err;

  Platform_ID = 0;
  Device_ID   = 0;

  if( ! Find_Platform() )
    return( false );

  if( ! Find_Device( target_device_name ) )
    return( false );

  //------------------- Create a compute context -------------------//

  Context = clCreateContext(0, 1, &Device_ID, 0, 0, &err);

  if( !Context )
    {
      Err_Message("### Error: ClDevice::Open_Device - Failed to create a compute context!\n");
      return(false);
    }

  //------------------- Create a command queue -------------------//

  Command_Queue = clCreateCommandQueue(Context, Device_ID, 0, &err);

  if( !Command_Queue )
    {
      Err_Message("### Error: ClDevice::Open_Device - Failed to create a command queue!\n");
      return(false);
    }

  return(true);
}

//====================================================================================================//

bool ClDevice::Find_Platform()
{
  cl_uint p_qnt = 0;

  char vendor_name[1000];

  cl_platform_id *p_id = NULL;

  //------------------- Get number of available platforms -------------------//

  if( clGetPlatformIDs(0, NULL, &p_qnt) != CL_SUCCESS || p_qnt == 0) { Err_Message("### Error: ClDevice::Find_Platform - No OpenCL platform found!\n"); goto error; }

  p_id = new cl_platform_id [p_qnt];

  if( p_id == NULL ) { Err_Message("### Error: ClDevice::Find_Platform - Insufficient memory to enumerate available platforms\n"); goto error; }

  if( clGetPlatformIDs(p_qnt, p_id, NULL) != CL_SUCCESS ) { Err_Message("### Error: ClDevice::Find_Platform - No OpenCL platform found!\n"); goto error; }

  Debug_Message_1("ClDevice::Find_Platform - Found %d platform(s)\n", p_qnt);

  //------------------- Iterate platforms and find target -------------------//

  for( int i = 0; i < p_qnt; ++i )
    {
      if( clGetPlatformInfo(p_id[i], CL_PLATFORM_VENDOR, sizeof(vendor_name)-1, (void *)vendor_name, 0) != CL_SUCCESS )
        {
          Err_Message("### Error: ClDevice::Find_Platform - clGetPlatformInfo(CL_PLATFORM_VENDOR) failed!\n");
          continue;
        }

      if( strcmp(vendor_name, "Xilinx") == 0)
        {
          Platform_ID = p_id[i];
          break;
        }
    }

  if ( ! Platform_ID )
    {
      Err_Message("### Error: ClDevice::Find_Platform - Target platform not found.\n");
      goto error;
    }

  return(true);

error:

  if(p_id)
    delete [] p_id;

  return(false);
}

//====================================================================================================//

bool ClDevice::Find_Device( const string& target_device_name )
{
  cl_uint d_qnt = 0;

  char device_name[1001];

  cl_device_id *d_id;

  if( ! Platform_ID )
    return( false );

  //------------------- Get number of available devices -------------------//

  if( clGetDeviceIDs(Platform_ID, CL_DEVICE_TYPE_ACCELERATOR, 0, NULL, &d_qnt) != CL_SUCCESS || d_qnt == 0) { Err_Message("### Error: ClDevice::Find_Device - Failed to get available devices on the platform!\n"); goto error; }

  d_id = new cl_device_id [d_qnt];

  if( d_id == NULL ) { Err_Message("### Error: ClDevice::Find_Device - Insufficient memory to enumerate available platforms\n"); goto error; }

  if( clGetDeviceIDs(Platform_ID, CL_DEVICE_TYPE_ACCELERATOR, d_qnt, d_id, NULL) != CL_SUCCESS ) { Err_Message("### Error: ClDevice::Find_Device - Failed to get available devices on platform!\n"); goto error; }

  //------------------- Iterate devices and find target -------------------//

  for( int i = 0; i < d_qnt; i++ )
    {
      if( clGetDeviceInfo(d_id[i], CL_DEVICE_NAME, sizeof(device_name)-1, device_name, NULL) != CL_SUCCESS )
        {
          Err_Message_1("### Error: ClDevice::Find_Device - Failed to get device name for device %d!\n", i);
          continue;
        }

      Debug_Message_1("ClDevice::Find_Device - Found device %s\n", device_name);

      string target_vendor_device_name = "xilinx:"+target_device_name;

      if ( device_name == target_device_name || device_name == target_vendor_device_name )
        {
          Device_ID = d_id[i];
          break;
        }
    }

  if( ! Device_ID )
    {
      Err_Message("### Error: ClDevice::Find_Device - Target device not found!\n");
      goto error;
    }

  Debug_Message_2("ClDevice::Find_Device - Platform ID = %d, Device_ID = %d\n", Platform_ID, Device_ID);

  return(true);

error:

  if(d_id)
    delete [] d_id;

  return(false);
}

//====================================================================================================//

static size_t load_file_to_memory(const char *filename, char **result)
{
    size_t size = 0;
    FILE *f = fopen(filename, "rb");
    if (f == NULL) {
        *result = NULL;
        return 0;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    *result = (char *)malloc(size+1);
    if (size != fread(*result, sizeof(char), size, f)) {
        free(*result);
        return 0;
    }
    fclose(f);
    (*result)[size] = 0;
    return size;
}

//====================================================================================================//

bool ClDevice::Open_Kernel(const string& xclbin, const string& kernel_name)
{
  if( Kernel_is_Opened() )
    Close_Kernel();

  Debug_Message_1("ClDevice::Open_Kernel - Loading %s\n", xclbin.c_str());

  cl_int err;

  char *kernel_ptr;

  //------------------- Load kernel file -------------------//

  size_t kernel_size = load_file_to_memory(xclbin.c_str(), &kernel_ptr);

  if ( ! kernel_size )
    {
      Err_Message_1("### Error: ClDevice::Open_Kernel - failed to load kernel from %s\n", xclbin.c_str());
      return(false);
    }

  //------------------- Create program from binary -------------------//

  int status;

  Program = clCreateProgramWithBinary(Context, 1, &Device_ID, &kernel_size, (const unsigned char **)&kernel_ptr, &status, &err);

  if( (! Program) || (err != CL_SUCCESS) )
    {
      Err_Message_1("### Error: ClDevice::Open_Kernel - Failed to create program from binary (err = %d)\n", err);
      return(false);
    }

  //------------------- Build the program executable -------------------//

  if( clBuildProgram(Program, 0, 0, 0, 0, 0) != CL_SUCCESS )
    {
      size_t len;
      char buffer[2048];

      clGetProgramBuildInfo(Program, Device_ID, CL_PROGRAM_BUILD_LOG, sizeof(buffer), buffer, &len);

      Err_Message_1("### Error: ClDevice::Open_Kernel - Failed to build program executable!\n    %s\n", buffer);

      return(false);
    }

  //------------------- Create kernel -------------------//

  Kernel = clCreateKernel(Program, kernel_name.c_str(), &err);

  if( ! Kernel || err != CL_SUCCESS )
    {
      Err_Message("### Error: ClDevice::Open_Kernel - Failed to create kernel!\n");
      return(false);
    }

  //------------------- Initialize kernel interface -------------------//

  return Init_Kernel_Interface();
}

//====================================================================================================//

bool ClDevice::Init_Kernel_Interface()
{
  int err = 0;
  size_t buf_size = 0;

  Krnl_Qnt = 0;

  GID_Counter = 0;

//  if( clSetKernelArg(Kernel, 0, sizeof(Krnl_Qnt), &Krnl_Qnt) != CL_SUCCESS )
//    {
//        Err_Message("### Error: ClDevice::Init_Kernel_Interface - Cannot set Krnl_Qnt");
//        return(false);
//    }

  //------------------- Allocate kernel's input buffer -------------------//

  buf_size = UNIT_COUNT * KERNEL_ARG_WORDS * sizeof(rsa_word_t);

  CL_Rqst_Buffer = clCreateBuffer(Context, CL_MEM_READ_ONLY, buf_size, NULL, NULL);

  if( ! CL_Rqst_Buffer )
    {
      Err_Message("### Error: ClDevice::Init_Kernel_Interface - Cannot allocate input data buffer\n");
      return(false);
    }

  if( clSetKernelArg(Kernel, 1, sizeof(CL_Rqst_Buffer), &CL_Rqst_Buffer) != CL_SUCCESS )
    {
      Err_Message("### Error: ClDevice::Init_Kernel_Interface - Cannot set input data buffer");
      return(false);
    }

  //------------------- Allocate kernel's output buffer -------------------//

  buf_size = UNIT_COUNT * KERNEL_RESULT_WORDS * sizeof(rsa_word_t);

  CL_Resp_Buffer = clCreateBuffer(Context, CL_MEM_READ_WRITE, buf_size, NULL, NULL);

  if( ! CL_Resp_Buffer )
    {
      Err_Message("### Error: ClDevice::Init_Kernel_Interface - Cannot allocate output data buffer\n");
      return(false);
    }

  if( clSetKernelArg(Kernel, 2, sizeof(CL_Resp_Buffer), &CL_Resp_Buffer) != CL_SUCCESS )
    {
      Err_Message("### Error: ClDevice::Init_Kernel_Interface - Cannot set output data buffer");
      return(false);
    }

  return(true);
}

//====================================================================================================//


struct rsa_montg_number_t
{
  explicit rsa_montg_number_t(size_t word_count = 0, const rsa_word_t* words_ptr = 0) : word_count(word_count), words_ptr(words_ptr)
    {
    }

    size_t get_actual_bit_size() const;

    size_t size() const { return word_count; }

    bool empty() const { return word_count == 0; }

    const rsa_word_t* begin() const { return words_ptr; }

    const rsa_word_t* end() const { return words_ptr + word_count; }

    rsa_word_t front() const { return words_ptr[      0     ]; }
    rsa_word_t back () const { return words_ptr[word_count-1]; }

    static size_t trimmed_size(size_t size, const rsa_word_t* words)
    {
      while ( size && !words[size-1] )
        {
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

inline size_t count_high_zero_bits(rsa_word_t v)
{
    return __builtin_clzll(v);
}

size_t rsa_montg_number_t::get_actual_bit_size() const
{
    if ( empty() ) return 0;
//    assert(back());
    return size()*RSA_WORD_BITS - count_high_zero_bits(back());
}


inline rsa_montg_number_t rsa_montg_trim(size_t word_count, const rsa_word_t* words_ptr)
{
    return rsa_montg_number_t( rsa_montg_number_t::trimmed_size(word_count, words_ptr), words_ptr);
}

inline rsa_montg_number_t rsa_montg_trim_bits(size_t bit_count, const rsa_word_t* words_ptr)
{
    return rsa_montg_trim((bit_count+RSA_WORD_BITS-1)/RSA_WORD_BITS, words_ptr);
}



template<size_t BITS> struct MPNInt
{
    static const size_t WORD_BITS = sizeof(mp_limb_t)*8;
    static const size_t WORD_COUNT = (BITS-1)/WORD_BITS+1;
    static const size_t TOTAL_BITS = WORD_BITS*WORD_COUNT;
    typedef mp_limb_t word_t;

    static size_t get_word_count(size_t bits)
    {
      return (bits-1)/WORD_BITS+1;
    }

    word_t words[WORD_COUNT];

    MPNInt()
    {
    }

    MPNInt(size_t bit)
    {
      std::fill(words, words+WORD_COUNT, 0);
      set_bit(bit);
    }

    void set_bit(size_t bit)
    {
//      assert(bit < TOTAL_BITS);
      words[bit/WORD_BITS] |= word_t(1)<<bit%WORD_BITS;
    }
};


static inline void rsa_montg_mod(rsa_word_t* result, rsa_montg_number_t data, rsa_montg_number_t mod)
{
  const bool use_mpn = sizeof(mp_limb_t) == sizeof(uint64_t);

  if ( use_mpn )
    {
      mp_limb_t q2[RSA_INPUT_WORDS+1];

      mpn_tdiv_qr(q2, (mp_limb_t*)result, 0, (const mp_limb_t*)data.begin(), data.size(), (const mp_limb_t*)mod.begin(), mod.size());
    }
  else
    {
      GMPInt m = GMPInt(mod.begin(), mod.size());
      GMPInt r = GMPInt(data.begin(), data.size());

      r = r%m;

      r.get_to_words(result, mod.size());
    }
}


static void calc_r2(rsa_word_t* out, size_t mod_bits, const rsa_word_t* mod)
{
  size_t mod_words = (mod_bits+RSA_WORD_BITS-1)/RSA_WORD_BITS;

  const size_t MAX_R2_BIT = GET_MONTG_R2_BIT(MAX_RSA_BITS);

  size_t r2_bit = GET_MONTG_R2_BIT(mod_bits);

//  assert((mod[mod_words-1] >> (mod_bits-1)%RSA_WORD_BITS) == 1);

  const size_t MAX_R2_WORDS = (MAX_R2_BIT+RSA_WORD_BITS)/RSA_WORD_BITS;

  size_t r2_words = (r2_bit+RSA_WORD_BITS)/RSA_WORD_BITS;

//  assert(r2_words <= MAX_R2_WORDS);

  rsa_word_t r2[MAX_R2_WORDS];

  fill(r2, r2+r2_words-1, 0);

  r2[r2_words-1] = rsa_word_t(1)<<(r2_bit%RSA_WORD_BITS);

  rsa_montg_mod(out, rsa_montg_number_t(r2_words, r2), rsa_montg_number_t(mod_words, mod));
}

inline bool correct_bit_count(const rsa_word_t* words, size_t bit_count, size_t max_bit_count)
{
    if ( bit_count < 2 || bit_count > max_bit_count )
        return false;

    rsa_word_t high_word = words[(bit_count-1)/RSA_WORD_BITS];

    size_t high_bit = (bit_count-1)%RSA_WORD_BITS;

    if ( (high_word>>high_bit) != 1 )
        return false;

    return true;
}


bool rsa_montg_init_params(MontgPowParams* params, rsa_montg_number_t mod, rsa_montg_number_t exp, PowerMode mode)
{
  size_t mod_bits = mod.get_actual_bit_size();
  size_t exp_bits = exp.get_actual_bit_size();

  if ( !correct_bit_count(mod.begin(), mod_bits, MAX_RSA_BITS) )
    {
        cerr << "Invalid mod_bits="<<mod_bits<<endl;
        return false;
    }

    if ( !correct_bit_count(exp.begin(), exp_bits, mod_bits) )
    {
        cerr << "Invalid exp_bits="<<exp_bits<<endl;
        return false;
    }

    params->mod_bits = mod_bits;
    params->exp_bits = exp_bits;
    params->n = GET_MONTG_WORD_COUNT(mod_bits)+1;


    fill(copy(mod.begin(), mod.end(), params->mod64), params->mod64+RSA_INPUT_WORDS, 0);

    fill(copy(exp.begin(), exp.end(), params->exp), params->exp+RSA_INPUT_WORDS, 0);

    calc_r2(params->r264, mod_bits, mod.begin());

    fill(params->r264+mod.size(), params->r264+RSA_INPUT_WORDS, 0);

//    assert(GMPInt(mod.begin(), mod.size()) == GMPInt(params->mod64, RSA_INPUT_WORDS));

    return true;
}

void ClDevice::Make_Request(const MontgPowParams& params, const rsa_word_t* data, rsa_word_t* args)
{
    bool const_time = params.mode == secure_power;
    const_time = false;

    size_t first_exp_bit = params.exp_bits-1;
    if ( const_time ) {
        first_exp_bit = params.mod_bits-1;
    }

    rsa_word_t sizes = params.mod_bits;
    sizes |= first_exp_bit << 16;
    sizes |= uint64_t(params.n) << 32;
    sizes |= uint64_t(const_time) << 40;
    args[ARG_SIZES_POS] = sizes;

    //-----------------------------------------------------------------------//

//    assert(ARG64_EXP_SIZE == RSA_INPUT_WORDS );

    copy(params.exp, params.exp+ARG64_EXP_SIZE, args+ARG64_EXP_POS);

    //-----------------------------------------------------------------------//

//    assert(ARG64_MOD_SIZE == RSA_INPUT_WORDS);

    copy(params.mod64, params.mod64+ARG64_MOD_SIZE, args+ARG64_MOD_POS);

    //-----------------------------------------------------------------------//

//    assert(ARG64_BASE_SIZE == RSA_INPUT_WORDS);

    copy(data, data+ARG64_BASE_SIZE, args+ARG64_BASE_POS);

    //-----------------------------------------------------------------------//

//    assert(ARG64_R2_SIZE == RSA_INPUT_WORDS);

    copy(params.r264, params.r264+ARG64_R2_SIZE, args+ARG64_R2_POS);
}

size_t get_actual_bit_size(rsa_word_t *words, size_t word_count)
{
  while ( word_count > 0 && !words[word_count-1] )
  {
      word_count -= 1;
  }

  size_t bit_size = word_count * sizeof(rsa_word_t) * 8;

  if ( word_count )
  {
      bit_size -= __builtin_clzll(words[word_count-1]);
  }

  return bit_size;
}


ClDevice::rr_state ClDevice::Add_Request(int &id, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m)
{
  id = -1;

  int idx = -1; 
                
  int qnt = 0;

  pthread_mutex_lock(&Rqst_Lock);
  //{
      if( Rqst_Qnt == UNIT_COUNT )
        {
          pthread_mutex_unlock(&Rqst_Lock);

          return( RR_SLOT_FULL );
        }

      timespec tm_s, tm_e; 

      clock_gettime(CLOCK_REALTIME, &tm_s);


      idx = Rqst_Qnt++;

      id = (idx & 0xFFF) | ((GID_Counter++) << 12);

  //}
  pthread_mutex_unlock(&Rqst_Lock);

      //---------------------------------------//

      rsa_word_t mod[RSA_INPUT_WORDS];

      qnt = (RSA_INPUT_WORDS * sizeof(rsa_word_t)) < (m->top * sizeof(BN_ULONG)) ? (RSA_INPUT_WORDS * sizeof(rsa_word_t)) / sizeof(BN_ULONG) : m->top;

      for(int i = 0; i < RSA_INPUT_WORDS; i++)
        mod[i] = 0;

      for(int i = 0; i < qnt; i++)
        ((BN_ULONG*)mod)[i] = m->d[i];

      size_t mod_bits = get_actual_bit_size(mod, qnt);

      //---------------------------------------//

      rsa_word_t exp[RSA_INPUT_WORDS];

      qnt = (RSA_INPUT_WORDS * sizeof(rsa_word_t)) < (p->top * sizeof(BN_ULONG)) ? (RSA_INPUT_WORDS * sizeof(rsa_word_t)) / sizeof(BN_ULONG) : p->top;

      for(int i = 0; i < RSA_INPUT_WORDS; i++)
        exp[i] = 0;

      for(int i = 0; i < qnt; i++)
        ((BN_ULONG*)exp)[i] = p->d[i];

      //---------------------------------------//

      Rqst_Aux[idx].stat = RR_SLOT_READY;
      Rqst_Aux[idx].id   = id;

      //---------------------------------------//

      rsa_word_t inp[RSA_INPUT_WORDS];

      qnt = (RSA_INPUT_WORDS * sizeof(rsa_word_t)) < (a->top * sizeof(BN_ULONG)) ? (RSA_INPUT_WORDS * sizeof(rsa_word_t)) / sizeof(BN_ULONG) : a->top;

      for(int i = 0; i < RSA_INPUT_WORDS; i++)
        inp[i] = 0;

      for(int i = 0; i < qnt; i++)
        ((BN_ULONG*)inp)[i] = a->d[i];

      //---------------------------------------//

      rsa_montg_init_params( &Rqst_Aux[idx].prm, rsa_montg_trim_bits(mod_bits, mod), rsa_montg_trim_bits(mod_bits, exp), fast_power );                              

      Make_Request(Rqst_Aux[idx].prm, inp, &Rqst_Buffer[KERNEL_ARG_WORDS*idx]);                                                                                      

      clock_gettime(CLOCK_REALTIME, &tm_e);

      Rqst_Time.tv_sec  += tm_e.tv_sec  - tm_s.tv_sec;
      Rqst_Time.tv_nsec += tm_e.tv_nsec - tm_s.tv_nsec;

      if(Rqst_Time.tv_nsec >  1000000000) {Rqst_Time.tv_sec++; Rqst_Time.tv_nsec-=1000000000;}
      if(Rqst_Time.tv_nsec < -1000000000) {Rqst_Time.tv_sec--; Rqst_Time.tv_nsec+=1000000000;}

  pthread_mutex_lock(&Rqst_Rdy_Lock);
  //{
      Rqst_Rdy_Qnt++;
  //}
  pthread_mutex_unlock(&Rqst_Rdy_Lock);

  return( RR_SLOT_READY );
}

//====================================================================================================//
//                                                                                                    //
// The caller is responcible to setup r->top to right value, espesially if bit size of r is less      //
// than default 2048 bit. If r->top == 0 then r->dmax*sizeof(BN_ULONG) or 2048 determine result.      //
//                                                                                                    //
//====================================================================================================//

ClDevice::rr_state ClDevice::Get_Response(int id, BIGNUM *r)
{
  int idx = id & 0xFFF;

  int top;

  if(idx < 0 || idx >= UNIT_COUNT)
    return( RR_SLOT_ERROR );

  rr_state r_stat;

  pthread_mutex_lock(&Resp_Lock);
  //{
      if( Resp_Aux[idx].id != id)
        {                                                                                                                                 
          pthread_mutex_unlock(&Resp_Lock);                                                                                      
          return( RR_SLOT_BUSY );              //#ToDo check if id correct
        }

      r_stat = Resp_Aux[idx].stat;

      if( r_stat != RR_SLOT_READY )
        {
          pthread_mutex_unlock(&Resp_Lock);
          return( r_stat );
        }
  //}
  //pthread_mutex_unlock(&Resp_Lock);

  // If stat is RR_SLOT_READY then nobody touch Resp_Aux[idx] and mutex should be unlocked
  // to permit multi threading processing for response

  timespec tm_s, tm_e; 

  clock_gettime(CLOCK_REALTIME, &tm_s);

  rsa_word_t d[RSA_OUTPUT_WORDS];

  Make_Response(Resp_Aux[idx].prm, d,  &Resp_Buffer[ idx * KERNEL_RESULT_WORDS ]);

  //#06.11 int qnt = r->top ? r->top : (RSA_OUTPUT_WORDS * sizeof(rsa_word_t)) < (r->dmax * sizeof(BN_ULONG)) ? (RSA_OUTPUT_WORDS * sizeof(rsa_word_t)) / sizeof(BN_ULONG) : r->dmax;

  //#06.11 for(int i = 0; i < qnt; i++)
  //#06.11   r->d[i] = ((BN_ULONG*)d)[i];

  //#06.11 r->top = qnt;

  for(top = 0; top < r->dmax && ((BN_ULONG*)d)[top]; top++)
    r->d[top] = ((BN_ULONG*)d)[top];

  r->top = top;

//  memset( &Resp_Aux[idx].prm, 0xAB, sizeof(MontgPowParams));

//  memset( &Resp_Buffer[ idx * KERNEL_RESULT_WORDS ], 0xAB, KERNEL_RESULT_WORDS * sizeof(rsa_word_t));

  //pthread_mutex_lock(&Resp_Lock);
  //{
      Resp_Aux[idx].stat = RR_SLOT_EMPTY;
      Resp_Aux[idx].id   = 0;

      Resp_Qnt--;

      clock_gettime(CLOCK_REALTIME, &tm_e);

      Resp_Time.tv_sec  += tm_e.tv_sec  - tm_s.tv_sec;
      Resp_Time.tv_nsec += tm_e.tv_nsec - tm_s.tv_nsec;

      if(Resp_Time.tv_nsec >  1000000000) {Resp_Time.tv_sec++; Resp_Time.tv_nsec-=1000000000;}
      if(Resp_Time.tv_nsec < -1000000000) {Resp_Time.tv_sec--; Resp_Time.tv_nsec+=1000000000;}
  //}
  pthread_mutex_unlock(&Resp_Lock);

//  printf("Response - thread: %d, ID: %0X, Resp_Qnt: %d\n", (unsigned int)pthread_self(), id, Resp_Qnt);                                                                                   

  return( RR_SLOT_READY );
}

void ClDevice::Make_Response(const MontgPowParams& params, rsa_word_t* data, const rsa_word_t* args)
{
//  assert(RESULT64_WORDS == array_size(params.mod64));

  copy(args, args+RESULT64_WORDS, data);

//  assert(GMPInt(data, RESULT64_WORDS) < GMPInt(params.mod64, RSA_INPUT_WORDS));
}

void ClDevice::Compute()
{
  timespec krnl_tm_s, krnl_tm_e; 
  timespec rqst_tm_s, rqst_tm_e; 
  timespec resp_tm_s, resp_tm_e; 

  int rqst_rdy_qnt = -1;

  cl_event done_event;

  pthread_mutex_lock(&Rqst_Lock);
  //{
      pthread_mutex_lock(&Resp_Lock);
      //{
          if( Rqst_Qnt < 1 || Resp_Qnt > 0 || Krnl_Qnt > 0)      //No request or some result still ungetted or kernel is busy
            {
              pthread_mutex_unlock(&Rqst_Lock);
              pthread_mutex_unlock(&Resp_Lock);
              return;
            }
      //}
      pthread_mutex_unlock(&Resp_Lock);

      do 
        {
          pthread_mutex_lock(&Rqst_Rdy_Lock);
          //{
              rqst_rdy_qnt = Rqst_Rdy_Qnt;
          //}
          pthread_mutex_unlock(&Rqst_Rdy_Lock);
        } 
      while( rqst_rdy_qnt < Rqst_Qnt);

      pthread_mutex_lock(&Krnl_Lock);
      //{
          clock_gettime(CLOCK_REALTIME, &rqst_tm_s);

          Krnl_Qnt = Rqst_Qnt;

          if( clSetKernelArg(Kernel, 0, sizeof(Krnl_Qnt), &Krnl_Qnt) )
            {
              Err_Message("### Error: clSetKernelArg( Krnl_Qnt ) failed\n");
              pthread_mutex_unlock(&Krnl_Lock);
              pthread_mutex_unlock(&Rqst_Lock);
              return;
            }

          size_t args_size = Krnl_Qnt * KERNEL_ARG_WORDS * sizeof(rsa_word_t);

          if( clEnqueueWriteBuffer(Command_Queue, CL_Rqst_Buffer, CL_TRUE, 0, args_size, Rqst_Buffer, 0, 0, &done_event) )
            {
              Err_Message("### Error: clEnqueueWriteBuffer( Rqst_Buffer ) failed\n");
              pthread_mutex_unlock(&Krnl_Lock);
              pthread_mutex_unlock(&Rqst_Lock);
              return;
            }

          for(int i = 0; i < Krnl_Qnt; i++)        //ToDo Do we need to clear all data in Rqst_* for security reason?
            {
              Krnl_Aux[i] = Rqst_Aux[i];

              Rqst_Aux[i].stat = RR_SLOT_EMPTY;

//#Debug              memset( &Rqst_Aux[i].prm, 0xAB, sizeof(MontgPowParams));

//#Debug              memset( &Rqst_Buffer[ i * KERNEL_ARG_WORDS ], 0xAB, KERNEL_ARG_WORDS * sizeof(rsa_word_t));
            }

          if( clWaitForEvents(1, &done_event) )
            {
              Err_Message("### Error: clWaitForEvents for Rqst_Buffer failed\n");
              pthread_mutex_unlock(&Krnl_Lock);
              pthread_mutex_unlock(&Rqst_Lock);
              return;
            }

          Rqst_Qnt = 0;

          pthread_mutex_lock(&Rqst_Rdy_Lock);
          //{
              Rqst_Rdy_Qnt = 0;
          //}
          pthread_mutex_unlock(&Rqst_Rdy_Lock);

          clock_gettime(CLOCK_REALTIME, &rqst_tm_e);

          DPut_Time.tv_sec  += rqst_tm_e.tv_sec  - rqst_tm_s.tv_sec;
          DPut_Time.tv_nsec += rqst_tm_e.tv_nsec - rqst_tm_s.tv_nsec;

          if(DPut_Time.tv_nsec >  1000000000) {DPut_Time.tv_sec++; DPut_Time.tv_nsec-=1000000000;}
          if(DPut_Time.tv_nsec < -1000000000) {DPut_Time.tv_sec--; DPut_Time.tv_nsec+=1000000000;}

  //}
  pthread_mutex_unlock(&Rqst_Lock);

          clock_gettime(CLOCK_REALTIME, &krnl_tm_s);

//          printf("Kernel Start\n");

          if( clEnqueueTask(Command_Queue, Kernel, 0, NULL, &done_event) )
            {
              Err_Message("### Error: clEnqueueTask() failed\n");
              pthread_mutex_unlock(&Krnl_Lock);
              return;
            }
  			
          if ( clWaitForEvents(1, &done_event) )
            {
              Err_Message("### Error: clWaitForEvents( Kernel ) failed\n");
              pthread_mutex_unlock(&Krnl_Lock);
              return;
  			    }

          clock_gettime(CLOCK_REALTIME, &krnl_tm_e);

          Krnl_Time.tv_sec  += krnl_tm_e.tv_sec  - krnl_tm_s.tv_sec;
          Krnl_Time.tv_nsec += krnl_tm_e.tv_nsec - krnl_tm_s.tv_nsec;

          if(Krnl_Time.tv_nsec >  1000000000) {Krnl_Time.tv_sec++; Krnl_Time.tv_nsec-=1000000000;}
          if(Krnl_Time.tv_nsec < -1000000000) {Krnl_Time.tv_sec--; Krnl_Time.tv_nsec+=1000000000;}

//          printf("Kernel done\n");

  pthread_mutex_lock(&Resp_Lock);
  //{
          clock_gettime(CLOCK_REALTIME, &resp_tm_s);
         
          Multiplication_Counter += Krnl_Qnt;
          
          Krnl_Run_Qnt++;

          Resp_Qnt  = Krnl_Qnt;

          size_t resp_size = Resp_Qnt * KERNEL_RESULT_WORDS * sizeof(rsa_word_t);

          if( clEnqueueReadBuffer(Command_Queue, CL_Resp_Buffer, CL_TRUE, 0, resp_size, Resp_Buffer, 0, 0, &done_event) )
            {
              Err_Message("### Error: clEnqueueReadBuffer( Resp_Buffer ) failed\n");
              pthread_mutex_unlock(&Krnl_Lock);
              pthread_mutex_unlock(&Resp_Lock);
              return;
            }

          if ( int err = clWaitForEvents(1, &done_event) )
            {
              Err_Message("### Error: clWaitForEvents for Resp_Buffer failed\n");
              pthread_mutex_unlock(&Krnl_Lock);
              pthread_mutex_unlock(&Resp_Lock);
              return;
            }

          clock_gettime(CLOCK_REALTIME, &resp_tm_e);

          DGet_Time.tv_sec  += resp_tm_e.tv_sec  - resp_tm_s.tv_sec;
          DGet_Time.tv_nsec += resp_tm_e.tv_nsec - resp_tm_s.tv_nsec;

          if(DGet_Time.tv_nsec >  1000000000) {DGet_Time.tv_sec++; DGet_Time.tv_nsec-=1000000000;}
          if(DGet_Time.tv_nsec < -1000000000) {DGet_Time.tv_sec--; DGet_Time.tv_nsec+=1000000000;}

          for(int i = 0; i < Resp_Qnt; i++)        //ToDo Do we need to clear all data in Rqst_* for security reason?
            {
              Resp_Aux[i] = Krnl_Aux[i];

              Resp_Aux[i].stat = RR_SLOT_READY;
            }

          Krnl_Qnt = 0;

//          printf("Data received from Kernel\n");
      //}
      pthread_mutex_unlock(&Krnl_Lock);
  //}
  pthread_mutex_unlock(&Resp_Lock);
}                                                                                                                                        