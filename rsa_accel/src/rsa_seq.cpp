#include "rsa_seq.h"

#ifdef USE_OPENCL
#include <CL/opencl.h>
#endif

#include "rsa_gmp.h"
#include "rsa_seq_impl.h"
#include "timer.h"
#include <vector>
#include <cassert>
#include "rsa_hls_def.h"

//#define TRACE

using namespace std;

// OpenCL wrapper control
bool benchmarking = false;
int bench_packet = 0;
bool bench_clock = false;
bool skip_opencl_call = false;
int kernel_call_count = 1;

struct TimerStatReporter {
    vector<const char*> names;
    vector<uint64_t> clocks;
    vector<uint64_t> counts;

    static void start();
    static void report(const char* name, uint64_t clock, uint64_t calls);
    
    ~TimerStatReporter();
};

void TimerStatReporter::report(const char* name, uint64_t clock, uint64_t count)
{
    static TimerStatReporter reporter;
    reporter.names.push_back(name);
    reporter.clocks.push_back(clock);
    reporter.counts.push_back(count);
}
void TimerStatReporter::start()
{
    report(0, 0, 0);
}
TimerStatReporter::~TimerStatReporter()
{
    const double frequency = TimerStat::get_CPU_frequency();
    for ( size_t i = names.size(); i--; ) {
        if ( counts[i] ) {
            std::cout << names[i] << ": "
                      <<clocks[i]<<"/"<<counts[i]<<" clocks = "
                      <<(double(clocks[i])/counts[i]/frequency*1e6)<<" mks"<<std::endl;
        }
    }
}

double TimerStat::get_sys_time()
{
    timeval tv;
    gettimeofday(&tv, 0);
    return tv.tv_sec+tv.tv_usec*1e-6;
}

double TimerStat::start_time;
uint64_t TimerStat::start_clock;
double TimerStat::frequency;

void TimerStat::init_start_clock()
{
    if ( !start_clock ) {
        TimerStatReporter::start();
        start_time = get_sys_time();
        start_clock = rdtsc();
    }
}

double TimerStat::get_CPU_frequency()
{
    if ( !frequency ) {
        double end_time = get_sys_time();
        uint64_t end_clock = rdtsc();

        double time = end_time - start_time;
        uint64_t clock = end_clock - start_clock;

        frequency = clock/time;
        cout << "CPU frequency: "<<frequency*1e-6<<" MHz"<<endl;
    }
    return frequency;
}

void TimerStat::report() const
{
    if ( bench_clock ) {
        TimerStatReporter::report(name, call_clocks, call_count);
    }
}

template<class T, size_t N>
inline size_t array_size(T (&)[N]) { return N; }

//#define ARRAY_FILL 77
#ifdef ARRAY_FILL
# define INIT_ARRAY(name) memset(&name, ARRAY_FILL, sizeof(name))
# define INIT_PTR_ARRAY(ptr, size) memset(ptr, ARRAY_FILL, sizeof(*ptr)*(size))
#else
# define INIT_ARRAY(name) do{}while(0)
# define INIT_PTR_ARRAY(ptr, size) do{}while(0)
#endif

inline size_t count_high_zero_bits(rsa_word_t v)
{
    return __builtin_clzll(v);
}

size_t rsa_montg_bit_count_from_exact_word_count(size_t exact_word_count,
                                                 const rsa_word_t* words)
{
    if ( !exact_word_count ) return 0;
    return exact_word_count*RSA_WORD_BITS-count_high_zero_bits(words[exact_word_count-1]);
}
size_t rsa_montg_bit_count_from_max_word_count(size_t max_word_count,
                                               const rsa_word_t* words)
{
    while ( max_word_count && !words[max_word_count-1] )
        --max_word_count;
    return rsa_montg_bit_count_from_exact_word_count(max_word_count, words);
}

template<int W>
inline
GMPInt gmp(const ap_uint<W>& v)
{
    const size_t K = RSAIntBase::WORD_BITS;
    const size_t M = (W-1)/K+1;
    RSAIntBase::word_t tmp[M];
    for ( int i = 0; i*K < W; ++i ) {
        tmp[i] = ap_uint<K>(v >> i*K);
    }
    return GMPInt(tmp, M);
}

ostream& operator<<(ostream& out, rsa_montg_number_t v)
{
    return out << GMPInt(v.begin(), v.size());
}

size_t rsa_montg_number_t::get_actual_bit_size() const
{
    if ( empty() ) return 0;
    assert(back());
    return size()*RSA_WORD_BITS - count_high_zero_bits(back());
}

template<size_t BITS>
struct MPNInt
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
        assert(bit < TOTAL_BITS);
        words[bit/WORD_BITS] |= word_t(1)<<bit%WORD_BITS;
    }
};

static inline void rsa_montg_mod(rsa_word_t* result, rsa_montg_number_t data, rsa_montg_number_t mod)
{
    const bool use_mpn = sizeof(mp_limb_t) == sizeof(uint64_t);
    if ( use_mpn ) {
        if ( data.size() < mod.size() ) {
            copy(data.begin(), data.end(), result);
            fill(result+data.size(), result+mod.size(), 0);
        }
        else {
            size_t q2_words = data.size()-mod.size()+1;
            mp_limb_t q2[q2_words];
            mpn_tdiv_qr(q2, (mp_limb_t*)result, 0, (const mp_limb_t*)data.begin(), data.size(), (const mp_limb_t*)mod.begin(), mod.size());
        }
    }
    else {
        GMPInt m = GMPInt(mod.begin(), mod.size());
        GMPInt r = GMPInt(data.begin(), data.size());
        r = r%m;
        r.get_to_words(result, mod.size());
    }
}

static
void calc_r2(rsa_word_t* out, size_t mod_bits, const rsa_word_t* mod, size_t montg_word_bits)
{
    size_t mod_words = rsa_bits_to_words(mod_bits);
    size_t r2_bit = GET_MONTG_R2_BIT2(mod_bits, montg_word_bits);
    assert((mod[mod_words-1] >> (mod_bits-1)%RSA_WORD_BITS) == 1);
    size_t r2_words = rsa_bits_to_words(r2_bit+1);
    rsa_word_t r2[r2_words];
    fill(r2, r2+r2_words-1, 0);
    r2[r2_words-1] = rsa_word_t(1)<<(r2_bit%RSA_WORD_BITS);
    rsa_montg_mod(out, rsa_montg_number_t(r2_words, r2), rsa_montg_number_t(mod_words, mod));
}

inline bool correct_bit_count(const rsa_word_t* words, size_t bit_count, size_t max_bit_count)
{
    if ( bit_count < 1 || bit_count > max_bit_count )
        return false;
    rsa_word_t high_word = words[(bit_count-1)/RSA_WORD_BITS];
    size_t high_bit = (bit_count-1)%RSA_WORD_BITS;
    if ( (high_word>>high_bit) != 1 )
        return false;
    return true;
}

MontgPowParams* rsa_montg_alloc_params()
{
    TIMER("alloc_params");
    MontgPowParams* params = new MontgPowParams;
#ifdef ARRAY_FILL
    memset(params, 0x23, sizeof(*params));
#endif
    return params;
}

void rsa_montg_free_params(MontgPowParams* params)
{
    TIMER("free_params");
    delete params;
}

MontgPowParams* rsa_montg_alloc_init_params(rsa_montg_number_t mod,
                                            rsa_montg_number_t exp,
                                            PowerMode mode)
{
    MontgPowParams* params = rsa_montg_alloc_params();
    if ( !rsa_montg_init_params(params, mod, exp, mode) ) {
        rsa_montg_free_params(params);
        return 0;
    }
    return params;
}

bool rsa_montg_init_params(MontgPowParams* params,
                           rsa_montg_number_t mod,
                           rsa_montg_number_t exp,
                           PowerMode mode)
{
    TIMER("init_params");
    size_t max_mod_bits = KernelNS::get_max_mod_bits();
    size_t montg_word_bits = KernelNS::get_montg_word_bits();
    size_t mod_bits = mod.get_actual_bit_size();
    size_t exp_bits = exp.get_actual_bit_size();
    if ( mod_bits > MAX_RSA_BITS ) {
        cerr << "Too long modulus: "<<mod_bits<<" bits > library limit "<<MAX_RSA_BITS<<"."<<endl;
        return false;
    }
    if ( mod_bits > max_mod_bits ) {
        cerr << "Too long modulus: "<<mod_bits<<" bits > kernel limit "<<max_mod_bits<<"."<<endl;
        return false;
    }
    if ( !correct_bit_count(mod.begin(), mod_bits, max_mod_bits) ) {
        cerr << "Invalid mod_bits="<<mod_bits<<endl;
        return false;
    }
    if ( !correct_bit_count(exp.begin(), exp_bits, mod_bits) ) {
        cerr << "Invalid exp_bits="<<exp_bits<<endl;
        return false;
    }
    
    params->mod_bits = mod_bits;
    params->exp_bits = exp_bits;
    params->n = GET_MONTG_WORD_COUNT2(mod_bits, montg_word_bits)+1;
    
    fill(copy(mod.begin(), mod.end(), params->mod64), params->mod64+MAX_RSA_WORDS, 0);
    fill(copy(exp.begin(), exp.end(), params->exp), params->exp+MAX_RSA_WORDS, 0);
    calc_r2(params->r264, mod_bits, mod.begin(), montg_word_bits);
    fill(params->r264+mod.size(), params->r264+MAX_RSA_WORDS, 0);
#ifdef TRACE
    cout << "init_params: mod: "<<GMPInt(params->mod64, MAX_RSA_WORDS)<<endl;
    cout << "init_params: exp: "<<GMPInt(params->exp, MAX_RSA_WORDS)<<endl;
    cout << "init_params: r2: "<<GMPInt(params->r264, MAX_RSA_WORDS)<<endl;
#endif
    assert(GMPInt(mod.begin(), mod.size()) == GMPInt(params->mod64, MAX_RSA_WORDS));
    return true;
}

rsa_word_t* rsa_montg_alloc_input()
{
    TIMER("alloc_input");
    rsa_word_t* ptr = new rsa_word_t[MAX_RSA_WORDS];
    INIT_PTR_ARRAY(ptr, MAX_RSA_WORDS);
    return ptr;
}

void rsa_montg_free_input(rsa_word_t* ptr)
{
    TIMER("free_input");
    delete[] ptr;
}

rsa_word_t* rsa_montg_alloc_output()
{
    TIMER("alloc_output");
    rsa_word_t* ptr = new rsa_word_t[MAX_RSA_WORDS];
    INIT_PTR_ARRAY(ptr, MAX_RSA_WORDS);
    return ptr;
}

void rsa_montg_free_output(rsa_word_t* ptr)
{
    TIMER("free_output");
    delete[] ptr;
}

void rsa_montg_init_public_input(rsa_word_t* input_ptr,
                                 rsa_montg_number_t data,
                                 rsa_montg_number_t mod)
{
    TIMER("init_public_input");
#ifdef TRACE
    cout << "init_input: base: "<<data<<endl;
#endif
    
    assert(mod.size() <= MAX_RSA_WORDS);
    assert(data.size() <= mod.size());

    copy(data.begin(), data.end(), input_ptr);
    if ( data.size() <= mod.size() ) {
        fill(input_ptr+data.size(), input_ptr+mod.size(), 0);
    }
}

rsa_word_t* rsa_montg_alloc_init_public_input(rsa_montg_number_t data,
                                              rsa_montg_number_t mod)
{
    rsa_word_t* input_ptr = rsa_montg_alloc_input();
    rsa_montg_init_public_input(input_ptr, data, mod);
    return input_ptr;
}

void rsa_montg_init_private_input(rsa_word_t* input_ptr,
                                  rsa_montg_number_t data,
                                  rsa_montg_number_t mod)
{
    TIMER("init_private_input");
    assert(mod.size() <= MAX_RSA_WORDS);
    if ( data.size() < mod.size() ) {
        fill(copy(data.begin(), data.end(), input_ptr), input_ptr+mod.size(), 0);
    }
    else {
        rsa_montg_mod(input_ptr, data, mod);
    }
    fill(input_ptr+mod.size(), input_ptr+MAX_RSA_WORDS, 0);
#ifdef TRACE
    cout << "init_input: base: "<<GMPInt(input_ptr, MAX_RSA_WORDS)<<endl;
#endif
}

rsa_word_t* rsa_montg_alloc_init_private_input(rsa_montg_number_t data,
                                               rsa_montg_number_t mod)
{
    rsa_word_t* input_ptr = rsa_montg_alloc_input();
    rsa_montg_init_private_input(input_ptr, data, mod);
    return input_ptr;
}

void rsa_montg_combine_private_outputs(rsa_word_t* output,
                                       const rsa_word_t* output1,
                                       const rsa_word_t* output2,
                                       rsa_montg_number_t mod1,
                                       rsa_montg_number_t mod2,
                                       rsa_montg_number_t coeff)
{
    TIMER("combine_private_output");
    const bool use_mpn = sizeof(rsa_word_t) == sizeof(mp_limb_t);
    if ( use_mpn ) {
        assert(mod1.size() >= mod2.size());
        assert(coeff.size() <= mod2.size());
        mp_limb_t tmp[MAX_RSA_WORDS];
        if ( mpn_sub(tmp, (const mp_limb_t*)output1, mod1.size(), (const mp_limb_t*)output2, mod2.size()) ) {
            mpn_add_n(tmp, tmp, (const mp_limb_t*)mod1.begin(), mod1.size());
        }
        mp_limb_t tmp2[MAX_RSA_WORDS+1];
        assert(mod1.size()+coeff.size() <= MAX_RSA_WORDS+1);
        mpn_mul(tmp2, tmp, mod1.size(), (const mp_limb_t*)coeff.begin(), coeff.size());
        rsa_montg_mod((rsa_word_t*)tmp, rsa_montg_trim(mod1.size()+coeff.size(), (const rsa_word_t*)tmp2), mod1);
        mpn_mul(tmp2, tmp, mod1.size(), (const mp_limb_t*)mod2.begin(), mod2.size());
        size_t res_words = rsa_montg_number_t::trimmed_size(mod1.size()+mod2.size(), (const rsa_word_t*)tmp2);
        assert(res_words <= MAX_RSA_WORDS);
        mp_limb_t c;
        if ( res_words >= mod2.size() ) {
            c = mpn_add((mp_limb_t*)output, tmp2, res_words, (const mp_limb_t*)output2, mod2.size());
        }
        else {
            c = mpn_add((mp_limb_t*)output, (const mp_limb_t*)output2, mod2.size(), tmp2, res_words);
            res_words = mod2.size();
        }
        if ( c ) {
            assert(res_words < MAX_RSA_WORDS);
            output[res_words++] = c;
        }
        fill(output+res_words, output+MAX_RSA_WORDS, 0);
    }
    else {
        //GMPInt ret = output2 + mulm(subm2(output1, output2, key.prime1), key.coefficient, key.prime1)*key.prime2;
        GMPInt m1(mod1.begin(), mod1.size());
        GMPInt m2(mod2.begin(), mod2.size());
        GMPInt r1(output1, mod1.size());
        GMPInt r2(output2, mod2.size());
        GMPInt c(coeff.begin(), coeff.size());
        GMPInt h = r1-r2;
        if ( h < 0 ) {
            h = h+m1;
        }
        h = h*c%m1*m2 + r2;
        h.get_to_words(output, MAX_RSA_WORDS);
    }
}

rsa_word_t* rsa_montg_alloc_combine_private_outputs(const rsa_word_t* output1,
                                                    const rsa_word_t* output2,
                                                    rsa_montg_number_t mod1,
                                                    rsa_montg_number_t mod2,
                                                    rsa_montg_number_t coeff)
{
    rsa_word_t* output = rsa_montg_alloc_output();
    rsa_montg_combine_private_outputs(output, output1, output2, mod1, mod2, coeff);
    return output;
}

namespace KernelNS {
    struct Buffer {
        Buffer() :
#ifdef USE_OPENCL
            arr(0), cl_buffer(0)
#else
            arr(0)
#endif
        {
        }
        void alloc(size_t word_count, bool write_only = false);
        void free();
        rsa_word_t* arr;
#ifdef USE_OPENCL
        cl_mem cl_buffer;
#endif
    };
}

# define kernel_entry rsaMontgPowNKernelEntry64
static const char* const kernel_entry_name = "rsaMontgPowNKernelEntry64";
static const size_t DEFAULT_RSA_BITS = 2048;
static const size_t LIMIT_RSA_BITS = 4096;
static const size_t DEFAULT_RSA_WORDS = DEFAULT_RSA_BITS/RSA_WORD_BITS;
// static const size_t DEFAULT_UNIT_COUNT = 400;
static const size_t LIMIT_UNIT_COUNT = 570;
static const size_t DEFAULT_KERNEL_ARG_WORDS = 1+4*DEFAULT_RSA_WORDS;
// kernel args:
//  sizes
//  exp[N]
//  mod[N]
//  data[N]
//  r2[N]

static const size_t DEFAULT_KERNEL_RESULT_WORDS = DEFAULT_RSA_WORDS;

#ifdef USE_OPENCL
template<size_t S, class E> inline size_t arraysize(E(&)[S]) { return S; }

struct ClDevice {
    ClDevice()
        : platform_id(0),
          device_id(0),
          context(0),
          commands(0),
          program(0),
          kernel(0)
    {
    }
    ~ClDevice();

    bool device_is_open() const { return commands; }
    bool kernel_is_open() const { return kernel; }
    
    operator const void*() const { return kernel_is_open()? this: 0; }
    bool operator!() const { return !kernel_is_open(); }

    void open_device(const string& target_device_name);
    void close_device();
    void open_kernel(const string& kernel_file_name, const string& program_entry_name);
    void close_kernel();

    cl_platform_id platform_id;
    cl_device_id device_id;
    cl_context context;
    cl_command_queue commands;
    cl_program program;
    cl_kernel kernel;
    //cl_mem args_buffer;
    //cl_mem results_buffer;
};

ClDevice::~ClDevice()
{
    if ( *this ) {
        close_kernel();
        close_device();
        cout << "INFO: ClDevice closed" << endl;
    }
}

void ClDevice::close_kernel()
{
    if ( kernel ) {
        cout << "INFO: closing kernel" << endl;
        clReleaseKernel(kernel);
        kernel = 0;
    }
    if ( program ) {
        cout << "INFO: closing program" << endl;
        clReleaseProgram(program);
        program = 0;
    }
}

void ClDevice::close_device()
{
    if ( commands ) {
        cout << "INFO: closing commands" << endl;
        clReleaseCommandQueue(commands);
        commands = 0;
    }
    if ( context ) {
        cout << "INFO: closing context" << endl;
        clReleaseContext(context);
        context = 0;
    }
    if ( device_id ) {
        cout << "INFO: closing device" << endl;
        clReleaseDevice(device_id);
        device_id = 0;
    }
    /*
    if ( platform_id ) {
        clReleasePlatform(platform_id);
        platform_id = 0;
    }
    */
}

void ClDevice::open_device(const string& target_device_name)
{
    if ( device_is_open() ) {
        close_kernel();
        close_device();
    }
    
    int err;                            // error code returned from api calls
    
    cout << "Build for target device: " << target_device_name << endl;

    cl_platform_id platforms[16];       // platform id
    cl_uint platform_count;
    err = clGetPlatformIDs(arraysize(platforms), platforms, &platform_count);
    if ( err != CL_SUCCESS ) {
        cerr << "Error: Failed to find an OpenCL platform!" << endl;
        abort();
    }
    cout << "INFO: Found " << platform_count << " platform" << (platform_count > 1? "s": "") << endl;

    // Find Xilinx Platform
    char vendor[1000];
    bool platform_found = false;
    for ( cl_uint i = 0; i < platform_count; ++i ) {
        err = clGetPlatformInfo(platforms[i], CL_PLATFORM_VENDOR, arraysize(vendor)-1, (void *)vendor, 0);
        if ( err != CL_SUCCESS ) {
            cerr << "Error: clGetPlatformInfo(CL_PLATFORM_VENDOR) failed!" << endl;
            abort();
        }
        if ( strcmp(vendor, "Xilinx") == 0) {
            cout << "INFO: Selected platform "<<i<<" from " << vendor << endl;
            platform_id = platforms[i];
            platform_found = true;
        }
    }
    if ( !platform_found ) {
        cerr << "ERROR: Platform Xilinx not found. Exit." << endl;
        abort();
    }
    
    // Connect to a compute device
    // find all devices and then select the target device
    cl_device_id devices[16];  // compute device id 
    cl_uint device_count;
    err = clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_ACCELERATOR,
                         arraysize(devices), devices, &device_count);
    if ( err != CL_SUCCESS ) {
        cout <<"Error: Failed to create a device group !"<<endl;
        abort();
    }

    //iterate all devices to select the target device. 
    for ( cl_uint i = 0; i < device_count; ++i ) {
        char name[1001];
        err = clGetDeviceInfo(devices[i], CL_DEVICE_NAME, arraysize(name)-1, name, 0);
        if ( err != CL_SUCCESS ) {
            cerr << "Error: Failed to get device name for device "<<i<<"!"<<endl;
            abort();
        }
        cout << "CL_DEVICE_NAME "<<name<<endl;
        string target_vendor_device_name = "xilinx:"+target_device_name;
        if ( name == target_device_name || name == target_vendor_device_name ) {
            device_id = devices[i];
            cout << "INFO: Selected "<<name<<" as the target device"<<endl;
        }
    }
    if ( !device_id ) {
        cerr << "ERROR: Target device "<<target_device_name<<" not found. Exit." << endl;
        abort();
    }
    cout << "INFO: device_id: "<<device_id<<endl;

    // Create a compute context 
    //
    context = clCreateContext(0, 1, &device_id, 0, 0, &err);
    if ( !context ) {
        cerr << "Error: Failed to create a compute context!" << endl;
        abort();
    }

    // Create a command commands
    //
    commands = clCreateCommandQueue(context, device_id, CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE, &err);
    if ( !commands ) {
        cerr << "Error: Failed to create a command commands!" << endl;
        abort();
    }
}


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

void ClDevice::open_kernel(const string& xclbin, const string& kernel_entry_name)
{
    if ( kernel_is_open() ) {
        close_kernel();
    }
    
    int err;                            // error code returned from api calls

    cout << "INFO: Loading " << xclbin << endl;
    char *kernel_ptr;
    size_t kernel_size = load_file_to_memory(xclbin.c_str(), &kernel_ptr);
    if ( !kernel_size ) {
        cerr << "Error: failed to load kernel from "<<xclbin<<endl;
        abort();
    }

    int status;
    // Create the compute program from offline
    program = clCreateProgramWithBinary(context, 1, &device_id, &kernel_size,
                                        (const unsigned char **)&kernel_ptr, &status, &err);
    if ( (!program) || (err!=CL_SUCCESS) ) {
        cerr << "Error: Failed to create compute program from binary "<<err<<"!"<<endl;
        abort();
    }

    // Build the program executable
    //
    err = clBuildProgram(program, 0, 0, 0, 0, 0);
    if ( err != CL_SUCCESS ) {
        size_t len;
        char buffer[2048];
        
        cerr << "Error: Failed to build program executable!" << endl;
        clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, sizeof(buffer), buffer, &len);
        cerr << buffer << endl;
        abort();
    }

    // Create the compute kernel in the program we wish to run
    //
    kernel = clCreateKernel(program, kernel_entry_name.c_str(), &err);
    if (!kernel || err != CL_SUCCESS) {
        cerr << "Error: Failed to create compute kernel!"<<endl;
        abort();
    }
}

static ClDevice device;

#endif

static
void dump_words(const rsa_word_t* buf, size_t words)
{
    cout << hex << setfill('0');
    uint64_t hash = 0;
    for ( size_t i = 0; i < words; ++i ) {
        hash = hash*17 ^ buf[i];
    }
    cout << "hash: "<<hash<<endl;
    for ( size_t i = 0; i < words; ++i ) {
        cout << ' ' << setw(16) << buf[i];
        if ( i % 4 == 3 ) cout << endl;
    }
    cout << dec << setfill('\0') << endl;
}

#ifdef USE_OPENCL
static
void dump_buffer(const cl_mem& buf, size_t words)
{
    rsa_word_t* tmp = new rsa_word_t[words];
    cl_event done_event = 0;
    if ( int err = clEnqueueReadBuffer(device.commands, buf, CL_TRUE, 0, words*sizeof(rsa_word_t), tmp, 0, 0, &done_event) ) {
        cerr << "Error: Failed to enqueue result receive! err="<<err<<endl;
        abort();
    }
    if ( int err = clWaitForEvents(1, &done_event) ) {
        cerr << "Error: Failed to wait read! err="<<err<<endl;
        abort();
    }
    dump_words(tmp, words);
    delete[] tmp;
}
#endif

namespace KernelNS {
    RSAMontgInfo kernel_info = {};

    RSAMontgInfo get_default_kernel_info();

    const RSAMontgInfo& get_kernel_info()
    {
        if ( !kernel_info.info_size ) {
            //kernel_info = get_default_kernel_info();
            kernel_info = read_kernel_info();
        }
        return kernel_info;
    }

    uint16_t get_max_mod_bits()
    {
        return get_kernel_info().max_mod_bits;
    }
    uint16_t get_max_req_count()
    {
        uint16_t max_req_count = get_kernel_info().max_req_count;
        return bench_packet? min(uint16_t(bench_packet), max_req_count): max_req_count;
    }
    uint16_t get_montg_word_bits()
    {
        return get_kernel_info().montg_word_bits;
    }

    void Buffer::alloc(size_t word_count, bool write_only)
    {
        assert(!arr);
        arr = new rsa_word_t[word_count];
#ifdef USE_OPENCL
        if ( device ) {
            assert(!cl_buffer);
            int flags = write_only? CL_MEM_WRITE_ONLY: CL_MEM_READ_ONLY;
            cl_buffer = clCreateBuffer(device.context, flags, word_count*sizeof(rsa_word_t), 0, 0);
            if ( !cl_buffer ) {
                cerr << "Error: cannot allocate buffer!"<<endl;
                abort();
            }
        }
#endif
    }
    void Buffer::free()
    {
#ifdef USE_OPENCL
        if ( cl_buffer ) {
            clReleaseMemObject(cl_buffer);
            cl_buffer = 0;
        }
#endif
        delete[] arr;
        arr = 0;
    }

    struct Args : public Buffer {
    };
    struct Results : public Buffer {
#ifdef USE_OPENCL
        Results() : req_count(0), kernel_call_done_event(0) {} 
        uint16_t req_count;
        cl_event kernel_call_done_event;
#endif
    };

    Args* alloc_args()
    {
        Args* args = new Args;
        args->alloc(get_max_req_count()*get_kernel_info().request_words);
        return args;
    }
    void free_args(Args* args)
    {
        args->free();
        delete args;
    }
    rsa_word_t* get_req_args(Args* args, uint16_t index)
    {
        assert(index < get_max_req_count());
        return args->arr+index*get_kernel_info().request_words;
    }
    const rsa_word_t* get_req_args(const Args* args, uint16_t index)
    {
        assert(index < get_max_req_count());
        return args->arr+index*get_kernel_info().request_words;
    }

    Results* alloc_results()
    {
        Results* results = new Results;
        results->alloc(get_max_req_count()*get_kernel_info().result_words, true);
        return results;
    }
    void free_results(Results* results)
    {
        results->free();
        delete[] results;
    }
    rsa_word_t* get_req_results(Results* results, uint16_t index)
    {
        assert(index < get_max_req_count());
        return results->arr+index*get_kernel_info().result_words;
    }
    const rsa_word_t* get_req_results(const Results* results, uint16_t index)
    {
        assert(index < get_max_req_count());
        return results->arr+index*get_kernel_info().result_words;
    }

    inline
    void set_int(rsa_word_t* dst, size_t dst_size, rsa_montg_number_t src)
    {
        assert(src.size() <= dst_size);
        fill(copy(src.begin(), src.end(), dst), dst+dst_size, 0);
    }

    // returns place for data
    pair<rsa_word_t*, size_t> init_params(rsa_word_t* args,
                                          const MontgPowParams& params)
    {
        pair<rsa_word_t*, size_t> ret;
        TIMER("init_params");

        size_t max_mod_bits = get_max_mod_bits();
        size_t max_mod_words = rsa_bits_to_words(max_mod_bits);

        bool const_time = params.mode == secure_power;
        const_time = false;

        size_t first_exp_bit = params.exp_bits-1;
        if ( const_time ) {
            first_exp_bit = params.mod_bits-1;
        }

        // set sizes
        uint64_t sizes = params.mod_bits;
        sizes |= first_exp_bit << 16;
        sizes |= uint64_t(params.n) << 32;
        sizes |= uint64_t(const_time) << 40;
        *args++ = sizes;
        
        // set exp
        std::copy(params.exp, params.exp+max_mod_words, args);
        args += max_mod_words;

        // set mod
        std::copy(params.mod64, params.mod64+max_mod_words, args);
        args += max_mod_words;

        // skip data
        ret.first = args;
        ret.second = max_mod_words;
        args += max_mod_words;

        // set r2
        std::copy(params.r264, params.r264+max_mod_words, args);
        return ret;
    }

    // returns place for data
    pair<rsa_word_t*, size_t> init_params(rsa_word_t* args,
                                          rsa_montg_number_t mod,
                                          rsa_montg_number_t exp,
                                          PowerMode mode)
    {
        pair<rsa_word_t*, size_t> ret;
        TIMER("init_params");
        size_t max_mod_bits = get_max_mod_bits();
        size_t max_mod_words = rsa_bits_to_words(max_mod_bits);
        size_t mod_bits = mod.get_actual_bit_size();
        size_t exp_bits = exp.get_actual_bit_size();
        if ( !correct_bit_count(mod.begin(), mod_bits, max_mod_bits) ) {
            cerr << "Invalid mod_bits="<<mod_bits<<endl;
            return ret;
        }
        if ( !correct_bit_count(exp.begin(), exp_bits, mod_bits) ) {
            cerr << "Invalid exp_bits="<<exp_bits<<endl;
            return ret;
        }
        size_t montg_word_bits = get_montg_word_bits();
        size_t n = GET_MONTG_WORD_COUNT2(mod_bits, montg_word_bits)+1;
        
        bool const_time = mode == secure_power;
        const_time = false;

        size_t first_exp_bit = exp_bits-1;
        if ( const_time ) {
            first_exp_bit = mod_bits-1;
        }

        // set sizes
        uint64_t sizes = mod_bits;
        sizes |= first_exp_bit << 16;
        sizes |= uint64_t(n) << 32;
        sizes |= uint64_t(const_time) << 40;
        *args++ = sizes;
        
        // set exp
        set_int(args, max_mod_words, exp);
        args += max_mod_words;

        // set mod
        set_int(args, max_mod_words, mod);
        args += max_mod_words;

        // skip data
        ret.first = args;
        ret.second = max_mod_words;
        args += max_mod_words;

        // set r2
        calc_r2(args, mod_bits, mod.begin(), montg_word_bits);
        fill(args+mod.size(), args+max_mod_words, 0);
        return ret;
    }

    bool init_req(Args* args,
                  uint16_t index,
                  const MontgPowParams& params,
                  rsa_montg_number_t data)
    {
        rsa_word_t* req_args = get_req_args(args, index);
        pair<rsa_word_t*, size_t> data_place = init_params(req_args, params);
        if ( !data_place.first ) {
            return false;
        }
        TIMER("init_public_input");
        set_int(data_place.first, data_place.second, data);
        return true;
    }
    bool init_req(Args* args,
                  uint16_t index,
                  const MontgPowParams& params,
                  const rsa_word_t* data)
    {
        size_t mod_words = rsa_bits_to_words(params.mod_bits);
        return init_req(args, index, params, rsa_montg_number_t(mod_words, data));
    }
    bool init_public_req(Args* args,
                         uint16_t index,
                         rsa_montg_number_t mod,
                         rsa_montg_number_t exp,
                         PowerMode mode,
                         rsa_montg_number_t data)
    {
        rsa_word_t* req_args = get_req_args(args, index);
        pair<rsa_word_t*, size_t> data_place = init_params(req_args, mod, exp, mode);
        if ( !data_place.first ) {
            return false;
        }
        TIMER("init_public_input");
        set_int(data_place.first, data_place.second, data);
        return true;
    }
    bool init_private_req(Args* args,
                          uint16_t index,
                          rsa_montg_number_t mod,
                          rsa_montg_number_t exp,
                          PowerMode mode,
                          rsa_montg_number_t data)
    {
        assert(index < get_max_req_count());
        rsa_word_t* req_args = get_req_args(args, index);
        pair<rsa_word_t*, size_t> data_place = init_params(req_args, mod, exp, mode);
        if ( !data_place.first ) {
            return false;
        }
        TIMER("init_private_input");
        if ( data.size() < mod.size() ) {
            set_int(data_place.first, data_place.second, data);
        }
        else {
            rsa_montg_mod(data_place.first, data, mod);
            fill(data_place.first+mod.size(), data_place.first+data_place.second, 0);
        }
        return true;
    }
    void get_output(rsa_word_t* output,
                    const Results* results,
                    uint16_t index)
    {
        assert(index < get_max_req_count());
        const rsa_word_t* output_ptr = get_req_results(results, index);
        copy(output_ptr, output_ptr+get_max_mod_words(), output);
    }
    void get_public_output(rsa_word_t* output,
                           const Results* results,
                           uint16_t index)
    {
        get_output(output, results, index);
    }
    void combine_private_outputs(rsa_word_t* output,
                                 const Results* results,
                                 uint16_t index1,
                                 uint16_t index2,
                                 rsa_montg_number_t mod1,
                                 rsa_montg_number_t mod2,
                                 rsa_montg_number_t coeff)
    {
        assert(index1 < get_max_req_count());
        assert(index2 < get_max_req_count());
        const rsa_word_t* output1 = get_req_results(results, index1);
        const rsa_word_t* output2 = get_req_results(results, index2);
        rsa_montg_combine_private_outputs(output, output1, output2, mod1, mod2, coeff);
    }

    void send_kernel_args(uint16_t req_count,
                          const Args* args)
    {
#ifdef USE_OPENCL
        const bool use_opencl = device != 0;
        if ( use_opencl ) {
            TIMER_N("OpenCL args", req_count);
            size_t size = req_count*get_kernel_info().request_words*sizeof(rsa_word_t);
            cl_event done_event = 0;
            if ( int err = clEnqueueWriteBuffer(device.commands, args->cl_buffer, CL_TRUE, 0, size, args->arr, 0, 0, &done_event) ) {
                cerr << "Error: Failed to enqueue args send! err="<<err<<endl;
                abort();
            }
            if ( int err = clWaitForEvents(1, &done_event) ) {
                cerr << "Error: Failed to wait write! err="<<err<<endl;
                abort();
            }
        }
#endif
    }
    void receive_kernel_results(uint16_t req_count,
                                Results* results)
    {
#ifdef USE_OPENCL
        const bool use_opencl = device != 0;
        if ( use_opencl ) {
            TIMER_N("OpenCL result start", req_count);
            assert(req_count == results->req_count);
            cl_event done_event = 0;
            size_t size = req_count*get_kernel_info().result_words*sizeof(rsa_word_t);
            if ( int err = clEnqueueReadBuffer(device.commands, results->cl_buffer, CL_TRUE, 0, size, results->arr, 0, 0, &done_event) ) {
                cerr << "Error: Failed to enqueue result receive! err="<<err<<endl;
                abort();
            }
            if ( int err = clWaitForEvents(1, &done_event) ) {
                cerr << "Error: Failed to wait read! err="<<err<<endl;
                abort();
            }
        }
#endif
    }
    void start_kernel_call(uint16_t req_count,
                           const Args* args,
                           Results* results)
    {
#ifdef USE_OPENCL
        const bool use_opencl = device != 0;
        if ( use_opencl ) {
            TIMER_N("OpenCL kernel call start", req_count);
            // set call arguments
            results->req_count = req_count;
            if ( int err = clSetKernelArg(device.kernel, 0,
                                          sizeof(results->req_count), &results->req_count) ) {
                cerr << "Error: cannot set count! err="<<err<<endl;
                abort();
            }
            if ( int err = clSetKernelArg(device.kernel, 1,
                                          sizeof(args->cl_buffer), &args->cl_buffer) ) {
                cerr << "Error: cannot initialize args param! err="<<err<<endl;
                abort();
            }
            if ( int err = clSetKernelArg(device.kernel, 2,
                                          sizeof(results->cl_buffer), &results->cl_buffer) ) {
                cerr << "Error: cannot initialize args param! err="<<err<<endl;
                abort();
            }
            // call kernel
            assert(!results->kernel_call_done_event);
            if ( int err = clEnqueueTask(device.commands, device.kernel, 0, NULL, &results->kernel_call_done_event) ) {
                cerr << "Error: Failed to enqueue kernel call! err="<<err<<endl;
                abort();
            }
            assert(results->kernel_call_done_event);
            return;
        }
#else
        {
            TIMER_N("Direct call", req_count);
            kernel_entry(req_count, args->arr, results->arr);
        }
#endif
    }
    void wait_kernel_call(Results* results)
    {
#ifdef USE_OPENCL
        const bool use_opencl = device != 0;
        if ( use_opencl ) {
            TIMER_N("OpenCL kernel call wait", results->req_count);
            assert(results->kernel_call_done_event);
            if ( int err = clWaitForEvents(1, &results->kernel_call_done_event) ) {
                cerr << "Error: Failed to wait kernel call! err="<<err<<endl;
                abort();
            }
            results->kernel_call_done_event = 0;
        }
#endif
    }
    void do_kernel_call(uint16_t req_count,
                        const Args* args,
                        Results* results)
    {
        if ( skip_opencl_call ) return;
        for ( int i = 0; i < kernel_call_count; ++i ) {
            start_kernel_call(req_count, args, results);
            wait_kernel_call(results);
        }
    }

    void kernel_call(uint16_t req_count,
                     const Args* args,
                     Results* results)
    {
        if ( !skip_opencl_call ) {
            send_kernel_args(req_count, args);
            do_kernel_call(req_count, args, results);
            receive_kernel_results(req_count, results);
        }
        if ( skip_opencl_call || kernel_call_count <= 0 ) {
            TIMER_N("zero_result", req_count);
            memset(get_req_results(results, 0), 0, req_count*get_kernel_info().result_words*sizeof(rsa_word_t));
        }
    }

    RSAMontgInfo get_default_kernel_info()
    {
        RSAMontgInfo info;
        info.info_size = sizeof(info);
        info.magic = info.kMagic;
        info.flags = 0;
        info.max_mod_bits = DEFAULT_RSA_BITS;
        info.max_req_count = UNIT_COUNT;
        info.montg_word_bits = DEFAULT_MONTG_WORD_BITS;
        info.request_words = DEFAULT_KERNEL_ARG_WORDS;
        info.result_words = DEFAULT_KERNEL_RESULT_WORDS;
        return info;
    }

    RSAMontgInfo read_kernel_info()
    {
        RSAMontgInfo info;
        info.max_mod_bits = LIMIT_RSA_BITS;
        size_t buffer_words = LIMIT_UNIT_COUNT*info.get_arg_word_count();
        memset(&info, 0, sizeof(info));

#ifdef USE_OPENCL
        const bool use_opencl = device != 0;
        if ( use_opencl ) {
            // read kernel info
            cl_event done_event = 0;

            cl_mem cl_buffer = clCreateBuffer(device.context, CL_MEM_READ_WRITE, sizeof(rsa_word_t)*buffer_words, 0, 0);
            if ( !cl_buffer ) {
                cerr << "Error: cannot allocate buffer!"<<endl;
                abort();
            }

            uint16_t req_count = 0;
            if ( int err = clSetKernelArg(device.kernel, 0,
                                          sizeof(req_count), &req_count) ) {
                cerr << "Error: cannot set count! err="<<err<<endl;
                abort();
            }
            if ( int err = clSetKernelArg(device.kernel, 1,
                                          sizeof(cl_buffer), &cl_buffer) ) {
                cerr << "Error: cannot initialize args param! err="<<err<<endl;
                abort();
            }
            if ( int err = clSetKernelArg(device.kernel, 2,
                                          sizeof(cl_buffer), &cl_buffer) ) {
                cerr << "Error: cannot initialize args param! err="<<err<<endl;
                abort();
            }
            if ( int err = clEnqueueWriteBuffer(device.commands, cl_buffer, CL_TRUE, 0, sizeof(info), &info, 0, 0, &done_event) ) {
                cerr << "Error: Failed to enqueue result send! err="<<err<<endl;
                abort();
            }
            if ( int err = clWaitForEvents(1, &done_event) ) {
                cerr << "Error: Failed to wait write! err="<<err<<endl;
                abort();
            }
            if ( int err = clEnqueueTask(device.commands, device.kernel, 0, NULL, &done_event) ) {
                cerr << "Error: Failed to enqueue kernel call! err="<<err<<endl;
                abort();
            }
            if ( int err = clWaitForEvents(1, &done_event) ) {
                cerr << "Error: Failed to wait kernel call! err="<<err<<endl;
                abort();
            }
            if ( int err = clEnqueueReadBuffer(device.commands, cl_buffer, CL_TRUE, 0, sizeof(info), &info, 0, 0, &done_event) ) {
                cerr << "Error: Failed to enqueue result receive! err="<<err<<endl;
                abort();
            }
            if ( int err = clWaitForEvents(1, &done_event) ) {
                cerr << "Error: Failed to wait read! err="<<err<<endl;
                abort();
            }
            clReleaseMemObject(cl_buffer);
        }
#else
        {
            rsa_word_t* buffer = new rsa_word_t[buffer_words];
            memcpy(buffer, &info, sizeof(info));
            kernel_entry(0, buffer, buffer);
            memcpy(&info, buffer, sizeof(info));
        }
#endif

        // verify info
        if ( info.info_size == 0 && info.magic == 0 ) {
            // no info from kernel
            cout << "INFO: Kernel doesn't report algorithm parameters, using defaults."<<endl;
            info = get_default_kernel_info();
        }
        else if ( info.info_size >= sizeof(info) && info.magic == info.kMagic ) {
            // valid info from kernel
        }
        else {
            cerr << "Error: Invalid algorithm parameters from kernel, using defaults." << endl;
        }
        if ( 1 ) {
            cout << "INFO: kernel parameters:";
            cout << " engines: "<<info.max_req_count;
            cout << " bits: "<<info.max_mod_bits;
            if ( info.montg_word_bits != DEFAULT_MONTG_WORD_BITS ) {
                cout << " word: "<<info.montg_word_bits;
            }
            if ( 0 && info.max_mod_bits != DEFAULT_RSA_BITS ) {
                cerr << "Error: incompatible mod bits: "<<info.max_mod_bits<<" <> "<<DEFAULT_RSA_BITS<<endl;
                abort();
            }
            if ( info.montg_word_bits != DEFAULT_MONTG_WORD_BITS ) {
                cerr << "Error: incompatible word bits: "<<info.montg_word_bits<<" <> "<<DEFAULT_MONTG_WORD_BITS<<endl;
                abort();
            }
            if ( 0 && info.request_words != DEFAULT_KERNEL_ARG_WORDS ) {
                cerr << "Error: incompatible request words: "<<info.request_words<<" <> "<<DEFAULT_KERNEL_ARG_WORDS<<endl;
                abort();
            }
            if ( 0 && info.result_words != DEFAULT_KERNEL_RESULT_WORDS ) {
                cerr << "Error: incompatible result words: "<<info.result_words<<" <> "<<DEFAULT_KERNEL_RESULT_WORDS<<endl;
                abort();
            }
            cout << endl;
        }
        return info;
    }
}

static
void dump_data(const char* name, const KernelNS::Buffer* buf, size_t words)
{
    cout << name << ": ptr="<<buf<<": "<<flush;
    dump_words(buf->arr, words);
#ifdef USE_OPENCL
    if ( 0 ) {
        cout << name << ": openCL buffer: "<<flush;
        dump_buffer(buf->cl_buffer, words);
    }
#endif
}

static
void dump_request(size_t req_count, const KernelNS::Args* args)
{
    cout << "Calling "<<kernel_entry_name<<"("<<req_count<<")" << endl;
    dump_data("args", args, req_count*KernelNS::get_kernel_info().request_words);
}

static
void dump_result(size_t req_count, const KernelNS::Results* results)
{
    cout << "Finished "<<kernel_entry_name<<"("<<req_count<<")" << endl;
    dump_data("result", results, req_count*KernelNS::get_kernel_info().result_words);
}

void rsa_montg_pow_N(size_t total_count, const MontgPowParams* const params[], const rsa_word_t* const input[], rsa_word_t* const output[])
{
    TIMER_N("pow_N", total_count);

    KernelNS::Args* args    = KernelNS::alloc_args();
    KernelNS::Results* results = KernelNS::alloc_results();

    size_t max_req_count = KernelNS::get_max_req_count();
    size_t packet_size = bench_packet? min(size_t(bench_packet), max_req_count): max_req_count;
    for( uint16_t req_count; (req_count = min(total_count, packet_size)); total_count -= req_count, params += req_count, input += req_count, output += req_count ) {
        assert(req_count > 0);
        assert(req_count <= KernelNS::get_max_req_count());

#if defined TRACE
        cout << "req_count: " << req_count << endl;
#endif

        for ( size_t i = 0; i < req_count; ++i ) {
            if ( !KernelNS::init_req(args, i, *params[i], input[i]) ) {
                cerr << "init_req("<<i<<") failed"<<endl;
                abort();
            }
        }

#ifdef TRACE
        if( 1 )
            dump_request(req_count, args);
#endif

        KernelNS::kernel_call(req_count, args, results);

#ifdef TRACE        
        if( 1 )
            dump_result(req_count, results);
#endif

        for ( size_t i = 0; i < req_count; ++i ) {
            KernelNS::get_output(output[i], results, i);
        }
    }

    KernelNS::free_args(args);
    KernelNS::free_results(results);
}

void rsa_montg_pow_1(const MontgPowParams* params,
                     const rsa_word_t* input,
                     rsa_word_t* output)
{
    rsa_montg_pow_N(1, &params, &input, &output);
}

// empty implementation of functions that aren't part of OpenCL kernel
// for testing outside of OpenCL framework
void rsa_montg_init(const char* ps_dev_name, const char* ps_kernel_fname)
{
#ifdef USE_OPENCL
    if ( ps_dev_name && !device ) {
        atexit(rsa_montg_cleanup);
        device.open_device(ps_dev_name);
        device.open_kernel(ps_kernel_fname, kernel_entry_name);
    }
#else
    cout << "WARNING: !USE_OPENCL" << endl;
#endif
}
void opencl_init(const char* ps_dev_name, const char* ps_kernel_fname)
{
    rsa_montg_init(ps_dev_name, ps_kernel_fname);
}
void rsa_montg_cleanup()
{
#ifdef USE_OPENCL
    if ( device ) {
        device.close_kernel();
        device.close_device();
    }
#endif
}
void opencl_cleanup()
{
    rsa_montg_cleanup();
}
