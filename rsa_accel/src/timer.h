#ifndef TIMER_H
#define TIMER_H

#include <sys/time.h>

inline uint64_t rdtsc()
{
    uint32_t hi, lo, cpu;
    asm("rdtscp":"=d"(hi),"=a"(lo),"=c"(cpu)::);
    return (uint64_t(hi)<<32)|lo;
}

class TimerStat
{
    const char* name;
    uint64_t call_count;
    uint64_t call_clocks;
public:
    TimerStat(const char* name)
        : name(name), call_count(0), call_clocks(0)
    {
        if ( !start_clock )
            init_start_clock();
    }
    ~TimerStat()
    {
        report();
    }
    void add(uint64_t count, uint64_t clocks)
    {
        call_count += count;
        call_clocks += clocks;
    }
    void report() const;

    static void init_start_clock();
    static double get_sys_time();
    static double get_CPU_frequency();
    
private:
    static uint64_t start_clock;
    static double start_time;
    static double frequency;
};

class Timer
{
    TimerStat& stat;
    unsigned count;
    uint64_t start;
public:
    Timer(TimerStat& stat, uint64_t count = 1)
        : stat(stat), count(count), start(rdtsc())
    {
    }
    ~Timer()
    {
        stat.add(count, rdtsc()-start);
    }
};
#define NAME2(a,b) a##b
#define TIMER(name) static TimerStat NAME2(stat,__LINE__)(name); Timer NAME2(timer,__LINE__)(NAME2(stat,__LINE__));
#define TIMER_N(name,count) static TimerStat NAME2(stat,__LINE__)(name); Timer NAME2(timer,__LINE__)(NAME2(stat,__LINE__), count);

inline
double get_time()
{
    timeval tv;
    gettimeofday(&tv, 0);
    return tv.tv_sec+tv.tv_usec*1e-6;
}

#endif
