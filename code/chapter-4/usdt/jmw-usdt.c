#include <sys/sdt.h>
#include <unistd.h> // sleep()
#include <x86intrin.h> // __rdtsc()

int main(int argc, char const *argv[]) {
    DTRACE_PROBE1(jmw-usdt, main-enter, __rdtsc());
    //sleep(1);
    DTRACE_PROBE1(jmw-usdt, main-exit, __rdtsc());
    return 0;
}

