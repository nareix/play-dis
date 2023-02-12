#include "utils.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

struct TCB {
};

static __attribute__((constructor)) void rtsoInit() {
	auto t = (TCB *)mmap(NULL, 0x1000, 
    PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
  asm("WRGSBASE %0" :: "r"(t));
}
