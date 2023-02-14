#include "utils.h"
#include "runtime.h"

#include <cstddef>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

namespace runtime {

struct ThreadCB {
	void *fn[2];
	uint64_t regs[10];
};

constexpr int offRegs = offsetof(ThreadCB, regs);
static thread_local ThreadCB tcb;

static __attribute__((naked)) void gettls() {
	asm("endbr64");
	asm("rdfsbase %rax; ret");
}

static __attribute__((naked)) void syscall() {
	asm("endbr64");
	// syscall: rax(nr) rdi(1) rsi(2) rdx(3) r10(4) r8(5) r9(6) rax(ret) 
	// caller:  rdi(1) rsi(2) rdx(3) rcx(4) r8(5) r9(6) rax(ret) r10 r11
	asm("mov %%rax, %%gs:%c0" :: "i"(offRegs+8*0));
	asm("mov %%rdi, %%gs:%c0" :: "i"(offRegs+8*1));
	asm("mov %%rsi, %%gs:%c0" :: "i"(offRegs+8*2));
	asm("mov %%rdx, %%gs:%c0" :: "i"(offRegs+8*3));
	asm("mov %%r10, %%gs:%c0" :: "i"(offRegs+8*4));
	asm("mov %%r8, %%gs:%c0" :: "i"(offRegs+8*5));
	asm("mov %%r9, %%gs:%c0" :: "i"(offRegs+8*6));
	asm("mov %%r11, %%gs:%c0" :: "i"(offRegs+8*7));
	asm("mov %%rsp, %%gs:%c0" :: "i"(offRegs+8*8));
	asm("pop %%r11; mov %%r11, %%gs:%c0" :: "i"(offRegs+8*9));
	asm("syscall");
	asm("mov %%gs:%c0, %%rdi" :: "i"(offRegs+8*1));
	asm("mov %%gs:%c0, %%rsi" :: "i"(offRegs+8*2));
	asm("mov %%gs:%c0, %%rdx" :: "i"(offRegs+8*3));
	asm("mov %%gs:%c0, %%r10" :: "i"(offRegs+8*4));
	asm("mov %%gs:%c0, %%r8" :: "i"(offRegs+8*5));
	asm("mov %%gs:%c0, %%r9" :: "i"(offRegs+8*6));
	asm("mov %%gs:%c0, %%r11" :: "i"(offRegs+8*7));
	asm("mov %%gs:%c0, %%rsp" :: "i"(offRegs+8*8));
	asm("jmp *%%gs:%c0" :: "i"(offRegs+8*9));
}

static void initTcb() {
	tcb.fn[0] = (void *)syscall;
	tcb.fn[1] = (void *)gettls;
  asm("WRGSBASE %0" :: "r"(&tcb));
}

void soInit() {
	initTcb();
}

}
