#include "elf_file.h"
#include "utils.h"
#include "runtime.h"
#include "loader.h"

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

static void printElfAddr(const std::string &filename, const ElfFile &file, uint64_t start) {
	fmtPrintf("add-symbol-file %s ", filename.c_str());
	for (auto i: file.secs) {
		if (i.sh->sh_addr) {
			fmtPrintf("-s %s 0x%lx ", i.name.c_str(), i.sh->sh_addr + start);
		}
	}
	fmtPrintf("\n");
}

static void enterBin(void *entry, void *stack) {
	fmtPrintf("start\n");
  asm("cmp $0, %0; cmovne %0, %%rsp" :: "r"(stack));
  asm("jmpq *%0" :: "r"(entry));
}

static error runBin(const std::string &filename) {
	ElfFile file;

	auto err = file.open(filename);
	if (err) {
		return err;
	}

	uint8_t *loadP;
	err = loadBin(file, loadP);
	if (err) {
		return err;
	}

	printElfAddr(filename, file, (uint64_t)loadP);

  auto entryP = loadP + file.eh()->e_entry - (*file.loads.begin())->p_vaddr;
  uint8_t *stackStart = nullptr;

	int stackSize = 1024*128;
	auto stackTop = (uint8_t *)mmap(NULL, stackSize, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (stackTop == MAP_FAILED) {
		return fmtErrorf("mmap stack failed");
	}
	auto stackEnd = stackTop + stackSize;
	stackStart = stackEnd;

	// << stackTop
	// .. stack ..
	// << stackStart
	// argc
	// .. argv ...
	// 0
	// .. envp ..
	// 0
	// .. aux ..
	// 0 0
	// << stackEnd

	std::vector<size_t> v;

	// argc argv
	v.push_back(1);
	v.push_back((size_t)filename.c_str());
	v.push_back(0);

	// env
	v.push_back(0);

	auto eh = file.eh();
	uint8_t *phStart = loadP + eh->e_phoff;

	// aux
	v.push_back(AT_HWCAP);
	v.push_back(0x178bfbff);
	v.push_back(AT_PAGESZ);
	v.push_back(4096);
	v.push_back(AT_CLKTCK);
	v.push_back(100);
	v.push_back(AT_PHDR);
	v.push_back((size_t)phStart);
	v.push_back(AT_PHENT);
	v.push_back((size_t)eh->e_phentsize);
	v.push_back(AT_PHNUM);
	v.push_back((size_t)eh->e_phnum);
	v.push_back(AT_ENTRY);
	v.push_back((size_t)entryP);
	v.push_back(AT_EXECFN);
	v.push_back((size_t)filename.c_str());
	v.push_back(AT_PLATFORM);
	v.push_back((size_t)"x86_64");
	v.push_back(0);
	v.push_back(0);

	auto vsize = v.size()*sizeof(v[0]);
	if (vsize > stackSize) {
		return fmtErrorf("auxv too large");
	}

	stackStart -= vsize;
	memcpy(stackStart, v.data(), vsize);

	enterBin(entryP, stackStart);
	__builtin_unreachable();
}

error cmdMain(std::vector<std::string> &args) {
	if (args.size() < 1) {
		return fmtErrorf("missing action");
	}
	auto action = args[0];

	if (action == "elfaddr") {
		if (args.size() < 3) {
			return fmtErrorf("missing filename");
		}
		auto filename = args[1];
		ElfFile file;
		auto err = file.open(filename);
		if (err) {
			return err;
		}
    uint64_t start;
    sscanf(args[2].c_str(), "%lx", &start);
		printElfAddr(filename, file, start);
		return nullptr;
	} else if (action == "run") {
		if (args.size() < 2) {
			return fmtErrorf("missing filename");
		}
		auto filename = args[1];
		return runBin(filename);
	}

	return fmtErrorf("invalid action");
}

void soInit() {
	initTcb();
}

}
