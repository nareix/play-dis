#include "elf.h"
#include "elf_file.h"
#include "utils.h"
#include "runtime.h"
#include "loader.h"

#include <cassert>
#include <cstdint>
#include <cstdint>
#include <filesystem>
#include <cstddef>
#include <functional>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include <sys/syscall.h>
#include <asm/prctl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vector>
#include <unordered_map>
#include <fstream>

namespace runtime {

struct ThreadCB {
	void *fn[2];
	uint64_t regs[10];
	void *stack;
	uint64_t fs;
	uint64_t gs;
};

static constexpr int TCBRegs(int i) {
	return offsetof(ThreadCB, regs) + i*8;
}
static constexpr int TCBStack = offsetof(ThreadCB, stack);
static constexpr int TCBFs = offsetof(ThreadCB, fs);

static ThreadCB __attribute__((naked)) *tcb() {
  asm("endbr64; RDGSBASE %rax; ret");
}

static void __attribute__((naked)) settcb(ThreadCB *t) {
  asm("endbr64; WRGSBASE %rdi; ret");
}

static __attribute__((naked)) void getfs() {
	asm("endbr64; mov %%gs:%c0, %%rax; ret" :: "i"(TCBFs));
}

static bool debug = true;

struct SyscallHandler {
public:
	static thread_local std::vector<std::string> dps;
	ThreadCB *t;
	uint64_t *regs;
	bool setRet;

	inline void arg(uint64_t x) {
		if (debug) {
			dps.push_back(fmtSprintf("0x%lx", x));
		}
	}

	inline void ret(uint64_t x) {
		setRet = true;
		regs[0] = x;
		arg(x);
	}

	bool arch_prctl() {
		auto code = regs[1];
		auto addr = regs[2];
		#define C(x) case x: if (debug) { dps.push_back(#x); }
		switch (code) {
			C(ARCH_SET_FS) {
				arg(addr);
				t->fs = addr;
				ret(0);
				return true;
			}
			C(ARCH_GET_FS) {
				ret(t->fs);
				return true;
			}
			C(ARCH_SET_GS) {
				arg(addr);
				t->gs = addr;
				ret(0);
				return true;
			}
			C(ARCH_GET_GS) {
				ret(t->gs);
				return true;
			}
			default: {
				return false;
			}
		}
		#undef C
	}

	bool handle() {
		auto regs = t->regs;
		auto nr = regs[0];
		bool r;

		#define C(x) case SYS_##x: if (debug) { dps.push_back(#x); } r = x(); break;
		switch (nr) {
			C(arch_prctl)
			default: {
				if (debug) {
					dps.push_back(fmtSprintf("syscall_%d", nr));
				}
				r = false;
				break;
			}
		}
		#undef C

		if (r) {
			assert(setRet);
		} 

		if (debug) {
			if (!r && !setRet) {
				dps.push_back("bypass");
			}
			auto &fn = dps[0];
			auto &ret = dps[dps.size()-1];
			fmtPrintf("%s(", fn.c_str());
			for (int i = 1; i < dps.size()-1; i++) {
				auto &p = dps[i];
				fmtPrintf("%s", p.c_str());
				if (i < dps.size()-2) {
					fmtPrintf(",");
				}
			}
			fmtPrintf(") = %s\n", ret.c_str());
			dps.clear();
		}

		return r;
	}
};

thread_local std::vector<std::string> SyscallHandler::dps;

static bool handleSyscall() {
	SyscallHandler h;
	h.t = tcb();
	h.regs = h.t->regs;
	h.setRet = false;
	return h.handle();
}

static __attribute__((naked)) void syscall() {
	asm("endbr64");

	// syscall: rax(nr) rdi(1) rsi(2) rdx(3) r10(4) r8(5) r9(6) rax(ret) 
	// caller:  rdi(1) rsi(2) rdx(3) rcx(4) r8(5) r9(6) rax(ret) r10 r11
	asm("mov %%rax, %%gs:%c0" :: "i"(TCBRegs(0)));
	asm("mov %%rdi, %%gs:%c0" :: "i"(TCBRegs(1)));
	asm("mov %%rsi, %%gs:%c0" :: "i"(TCBRegs(2)));
	asm("mov %%rdx, %%gs:%c0" :: "i"(TCBRegs(3)));
	asm("mov %%r10, %%gs:%c0" :: "i"(TCBRegs(4)));
	asm("mov %%r8, %%gs:%c0" :: "i"(TCBRegs(5)));
	asm("mov %%r9, %%gs:%c0" :: "i"(TCBRegs(6)));
	asm("mov %%r11, %%gs:%c0" :: "i"(TCBRegs(7)));
	asm("pop %%r11; mov %%r11, %%gs:%c0" :: "i"(TCBRegs(9)));
	asm("mov %%rsp, %%gs:%c0" :: "i"(TCBRegs(8)));
	asm("mov %%gs:%c0, %%rsp" :: "i"(TCBStack));

	asm("call %P0" :: "i"(handleSyscall));

	asm("mov %%gs:%c0, %%rdi" :: "i"(TCBRegs(1)));
	asm("mov %%gs:%c0, %%rsi" :: "i"(TCBRegs(2)));
	asm("mov %%gs:%c0, %%rdx" :: "i"(TCBRegs(3)));
	asm("mov %%gs:%c0, %%r10" :: "i"(TCBRegs(4)));
	asm("mov %%gs:%c0, %%r8" :: "i"(TCBRegs(5)));
	asm("mov %%gs:%c0, %%r9" :: "i"(TCBRegs(6)));
	asm("mov %%gs:%c0, %%r11" :: "i"(TCBRegs(7)));
	asm("mov %%gs:%c0, %%rsp" :: "i"(TCBRegs(8)));

	asm("cmp $0, %rax; jne 1f");
	asm("mov %%gs:%c0, %%rax" :: "i"(TCBRegs(0)));
	asm("syscall; jmp 2f; 1:");
	asm("mov %%gs:%c0, %%rax" :: "i"(TCBRegs(0)));
	asm("2: jmp *%%gs:%c0" :: "i"(TCBRegs(9)));
}

static error initTcb() {
	auto size = 1024*128;
	auto stack = (uint8_t *)mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (stack == MAP_FAILED) {
		return fmtErrorf("mmap syscall stack failed");
	}

	auto t = (ThreadCB *)malloc(sizeof(ThreadCB));
	memset(t, 0, sizeof(ThreadCB));
	t->fn[0] = (void *)syscall;
	t->fn[1] = (void *)getfs;
	t->stack = stack + size;
	settcb(t);

	return nullptr;
}

static std::unordered_map<std::string, uint64_t> fileAddrMap;

static void enterBin(void *entry, void *stack) {
  asm("cmp $0, %0; cmovne %0, %%rsp" :: "r"(stack));
  asm("jmpq *%0" :: "r"(entry));
}

static error runBin(const std::vector<std::string> &args) {
	auto &filename = args[0];

	ElfFile file;

	auto err = file.open(filename);
	if (err) {
		return err;
	}

	uint64_t loadAt = 0;
	auto basename = std::filesystem::path(filename).filename();
	auto addri = fileAddrMap.find(basename);
	if (addri != fileAddrMap.end()) {
		loadAt = addri->second;
	}

	uint8_t *loadP;
	err = loadBin(file, loadP, loadAt);
	if (err) {
		return err;
	}

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
	v.push_back(args.size());
	for (auto &s: args) {
		v.push_back((size_t)s.c_str());
	}
	v.push_back(0);

	// env
	v.push_back(0);

	auto eh = file.eh();
	uint8_t *phStart = loadP + eh->e_phoff;

	// aux
	v.push_back(AT_HWCAP);
	v.push_back(0x178bfbff);
	v.push_back(AT_PAGESZ);
	v.push_back(getpagesize());
	v.push_back(AT_CLKTCK);
	v.push_back(100);
	v.push_back(AT_PHDR);
	v.push_back((size_t)phStart);
	v.push_back(AT_BASE);
	v.push_back((size_t)loadP);
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

	err = initTcb();
	if (err) {
		return err;
	}

	enterBin(entryP, stackStart);
	__builtin_unreachable();
}

error cmdMain(std::vector<std::string> &args0) {
	std::vector<std::string> args;
	std::string addrFile;

  for (int i = 0; i < args0.size(); i++) {
    auto &o = args0[i];
		if (o == "-a") {
      if (i+1 >= args0.size()) {
        return fmtErrorf("missing param");
      }
			addrFile = args0[i+1];
			i++;
			continue;
		}
    args.push_back(o);
	}

	if (args.size() < 1) {
		return fmtErrorf("missing action");
	}
	auto action = args[0];
	args.erase(args.begin());

	auto forElfFiles = [&](
		std::function<void(const std::string&, const ElfFile &, uint64_t)> fn
	) -> error {
		if (args.size() == 0) {
			return fmtErrorf("missing filename");
		}
		auto addrStart = 0x00007ff000000000UL;
		auto addrInc   = 0x0000000100000000UL;
		auto addr = addrStart;
		for (auto filename: args) {
			ElfFile file;
			auto err = file.open(filename);
			if (err) {
				return err;
			}
			fn(filename, file, addr);
			addr += addrInc;
		}
		return nullptr;
	};

	if (action == "gdbcmd") {
		return forElfFiles([&](const std::string &filename, const ElfFile &file, uint64_t addr) {
			fmtPrintf("add-symbol-file %s ", filename.c_str());
			for (auto i: file.secs) {
				if (i.sh->sh_addr) {
					fmtPrintf("-s %s 0x%lx ", i.name.c_str(), i.sh->sh_addr + addr);
				}
			}
			fmtPrintf("\n");
		});

	} else if (action == "addrs") {
		return forElfFiles([&](const std::string &filename, const ElfFile &file, uint64_t addr) {
			auto basename = std::filesystem::path(filename).filename();
			fmtPrintf("%s 0x%lx\n", basename.c_str(), addr);
		});

	} else if (action == "run") {
		if (addrFile != "") {
			std::ifstream file(addrFile);
			std::string line;
			while (std::getline(file, line)) {
				std::stringstream sline(line);
				std::string basename;
				uint64_t addr;
				sline >> basename >> std::hex >> addr;
				fileAddrMap.emplace(basename, addr);
			}
		}
		if (args.size() == 0) {
			return fmtErrorf("missing filename");
		}
		return runBin(args);
	}

	return fmtErrorf("invalid action");
}

void soInit() {
	initTcb();
}

}
