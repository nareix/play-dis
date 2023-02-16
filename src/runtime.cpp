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
#include <unordered_set>
#include <vector>
#include <unordered_map>
#include <fstream>

namespace runtime {

struct ThreadCB {
	void *fn[2];
	uint64_t regs[11];
	void *stack;
	uint64_t fs;
	uint64_t gs;
};

static constexpr int TCBRegs(int i) {
	return offsetof(ThreadCB, regs) + i*8;
}
static const int TCBStack = offsetof(ThreadCB, stack);
static const int TCBFs = offsetof(ThreadCB, fs);

static __attribute__((naked)) ThreadCB *tcb() {
  asm("endbr64; rdgsbase %rax; ret");
}

static __attribute__((naked))  void settcb(ThreadCB *t) {
  asm("endbr64; wrgsbase %rdi; ret");
}

static __attribute__((naked)) void getfs() {
	asm("endbr64; mov %%gs:%c0, %%rax; ret" :: "i"(TCBFs));
}

static bool debug = true;

struct FileAddr {
	std::string trname;
	uint64_t addr;
};

struct Syscall {
public:
	static thread_local std::vector<std::pair<std::string,std::string>> dps;
	static thread_local std::unordered_map<int, int> hookedFdIdx;
	static std::vector<FileAddr> fdHooks;
	static std::unordered_map<std::string, int> fdHookIdx;

	ThreadCB *t;
	uint64_t *regs;
	bool handled;

	enum { D, X, } retfmt;

	void arg(const char *k, uint64_t v) {
		dps.push_back({k, fmtSprintf("0x%lx", v)});
	}

	void arg(const char *k, int v) {
		dps.push_back({k, fmtSprintf("%d", v)});
	}

	void arg(const char *k, const std::string &v) {
		dps.push_back({k, v});
	}

	void argret() {
		if (retfmt == X) {
			arg("", regs[0]);
		} else {
			arg("", int(regs[0]));
		}
	}

	#define A(k) if (debug) { arg(#k, k); }
	#define A0(k, v) if (debug) { arg(#k, v); }

	inline void ret(uint64_t r) {
		handled = true;
		regs[0] = r;
		if (debug) {
			argret();
		}
	}

	void arch_prctl() {
		auto code = regs[1];
		auto addr = regs[2];
		#define C(x) case x: A0(code, #x);
		switch (code) {
			C(ARCH_SET_FS) {
				A(addr);
				t->fs = addr;
				ret(0);
				break;
			}
			C(ARCH_GET_FS) {
				ret(t->fs);
				break;
			}
			C(ARCH_SET_GS) {
				A(addr);
				t->gs = addr;
				ret(0);
				break;
			}
			C(ARCH_GET_GS) {
				ret(t->gs);
				break;
			}
			default: {
				A(code);
				break;
			}
		}
		#undef C
	}

	void brk() {
		auto p = regs[1];
		A(p);
		retfmt = X;
	}

	void openat() {
		auto fd = int(regs[1]);
		auto filename = (const char *)regs[2];
		auto flags = regs[3];
		auto mode = regs[4];
		A(fd);
		A(filename);
		A(flags);
		A(mode);

		hookOpen(filename, regs[2]);
	}

	void mprotect() {
		auto start = regs[1];
		auto len = int(regs[2]);
		auto prot = regs[3];
		A(start);
		A(len);
		A(prot);
	}

	void mmap() {
		auto &addr = regs[1];
		auto len = int(regs[2]);
		auto prot = regs[3];
		auto flags = regs[4];
		auto fd = int(regs[5]);
		auto off = regs[6];
		A(addr);
		A(len);
		A(prot);
		A(flags);
		A(fd);
		A(off);
		retfmt = X;

		if (fd != -1 && addr == 0 && off == 0) {
			hookMmap(fd, addr);
		}
	}

	void munmap() {
		auto addr = regs[1];
		auto len = int(regs[2]);
		A(addr);
		A(len);
	}

	void madvise() {
		auto start = regs[1];
		auto len = int(regs[2]);
		auto behavior = regs[2];
		A(start);
		A(len);
		A(behavior);
	}

	void close() {
		auto fd = int(regs[1]);
		A(fd);

		hookClose(fd);
	}

	void writev() {
		auto fd = int(regs[1]);
		auto vec = regs[2];
		auto vlen = int(regs[3]);
		A(fd);
		A(vec);
		A(vlen);
	}

	void write() {
		auto fd = int(regs[1]);
		auto buf = regs[2];
		auto n = int(regs[3]);
		A(fd);
		A(buf);
		A(n);
	}

	void read() {
		auto fd = int(regs[1]);
		auto buf = regs[2];
		auto n = int(regs[3]);
		A(fd);
		A(buf);
		A(n);
	}

	void newfstatat() {
		auto fd = int(regs[1]);
		auto filename = (const char *)regs[2];
		auto sb = regs[3];
		auto flag = regs[4];
		A(fd);
		A(filename);
		A(sb);
		A(flag);
	}

	void getuid() {
	}

	void dup2() {
		auto oldfd = int(regs[1]);
		auto newfd = int(regs[2]);
		A(oldfd);
		A(newfd);
	}

	void ioctl() {
		auto fd = int(regs[1]);
		auto cmd = int(regs[2]);
		auto args = regs[3];
		A(fd);
		A(cmd);
		A(args);
	}

	void open() {
		auto filename = (const char *)(regs[1]);
		auto flags = regs[2];
		auto mode = regs[3];
		A(filename);
		A(flags);
		A(mode);

		hookOpen(filename, regs[1]);
	}

	void pread64() {
		auto fd = int(regs[1]);
		auto buf = regs[2];
		auto count = int(regs[3]);
		auto off = regs[4];
		A(fd);
		A(buf);
		A(count);
		A(off);
	}

	void pwrite64() {
		auto fd = int(regs[1]);
		auto buf = regs[2];
		auto count = int(regs[3]);
		auto off = regs[4];
		A(fd);
		A(buf);
		A(count);
		A(off);
	}

	void set_tid_address() {
		auto tidptr = regs[1];
		A(tidptr);
		ret(getpid());
	}

	void uname() {
		auto name = regs[1];
		A(name);
	}

	void access() {
		auto filename = (const char *)(regs[1]);
		auto mode = regs[2];
		A(filename);
		A(mode);
	}

	void getcwd() {
		auto buf = regs[1];
		auto size = int(regs[2]);
		A(buf);
		A(size);
	}

	void set_robust_list() {
		auto head = regs[1];
		auto len = int(regs[2]);
		A(head);
		A(len);
	}

	void rseq() {
		auto rseq = regs[1];
		auto len = int(regs[2]);
		auto flags = regs[3];
		auto sig = regs[4];
		A(rseq);
		A(len);
		A(flags);
		A(sig);
	}

	void exit_group() {
		auto err = int(regs[1]);
		A(err);
		ret(0);
	}

	static int checkHook(const std::string &filename) {
		auto basename = std::filesystem::path(filename).filename();
		auto i = fdHookIdx.find(basename);
		if (i == fdHookIdx.end()) {
			return -1;
		}
		return i->second;
	}

	void hookClose(int fd) {
		auto i = hookedFdIdx.find(fd);
		if (i == hookedFdIdx.end()) {
			return;
		}
		hookedFdIdx.erase(i);

		if (debug) {
			fmtPrintf("fd %d hook closed\n", fd);
		}
	}

	void hookOpen(const std::string &filename, uint64_t &newname) {
		auto i = checkHook(filename);
		if (i == -1) {
			return;
		}
		auto &h = fdHooks[i];

		newname = (uint64_t)h.trname.c_str();
		syscall();
		handled = true;

		auto fd = int(regs[0]);
		if (debug) {
			fmtPrintf("fd %d hooked newname %s\n", fd, h.trname.c_str());
		}
		hookedFdIdx[fd] = i;
	}

	void hookMmap(int fd, uint64_t &addr) {
		auto i = hookedFdIdx.find(fd);
		if (i == hookedFdIdx.end()) {
			return;
		}

		auto &h = fdHooks[i->second];
		addr = h.addr;

		if (debug) {
			fmtPrintf("mmap fd %d hooked new addr %lx\n", fd, addr);
		}
	}

	bool handle() {
		auto nr = regs[0];
		retfmt = D;

		#define C(x) case SYS_##x: arg("", #x); x(); break;
		switch (nr) {
			C(brk)
			C(openat)
			C(open)
			C(arch_prctl)
			C(mmap)
			C(mprotect)
			C(close)
			C(write)
			C(read)
			C(pread64)
			C(pwrite64)
			C(writev)
			C(newfstatat)
			C(ioctl)
			C(dup2)
			C(getuid)
			C(set_tid_address)
			C(uname)
			C(access)
			C(getcwd)
			C(set_robust_list)
			C(rseq)
			C(madvise)
			C(munmap)
			C(exit_group)
			default: {
				arg("", fmtSprintf("syscall_%d", nr));
				break;
			}
		}
		#undef C

		if (!handled) {
			syscall();
		}

		if (debug) {
			if (!handled) {
				argret();
			}
			auto &fn = dps[0];
			auto &ret = dps[dps.size()-1];
			fmtPrintf("%s(", fn.second.c_str());
			for (int i = 1; i < dps.size()-1; i++) {
				auto &p = dps[i];
				fmtPrintf("%s=%s", p.first.c_str(), p.second.c_str());
				if (i < dps.size()-2) {
					fmtPrintf(",");
				}
			}
			fmtPrintf(") = %s", ret.second.c_str());
			if (!handled) {
				fmtPrintf(" (bypass)");
			}
			fmtPrintf("\n");
			dps.clear();
		}

		return handled;
	}

	#undef A
	#undef A0

	static bool handle0() {
		Syscall h;
		h.t = tcb();
		h.regs = h.t->regs;
		h.handled = false;
		return h.handle();
	}

	// syscall: rax(nr) rdi(1) rsi(2) rdx(3) r10(4) r8(5) r9(6) rax(ret) 
	// caller:  rdi(1) rsi(2) rdx(3) rcx(4) r8(5) r9(6) rax(ret) r10 r11

	static __attribute__((naked)) void entry() {
		asm("endbr64");
		// save caller regs
		asm("mov %%rax, %%gs:%c0" :: "i"(TCBRegs(0)));
		asm("mov %%rdi, %%gs:%c0" :: "i"(TCBRegs(1)));
		asm("mov %%rsi, %%gs:%c0" :: "i"(TCBRegs(2)));
		asm("mov %%rdx, %%gs:%c0" :: "i"(TCBRegs(3)));
		asm("mov %%r10, %%gs:%c0" :: "i"(TCBRegs(4)));
		asm("mov %%r8, %%gs:%c0" :: "i"(TCBRegs(5)));
		asm("mov %%r9, %%gs:%c0" :: "i"(TCBRegs(6)));
		asm("mov %%r11, %%gs:%c0" :: "i"(TCBRegs(7)));
		// pop and save ret addr
		asm("pop %%r11; mov %%r11, %%gs:%c0" :: "i"(TCBRegs(9)));
		// swap to host stack
		asm("mov %%rsp, %%gs:%c0" :: "i"(TCBRegs(8)));
		asm("mov %%gs:%c0, %%rsp" :: "i"(TCBStack));
		// call handler
		asm("call %P0" :: "i"(handle0));
		// restore call regs
		asm("mov %%gs:%c0, %%rax" :: "i"(TCBRegs(0)));
		asm("mov %%gs:%c0, %%rdi" :: "i"(TCBRegs(1)));
		asm("mov %%gs:%c0, %%rsi" :: "i"(TCBRegs(2)));
		asm("mov %%gs:%c0, %%rdx" :: "i"(TCBRegs(3)));
		asm("mov %%gs:%c0, %%r10" :: "i"(TCBRegs(4)));
		asm("mov %%gs:%c0, %%r8" :: "i"(TCBRegs(5)));
		asm("mov %%gs:%c0, %%r9" :: "i"(TCBRegs(6)));
		asm("mov %%gs:%c0, %%r11" :: "i"(TCBRegs(7)));
		// switch to guest stack
		asm("mov %%gs:%c0, %%rsp" :: "i"(TCBRegs(8)));
		// jmp to ret addr
		asm("jmp *%%gs:%c0" :: "i"(TCBRegs(9)));
	}

	static __attribute__((naked)) void syscall() {
		// restore call regs
		asm("mov %%gs:%c0, %%rax" :: "i"(TCBRegs(0)));
		asm("mov %%gs:%c0, %%rdi" :: "i"(TCBRegs(1)));
		asm("mov %%gs:%c0, %%rsi" :: "i"(TCBRegs(2)));
		asm("mov %%gs:%c0, %%rdx" :: "i"(TCBRegs(3)));
		asm("mov %%gs:%c0, %%r10" :: "i"(TCBRegs(4)));
		asm("mov %%gs:%c0, %%r8" :: "i"(TCBRegs(5)));
		asm("mov %%gs:%c0, %%r9" :: "i"(TCBRegs(6)));
		asm("mov %%gs:%c0, %%r11" :: "i"(TCBRegs(7)));
		// swap to guest stack
		asm("mov %%rsp, %%gs:%c0" :: "i"(TCBRegs(10)));
		asm("mov %%gs:%c0, %%rsp" :: "i"(TCBRegs(8)));
		// syscall
		asm("syscall");
		// save results
		asm("mov %%rax, %%gs:%c0" :: "i"(TCBRegs(0)));
		asm("mov %%rsp, %%gs:%c0" :: "i"(TCBRegs(8)));
		// swap to host stack
		asm("mov %%gs:%c0, %%rsp" :: "i"(TCBRegs(10)));
		asm("ret");
	}
};

thread_local decltype(Syscall::dps) Syscall::dps;
thread_local decltype(Syscall::hookedFdIdx) Syscall::hookedFdIdx;
decltype(Syscall::fdHookIdx) Syscall::fdHookIdx;
decltype(Syscall::fdHooks) Syscall::fdHooks;

static error initTcb() {
	auto size = 1024*128;
	auto stack = (uint8_t *)mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (stack == MAP_FAILED) {
		return fmtErrorf("mmap syscall stack failed");
	}

	static thread_local ThreadCB t0;
	auto t = &t0;
	t->fn[0] = (void *)Syscall::entry;
	t->fn[1] = (void *)getfs;
	t->stack = stack + size;
	settcb(t);

	return nullptr;
}

static void enterBin(void *entry, void *stack) {
  asm("mov %0, %%rsp; mov $0, %%rbp; jmpq *%1" :: "r"(stack), "r"(entry));
}

static error runBin(const std::vector<std::string> &args) {
	auto filename = args[0];

	uint64_t loadAt = 0;
	auto i = Syscall::checkHook(filename);
	if (i != -1) {
		auto &h = Syscall::fdHooks[i];
		loadAt = h.addr;
		filename = h.trname;
	}

	ElfFile file;
	auto err = file.open(filename);
	if (err) {
		return err;
	}

	uint8_t *loadP;
	err = loadBin(file, loadP, loadAt);
	if (err) {
		return err;
	}

  auto entryP = loadP + file.eh()->e_entry - (*file.loads.begin())->p_vaddr;

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

	static thread_local uint64_t random[2];
	random[0] = std::rand();
	random[1] = std::rand();

	// aux
	auto aux = [&](size_t k, size_t val) {
		v.push_back(k);
		v.push_back(val);
	};
	aux(AT_HWCAP, 0x178bfbff);
	aux(AT_HWCAP2, 0x2);
	aux(AT_PAGESZ, getpagesize());
	aux(AT_CLKTCK, 100);
	aux(AT_PHDR, (size_t)phStart);
	aux(AT_BASE, (size_t)loadP);
	aux(AT_UID, 0);
	aux(AT_EUID, 0);
	aux(AT_GID, 0);
	aux(AT_EGID, 0);
	aux(AT_SECURE, 0);
	aux(AT_PHENT, (size_t)eh->e_phentsize);
	aux(AT_PHNUM, (size_t)eh->e_phnum);
	aux(AT_ENTRY, (size_t)entryP);
	aux(AT_EXECFN, (size_t)filename.c_str());
	aux(AT_PLATFORM, (size_t)"x86_64");
	aux(AT_RANDOM, (size_t)random);
	aux(0, 0);

	auto stackSize = 1024*128;
	auto stackTop = (uint8_t *)mmap(NULL, stackSize, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (stackTop == MAP_FAILED) {
		return fmtErrorf("mmap stack failed");
	}
	auto stackEnd = stackTop + stackSize;

	auto vsize = v.size()*sizeof(v[0]);
	auto stackStart = (void *)(uint64_t(stackEnd - vsize) & ~15);
	if (stackStart < stackTop) {
		return fmtErrorf("auxv too large");
	}
	memcpy(stackStart, v.data(), vsize);

	err = initTcb();
	if (err) {
		return err;
	}

	enterBin(entryP, stackStart);
	__builtin_unreachable();
}

error cmdMain(std::vector<std::string> &args) {
	if (args.size() == 0) {
		return fmtErrorf("missing filename");
	}

	auto addrFile = "addrs";
	if (std::filesystem::exists(addrFile)) {
		std::ifstream file(addrFile);
		std::string line;
		while (std::getline(file, line)) {
			std::stringstream sline(line);
			std::string basename;
			std::string trname;
			uint64_t addr;
			sline >> basename >> trname >> std::hex >> addr;
			auto i = Syscall::fdHooks.size();
			Syscall::fdHooks.push_back({trname, addr});
			Syscall::fdHookIdx.emplace(basename, i);
		}
	}

	return runBin(args);
}

}
