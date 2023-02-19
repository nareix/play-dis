#include "X86BaseInfo.h"
#include "elf.h"
#include "elf_file.h"
#include "utils.h"
#include "runtime.h"

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <map>
#include <functional>
#include <cstdint>
#include <cstdint>
#include <filesystem>
#include <cstddef>
#include <functional>
#include <optional>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include <sys/syscall.h>
#include <asm/prctl.h>
#include <sys/types.h>
#include <type_traits>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unordered_set>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <signal.h>

namespace runtime {

struct HostThread;

struct HostRegs {
  void *fn[2];
  uint64_t regs[11];
  void *stack;
  HostThread *t;
  uint64_t fs;
};

struct Host {
  static __attribute__((naked)) void setr(HostRegs *t) {
    asm("endbr64; wrgsbase %rdi; ret");
  }

  static __attribute__((naked)) HostRegs *r() {
    asm("endbr64; rdgsbase %rax; ret");
  }
};

struct Host H;

static bool debug = true;

struct FileHooks {
  struct File {
    std::string trname;
    uint64_t addr;
  };
  std::vector<File> e;
  std::unordered_map<std::string, int> m;

  void add(const std::string &k, const File &v) {
    auto n = e.size();
    m.emplace(k, n);
    e.push_back(v);
  }

  int find(const std::string &filename) {
    auto i = m.find(std::filesystem::path(filename).filename());
    if (i == m.end()) {
      return -1;
    }
    return i->second;
  }
};

static FileHooks fileHooks;

struct ProcFile {
  int hook;
};

struct VMAs {
  struct VMA {
    uint64_t start;
    uint64_t end;
    int prot;
    int fd;

    std::string str() {
      std::string p = "";
      if (prot & PROT_READ) {
        p += "r";
      } else {
        p += "-";
      }
      if (prot & PROT_WRITE) {
        p += "w";
      } else {
        p += "-";
      }
      if (prot & PROT_EXEC) {
        p += "x";
      } else {
        p += "-";
      }
      return fmtSprintf("%lx-%lx %sp %d", start, end, p.c_str(), fd);
    }
  };

  std::map<int, VMA> m;

  using Node = decltype(m.end());
  using Nodes = std::vector<Node>;

  void dump(const Nodes &rs) {
    for (auto r: rs) {
      auto &a = r->second;
      fmtPrintf("vma %s\n", a.str().c_str());
    }
  }

  Nodes all() {
    Nodes a;
    for (auto r = m.begin(); r != m.end(); r++) {
      a.push_back(r);
    }
    return a;
  }

  Nodes nodes(uint64_t &start, uint64_t &end) {
    assert(start <= end);
    start = sysPageFloor(start);
    end = sysPageCeil(end);

    auto si = m.lower_bound(start);
    auto ei = m.lower_bound(end);

    if (si != m.begin()) {
      si--;
    }
    if (ei != m.end()) {
      ei++;
    }

    Nodes rs;
    for (auto i = si; i != m.end(); i++) {
      rs.push_back(i);
      if (i == ei) {
        break;
      }
    }

    split(rs, start);
    split(rs, end);

    return rs;
  }

  void split(Nodes &rs, uint64_t p) {
    for (auto ri = rs.begin(); ri < rs.end(); ri++) {
      auto &old = (*ri)->second;
      if (old.start < p && p < old.end) {
        auto newr = old;
        newr.start = old.start;
        newr.end = p;
        rs.insert(ri, m.emplace(p, newr).first);
        old.start = p;
        return;
      }
    }
  }

  void merge0(const Nodes &rs) {
    auto p = rs[rs.size()-1];
    for (int i = rs.size()-2; i >= 0; i--) {
      auto li = rs[i];
      auto &l = li->second;
      auto &r = p->second;
      if (l.end == r.start && l.fd == r.fd && l.prot == r.prot) {
        r.start = l.start;
        m.erase(li);
      } else {
        p = li;
      }
    }
  }

  void remove0(Nodes &rs, uint64_t start, uint64_t end) {
    auto ri = rs.begin();
    while (ri != rs.end()) {
      auto r = *ri;
      if (start <= r->second.start && r->second.end <= end) {
        m.erase(r);
        rs.erase(ri);
      } else {
        ri++;
      }
    }
  }

  void remove(uint64_t start, uint64_t end) {
    auto rs = nodes(start, end);
    remove0(rs, start, end);
  }

  void updateProt(uint64_t start, uint64_t end, int prot) {
    auto rs = nodes(start, end);
    for (auto r: rs) {
      if (start <= r->second.start && r->second.end <= end) {
        r->second.prot = prot;
      }
    }
    merge0(rs);
  }

  void add(uint64_t start, uint64_t end, VMA a) {
    auto rs = nodes(start, end);
    remove0(rs, start, end);
    a.start = start;
    a.end = end;
    rs.push_back(m.emplace(end, a).first);
    std::sort(rs.begin(), rs.end(), [](auto l, auto r) {
      return l->second.end < r->second.end;
    });
    merge0(rs);
  }
};

struct Proc {
  uint64_t fs;
  uint64_t gs;
  std::vector<ProcFile*> files;
  VMAs vm;
  uint64_t brkEnd;

  struct Syscall {
    uint64_t &arg;
    const std::function<uint64_t()> &call;
  };

  uint64_t brk(uint64_t addr) {
    if (addr == 0) {
      return brkEnd;
    }

    int len = addr - brkEnd;
    int prot = PROT_READ|PROT_WRITE;
    auto p = ::mmap((void *)brkEnd, len, prot, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    if (p == MAP_FAILED) {
      return -1;
    }
    vm.add(brkEnd, brkEnd+len, {.prot = prot, .fd = -1});

    brkEnd = addr;
    return addr;
  }

  void close(int fd) {
    if (fd >= files.size()) {
      return;
    }

    auto f = files[fd];
    if (!f) {
      return;
    }

    delete f;
    files[fd] = nullptr;
  }

  void open(const std::string &filename, const Syscall &s) {
    auto hooked = false;
    auto hook = fileHooks.find(filename);
    if (hook != -1) {
      hooked = true;
      s.arg = (uint64_t)fileHooks.e[hook].trname.c_str();
    }

    int fd = s.call();
    if (fd == -1) {
      return;
    }

    files.resize(fd+1);
    auto f = new ProcFile();
    f->hook = hook;
    files[fd] = f;

    if (debug && hooked) {
      fmtPrintf("fd %d opened with hook %s\n", fd, (void *)s.arg);
    }
  }

  void mmap(uint64_t addr, int len, int prot, int flags, int fd, uint64_t off, const Syscall &s) {
    auto hooked = false;
    if (fd != -1 && addr == 0 && off == 0) {
      auto f = files[fd];
      if (f->hook != -1) {
        hooked = true;
        s.arg = fileHooks.e[f->hook].addr;
      }
    }

    if (debug && hooked) {
      fmtPrintf("mmap fd %d hook addr %lx\n", fd, s.arg);
    }

    auto raddr = (void *)s.call();
    if (raddr == MAP_FAILED) {
      return;
    }

    vm.add((uint64_t)raddr, (uint64_t)raddr+len, {.prot = prot, .fd = fd});
  }

  void unmap(uint64_t addr, int len) {
    vm.remove(addr, addr+len);
  }

  void fork() {
    if (debug) {
      vm.dump(vm.all());
    }
    asm("int3");
  }
};

struct HostThread {
  std::vector<Proc> ps = {{}};
  Proc &p = ps[0];
};

struct Syscall {
  static thread_local std::vector<std::pair<std::string,std::string>> dbgarg;
  enum { D, X } retfmt;

  void arg(const char *k, uint64_t v) {
    dbgarg.push_back({k, fmtSprintf("0x%lx", v)});
  }

  void arg(const char *k, int v) {
    dbgarg.push_back({k, fmtSprintf("%d", v)});
  }

  void arg(const char *k, const std::string &v) {
    dbgarg.push_back({k, v});
  }

  void argret() {
    if (retfmt == X) {
      arg("", regs[0]);
    } else {
      arg("", int(regs[0]));
    }
  }

  std::string strflags(uint64_t m, const std::vector<std::pair<uint64_t,std::string>> &v) {
    std::vector<std::string> sv;
    for (auto &p: v) {
      if (m & p.first) {
        sv.push_back(p.second);
        m &= ~p.first;
      }
    }
    if (m || sv.size() == 0) {
      sv.push_back(fmtSprintf("0x%x", m));
    }
    std::ostringstream c;
    std::copy(sv.begin(), sv.end(), std::ostream_iterator<std::string>(c, "|"));
    auto r = c.str();
    r.resize(r.size()-1);
    return r;
  }

  #define F(x) {x, #x}

  std::string sprot(int v) {
    return strflags(v, {
      F(PROT_READ),
      F(PROT_WRITE),
      F(PROT_EXEC),
    });
  }

  std::string smmapflags(int v) {
    return strflags(v, {
      F(MAP_FIXED),
      F(MAP_ANONYMOUS),
      F(MAP_SHARED),
      F(MAP_PRIVATE),
      F(MAP_POPULATE),
      F(MAP_GROWSDOWN),
      F(MAP_STACK),
    });
  }

  #undef F

  #define A(k) if (debug) { arg(#k, k); }
  #define A0(k, v) if (debug) { arg(#k, v); }
  #define AF(k, f) if (debug) { arg(#k, f(k)); }

  inline void ret(uint64_t r) {
    handled = true;
    regs[0] = r;
    if (debug) {
      argret();
    }
  }

  uint64_t syscall() {
    syscall0();
    ret(regs[0]);
    return regs[0];
  }
  std::function<uint64_t()> syscall1 = std::bind(&Syscall::syscall, this);

  HostRegs *hr;
  HostThread *t = hr->t;
  Proc &p = t->p;
  uint64_t *regs = hr->regs;
  bool handled;

  void arch_prctl() {
    auto code = regs[1];
    auto addr = regs[2];
    #define C(x) case x: A0(code, #x);
    switch (code) {
      C(ARCH_SET_FS) {
        A(addr);
        p.fs = addr;
        hr->fs = p.fs;
        ret(0);
        break;
      }
      C(ARCH_GET_FS) {
        ret(p.fs);
        break;
      }
      C(ARCH_SET_GS) {
        A(addr);
        p.gs = addr;
        ret(0);
        break;
      }
      C(ARCH_GET_GS) {
        ret(p.gs);
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
    auto addr = regs[1];
    A(addr);
    retfmt = X;

    ret(p.brk(addr));
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

    p.open(filename, {regs[2], syscall1});
  }

  void mprotect() {
    auto start = regs[1];
    auto len = int(regs[2]);
    auto prot = regs[3];
    A(start);
    A(len);
    AF(prot, sprot);

    p.vm.updateProt(start, start+len, prot);
  }

  void mmap() {
    auto addr = regs[1];
    auto len = int(regs[2]);
    auto prot = regs[3];
    auto flags = regs[4];
    auto fd = int(regs[5]);
    auto off = regs[6];
    A(addr);
    A(len);
    AF(prot, sprot);
    AF(flags, smmapflags);
    A(fd);
    A(off);
    retfmt = X;

    p.mmap(addr, len, prot, flags, fd, off, {regs[1], syscall1});
  }

  void munmap() {
    auto addr = regs[1];
    auto len = int(regs[2]);
    A(addr);
    A(len);

    p.unmap(addr, len);
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

    p.close(fd);
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

    p.open(filename, {regs[1], syscall1});
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
    ret(::getpid());
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

  void rt_sigaction() {
    auto sig = int(regs[1]);
    auto act = regs[2];
    auto oldact = regs[3];
    auto size = int(regs[4]);
    A(sig);
    A(act);
    A(oldact);
    A(size);
  }

  void rt_sigprocmask() {
    auto how = int(regs[1]);
    auto set = regs[2];
    auto oldset = regs[3];
    auto size = int(regs[4]);
    A(how);
    A(set);
    A(oldset);
    A(size);
  }

  void stat() {
    auto filename = (const char *)(regs[1]);
    auto sb = regs[2];
    A(filename);
    A(sb);
  }

  void poll() {
    auto fds = regs[1];
    auto n = int(regs[2]);
    auto timeout = int(regs[2]);
    A(fds);
    A(n);
    A(timeout);
  }

  void fork() {
    p.fork();
  }

  void getpid() {
  }

  void gettid() {
  }

  void getppid() {
  }

  void getpgid() {
    auto pid = int(regs[1]);
    A(pid);
  }

  void setpgid() {
    auto pid = int(regs[1]);
    auto pgid = int(regs[2]);
    A(pid);
    A(pgid);
  }

  void wait4() {
    auto pid = int(regs[1]);
    auto stat_addr = regs[2];
    auto options = regs[2];
    auto ru = regs[2];
    A(pid);
    A(stat_addr);
    A(options);
    A(ru);
  }

  void rt_sigreturn() {
  }

  void geteuid() {
  }

  void fcntl() {
    auto fd = int(regs[1]);
    auto cmd = regs[2];
    auto args = regs[2];
    A(fd);
    A(cmd);
    A(args);
  }

  void lseek() {
    auto fd = int(regs[1]);
    auto off = int(regs[2]);
    auto whence = int(regs[3]);
    A(fd);
    A(off);
    A(whence);
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
      C(rt_sigaction)
      C(rt_sigprocmask)
      C(stat)
      C(poll)
      C(fork)
      C(getpid)
      C(gettid)
      C(setpgid)
      C(wait4)
      C(rt_sigreturn)
      C(geteuid)
      C(fcntl)
      C(lseek)
      C(getpgid)
      C(getppid)
      default: {
        arg("", fmtSprintf("syscall_%d", nr));
        break;
      }
    }
    #undef C

    auto bypass = !handled;
    if (bypass) {
      syscall();
    }

    if (debug) {
      auto &fn = dbgarg[0];
      auto &ret = dbgarg[dbgarg.size()-1];
      fmtPrintf("%s(", fn.second.c_str());
      for (int i = 1; i < dbgarg.size()-1; i++) {
        auto &p = dbgarg[i];
        fmtPrintf("%s=%s", p.first.c_str(), p.second.c_str());
        if (i < dbgarg.size()-2) {
          fmtPrintf(",");
        }
      }
      fmtPrintf(") = %s", ret.second.c_str());
      if (bypass) {
        fmtPrintf(" (bypass)");
      }
      fmtPrintf("\n");
      dbgarg.clear();
    }

    return handled;
  }

  #undef A
  #undef A0
  #undef AF

  static bool handle0() {
    return Syscall{.hr = H.r()}.handle();
  }

  // syscall: rax(nr) rdi(1) rsi(2) rdx(3) r10(4) r8(5) r9(6) rax(ret) 
  // caller:  rdi(1) rsi(2) rdx(3) rcx(4) r8(5) r9(6) rax(ret) r10 r11

  static constexpr int R(int i) {
    return offsetof(HostRegs, regs) + i*8;
  }
  static const int Stack = offsetof(HostRegs, stack);
  static const int Fs = offsetof(HostRegs, fs);

  static __attribute__((naked)) void getfs() {
    asm("endbr64; mov %%gs:%c0, %%rax; ret" :: "i"(Fs));
  }

  static __attribute__((naked)) void entry() {
    asm("endbr64");
    // save caller regs
    asm("mov %%rax, %%gs:%c0" :: "i"(R(0)));
    asm("mov %%rdi, %%gs:%c0" :: "i"(R(1)));
    asm("mov %%rsi, %%gs:%c0" :: "i"(R(2)));
    asm("mov %%rdx, %%gs:%c0" :: "i"(R(3)));
    asm("mov %%r10, %%gs:%c0" :: "i"(R(4)));
    asm("mov %%r8, %%gs:%c0" :: "i"(R(5)));
    asm("mov %%r9, %%gs:%c0" :: "i"(R(6)));
    asm("mov %%r11, %%gs:%c0" :: "i"(R(7)));
    // pop and save ret addr
    asm("pop %%r11; mov %%r11, %%gs:%c0" :: "i"(R(9)));
    // swap to host stack
    asm("mov %%rsp, %%gs:%c0" :: "i"(R(8)));
    asm("mov %%gs:%c0, %%rsp" :: "i"(Stack));
    // call handler
    asm("call %P0" :: "i"(handle0));
    // restore call regs
    asm("mov %%gs:%c0, %%rax" :: "i"(R(0)));
    asm("mov %%gs:%c0, %%rdi" :: "i"(R(1)));
    asm("mov %%gs:%c0, %%rsi" :: "i"(R(2)));
    asm("mov %%gs:%c0, %%rdx" :: "i"(R(3)));
    asm("mov %%gs:%c0, %%r10" :: "i"(R(4)));
    asm("mov %%gs:%c0, %%r8" :: "i"(R(5)));
    asm("mov %%gs:%c0, %%r9" :: "i"(R(6)));
    asm("mov %%gs:%c0, %%r11" :: "i"(R(7)));
    // switch to guest stack
    asm("mov %%gs:%c0, %%rsp" :: "i"(R(8)));
    // jmp to ret addr
    asm("jmp *%%gs:%c0" :: "i"(R(9)));
  }

  static __attribute__((naked)) void syscall0() {
    asm("endbr64");
    // restore call regs
    asm("mov %%gs:%c0, %%rax" :: "i"(R(0)));
    asm("mov %%gs:%c0, %%rdi" :: "i"(R(1)));
    asm("mov %%gs:%c0, %%rsi" :: "i"(R(2)));
    asm("mov %%gs:%c0, %%rdx" :: "i"(R(3)));
    asm("mov %%gs:%c0, %%r10" :: "i"(R(4)));
    asm("mov %%gs:%c0, %%r8" :: "i"(R(5)));
    asm("mov %%gs:%c0, %%r9" :: "i"(R(6)));
    asm("mov %%gs:%c0, %%r11" :: "i"(R(7)));
    // swap to guest stack
    asm("mov %%rsp, %%gs:%c0" :: "i"(R(10)));
    asm("mov %%gs:%c0, %%rsp" :: "i"(R(8)));
    // syscall
    asm("syscall");
    // save results
    asm("mov %%rax, %%gs:%c0" :: "i"(R(0)));
    asm("mov %%rsp, %%gs:%c0" :: "i"(R(8)));
    // swap to host stack
    asm("mov %%gs:%c0, %%rsp" :: "i"(R(10)));
    asm("ret");
  }
};

thread_local decltype(Syscall::dbgarg) Syscall::dbgarg;

static error initH() {
  auto size = 1024*128;
  auto stack = (uint8_t *)mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (stack == MAP_FAILED) {
    return fmtErrorf("mmap syscall stack failed");
  }

  static thread_local HostThread t;
  static thread_local HostRegs hr;

  H.setr(&hr);
  hr.fn[0] = (void *)Syscall::entry;
  hr.fn[1] = (void *)Syscall::getfs;
  hr.stack = stack + size;
  hr.t = &t;

  return nullptr;
}

static __attribute__((naked)) void enterBin(void *entry, void *stack) {
  asm("mov %rsi, %rsp; jmpq *%rdi");
}

static error runBin(const std::vector<std::string> &args) {
  auto err = initH();
  if (err) {
    return err;
  }

  auto &proc = H.r()->t->p;

  auto filename = args[0];
  uint8_t *loadP = nullptr;

  auto hook = fileHooks.find(filename);
  if (hook != -1) {
    auto &h = fileHooks.e[hook];
    loadP = (uint8_t *)h.addr;
    filename = h.trname;
  }

  ElfFile file;
  err = file.open(filename);
  if (err) {
    return err;
  }

  auto segs = file.mmapSegs();
  auto segn = segs[segs.size()-1];
  auto loadSize = segn.start + segn.len - segs[0].start;

  {
    auto p = (uint8_t *)mmap(loadP, loadSize, PROT_NONE, MAP_PRIVATE, file.f.fd, 0);
    if (p == MAP_FAILED) {
      return fmtErrorf("load failed");
    }
    if (loadP && p != loadP) {
      return fmtErrorf("load failed");
    }
    loadP = p;
  }

  for (auto &seg: segs) {
    int flags;
    int fd;
    if (seg.anon) {
      flags = MAP_PRIVATE|MAP_ANONYMOUS;
      fd = -1;
    } else {
      flags = MAP_PRIVATE;
      fd = file.f.fd;
    }
    flags |= MAP_FIXED;

    auto segP = loadP + seg.start;
    auto p = (uint8_t *)mmap(segP, seg.len, seg.prot, flags, fd, seg.off);
    if (p == MAP_FAILED) {
      return fmtErrorf("load failed");
    }
    if (seg.fill0) {
      memset(p + seg.len, 0, seg.fill0);
    }

    if (debug) {
      fmtPrintf("load %lx len %lx off %lx anon %d fill0 %d\n", 
        segP, seg.len, seg.off, seg.anon, seg.fill0);
    }

    proc.vm.add((uint64_t)segP, (uint64_t)segP+seg.len, {.prot = seg.prot, .fd = fd});
  }
  proc.brkEnd = (uint64_t)(loadP + sysPageCeil(loadSize));

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
  aux(AT_PAGESZ, sysPageSize);
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

  auto stackSize = 1024*64;
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

  proc.vm.add((uint64_t)stackTop, (uint64_t)stackTop+stackSize, {.prot = PROT_READ|PROT_WRITE, .fd = -1});

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
      fileHooks.add(basename, {trname, addr});
    }
  }

  return runBin(args);
}

}
