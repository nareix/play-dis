#include <vector>
#include <string>

#include "translater.h"
#include "loader.h"
#include "elf_file.h"

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

static int doLoad(const std::vector<std::string> &args) {
  if (args.size() == 0) {
    fprintf(stderr, "need filename\n");
    return -1;
  }

  auto filename = args[0];
  ElfFile file;
  int fd;
  if (!ElfFile::open(filename, file, fd)) {
    return -1;
  }

  uint8_t *loadAddr, *loadAddrPhX = nullptr;
  if (!loadBin(file, fd, loadAddr, loadAddrPhX)) {
    return -1;
  }
  if (!loadAddrPhX) {
    return -1;
  }

  struct Runtime {
    static void *getTls() {
      asm("ud2");
      return nullptr;
    }

    static void syscall(uint64_t idx, ...) {
      asm("ud2");
    }
  };

  void *funcs[] = {
    (void *)Runtime::getTls,
    (void *)Runtime::syscall,
  };

  {
    Translater::Result res;
    Translater::translate(file, res);

    auto p = (uint8_t *)mmap(NULL, res.stubCode.size(), PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
      return -1;
    }

    u8_view stubCode = {p, res.stubCode.size()};
    memcpy((void *)stubCode.data(), res.stubCode.data(), res.stubCode.size());
    u8_view code = {loadAddrPhX, file.phX->p_filesz};

    auto diff = std::abs(stubCode.data() - code.data());
    fprintf(stderr, "stub %p code %p diff=%lx maxdiff=%lx\n", stubCode.data(), code.data(), diff, (1L<<31));
    if (diff > (1L<<31)) {
      return -1;
    }

    Translater::applyPatch(code, res.patches, res.patchCode);
    Translater::applyReloc(code, stubCode, res.relocs, funcs);
  }

  auto entryAddr = loadAddr + file.eh()->e_entry - (*file.loads.begin())->p_vaddr;
  uint8_t *stackStart = nullptr;

  auto prepareAux = [&]() -> int {
    int stackSize = 1024*128;
    auto stackTop = (uint8_t *)mmap(NULL, stackSize, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (stackTop == MAP_FAILED) {
      return -1;
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
    uint8_t *phStart = (uint8_t *)eh + eh->e_phoff;

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
    v.push_back((size_t)entryAddr);
    v.push_back(AT_EXECFN);
    v.push_back((size_t)filename.c_str());
    v.push_back(AT_PLATFORM);
    v.push_back((size_t)"x86_64");
    v.push_back(0);
    v.push_back(0);

    auto vsize = v.size()*sizeof(v[0]);
    if (vsize > stackSize) {
      return -1;
    }

    stackStart -= vsize;
    memcpy(stackStart, v.data(), vsize);

    return 0;
  };

  if (prepareAux() != 0) {
    return -1;
  }

  fprintf(stderr, "start\n");

  asm("cmp $0, %0; cmovne %0, %%rsp" :: "r"(stackStart));
  asm("jmpq *%0" :: "r"(entryAddr));

  return 0;
}

int main(int argc, char **argv) {
  std::vector<std::string> args;

  for (int i = 1; i < argc; i++) {
    args.push_back(std::string(argv[i]));
  }

  if (args.size() == 0) {
    fprintf(stderr, "need action\n");
    return -1;
  }

  auto action = args[0];
  args = {args.begin()+1, args.end()};

  if (action == "trans") {
    return Translater::cmdMain(args);
  } else if (action == "load") {
    return doLoad(args);
  } else {
    fprintf(stderr, "invalid action\n");
    return -1;
  }

  return -1;
}
