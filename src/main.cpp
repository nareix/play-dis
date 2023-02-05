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
  if (!openElfFile(filename, file, fd)) {
    return -1;
  }

  uint8_t *loadAddr;
  if (!loadBin(file, fd, loadAddr)) {
    return -1;
  }

  auto entryAddr = loadAddr + file.eh()->e_entry - (*file.loads.begin())->p_vaddr;
  int stackSize = 1024*128;
  auto stackTop = (uint8_t *)mmap(NULL, stackSize, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (stackTop == MAP_FAILED) {
    return -1;
  }
  auto stackEnd = stackTop + stackSize;
  auto stackStart = stackEnd;

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

  auto text = std::find_if(file.secs.begin(), file.secs.end(), [](auto &s) {
    return s.name == ".text";
  });
  if (text == file.secs.end()) {
    return -1;
  }

  auto textLoadAddr = loadAddr + text->sh->sh_offset - file.loads[0]->p_offset;
  fprintf(stderr, "add-symbol-file %s %p\n", filename.c_str(), textLoadAddr);

  asm("mov %0, %%rsp" :: "r"(stackStart));
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
    return translateBinMain(args);
  } else if (action == "load") {
    return doLoad(args);
  } else {
    fprintf(stderr, "invalid action\n");
    return -1;
  }

  return -1;
}
