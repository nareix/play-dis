#include "elf_file.h"
#include "loader.h"

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

bool loadBin(const ElfFile &file, int fd) {
  auto eh = file.eh();
  auto &loads = file.loads;

  auto lastLoad = loads[loads.size()-1];
  auto loadSize = lastLoad->p_vaddr + lastLoad->p_memsz + loads[0]->p_vaddr;
  auto loadFileStart = loads[0]->p_offset;

  void *loadAddr = mmap(NULL, loadSize, PROT_READ, MAP_PRIVATE, fd, 0);
  if (loadAddr == MAP_FAILED) {
    return false;
  }

  for (auto ph: loads) {
  }

  return true;
}

