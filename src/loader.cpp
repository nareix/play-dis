#include "elf_file.h"
#include "loader.h"

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

static const bool debug = true;

bool loadBin(const ElfFile &file, int fd, uint8_t *&loadAddr, uint8_t *&loadAddrPhX) {
  auto eh = file.eh();
  auto &loads = file.loads;

  auto load0 = loads.begin();
  auto loadn = loads.end()-1;
  auto loadSize = (*loadn)->p_vaddr + (*loadn)->p_memsz + (*load0)->p_vaddr;
  auto fileSize = file.buf.size();

  auto align = 1UL << (64 - __builtin_clzll(fileSize) + 8);
  if (debug) {
    fprintf(stderr, "loadbin: align %lx\n", loadSize);
  }

  loadAddr = (uint8_t *)mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
  if (loadAddr == MAP_FAILED) {
    return false;
  }

  munmap(loadAddr, fileSize);
  loadAddr = (uint8_t *)((uint64_t)loadAddr & ~(align-1));
  loadAddr = (uint8_t *)mmap(loadAddr, fileSize, PROT_READ, MAP_PRIVATE|MAP_FIXED, fd, 0);
  if (loadAddr == MAP_FAILED) {
    return false;
  }

  if (debug) {
    fprintf(stderr, "loadbin: %p n %zu\n", loadAddr, loads.size());
  }

  for (int i = 0; i < loads.size(); i++) {
    auto ph = loads[i];
    auto diff = ph->p_vaddr & (ph->p_align-1);
    auto vaddrStart = ph->p_vaddr - diff;
    auto fileOff = ph->p_offset - diff;
    auto vaddrEnd = ph->p_vaddr + ph->p_filesz;
    auto mapSize = vaddrEnd - vaddrStart;
    int prot = 0;

    if (ph->p_flags & PF_X) {
      prot |= PROT_EXEC;
    }
    if (ph->p_flags & PF_R) {
      prot |= PROT_READ;
    }
    if (ph->p_flags & (PF_W|PF_X)) {
      prot |= PROT_WRITE;
    }

    auto p = (uint8_t *)mmap(loadAddr + vaddrStart, mapSize, prot, MAP_PRIVATE|MAP_FIXED, fd, fileOff);
    if (debug) {
      fprintf(stderr, "loadbin: ph[%d] %p size %lx off %lx\n", i, p, mapSize, fileOff);
    }
    if (p == MAP_FAILED) {
      return false;
    }

    if (ph == file.phX) {
      loadAddrPhX = p + diff;
    }

    auto vaddrEndAlign = (vaddrEnd + ph->p_align - 1) & ~(ph->p_align-1);
    auto vaddrMemEnd = ph->p_vaddr + ph->p_memsz;
    if (vaddrMemEnd > vaddrEndAlign) {
      auto mapSize = vaddrMemEnd - vaddrEndAlign;

      void *p = mmap(loadAddr + vaddrEndAlign, mapSize, prot, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);
      if (debug) {
        fprintf(stderr, "loadbin: ph[%d] zero %p size %lx\n", i, p, mapSize);
      }
      if (p == MAP_FAILED) {
        return false;
      }
    }
  }

  return true;
}
