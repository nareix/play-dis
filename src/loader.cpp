#include "elf_file.h"
#include "loader.h"
#include "utils.h"

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

static bool debug = true;

error loadBin(const ElfFile &file, uint8_t *&loadP) {
  auto eh = file.eh();
  auto &loads = file.loads;

  auto load0 = loads.begin();
  auto loadn = loads.end()-1;
  auto loadSize = (*loadn)->p_vaddr + (*loadn)->p_memsz + (*load0)->p_vaddr;
  auto fileSize = file.buf.size();

  auto align = 1UL << (64 - __builtin_clzll(fileSize) + 8);
  if (debug) {
    fmtPrintf("loadbin: align %lx\n", loadSize);
  }

  loadP = (uint8_t *)mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE, file.f.fd, 0);
  if (loadP == MAP_FAILED) {
    return fmtErrorf("mmap failed #0");
  }

  munmap(loadP, fileSize);
  loadP = (uint8_t *)((uint64_t)loadP & ~(align-1));
  loadP = (uint8_t *)mmap(loadP, fileSize, PROT_READ, MAP_PRIVATE|MAP_FIXED, file.f.fd, 0);
  if (loadP == MAP_FAILED) {
    return fmtErrorf("mmap failed #1");
  }

  if (debug) {
    fmtPrintf("loadbin: %p n %zu\n", loadP, loads.size());
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

    auto p = (uint8_t *)mmap(loadP + vaddrStart, mapSize, prot, MAP_PRIVATE|MAP_FIXED, file.f.fd, fileOff);
    if (debug) {
      fmtPrintf("loadbin: ph[%d] %p size %lx off %lx\n", i, p, mapSize, fileOff);
    }
    if (p == MAP_FAILED) {
      return fmtErrorf("mmap failed #2.%d", i);
    }

    auto vaddrEndAlign = (vaddrEnd + ph->p_align - 1) & ~(ph->p_align-1);
    auto vaddrMemEnd = ph->p_vaddr + ph->p_memsz;
    if (vaddrMemEnd > vaddrEndAlign) {
      auto mapSize = vaddrMemEnd - vaddrEndAlign;

      void *p = mmap(loadP + vaddrEndAlign, mapSize, prot, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);
      if (debug) {
        fmtPrintf("loadbin: ph[%d] zero %p size %lx\n", i, p, mapSize);
      }
      if (p == MAP_FAILED) {
        return fmtErrorf("mmap failed #2.%d.1", i);
      }
    }
  }

  return nullptr;
}
