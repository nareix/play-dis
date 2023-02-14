#include "elf_file.h"
#include "utils.h"

#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

static bool dynFindTag(Slice file, Elf64_Phdr *ph, Elf64_Sxword tag, Elf64_Xword &v) {
  auto dynStart = file.data() + ph->p_offset;
  for (auto e = (Elf64_Dyn *)dynStart; (uint8_t *)e < file.end(); e++) {
    if (e->d_tag == DT_NULL) {
      break;
    }
    if (e->d_tag == tag) {
      v = e->d_un.d_val;
      return true;
    }
  }
  return false;
}

static error parse(Slice buf, ElfFile &file) {
  auto eh = (Elf64_Ehdr *)buf.data();
  if (buf.size() < sizeof(Elf64_Ehdr)) {
    return fmtErrorf("size not match #1");
  }

  uint8_t osabi = eh->e_ident[EI_OSABI];
  if (
    eh->e_ident[EI_MAG0] != ELFMAG0 || eh->e_ident[EI_MAG1] != ELFMAG1 ||
    eh->e_ident[EI_MAG2] != ELFMAG2 || eh->e_ident[EI_MAG3] != ELFMAG3 ||
    eh->e_ident[EI_CLASS] != ELFCLASS64 ||
    eh->e_ident[EI_DATA] != ELFDATA2LSB ||
    (osabi != ELFOSABI_LINUX && osabi != ELFOSABI_SYSV) ||
    eh->e_machine != EM_X86_64 ||
    (eh->e_type != ET_DYN && eh->e_type != ET_EXEC)
    )
  {
    return fmtErrorf("invalid spec");
  }

  if (eh->e_phentsize != sizeof(Elf64_Phdr)) {
    return fmtErrorf("invalid spec");
  }
  if (eh->e_shentsize != sizeof(Elf64_Shdr)) {
    return fmtErrorf("invalid spec");
  }

  uint8_t *shStart = (uint8_t *)eh + eh->e_shoff;
  Elf64_Shdr *shStrtab = (Elf64_Shdr *)(shStart + eh->e_shentsize*eh->e_shstrndx);
  const char *strtab = (const char *)((uint8_t *)eh + shStrtab->sh_offset);
  for (int i = 0; i < eh->e_shnum; i++) {
    Elf64_Shdr *sh = (Elf64_Shdr *)(shStart + eh->e_shentsize*i);
    auto s = (const char *)strtab + sh->sh_name;
    int maxlen = (uint8_t *)buf.end() - (uint8_t *)s;
    if (maxlen < 0) {
      return fmtErrorf("size not match #2");
    }
    std::string name = std::string(s, strnlen(s, maxlen));
    file.secs.push_back({sh, std::move(name)});
  }

  std::vector<Elf64_Phdr*> phs, loads;

  uint8_t *phStart = (uint8_t *)eh + eh->e_phoff;
  for (int i = 0; i < eh->e_phnum; i++) {
    Elf64_Phdr *ph = (Elf64_Phdr *)(phStart + eh->e_phentsize*i);
    if ((uint8_t *)ph + sizeof(Elf64_Phdr) > buf.end()) {
      return fmtErrorf("size not match #3");
    }
    if (ph->p_offset + ph->p_filesz > buf.size()) {
      return fmtErrorf("size not match #4: %d", i);
    }
    phs.push_back(ph);
  }

  for (auto ph: phs) {
    if (ph->p_type == PT_LOAD) {
      loads.push_back(ph);
    }
  }
  if (loads.size() == 0) {
    return fmtErrorf("no load sec");
  }

  Elf64_Phdr *phX = nullptr;
  auto iphX = std::find_if(loads.begin(), loads.end(), [](auto ph) {
    return ph->p_flags & PF_X;
  });
  if (iphX == phs.end()) {
    return fmtErrorf("no load x sec");
  }
  phX = *iphX;

  bool isPIE = false;
  if (eh->e_type == ET_EXEC) {
    auto it = std::find_if(phs.begin(), phs.end(), [](Elf64_Phdr *ph) -> bool {
      return ph->p_type == PT_DYNAMIC;
    });
    if (it != phs.end()) {
      Elf64_Xword flags1 = 0;
      dynFindTag(buf, *it, DT_FLAGS_1, flags1);
      isPIE = flags1 & DF_1_PIE;
    }
  }

  file.buf = buf;
  file.phX = phX;
  file.loads = std::move(loads);
  file.isPIE = isPIE;
  return nullptr;
}

error ElfFile::open(const std::string &filename) {
  File f;

  auto err = f.open(filename.c_str());
  if (err) {
    return err;
  }

  Slice buf;
  err = f.mmap(buf);
  if (err) {
    return err;
  }

  err = parse(buf, *this);
  if (err) {
    return fmtErrorf("elf not supported: %s", err.msg().c_str());
  }

  this->buf = buf;
  this->f = std::move(f);

  return nullptr;
}

