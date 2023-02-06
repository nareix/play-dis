#include "elf_file.h"

#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

static bool dynFindTag(u8_view file, Elf64_Phdr *ph, Elf64_Sxword tag, Elf64_Xword &v) {
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

bool ElfFile::parse(u8_view buf, ElfFile &file) {
  auto eh = (Elf64_Ehdr *)buf.data();
  if (buf.size() < sizeof(Elf64_Ehdr)) {
    return false;
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
    return false;
  }

  uint8_t *shStart = (uint8_t *)eh + eh->e_shoff;
  Elf64_Shdr *shStrtab = (Elf64_Shdr *)(shStart + eh->e_shentsize*eh->e_shstrndx);
  const char *strtab = (const char *)((uint8_t *)eh + shStrtab->sh_offset);
  for (int i = 0; i < eh->e_shnum; i++) {
    Elf64_Shdr *sh = (Elf64_Shdr *)(shStart + eh->e_shentsize*i);
    auto s = (const char *)strtab + sh->sh_name;
    int maxlen = (uint8_t *)buf.end() - (uint8_t *)s;
    if (maxlen < 0) {
      return false;
    }
    std::string name = std::string(s, strnlen(s, maxlen));
    file.secs.push_back({sh, std::move(name)});
  }

  std::vector<Elf64_Phdr*> phs, loads;

  uint8_t *phStart = (uint8_t *)eh + eh->e_phoff;
  for (int i = 0; i < eh->e_phnum; i++) {
    Elf64_Phdr *ph = (Elf64_Phdr *)(phStart + eh->e_phentsize*i);
    if ((uint8_t *)ph + sizeof(Elf64_Phdr) > buf.end()) {
      return false;
    }
    if (ph->p_offset + ph->p_filesz >= buf.size()) {
      return false;
    }
    phs.push_back(ph);
  }

  for (auto ph: phs) {
    if (ph->p_type == PT_LOAD) {
      loads.push_back(ph);
    }
  }
  if (loads.size() == 0) {
    return false;
  }

  Elf64_Phdr *phX = nullptr;
  auto iphX = std::find_if(loads.begin(), loads.end(), [](auto ph) {
    return ph->p_flags & PF_X;
  });
  if (iphX == phs.end()) {
    return false;
  }
  phX = *iphX;

  if (eh->e_type == ET_EXEC) {
    auto it = std::find_if(phs.begin(), phs.end(), [](Elf64_Phdr *ph) -> bool {
      return ph->p_type == PT_DYNAMIC;
    });
    if (it == phs.end()) {
      return false;
    }
    Elf64_Xword flags1 = 0;
    dynFindTag(buf, *it, DT_FLAGS_1, flags1);
    if (!(flags1 & DF_1_PIE)) {
      return false;
    }
  }

  file.buf = buf;
  file.phX = phX;
  file.loads = std::move(loads);
  return true;
}

bool ElfFile::open(const std::string &filename, ElfFile &file, int &fd) {
  fd = ::open(filename.c_str(), O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "open %s failed\n", filename.c_str());
    return false;
  }

  struct stat sb;
  if (fstat(fd, &sb) == -1) {
    fprintf(stderr, "stat %s failed\n", filename.c_str());
    return false;
  }
  auto fileSize = sb.st_size;

  auto fileAddr = (uint8_t *)mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
  if (fileAddr == MAP_FAILED) {
    fprintf(stderr, "mmap %s failed\n", filename.c_str());
    return false;
  }

  u8_view buf = {fileAddr, (size_t)fileSize};
  if (!parse(buf, file)) {
    fprintf(stderr, "elf not supported\n");
    return false;
  }

  return true;
}

