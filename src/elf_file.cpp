#include "elf_file.h"

static bool elfGetPhs(u8_view file, ElfPhs &phs) {
  auto eh = (Elf64_Ehdr *)file.data();
  uint8_t *phStart = (uint8_t *)eh + eh->e_phoff;
  for (int i = 0; i < eh->e_phnum; i++) {
    Elf64_Phdr *ph = (Elf64_Phdr *)(phStart + eh->e_phentsize*i);
    if ((uint8_t *)ph + sizeof(Elf64_Phdr) > file.end()) {
      return false;
    }
    if (ph->p_offset + ph->p_filesz >= file.size()) {
      return false;
    }
    phs.push_back(ph);
  }
  return true;
}

static bool elfDynFindTag(u8_view file, Elf64_Phdr *ph, Elf64_Sxword tag, Elf64_Xword &v) {
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

bool parseElf(u8_view buf, ElfFile &file) {
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

  ElfPhs phs, loads;
  elfGetPhs(buf, phs);

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
    return ph->p_type == PT_LOAD && ph->p_flags & PF_X;
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
    elfDynFindTag(buf, *it, DT_FLAGS_1, flags1);
    if (!(flags1 & DF_1_PIE)) {
      return false;
    }
  }

  file.buf = buf;
  file.phX = phX;
  file.loads = std::move(loads);
  return true;
}

