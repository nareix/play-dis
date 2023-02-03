#pragma once

#include <vector>

#include "elf.h"
#include "utils.h"

using ElfPhs = std::vector<Elf64_Phdr*>;

struct ElfFile {
  u8_view buf;
  Elf64_Phdr *phX;
  ElfPhs loads;

  Elf64_Ehdr *eh() {
    return (Elf64_Ehdr *)buf.data();
  }
};

bool parseElf(u8_view buf, ElfFile &file);
