#pragma once

#include <vector>

#include "elf.h"
#include "utils.h"

struct ElfFile {
  u8_view buf;
  Elf64_Phdr *phX;

  struct Section {
    Elf64_Shdr *sh;
    std::string name;
  };

  std::vector<Elf64_Phdr*> loads;
  std::vector<Section> secs;

  Elf64_Ehdr *eh() const {
    return (Elf64_Ehdr *)buf.data();
  }
};

bool parseElf(u8_view buf, ElfFile &file);
bool openElfFile(const std::string &filename, ElfFile &file, int &fd);
