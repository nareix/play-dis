#pragma once

#include <vector>

#include "elf.h"
#include "utils.h"

class ElfFile {
public:
  Slice buf;
  Elf64_Phdr *phX;
  File f;

  struct Section {
    Elf64_Shdr *sh;
    std::string name;
  };

  std::vector<Elf64_Phdr*> loads;
  std::vector<Section> secs;
  bool isPIE;

  Elf64_Ehdr *eh() const {
    return (Elf64_Ehdr *)buf.data();
  }

  static error open(const std::string &filename, ElfFile &file);
};
