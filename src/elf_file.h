#pragma once

#include <vector>

#include "elf.h"
#include "utils.h"

class ElfFile {
public:
  Slice buf;
  Elf64_Phdr *phX;
  File f;

  struct MmapSeg {
    uint64_t start;
    uint64_t len;
    uint64_t off;
    int prot;
    bool anon;
    uint64_t fill0;
  };
  std::vector<MmapSeg> mmapSegs() const;

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

  error open(const std::string &filename);
};
