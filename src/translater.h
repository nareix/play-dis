#pragma once

#include <vector>
#include <string>

#include "elf_file.h"

enum {
  kStubReloc,
  kTextReloc,
  kRelocNr,
};

enum {
  kRelText,
  kRelStub,
  kRelCall,
  kRelRIP,
};

enum {
  kFnGetTls,
  kFnSyscall,
  kFnNr,
};

struct SimpleReloc {
  uint32_t addr;
  unsigned slot:2;
  unsigned type:3;
};

struct TranslateResult {
  std::vector<uint8_t> newText;
  std::vector<SimpleReloc> relocs;
};

void translateBin(const ElfFile &file, TranslateResult &res);
int translateBinMain(const std::vector<std::string> &args);
