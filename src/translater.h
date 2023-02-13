#pragma once

#include <vector>
#include <string>
#include <optional>

#include "utils.h"
#include "elf_file.h"

namespace translater {
  enum class SlotType: int {
    Patch,
    Stub,
  };

  enum class RelType: int {
    Add,
    Sub,
  };

  struct Reloc {
    uint32_t addr;
    unsigned slot:2;
    unsigned rel:3;
  };

  struct Patch {
    uint32_t addr;
    uint32_t off;
    uint16_t size;
  };

  struct Result {
    std::vector<Reloc> relocs;
    std::vector<uint8_t> stubCode;
    std::vector<uint8_t> patchCode;
    std::vector<Patch> patches;
  };

  void translate(const ElfFile &file, Result &res);
  error writeElfFile(const Result &res, const ElfFile &input, const std::string &setInterp, const std::string &output);
  error cmdMain(const std::vector<std::string> &args);
}
