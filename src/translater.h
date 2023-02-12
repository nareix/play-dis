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

  // static bool isStub(u8_view code);
  // static void relocStubFunc(u8_view code, int i, void *p);

  struct Result {
    std::vector<Reloc> relocs;
    std::vector<uint8_t> stubCode;
    std::vector<uint8_t> patchCode;
    std::vector<Patch> patches;
  };

  void translate(const ElfFile &file, Result &res);
  bool writeElfFile(const Result &res, const ElfFile &input, const std::string &output);
  int cmdMain(const std::vector<std::string> &args);
}
