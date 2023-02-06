#pragma once

#include <vector>
#include <string>
#include <optional>

#include "utils.h"
#include "elf_file.h"

class Translater {
public:
  enum class RelocType {
    Stub,
    Text,
    Nr,
  };

  enum class RelType {
    Text,
    Stub,
    Call,
    RIP,
  };

  enum class FuncType {
    GetTls,
    Syscall,
    Nr,
  };

  struct Reloc {
    uint32_t addr;
    unsigned slot:2;
    unsigned type:3;
  };

  struct Result {
    std::vector<Reloc> relocs;
    std::vector<uint8_t> stubCode;
  };

  static bool verbose;
  static bool summary;
  static bool debug;
  static bool debugOnlyBefore;
  static bool forAll;
  static int forSingleInstr;

  static void translate(const ElfFile &file, u8_view newText, Result &res);
  static void apply(u8_view newText, const Result &res);
  static int cmdMain(const std::vector<std::string> &args);
};
