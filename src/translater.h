#pragma once

#include <vector>
#include <string>
#include <optional>

#include "utils.h"
#include "elf_file.h"

class Translater {
public:
  enum class SlotType: int {
    Patch,
    Stub,
  };

  enum class RelType: int {
    Add,
    Sub,
  };

  enum class FuncType: int {
    GetTls,
    Syscall,
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

  static bool verbose;
  static bool summary;
  static bool debug;
  static bool debugOnlyBefore;
  static bool forAll;
  static int forSingleInstr;

  static void translate(const ElfFile &file, Result &res);
  static bool writeElfFile(const Result &res, const ElfFile &input, const std::string &output);
  static int cmdMain(const std::vector<std::string> &args);
};
