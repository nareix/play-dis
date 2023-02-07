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
    Func,
  };

  enum class FuncType: int {
    GetTls,
    Syscall,
    Nr,
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

  static bool verbose;
  static bool summary;
  static bool debug;
  static bool debugOnlyBefore;
  static bool forAll;
  static int forSingleInstr;

  static void translate(const ElfFile &file, Result &res);
  static void applyPatch(u8_view code, const std::vector<Patch> &patches, const std::vector<uint8_t> &patchCode);
  static void applyReloc(u8_view code, u8_view stubCode, const std::vector<Reloc> &relocs, void **funcs);
  static int cmdMain(const std::vector<std::string> &args);
};
