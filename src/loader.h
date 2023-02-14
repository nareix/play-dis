#pragma once

#include "elf_file.h"

error loadBin(const ElfFile &file, uint8_t *&loadAddr);
