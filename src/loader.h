#pragma once

#include "elf_file.h"

bool loadBin(const ElfFile &file, int fd, uint8_t *&loadAddr, uint8_t *&loadAddrPhX);
