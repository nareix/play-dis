#pragma once

#include <stdint.h>
#include <functional>
#include <optional>

bool loadBin(const ElfFile &file, int fd, uint8_t *&loadAddr);
