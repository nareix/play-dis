#pragma once

#include <stdint.h>
#include "utils.h"

namespace runtime {
  void soInit();
  error cmdMain(std::vector<std::string> &args);
}
