
#include "compiler.h"
#include "utils.h"
#include <cstring>

namespace compiler {

struct Parser {
};

error cmdMain(const std::vector<std::string> &args) {
  if (args.size() == 0) {
    return fmtErrorf("need args");
  }

  return nullptr;
}

}

