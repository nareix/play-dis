#include <cstddef>
#include <map>
#include <sstream>
#include <vector>
#include <string>

#include "elf.h"
#include "runtime.h"
#include "translater.h"
#include "elf_file.h"
#include "compiler.h"
#include "utils.h"

static error runMain(int argc, char **argv) {
  std::vector<std::string> args;

  for (int i = 1; i < argc; i++) {
    args.push_back(argv[i]);
  }

  if (args.size() == 0) {
    return fmtErrorf("need action");
  }

  auto action = args[0];
  args = {args.begin()+1, args.end()};

  if (action == "tr" || action == "trans" || action == "translate") {
    return translater::cmdMain(args);
  } else if (action == "rt" || action == "runtime") {
    return runtime::cmdMain(args);
  } else if (action == "build") {
    return compiler::cmdMain(args);
  } else if (action == "play") {
    return nullptr;
  }

  return fmtErrorf("invalid action");
}

int main(int argc, char **argv) {
  auto err = runMain(argc, argv);
  if (err) {
    fprintf(stderr, "%s\n", err.msg().c_str());
    return -1;
  }
  return 0;
}
