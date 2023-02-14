#include <cstddef>
#include <vector>
#include <string>

#include "elf.h"
#include "runtime.h"
#include "translater.h"
#include "loader.h"
#include "elf_file.h"
#include "utils.h"

static error runMain(int argc, char **argv) {
  std::vector<std::string> args;

  for (int i = 1; i < argc; i++) {
    args.push_back(std::string(argv[i]));
  }

  if (args.size() == 0) {
    return fmtErrorf("need action");
  }

  auto action = args[0];
  args = {args.begin()+1, args.end()};

  if (action == "trans" || action == "translate") {
    return translater::cmdMain(args);
  } else if (action == "rt" || action == "runtime") {
    return runtime::cmdMain(args);
  }

  return fmtErrorf("invalid action");
}

int main(int argc, char **argv) {
  auto err = runMain(argc, argv);
  if (err) {
    auto s = err.msg();
    fputs(s.c_str(), stderr);
    fputs("\n", stderr);
    return -1;
  }
  return 0;
}
