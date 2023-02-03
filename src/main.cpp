#include <vector>
#include <string>

#include "translater.h"
#include "elf_file.h"

static int doLoad(const std::vector<std::string> &args) {
  if (args.size() == 0) {
    fprintf(stderr, "need filename\n");
    return -1;
  }

  auto filename = args[0];
  ElfFile file;
  int fd;
  if (!loadElfFile(filename, file, fd)) {
    return -1;
  }

  return 0;
}

int main(int argc, char **argv) {
  std::vector<std::string> args;

  for (int i = 1; i < argc; i++) {
    args.push_back(std::string(argv[i]));
  }

  if (args.size() == 0) {
    fprintf(stderr, "need action\n");
    return -1;
  }

  auto action = args[0];
  args = {args.begin()+1, args.end()};

  if (action == "trans") {
    return translateBinMain(args);
  } else if (action == "load") {
    return doLoad(args);
  } else {
    fprintf(stderr, "invalid action\n");
    return -1;
  }

  return -1;
}
