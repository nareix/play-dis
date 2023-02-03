#include <vector>
#include <string>

int main(int argc, char **argv) {
  std::vector<std::string> args0;

  for (int i = 1; i < argc; i++) {
    args0.push_back(std::string(argv[i]));
  }

  if (args0[0] == "trans") {
  }
}
