#include "utils.h"

#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>


File &File::operator=(File &&rhs) {
  fd = rhs.fd;
  rhs.fd = -1;
  return *this;
}

File::~File() {
  if (fd != -1) {
    close(fd);
  }
}

error File::open(const std::string &filename) {
  auto fd = ::open(filename.c_str(), O_RDONLY);
  if (fd == -1) {
    return fmtErrorf("open %s failed\n", filename.c_str());
  }
  this->fd = fd;
  return nullptr;
}

error File::create(const std::string &filename) {
  int fd = ::open(filename.c_str(), O_RDWR|O_CREAT|O_TRUNC, 0744);
  if (fd == -1) {
    return fmtErrorf("create %s failed\n", filename.c_str());
  }
  this->fd = fd;
  return nullptr;
}
