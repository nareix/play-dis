#include "utils.h"

#include <cstddef>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

File &File::operator=(File &&rhs) {
  fd = rhs.fd;
  rhs.fd = -1;
  mmapP = rhs.mmapP;
  rhs.mmapP = nullptr;
  return *this;
}

File::~File() {
  if (mmapP != nullptr) {
    msync(mmapP, size(), MS_SYNC);
    mmapP = nullptr;
  }
  if (fd != -1) {
    close(fd);
  }
}

error File::open(const std::string &filename) {
  auto fd = ::open(filename.c_str(), O_RDWR);
  if (fd == -1) {
    return fmtErrorf("open %s failed", filename.c_str());
  }
  this->fd = fd;
  return nullptr;
}

size_t File::size() {
  struct stat64 sb = {};
  if (fstat64(fd, &sb) == -1) {
    return fmtErrorf("fstat64 failed");
  }
  return sb.st_size;
}

error File::truncate(size_t n) {
  if (::ftruncate64(fd, n) == -1) {
    return fmtErrorf("ftruncate failed");
  }
  return nullptr;
}

error File::mmap(Slice &buf) {
  auto n = size();
  auto p = (uint8_t *)::mmap(NULL, n, PROT_READ, MAP_PRIVATE, fd, 0);
  if (p == MAP_FAILED) {
    return fmtErrorf("mmap failed");
  }
  buf = {p, n};
  mmapP = p;
  return nullptr;
}

error File::mmapWrite(Slice &buf) {
  auto n = size();
  auto p = (uint8_t *)::mmap(NULL, n, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if (p == MAP_FAILED) {
    return fmtErrorf("mmap failed");
  }
  buf = {p, n};
  mmapP = p;
  return nullptr;
}

error File::create(const std::string &filename) {
  int fd = ::open(filename.c_str(), O_RDWR|O_CREAT|O_TRUNC, 0744);
  if (fd == -1) {
    return fmtErrorf("create %s failed", filename.c_str());
  }
  this->fd = fd;
  return nullptr;
}
