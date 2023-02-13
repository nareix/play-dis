#pragma once

#include <string>
#include <functional>
#include <string_view>
#include <memory>

class Slice: public std::basic_string_view<uint8_t> {
public:
  template<typename... Args>
    Slice( Args&&... args ) 
       : std::basic_string_view<uint8_t>(std::forward<Args>(args)...) {  }

  Slice() { 
    Slice(nullptr, 0); 
  }

  Slice slice(size_t start) {
    return {data() + start, size() - start};
  }

  Slice slice(size_t start, size_t size) {
    return {data() + start, size};
  }
};

class DeferF {
  std::function<void()> f;
public:
  DeferF(std::function<void()> f): f(f) {}
  ~DeferF() { f(); }
};

#define defer(f) DeferF __df##__COUNTER__(f)

template <typename... Types>
static inline std::string fmtSprintf(const char *fmt, Types... args) {
  ssize_t n = snprintf(NULL, 0, fmt, args...);
  char buf[n+1];
  snprintf(buf, n+1, fmt, args...);
  return std::string(buf);
}

class IError {
public:
  virtual std::string msg() = 0;
  virtual bool ok() const = 0;
  virtual ~IError() = default;
};

class StrError: public IError {
  std::string s;
public:
  StrError(const std::string &s): s(s) {}
  virtual std::string msg() override { return s; }
  virtual bool ok() const override { return true; };
};

class error {
  std::unique_ptr<IError> i;
public:
  error(IError *i): i(i) {}
  error(const std::nullptr_t &) { }
  std::string msg() { return i ? i->msg() : ""; };
  operator bool() const { return i ? i->ok() : false; }
};

template <typename... Types>
static inline error fmtErrorf(Types... args) {
  return new StrError(fmtSprintf(args...));
}

class File {
public:
  int fd = -1;
  ~File();
  File & operator=(File &&rhs);
  File() {}
  error open(const std::string &file);
  error create(const std::string &file);
  error truncate(size_t size);
};
