#pragma once

#include <string>
#include <functional>
#include <string_view>
#include <system_error>

class u8_view: public std::basic_string_view<uint8_t> {
public:
  template<typename... Args>
    u8_view( Args&&... args ) 
       : std::basic_string_view<uint8_t>(std::forward<Args>(args)...) {  }

  u8_view() { 
    u8_view(nullptr, 0); 
  }

  u8_view slice(size_t start) {
    return {data() + start, size() - start};
  }

  u8_view slice(size_t start, size_t size) {
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

class error {
public:
  virtual std::string Error() { return ""; };
  virtual explicit operator bool() const { return false; }
};

class FmtError: public error {
  std::string s;
public:
  FmtError(const std::string& s): s(s) {}
  std::string Error() override { return s; };
  explicit operator bool() const override { return true; }
};

template <typename... Types>
static inline error fmtErrorf(Types... args) {
  return FmtError(fmtSprintf(args...));
}
