#pragma once

#include <string>
#include <string_view>

template <typename... Types>
std::string fmt(const char *f, Types... args) {
  ssize_t n = snprintf(NULL, 0, f, args...);
  char buf[n+1];
  snprintf(buf, n+1, f, args...);
  return std::string(buf);
}

class u8_view: public std::basic_string_view<uint8_t> {
public:
  template<typename... Args>
    u8_view( Args&&... args ) 
       : std::basic_string_view<uint8_t>(std::forward<Args>(args)...) {  }

  u8_view() { u8_view(nullptr, 0); }

  u8_view slice(size_t start) {
    return {data()+start, size()-start};
  }

  u8_view slice(size_t start, size_t size) {
    return {data()+start, size};
  }
};
