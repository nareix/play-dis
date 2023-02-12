
#include "runtime.h"

static __attribute__((constructor)) void init() {
  runtime::soInit();
}
