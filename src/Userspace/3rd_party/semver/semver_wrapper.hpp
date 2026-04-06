#pragma once

// On older glibc (< 2.28), <sys/types.h> transitively defines major() and
// minor() as macros (from <sys/sysmacros.h>). These collide with the
// semver::version::major() / minor() methods and silently rename them.
// Undefine the macros before including the real header to prevent this.
#ifdef major
#undef major
#endif

#ifdef minor
#undef minor
#endif

#include "semver.hpp"
