#include <seccomp.h>

/*
 * SCMP_ACT_ERRNO / SCMP_ACT_TRACE are function-like macros that OR the errno
 * into the low 16 bits, so jextract cannot turn them into constants. Expanding
 * them with a zero argument inside an enum gives jextract something it can
 * emit, which keeps the base values header-derived instead of hard-coded.
 */
enum takoyaki_scmp_action_base {
    TAKOYAKI_SCMP_ACT_ERRNO_BASE = SCMP_ACT_ERRNO(0),
    TAKOYAKI_SCMP_ACT_TRACE_BASE = SCMP_ACT_TRACE(0),
};

/* SCMP_FLTATR_CTL_WAITKILL was added in libseccomp 2.5.4. Provide a fallback
 * so that jextract always emits the constant regardless of header version. */
#ifndef SCMP_FLTATR_CTL_WAITKILL
#define SCMP_FLTATR_CTL_WAITKILL 10
#endif
