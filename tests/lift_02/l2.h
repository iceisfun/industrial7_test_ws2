/* Shared helpers for the lift_02 area (Winsock name/address/protocol helpers).
 * Everything in ws2_32 is reached through U(); nothing here links the library under test. */
#ifndef L2_H
#define L2_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2bth.h>
#include <wchar.h>

#define L2_COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define L2_SENTINEL 0xdeadbeefu


/* WSAStartup(2.2) once for the process; returns nonzero when sockets are usable. */
int l2_startup(void);
/* Nonzero when an AF_INET6 stream socket can be created (loopback-only guests still have ::1). */
int l2_have_ipv6(void);

static inline unsigned short l2_swap16(unsigned short v) { return (unsigned short)((v << 8) | (v >> 8)); }
static inline unsigned long l2_swap32(unsigned long v) {
    return ((v & 0xffUL) << 24) | ((v & 0xff00UL) << 8) | ((v >> 8) & 0xff00UL) | ((v >> 24) & 0xffUL);
}
/* Decode a string of hex byte pairs into out[n]. */
void l2_unhex(const char *hex, unsigned char *out, size_t n);
/* Widen a plain ASCII string. */
void l2_widen(const char *s, WCHAR *w, size_t cap);

/* Start the test body only when WinSock came up. */
#define L2_NEED_WSA() do { if (!l2_startup()) { t_skip("WSAStartup failed"); return; } } while (0)
#endif
