/* Shared helpers for the legacy (BSD style) name service tests: gethostname, gethostby*, getservby*,
 * getprotoby*. ws2_32 is never linked; every call goes through U()/UIN(). */
#ifndef LNS_H
#define LNS_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

#define LNS_COUNT(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* Winsock error numbers used by these APIs, spelled out so that the expectations read as numbers. */
#define LNS_E_FAULT      10014   /* WSAEFAULT */
#define LNS_E_INVAL      10022   /* WSAEINVAL */
#define LNS_E_NOTINIT    10093   /* WSANOTINITIALISED */
#define LNS_E_HOSTNF     11001   /* WSAHOST_NOT_FOUND */
#define LNS_E_NODATA     11004   /* WSANO_DATA */

static unsigned short lns_swap16(unsigned short v) { return (unsigned short)((v << 8) | (v >> 8)); }

/* Make sure the process has no live WSAStartup reference (the rule "calls before WSAStartup fail"). */
static void lns_force_down(void)
{
    int i;
    if (!U(WSACleanup)) return;
    for (i = 0; i < 16; i++) if (U(WSACleanup)() != 0) break;
}
/* One WSAStartup(2.2) reference for the duration of a test. */
static int lns_up(void)
{
    WSADATA d;
    if (!U(WSAStartup)) return -1;
    return U(WSAStartup)(0x202, &d);
}
static void lns_down(void) { if (U(WSACleanup)) U(WSACleanup)(); }
#define LNS_ERR()      (U(WSAGetLastError)())
#define LNS_SETERR(e)  (U(WSASetLastError)(e))

/* Standard prologue for a test using only the listed exports: skips on a missing export or a failed startup. */
#define LNS_NEED(fn) do { REQUIRE(U(fn)); REQUIRE(U(WSAStartup)); REQUIRE(U(WSACleanup)); \
    REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError)); \
    if (lns_up()) { t_skip("WSAStartup failed"); return; } } while (0)
#define LNS_DONE() lns_down()

static int lns_list_len(char **l)
{
    int n = 0;
    if (!l) return -1;
    while (l[n]) n++;
    return n;
}
static int lns_str_in_list(char **l, const char *s)
{
    int i;
    if (!l) return 0;
    for (i = 0; l[i]; i++) if (!_stricmp(l[i], s)) return 1;
    return 0;
}
/* True when [p, p+n) lies inside the object that starts at base and is size bytes long. */
static int lns_inside(const void *base, size_t size, const void *p, size_t n)
{
    const char *b = base, *q = p;
    return q >= b && q + n <= b + size;
}
#endif
