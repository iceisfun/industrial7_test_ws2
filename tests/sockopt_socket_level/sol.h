/* Shared helpers for the sockopt_socket_level area: SOL_SOCKET option behaviour.
 * ws2_32.dll is never linked; every Winsock call goes LoadLibrary -> GetProcAddress -> invoke through U(). */
#ifndef SOL_H
#define SOL_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#ifndef SO_BSP_STATE
#define SO_BSP_STATE 0x1009
#endif
#ifndef SO_GROUP_ID
#define SO_GROUP_ID 0x2001
#endif
#ifndef SO_GROUP_PRIORITY
#define SO_GROUP_PRIORITY 0x2002
#endif
#ifndef SO_MAX_MSG_SIZE
#define SO_MAX_MSG_SIZE 0x2003
#endif
#ifndef SO_CONDITIONAL_ACCEPT
#define SO_CONDITIONAL_ACCEPT 0x3002
#endif
#ifndef SO_PAUSE_ACCEPT
#define SO_PAUSE_ACCEPT 0x3003
#endif
#ifndef SO_COMPARTMENT_ID
#define SO_COMPARTMENT_ID 0x3004
#endif
#ifndef SO_RANDOMIZE_PORT
#define SO_RANDOMIZE_PORT 0x3005
#endif
#ifndef SO_PORT_SCALABILITY
#define SO_PORT_SCALABILITY 0x3006
#endif
#ifndef SO_REUSE_UNICASTPORT
#define SO_REUSE_UNICASTPORT 0x3007
#endif
#ifndef SO_REUSE_MULTICASTPORT
#define SO_REUSE_MULTICASTPORT 0x3008
#endif
#ifndef SO_USELOOPBACK
#define SO_USELOOPBACK 0x0040
#endif
#ifndef SO_EXCLUSIVEADDRUSE
#define SO_EXCLUSIVEADDRUSE ((int)(~SO_REUSEADDR))
#endif
#ifndef SO_UPDATE_ACCEPT_CONTEXT
#define SO_UPDATE_ACCEPT_CONTEXT 0x700B
#endif
#ifndef SO_UPDATE_CONNECT_CONTEXT
#define SO_UPDATE_CONNECT_CONTEXT 0x7010
#endif
#ifndef SO_CONNECT_TIME
#define SO_CONNECT_TIME 0x700C
#endif
#ifndef SO_OPENTYPE
#define SO_OPENTYPE 0x7008
#endif

/* Single-evaluation comparisons: the harness EXPECT_EQ evaluates its arguments twice. */
#define EQ(a, b) do { unsigned long long a_ = (unsigned long long)(ULONG_PTR)(a), b_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", a_, b_); } while (0)
#define NE(a, b) do { unsigned long long a_ = (unsigned long long)(ULONG_PTR)(a), b_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(a_ != b_, __FILE__, __LINE__, #a " != " #b, "got 0x%llx", a_); } while (0)
#define NELEM(a) ((int)(sizeof(a) / sizeof((a)[0])))

static int    werr(void)                         { return U(WSAGetLastError)(); }
static void   wset(int e)                        { U(WSASetLastError)(e); }
static SOCKET mk(int af, int type, int proto)    { return U(socket)(af, type, proto); }
static int    cls(SOCKET s)                      { return U(closesocket)(s); }
static int    gso(SOCKET s, int lvl, int opt, void *v, int *len)       { return U(getsockopt)(s, lvl, opt, (char *)v, len); }
static int    sso(SOCKET s, int lvl, int opt, const void *v, int len)  { return U(setsockopt)(s, lvl, opt, (const char *)v, len); }
static int    nonblock(SOCKET s, int on)         { u_long v = on ? 1 : 0; return U(ioctlsocket)(s, FIONBIO, &v); }

/* Per-test stack bring-up: always pair ws_up()/ws_down(). Returns 0 (and skips) when WSAStartup fails. */
static int ws_up(void)
{
    WSADATA d;
    int r;
    if (!U(WSAStartup)) { t_skip("missing export"); return 0; }
    r = U(WSAStartup)(MAKEWORD(2, 2), &d);
    if (r) { t_skip("WSAStartup failed: %d", r); return 0; }
    return 1;
}
static void ws_down(void) { U(WSACleanup)(); }
#define NEED() do { if (!ws_up()) return; } while (0)

static void lo4(struct sockaddr_in *a, unsigned short port_be)
{
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = 0x0100007f;
    a->sin_port = port_be;
}

/* Socket kinds covered by the per-type tables. */
enum { K_TCP4, K_UDP4, K_TCP6, K_UDP6, K_COUNT };
static const char *const kind_name[K_COUNT] = { "tcp4", "udp4", "tcp6", "udp6" };
static int kind_stream(int k) { return k == K_TCP4 || k == K_TCP6; }
static SOCKET mk_kind(int k)
{
    switch (k) {
    case K_TCP4: return mk(AF_INET,  SOCK_STREAM, IPPROTO_TCP);
    case K_UDP4: return mk(AF_INET,  SOCK_DGRAM,  IPPROTO_UDP);
    case K_TCP6: return mk(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    default:     return mk(AF_INET6, SOCK_DGRAM,  IPPROTO_UDP);
    }
}
/* A socket of kind k, or INVALID_SOCKET with a skip note (IPv6 may be absent). */
static SOCKET mk_kind_or_skip(int k)
{
    SOCKET s = mk_kind(k);
    if (s == INVALID_SOCKET) t_skip("cannot create %s socket (err %d)", kind_name[k], werr());
    return s;
}

/* Connected loopback TCP pair; returns 1 on success. Listener is closed again. */
static int make_pair(SOCKET *a, SOCKET *b)
{
    struct sockaddr_in addr; int n = sizeof addr;
    SOCKET l = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP), c, s;
    *a = *b = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    lo4(&addr, 0);
    if (U(bind)(l, (struct sockaddr *)&addr, sizeof addr) || U(listen)(l, 1) || U(getsockname)(l, (struct sockaddr *)&addr, &n)) { cls(l); return 0; }
    c = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c == INVALID_SOCKET || U(connect)(c, (struct sockaddr *)&addr, sizeof addr)) { cls(l); if (c != INVALID_SOCKET) cls(c); return 0; }
    s = U(accept)(l, NULL, NULL);
    cls(l);
    if (s == INVALID_SOCKET) { cls(c); return 0; }
    *a = c; *b = s;
    return 1;
}

/* Bound (loopback, ephemeral) socket of the given kind's family; returns 0 on failure. */
static int bind_lo(SOCKET s, int v6)
{
    if (!v6) { struct sockaddr_in a; lo4(&a, 0); return U(bind)(s, (struct sockaddr *)&a, sizeof a) == 0; }
    else { struct sockaddr_in6 a; memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1; return U(bind)(s, (struct sockaddr *)&a, sizeof a) == 0; }
}
#endif
