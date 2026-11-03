/* socket_create area: shared helpers. Every Winsock call goes through a pointer resolved with
 * LoadLibrary/GetProcAddress (U/UIN); nothing from the DLL under test is linked. */
#ifndef SC_H
#define SC_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#ifndef AF_UNIX
#define AF_UNIX 1
#endif
#ifndef AF_HYPERV
#define AF_HYPERV 34
#endif
#ifndef WSA_FLAG_NO_HANDLE_INHERIT
#define WSA_FLAG_NO_HANDLE_INHERIT 0x80
#endif
#ifndef WSA_FLAG_REGISTERED_IO
#define WSA_FLAG_REGISTERED_IO 0x100
#endif
#ifndef WSA_FLAG_ACCESS_SYSTEM_SECURITY
#define WSA_FLAG_ACCESS_SYSTEM_SECURITY 0x40
#endif
#ifndef SO_OPENTYPE
#define SO_OPENTYPE 0x7008
#endif
#define SC_BAD 0xdead
/* Compare once: the argument may be a call with side effects (unlike EXPECT_EQ, which evaluates twice). */
#define SC_EQ(e, w) do { long long v_ = (long long)(e); long long w_ = (long long)(w); \
    t_check(v_ == w_, __FILE__, __LINE__, #e " == " #w, "got %lld (0x%llx) want %lld (0x%llx)", v_, v_, w_, w_); } while (0)

static inline int  sc_err(void) { return U(WSAGetLastError)(); }
static inline void sc_seterr(int e) { U(WSASetLastError)(e); }

/* One WSAStartup per process, taken lazily; a missing stack turns the test into a skip. */
static inline int sc_up(void) {
    static int state;
    if (state == 0) {
        WSADATA d;
        if (!t_proc_in("ws2_32.dll", "WSAStartup") || !t_proc_in("ws2_32.dll", "socket")) state = -1;
        else state = (U(WSAStartup)(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    if (state < 0) { t_skip("ws2_32 unavailable"); return 0; }
    return 1;
}

/* Whether the process token is elevated. Raw sockets for protocols other than ICMP/ICMPv6, and the
 * IP_HDRINCL / IPV6_HDRINCL options, are refused with WSAEACCES to a token that is not. */
static inline int sc_elevated(void) {
    HANDLE tok; TOKEN_ELEVATION te; DWORD n = 0; int r = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &te, sizeof te, &n)) r = te.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}
#define SC_UP() do { if (!sc_up()) return; } while (0)

static inline SOCKET sc_make(int af, int ty, int pr, DWORD fl) { return U(WSASocketW)(af, ty, pr, NULL, 0, fl); }
static inline void sc_close(SOCKET s) { if (s != INVALID_SOCKET) U(closesocket)(s); }

static inline int sc_gso(SOCKET s, int lvl, int opt, void *v, int *l) { return U(getsockopt)(s, lvl, opt, (char *)v, l); }
static inline int sc_sso(SOCKET s, int lvl, int opt, const void *v, int l) { return U(setsockopt)(s, lvl, opt, (const char *)v, l); }

static inline int sc_sotype(SOCKET s) {
    int t = -12345, n = sizeof t;
    if (sc_gso(s, SOL_SOCKET, SO_TYPE, &t, &n)) return -1;
    return t;
}
static inline int sc_getinfo(SOCKET s, WSAPROTOCOL_INFOW *pi) {
    int n = sizeof *pi;
    memset(pi, 0x5a, sizeof *pi);
    return sc_gso(s, SOL_SOCKET, SO_PROTOCOL_INFOW, pi, &n);
}

/* loopback addresses; the port is always 0 so the OS picks one */
static inline void sc_loop4(struct sockaddr_in *a) {
    memset(a, 0, sizeof *a); a->sin_family = AF_INET; a->sin_addr.s_addr = 0x0100007f;
}
static inline void sc_loop6(struct sockaddr_in6 *a) {
    memset(a, 0, sizeof *a); a->sin6_family = AF_INET6; a->sin6_addr.s6_addr[15] = 1;
}

/* NT view of a socket handle, resolved from ntdll by name */
typedef LONG (NTAPI *sc_NtQueryInformationFile_t)(HANDLE, PVOID, PVOID, ULONG, ULONG);
typedef LONG (NTAPI *sc_NtQueryObject_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *sc_NtQueryVolumeInformationFile_t)(HANDLE, PVOID, PVOID, ULONG, ULONG);
#endif
