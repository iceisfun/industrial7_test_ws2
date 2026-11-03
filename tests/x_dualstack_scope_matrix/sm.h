/* Shared helpers for the x_dualstack_scope_matrix area.  Every Winsock call goes through a pointer
 * resolved with GetProcAddress (U/UIN); nothing from the DLLs under test is linked. */
#ifndef SM_H
#define SM_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif
#ifndef IPV6_UNICAST_IF
#define IPV6_UNICAST_IF 31
#endif
#ifndef IP_UNICAST_IF
#define IP_UNICAST_IF 31
#endif
#ifndef SIO_ADDRESS_LIST_QUERY
#define SIO_ADDRESS_LIST_QUERY _WSAIOR(IOC_W32, 22)
#endif

#ifndef NI_NUMERICSCOPE
#define NI_NUMERICSCOPE 0x02
#endif
#define SA6LEN ((int)sizeof(struct sockaddr_in6))
#define SA4LEN ((int)sizeof(struct sockaddr_in))

static inline int s_err(void) { return U(WSAGetLastError)(); }
static inline unsigned short s_h16(unsigned short v) { return (unsigned short)((v << 8) | (v >> 8)); }
static inline unsigned int s_h32(unsigned int v) {
    return (v << 24) | ((v & 0xff00u) << 8) | ((v >> 8) & 0xff00u) | (v >> 24);
}

static inline int s_up(void) {
    static int st;
    if (!st) {
        WSADATA d;
        if (!t_proc_in("ws2_32.dll", "WSAStartup") || !t_proc_in("ws2_32.dll", "socket")) st = -1;
        else st = U(WSAStartup)(MAKEWORD(2, 2), &d) == 0 ? 1 : -1;
    }
    if (st < 0) { t_skip("winsock unavailable"); return 0; }
    return 1;
}
static inline SOCKET s_open(int af, int ty) {
    SOCKET s = U(socket)(af, ty, 0);
    if (s != INVALID_SOCKET) { DWORD ms = 3000; U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms); }
    return s;
}
static inline void s_close(SOCKET s) { if (s != INVALID_SOCKET) U(closesocket)(s); }
static inline int s_setint(SOCKET s, int lv, int nm, int v) { return U(setsockopt)(s, lv, nm, (const char *)&v, sizeof v); }
static inline int s_getint(SOCKET s, int lv, int nm, int *v) { int l = sizeof *v; *v = -77; return U(getsockopt)(s, lv, nm, (char *)v, &l); }
static inline int s_v6only(SOCKET s, int v) { return s_setint(s, IPPROTO_IPV6, IPV6_V6ONLY, v); }

/* ---- socket kinds ---------------------------------------------------------- */
enum { SK_V4, SK_V6D, SK_V6O, SK_V6DEF, SK_N };   /* v4; v6 dual (V6ONLY 0); v6 only (V6ONLY 1); v6 as created */
static const char *const SK_NAME[SK_N] = { "v4", "v6dual", "v6only", "v6def" };
static inline SOCKET s_mk(int sk, int ty) {
    SOCKET s = s_open(sk == SK_V4 ? AF_INET : AF_INET6, ty);
    if (s == INVALID_SOCKET) return s;
    if (sk == SK_V6D) s_v6only(s, 0);
    if (sk == SK_V6O) s_v6only(s, 1);
    return s;
}

/* ---- address kinds -------------------------------------------------------- */
enum {
    AK_V4ANY, AK_V4LOOP, AK_V6ANY, AK_V6LOOP, AK_MAPANY, AK_MAPLOOP,
    AK_LL, AK_LL_SCOPE, AK_LL_BADSCOPE, AK_V6LOOP_SCOPE, AK_V6LOOP_BADSCOPE, AK_V6ANY_SCOPE, AK_DOC, AK_N
};
static const char *const AK_NAME[AK_N] = {
    "v4any", "v4loop", "v6any", "v6loop", "mapany", "maploop",
    "ll", "ll+loopidx", "ll+badscope", "v6loop+loopidx", "v6loop+badscope", "v6any+loopidx", "doc"
};
#define BAD_SCOPE 0x7777u

/* index of the loopback interface, resolved at run time (0 when it cannot be found) */
static inline unsigned s_loopidx(void) {
    static int done; static unsigned idx;
    if (!done) {
        typedef DWORD (WINAPI *gbi_t)(struct sockaddr *, DWORD *);
        HMODULE m = t_module("iphlpapi.dll");
        gbi_t f = m ? (gbi_t)GetProcAddress(m, "GetBestInterfaceEx") : NULL;
        struct sockaddr_in a; DWORD i = 0;
        memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = s_h32(0x7f000001u);
        if (f && f((struct sockaddr *)&a, &i) == 0) idx = i;
        done = 1;
    }
    return idx;
}

/* Builds the sockaddr of kind k into buf (>= 28 bytes); returns the length to pass. */
static inline int s_mkaddr(void *buf, int k, unsigned short port_net) {
    struct sockaddr_in *a4 = buf; struct sockaddr_in6 *a6 = buf;
    memset(buf, 0, 28);
    if (k == AK_V4ANY || k == AK_V4LOOP) {
        a4->sin_family = AF_INET; a4->sin_port = port_net;
        if (k == AK_V4LOOP) a4->sin_addr.s_addr = s_h32(0x7f000001u);
        return SA4LEN;
    }
    a6->sin6_family = AF_INET6; a6->sin6_port = port_net;
    switch (k) {
    case AK_V6LOOP: case AK_V6LOOP_SCOPE: case AK_V6LOOP_BADSCOPE: a6->sin6_addr.u.Byte[15] = 1; break;
    case AK_MAPANY: a6->sin6_addr.u.Byte[10] = a6->sin6_addr.u.Byte[11] = 0xff; break;
    case AK_MAPLOOP:
        a6->sin6_addr.u.Byte[10] = a6->sin6_addr.u.Byte[11] = 0xff;
        a6->sin6_addr.u.Byte[12] = 127; a6->sin6_addr.u.Byte[15] = 1; break;
    case AK_LL: case AK_LL_SCOPE: case AK_LL_BADSCOPE:
        a6->sin6_addr.u.Byte[0] = 0xfe; a6->sin6_addr.u.Byte[1] = 0x80; a6->sin6_addr.u.Byte[15] = 1; break;
    case AK_DOC:
        a6->sin6_addr.u.Byte[0] = 0x20; a6->sin6_addr.u.Byte[1] = 0x01; a6->sin6_addr.u.Byte[2] = 0x0d;
        a6->sin6_addr.u.Byte[3] = 0xb8; a6->sin6_addr.u.Byte[15] = 1; break;
    }
    if (k == AK_LL_SCOPE || k == AK_V6LOOP_SCOPE || k == AK_V6ANY_SCOPE) a6->sin6_scope_id = s_loopidx();
    if (k == AK_LL_BADSCOPE || k == AK_V6LOOP_BADSCOPE) a6->sin6_scope_id = BAD_SCOPE;
    return SA6LEN;
}

/* Classifies a returned sockaddr into a short deterministic label: family, address class, scope class. */
static inline void s_desc(const void *sa, int len, char *out, size_t cap) {
    const struct sockaddr_in *a4 = sa; const struct sockaddr_in6 *a6 = sa;
    const unsigned char *b = a6->sin6_addr.u.Byte;
    static const unsigned char z[16];
    if (len <= 0) { snprintf(out, cap, "len%d", len); return; }
    if (a4->sin_family == AF_INET) {
        unsigned ip = s_h32(a4->sin_addr.s_addr);
        snprintf(out, cap, "v4:%s:len%d", ip == 0 ? "any" : ip == 0x7f000001u ? "loop" : "other", len);
    } else if (a4->sin_family == AF_INET6) {
        const char *c;
        static const unsigned char mp[10];
        if (!memcmp(b, z, 16)) c = "any";
        else if (!memcmp(b, z, 15) && b[15] == 1) c = "loop";
        else if (!memcmp(b, mp, 10) && b[10] == 0xff && b[11] == 0xff)
            c = (!b[12] && !b[13] && !b[14] && !b[15]) ? "map:any" : (b[12] == 127 && !b[13] && !b[14] && b[15] == 1) ? "map:loop" : "map:other";
        else if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) c = "ll";
        else c = "other";
        snprintf(out, cap, "v6:%s:scope%s:len%d", c,
                 a6->sin6_scope_id == 0 ? "0" : a6->sin6_scope_id == s_loopidx() ? "loop" : a6->sin6_scope_id == BAD_SCOPE ? "bad" : "other", len);
    } else snprintf(out, cap, "fam%d:len%d", a4->sin_family, len);
}

/* ---- bounded connect ------------------------------------------------------ */
/* Returns 0 on success, else the WSA error (immediate or reported by SO_ERROR); -1 when it did not finish. */
static inline int s_connect(SOCKET c, const void *a, int len, int ms) {
    unsigned long on = 1, off = 0; int rc, e;
    fd_set w, x; TIMEVAL tv; int n;
    U(ioctlsocket)(c, FIONBIO, &on);
    rc = U(connect)(c, (const struct sockaddr *)a, len);
    if (rc == 0) { U(ioctlsocket)(c, FIONBIO, &off); return 0; }
    e = s_err();
    if (e != WSAEWOULDBLOCK) { U(ioctlsocket)(c, FIONBIO, &off); return e; }
    w.fd_count = 1; w.fd_array[0] = c; x.fd_count = 1; x.fd_array[0] = c;
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    n = U(select)(0, NULL, &w, &x, &tv);
    U(ioctlsocket)(c, FIONBIO, &off);
    if (n <= 0) return -1;
    if (x.fd_count) { int v = 0, l = sizeof v; U(getsockopt)(c, SOL_SOCKET, SO_ERROR, (char *)&v, &l); return v ? v : -2; }
    return 0;
}
static inline int s_readable(SOCKET s, int ms) {
    fd_set r; TIMEVAL tv;
    r.fd_count = 1; r.fd_array[0] = s;
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return U(select)(0, &r, NULL, NULL, &tv) == 1;
}
static inline unsigned short s_port(SOCKET s) {
    struct sockaddr_in6 a; int l = sizeof a;
    memset(&a, 0, sizeof a);
    if (U(getsockname)(s, (struct sockaddr *)&a, &l) != 0) return 0;
    return a.sin6_port;   /* same offset in sockaddr_in */
}
#endif
