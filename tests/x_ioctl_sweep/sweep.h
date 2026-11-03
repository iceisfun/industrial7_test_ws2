/* Engine shared by the x_ioctl_sweep tests: builds a fresh socket of a given kind, issues one control or
 * option call with a given buffer shape and reduces the outcome to (return value, WSA error, byte count).
 * A call that blocks is released by a watchdog that closes its socket; such a cell is reported as BLOCKED.
 * ws2_32 is reached only through U(). */
#ifndef SWEEP_H
#define SWEEP_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <mstcpip.h>
#include <setjmp.h>

#ifndef AF_UNIX
#define AF_UNIX 1
#endif

enum { SK_TCP = 0, SK_UDP, SK_RAW, SK_UNIX, SK_COUNT };
static const char *const sw_kind_name[SK_COUNT] = { "tcp", "udp", "raw", "unix" };

#ifdef SW_PROBE
static int sw_corrupt_seen;
static int sw_heaps_ok(void)
{
    HANDLE h[64]; DWORD n = GetProcessHeaps(64, h), i;
    for (i = 0; i < n && i < 64; ++i) if (!HeapValidate(h[i], 0, NULL)) return 0;
    return 1;
}
#define SW_HEAPCHECK() do { if (!sw_corrupt_seen && !sw_heaps_ok()) { sw_corrupt_seen = 1; printf("  NOTE CORRUPT %s\n", sw_last); fflush(stdout); } } while (0)
#else
#define SW_HEAPCHECK() ((void)0)
#endif
typedef struct { int ret; int err; unsigned val; } sw_res;   /* ret -2 = blocked, -3 = no socket */
#define SW_BLOCKED (-2)
#define SW_EXC     (-4)
#define SW_NOSOCK  (-3)
#define SW_UNSET   0xdeadbeefu

static volatile SOCKET sw_watch_sock = INVALID_SOCKET;
static volatile DWORD sw_watch_start;
static volatile LONG sw_watch_fired;
static volatile LONG sw_watch_stop;
static HANDLE sw_watch_thread;

static DWORD WINAPI sw_watchdog(LPVOID p)
{
    while (!sw_watch_stop) {
        SOCKET s = sw_watch_sock;
        if (s != INVALID_SOCKET && GetTickCount() - sw_watch_start > 1500) {
            sw_watch_fired = 1;
            sw_watch_sock = INVALID_SOCKET;
            U(closesocket)(s);
        }
        Sleep(20);
    }
    return 0;
}

static char sw_last[160];
static jmp_buf *sw_jb;
static LONG CALLBACK sw_veh(PEXCEPTION_POINTERS ep)
{
    DWORD c = ep->ExceptionRecord->ExceptionCode;
    if (c == 0xC0000005 && sw_jb) { jmp_buf *j = sw_jb; sw_jb = NULL; longjmp(*j, 1); }
    if (c == 0xC0000005 || c == 0xC0000374) { printf("  NOTE LASTCELL %08lx %s\n", c, sw_last); fflush(stdout); }
    return EXCEPTION_CONTINUE_SEARCH;
}

static int sw_elevated(void)
{
    static int memo = -1;
    if (memo < 0) {
        HANDLE t; TOKEN_ELEVATION e; DWORD n = 0;
        memo = 0;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
            if (GetTokenInformation(t, TokenElevation, &e, sizeof e, &n)) memo = e.TokenIsElevated ? 1 : 0;
            CloseHandle(t);
        }
    }
    return memo;
}

static int sw_up(void)
{
    static int veh;
    if (!veh) { veh = 1; AddVectoredExceptionHandler(1, sw_veh); }
    static int done = -1;
    WSADATA d;
    if (done < 0) {
        done = (U(WSAStartup) && U(WSAStartup)(MAKEWORD(2, 2), &d) == 0) ? 1 : 0;
        if (done) sw_watch_thread = CreateThread(NULL, 0, sw_watchdog, NULL, 0, NULL);
        if (!sw_watch_thread) done = 0;
    }
    return done;
}

static SOCKET sw_make(int kind)
{
    switch (kind) {
    case SK_TCP:  return U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    case SK_UDP:  return U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    case SK_RAW:  return U(socket)(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    default:      return U(socket)(AF_UNIX, SOCK_STREAM, 0);
    }
}

/* Whether this token can create sockets of the kind at all (raw needs elevation). */
static int sw_kind_available(int kind)
{
    static int memo[SK_COUNT] = { -1, -1, -1, -1 };
    if (memo[kind] < 0) {
        SOCKET s = sw_make(kind);
        memo[kind] = (s != INVALID_SOCKET);
        if (s != INVALID_SOCKET) U(closesocket)(s);
    }
    return memo[kind];
}

static void sw_arm(SOCKET s) { sw_watch_fired = 0; sw_watch_start = GetTickCount(); sw_watch_sock = s; }
static int  sw_disarm(void)  { sw_watch_sock = INVALID_SOCKET; Sleep(0); return (int)sw_watch_fired; }

/* ---- WSAIoctl ---------------------------------------------------------- */
typedef struct { unsigned in, out; } sw_ishape;

static sw_res sw_wsaioctl(int kind, unsigned code, sw_ishape sh)
{
    sw_res r;
    unsigned char in[2048], out[2048];
    DWORD n = SW_UNSET;
    SOCKET s = sw_make(kind);
    int rc;
    memset(in, 0, sizeof in); memset(out, 0xCC, sizeof out);
    if (s == INVALID_SOCKET) { r.ret = SW_NOSOCK; r.err = U(WSAGetLastError)(); r.val = 0; return r; }
    U(WSASetLastError)(0);
    snprintf(sw_last, sizeof sw_last, "WSAIoctl %s %08x in=%u out=%u", sw_kind_name[kind], code, sh.in, sh.out);
    sw_arm(s);
    { jmp_buf jb; sw_jb = &jb; if (setjmp(jb)) { sw_disarm(); r.ret = SW_EXC; r.err = 0; r.val = 0; U(closesocket)(s); return r; }
    rc = U(WSAIoctl)(s, code, sh.in ? in : NULL, sh.in, sh.out ? out : NULL, sh.out, &n, NULL, NULL); sw_jb = NULL; }
    SW_HEAPCHECK();
    r.err = U(WSAGetLastError)();
    if (sw_disarm()) { r.ret = SW_BLOCKED; r.err = 0; r.val = 0; return r; }
    r.ret = rc; r.val = n;
    U(closesocket)(s);
    return r;
}

static sw_res sw_ioctlsocket(int kind, unsigned code)
{
    sw_res r;
    u_long arg = 0;
    SOCKET s = sw_make(kind);
    int rc;
    if (s == INVALID_SOCKET) { r.ret = SW_NOSOCK; r.err = U(WSAGetLastError)(); r.val = 0; return r; }
    U(WSASetLastError)(0);
    snprintf(sw_last, sizeof sw_last, "ioctlsocket %s %08x", sw_kind_name[kind], code);
    sw_arm(s);
    { jmp_buf jb; sw_jb = &jb; if (setjmp(jb)) { sw_disarm(); r.ret = SW_EXC; r.err = 0; r.val = 0; U(closesocket)(s); return r; }
    rc = U(ioctlsocket)(s, (long)code, &arg); sw_jb = NULL; }
    SW_HEAPCHECK();
    r.err = U(WSAGetLastError)();
    if (sw_disarm()) { r.ret = SW_BLOCKED; r.err = 0; r.val = 0; return r; }
    r.ret = rc; r.val = (unsigned)arg;
    U(closesocket)(s);
    return r;
}

/* ---- options ------------------------------------------------------------ */
/* A getsockopt shape is the length passed in; the value is the first four bytes of the buffer afterwards
 * together with the returned length (val = length in the upper 8 bits is avoided: len is kept apart). */
typedef struct { int ret; int err; unsigned len; unsigned val; } sw_ores;

static sw_ores sw_getopt(int kind, int level, int opt, unsigned len)
{
    sw_ores r;
    unsigned char buf[256];
    int l = (int)len, rc;
    SOCKET s;
    /* SO_MAXPATHDG with a 64-byte buffer damages the process heap on Windows 10; never issue that call. */
    if (level == SOL_SOCKET && opt == 0x700a && len >= 64) { r.ret = SW_EXC; r.err = 0; r.len = r.val = 0; return r; }
    s = sw_make(kind);
    memset(buf, 0xCC, sizeof buf);
    if (s == INVALID_SOCKET) { r.ret = SW_NOSOCK; r.err = U(WSAGetLastError)(); r.len = r.val = 0; return r; }
    U(WSASetLastError)(0);
    snprintf(sw_last, sizeof sw_last, "getsockopt %s %04x len=%u", sw_kind_name[kind], opt, len);
    sw_arm(s);
    { jmp_buf jb; sw_jb = &jb; if (setjmp(jb)) { sw_disarm(); r.ret = SW_EXC; r.err = 0; r.len = r.val = 0; U(closesocket)(s); return r; }
    rc = U(getsockopt)(s, level, opt, (char *)buf, &l); sw_jb = NULL; }
    SW_HEAPCHECK();
    r.err = U(WSAGetLastError)();
    if (sw_disarm()) { r.ret = SW_BLOCKED; r.err = 0; r.len = r.val = 0; return r; }
    r.ret = rc; r.len = (unsigned)l;
    r.val = 0;
    if (rc == 0 && l >= 4 && len >= 4) memcpy(&r.val, buf, 4);
    else if (rc == 0 && l >= 1 && len >= 1) r.val = buf[0] | 0xAA000000u;
    U(closesocket)(s);
    return r;
}

typedef struct { unsigned len; unsigned val; } sw_oshape;

static sw_ores sw_setopt(int kind, int level, int opt, sw_oshape sh)
{
    sw_ores r;
    unsigned char buf[256];
    int rc;
    SOCKET s = sw_make(kind);
    memset(buf, 0, sizeof buf);
    memcpy(buf, &sh.val, 4);
    if (s == INVALID_SOCKET) { r.ret = SW_NOSOCK; r.err = U(WSAGetLastError)(); r.len = r.val = 0; return r; }
    U(WSASetLastError)(0);
    snprintf(sw_last, sizeof sw_last, "setsockopt %s %04x len=%u val=%u", sw_kind_name[kind], opt, sh.len, sh.val);
    sw_arm(s);
    { jmp_buf jb; sw_jb = &jb; if (setjmp(jb)) { sw_disarm(); r.ret = SW_EXC; r.err = 0; r.len = r.val = 0; U(closesocket)(s); return r; }
    rc = U(setsockopt)(s, level, opt, (const char *)buf, (int)sh.len); sw_jb = NULL; }
    SW_HEAPCHECK();
    r.err = U(WSAGetLastError)();
    if (sw_disarm()) { r.ret = SW_BLOCKED; r.err = 0; r.len = r.val = 0; return r; }
    r.ret = rc; r.len = 0; r.val = 0;
    if (level == SOL_SOCKET && opt == 0x7008) { int z = 0; U(setsockopt)(s, SOL_SOCKET, 0x7008, (char *)&z, 4); }
    U(closesocket)(s);
    return r;
}
#endif
