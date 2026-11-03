/* Shared helpers for the x_child_process_inherit area: Winsock objects crossing process boundaries.
 * Every Winsock call goes through U(); nothing links the DLL under test. Children are this exe relaunched with
 * --child <name> <args>; they report through their exit code (a bitmask of failed steps, or an observed error
 * number, depending on the child) and are always bounded and killed on timeout. Sockets are handed to children
 * through an explicit handle list, so unrelated inheritable sockets of the parent never leak into them. */
#ifndef XC_H
#define XC_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <afunix.h>

#ifndef WSA_FLAG_NO_HANDLE_INHERIT
#define WSA_FLAG_NO_HANDLE_INHERIT 0x80
#endif
#ifndef SO_UPDATE_ACCEPT_CONTEXT
#define SO_UPDATE_ACCEPT_CONTEXT 0x700B
#endif

#define SYNC 0
#define OVLD WSA_FLAG_OVERLAPPED
#define PLAIN (-1)                       /* the plain socket() call */
#define NOINH WSA_FLAG_NO_HANDLE_INHERIT
#define XC_WAIT 5000
#define XC_CHILD_TIMEOUT 25000
#define XC_HANDLE_LIST_ATTR 0x00020002   /* PROC_THREAD_ATTRIBUTE_HANDLE_LIST */

#define XEQ(a, b) do { long long a_ = (long long)(a), b_ = (long long)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", a_, b_); } while (0)

static int xc_up(void)
{
    static int st;
    if (!st) {
        WSADATA d;
        st = (U(WSAStartup) && U(WSAStartup)(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    if (st < 0) t_skip("WSAStartup unavailable");
    return st > 0;
}
#define UP() do { if (!xc_up()) return; } while (0)

static int  xc_werr(void)     { return U(WSAGetLastError)(); }
static void xc_setwerr(int e) { U(WSASetLastError)(e); }
static void xc_close(SOCKET s) { if (s != INVALID_SOCKET && s != 0) U(closesocket)(s); }

static struct sockaddr_in xc_lo(unsigned short port_host)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = 0x0100007fu;
    a.sin_port = (unsigned short)(((port_host & 0xff) << 8) | (port_host >> 8));
    return a;
}
static unsigned short xc_port_of(const struct sockaddr_in *a) { return (unsigned short)(((a->sin_port & 0xff) << 8) | (a->sin_port >> 8)); }

static SOCKET xc_make(int af, int type, int flags)
{
    if (flags == PLAIN) return U(socket)(af, type, 0);
    return U(WSASocketW)(af, type, 0, NULL, 0, (DWORD)flags);
}
static void xc_rcvtimeo(SOCKET s, int ms) { U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms); }

static int xc_readable(SOCKET s, int ms)
{
    fd_set f; struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    f.fd_count = 1; f.fd_array[0] = s;
    return U(select)(0, &f, NULL, NULL, &tv) > 0;
}

/* Bound (ephemeral loopback) socket of the given type. */
static SOCKET xc_bound(int type, int flags, struct sockaddr_in *out)
{
    struct sockaddr_in a = xc_lo(0); int n = sizeof a;
    SOCKET s = xc_make(AF_INET, type, flags);
    if (s == INVALID_SOCKET) return s;
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a) || U(getsockname)(s, (struct sockaddr *)&a, &n)) { xc_close(s); return INVALID_SOCKET; }
    if (out) *out = a;
    return s;
}
static SOCKET xc_listener(int flags, struct sockaddr_in *out)
{
    SOCKET l = xc_bound(SOCK_STREAM, flags, out);
    if (l == INVALID_SOCKET) return l;
    if (U(listen)(l, SOMAXCONN)) { xc_close(l); return INVALID_SOCKET; }
    return l;
}
static SOCKET xc_accept(SOCKET l, int ms)
{
    if (!xc_readable(l, ms)) return INVALID_SOCKET;
    return U(accept)(l, NULL, NULL);
}
/* Connected TCP pair: c = client, s = accepted. flags apply to client and listener. */
static int xc_pair_flags(int cflags, int lflags, SOCKET *c, SOCKET *s, struct sockaddr_in *laddr)
{
    struct sockaddr_in a; SOCKET l = xc_listener(lflags, &a);
    *c = *s = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    *c = xc_make(AF_INET, SOCK_STREAM, cflags);
    if (*c == INVALID_SOCKET || U(connect)(*c, (struct sockaddr *)&a, sizeof a)) { xc_close(*c); xc_close(l); *c = INVALID_SOCKET; return 0; }
    *s = xc_accept(l, XC_WAIT);
    xc_close(l);
    if (*s == INVALID_SOCKET) { xc_close(*c); *c = INVALID_SOCKET; return 0; }
    xc_rcvtimeo(*c, XC_WAIT); xc_rcvtimeo(*s, XC_WAIT);
    if (laddr) *laddr = a;
    return 1;
}
static int xc_pair(int flags, SOCKET *c, SOCKET *s) { return xc_pair_flags(flags, flags, c, s, NULL); }
#define PAIR_OR_SKIP(c, s, flags) do { if (!xc_pair(flags, &c, &s)) { t_skip("loopback pair unavailable"); return; } } while (0)

static int xc_send(SOCKET s, const char *p, int n) { return U(send)(s, p, n, 0); }
static int xc_recv_n(SOCKET s, char *b, int n)
{
    int got = 0;
    while (got < n) { int r = U(recv)(s, b + got, n - got, 0); if (r <= 0) return got ? got : r; got += r; }
    return got;
}
/* Exact-content receive of a short string. */
static int xc_expect(SOCKET s, const char *want)
{
    char b[64] = {0}; int n = (int)strlen(want);
    return xc_recv_n(s, b, n) == n && !memcmp(b, want, n);
}
static int xc_is_socket(SOCKET s)
{
    int ty = 0, l = sizeof ty;
    return U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&ty, &l) == 0;
}
static int xc_type_of(SOCKET s)
{
    int ty = -1, l = sizeof ty;
    if (U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&ty, &l)) return -1;
    return ty;
}
static int xc_name_port(SOCKET s, int peer)
{
    struct sockaddr_in a; int n = sizeof a; memset(&a, 0, sizeof a);
    if ((peer ? U(getpeername) : U(getsockname))(s, (struct sockaddr *)&a, &n)) return -1;
    return xc_port_of(&a);
}
static DWORD xc_hflags(HANDLE h)
{
    DWORD f = 0xdead;
    if (!GetHandleInformation(h, &f)) return 0xffffffffu;
    return f & HANDLE_FLAG_INHERIT;
}

/* ---- processes ---------------------------------------------------------------------------------------- */
/* Start a child with exactly the listed handles inherited (none: bInheritHandles FALSE). Returns the process
 * handle, or NULL with *err set to GetLastError(). */
static HANDLE xc_spawn(const char *name, const char *args, const HANDLE *list, int n, DWORD *err)
{
    char cmd[4096]; STARTUPINFOEXA si; PROCESS_INFORMATION pi; SIZE_T sz = 0; BOOL ok; HANDLE copy[16];
    LPPROC_THREAD_ATTRIBUTE_LIST al = NULL; int i;
    memset(&si, 0, sizeof si); memset(&pi, 0, sizeof pi);
    si.StartupInfo.cb = sizeof si;
    snprintf(cmd, sizeof cmd, "\"%s\" --child %s %s", t_self_path(), name, args ? args : "");
    if (err) *err = 0;
    if (n > 0) {
        for (i = 0; i < n; i++) copy[i] = list[i];
        InitializeProcThreadAttributeList(NULL, 1, 0, &sz);
        al = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sz);
        if (!al || !InitializeProcThreadAttributeList(al, 1, 0, &sz)) { if (err) *err = GetLastError(); return NULL; }
        if (!UpdateProcThreadAttribute(al, 0, XC_HANDLE_LIST_ATTR, copy, n * sizeof(HANDLE), NULL, NULL)) {
            if (err) *err = GetLastError();
            DeleteProcThreadAttributeList(al); HeapFree(GetProcessHeap(), 0, al); return NULL;
        }
        si.lpAttributeList = al;
    }
    ok = CreateProcessA(NULL, cmd, NULL, NULL, n > 0, n > 0 ? EXTENDED_STARTUPINFO_PRESENT : 0, NULL, NULL, &si.StartupInfo, &pi);
    if (!ok && err) *err = GetLastError();
    if (al) { DeleteProcThreadAttributeList(al); HeapFree(GetProcessHeap(), 0, al); }
    if (!ok) return NULL;
    CloseHandle(pi.hThread);
    return pi.hProcess;
}
/* Wait for a child: its exit code, or 0xDEAD0001 after killing it on timeout. Consumes the handle. */
static DWORD xc_wait(HANDLE p, DWORD ms)
{
    DWORD code = 0xDEAD0000;
    if (!p) return code;
    if (WaitForSingleObject(p, ms) != WAIT_OBJECT_0) { TerminateProcess(p, 1); WaitForSingleObject(p, 5000); code = 0xDEAD0001; }
    else GetExitCodeProcess(p, &code);
    CloseHandle(p);
    return code;
}
static void xc_kill(HANDLE p) { if (p) { TerminateProcess(p, 9); WaitForSingleObject(p, 5000); CloseHandle(p); } }
static DWORD xc_run(const char *name, const char *args, const HANDLE *list, int n)
{
    DWORD err; HANDLE p = xc_spawn(name, args, list, n, &err);
    if (!p) return 0xDEAD0000;
    return xc_wait(p, XC_CHILD_TIMEOUT);
}
/* printf into a small buffer for argument strings */
#define XARGS(buf, ...) (snprintf(buf, sizeof buf, __VA_ARGS__), buf)
#define H(s) ((HANDLE)(ULONG_PTR)(s))
static unsigned long long xc_u(SOCKET s) { return (unsigned long long)s; }
static SOCKET xc_arg_sock(char **argv, int i) { return (SOCKET)(ULONG_PTR)_strtoui64(argv[i], NULL, 10); }
static int xc_arg_int(char **argv, int i) { return atoi(argv[i]); }
static void xc_child_up(void) { WSADATA d; U(WSAStartup)(MAKEWORD(2, 2), &d); }
#define STEP(bit, cond) do { if (!(cond)) fails |= (1u << (bit)); } while (0)

/* hex transport for WSAPROTOCOL_INFOW blobs on a command line */
static void xc_hex(const void *p, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef"; const unsigned char *b = p; size_t i;
    for (i = 0; i < n; i++) { out[2 * i] = d[b[i] >> 4]; out[2 * i + 1] = d[b[i] & 15]; }
    out[2 * n] = 0;
}
static int xc_unhex(const char *s, void *p, size_t n)
{
    unsigned char *b = p; size_t i;
    if (strlen(s) != 2 * n) return 0;
    for (i = 0; i < n; i++) {
        int hi = s[2 * i], lo = s[2 * i + 1];
        hi = hi <= '9' ? hi - '0' : hi - 'a' + 10; lo = lo <= '9' ? lo - '0' : lo - 'a' + 10;
        b[i] = (unsigned char)(hi * 16 + lo);
    }
    return 1;
}
static char *xc_blobarg(const WSAPROTOCOL_INFOW *pi)
{
    static char buf[2 * sizeof(WSAPROTOCOL_INFOW) + 1];
    xc_hex(pi, sizeof *pi, buf);
    return buf;
}
/* WSASocketW(FROM_PROTOCOL_INFO) from a hex blob argument. */
static SOCKET xc_from_blob(const char *hex, int flags)
{
    WSAPROTOCOL_INFOW pi;
    if (!xc_unhex(hex, &pi, sizeof pi)) return INVALID_SOCKET;
    return U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi, 0, (DWORD)flags);
}

/* ---- protocol-info channel: the blob needs the child's pid, so it travels through an inherited pipe ---- */
static unsigned xc_e8(int e) { return e == 0 ? 0u : (e >= 10000 && e < 10255) ? (unsigned)(e - 10000) : 255u; }
/* Start <name> with the read end of a pipe in its handle list (first argument), duplicate 'share' to the new
 * process and write the blob into the pipe. *dup_rc / *dup_err report the WSADuplicateSocketW outcome. */
static HANDLE xc_spawn_blob(const char *name, const char *args, SOCKET share, const HANDLE *extra, int nextra, int *dup_rc, int *dup_err)
{
    HANDLE rd, wr, list[8], p; SECURITY_ATTRIBUTES sa; char a[2048]; WSAPROTOCOL_INFOW pi; DWORD n; int i;
    sa.nLength = sizeof sa; sa.lpSecurityDescriptor = NULL; sa.bInheritHandle = TRUE;
    if (!CreatePipe(&rd, &wr, &sa, 4096)) return NULL;
    SetHandleInformation(wr, HANDLE_FLAG_INHERIT, 0);
    list[0] = rd;
    for (i = 0; i < nextra; i++) list[1 + i] = extra[i];
    snprintf(a, sizeof a, "%llu %s", (unsigned long long)(ULONG_PTR)rd, args ? args : "");
    p = xc_spawn(name, a, list, 1 + nextra, NULL);
    CloseHandle(rd);
    if (!p) { CloseHandle(wr); return NULL; }
    memset(&pi, 0, sizeof pi);
    *dup_rc = U(WSADuplicateSocketW)(share, GetProcessId(p), &pi);
    *dup_err = *dup_rc ? U(WSAGetLastError)() : 0;
    if (*dup_rc) memset(&pi, 0, sizeof pi);
    WriteFile(wr, &pi, sizeof pi, &n, NULL);
    CloseHandle(wr);
    return p;
}
/* Child side: read the blob from the pipe handle in argv[i]. */
static int xc_read_blob(char **argv, int i, WSAPROTOCOL_INFOW *pi)
{
    DWORD n = 0; HANDLE h = (HANDLE)(ULONG_PTR)_strtoui64(argv[i], NULL, 10);
    memset(pi, 0, sizeof *pi);
    return ReadFile(h, pi, sizeof *pi, &n, NULL) && n == sizeof *pi && pi->dwServiceFlags1 != 0;
}
/* A target process that does nothing until killed, for duplications whose result the test inspects itself. */
static HANDLE xc_idle(void) { return xc_spawn("idle", "", NULL, 0, NULL); }
#endif
