/* Helpers for the x_af_unix_deep area: lazy WSAStartup, sockaddr_un construction with explicit lengths, scratch
 * socket paths of exact length, a connected stream trio, bounded waits and a small result-recording note
 * facility. Every Winsock call goes through U(); nothing here links the library under test. */
#ifndef XUD_H
#define XUD_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <afunix.h>

#ifndef POLLRDNORM
#define POLLRDNORM 0x0100
#define POLLRDBAND 0x0200
#define POLLWRNORM 0x0010
#define POLLERR 0x0001
#define POLLHUP 0x0002
#define POLLNVAL 0x0004
#endif
#ifndef SIO_AF_UNIX_GETPEERPID
#define SIO_AF_UNIX_GETPEERPID _WSAIOR(IOC_VENDOR, 256)
#endif

/* Evaluate each argument once. */
#define XEQ(a, b) do { unsigned long long a_ = (unsigned long long)(ULONG_PTR)(a), b_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", a_, b_); } while (0)
#define XNE(a, b) do { unsigned long long a_ = (unsigned long long)(ULONG_PTR)(a), b_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(a_ != b_, __FILE__, __LINE__, #a " != " #b, "got 0x%llx", a_); } while (0)
/* Observation: logged only. */
#define OBS(...) t_note(__VA_ARGS__)

static int x_up(void)
{
    static int state;
    if (!state) {
        WSADATA d;
        __typeof__(&WSAStartup) f = U(WSAStartup);
        state = (f && f(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    if (state < 0) t_skip("WSAStartup unavailable");
    return state > 0;
}
#define UP() do { if (!x_up()) return; } while (0)
static int x_err(void) { return U(WSAGetLastError)(); }

static SOCKET x_sock_t(int type, DWORD flags)
{
    SOCKET s;
    if (!x_up()) return INVALID_SOCKET;
    s = U(WSASocketW)(AF_UNIX, type, 0, NULL, 0, flags);
    if (s == INVALID_SOCKET && x_err() == WSAEAFNOSUPPORT) t_skip("AF_UNIX not supported");
    return s;
}
static SOCKET x_sock(void) { return x_sock_t(SOCK_STREAM, WSA_FLAG_OVERLAPPED); }
#define SOCK_OR_RETURN(v) SOCKET v = x_sock(); if (v == INVALID_SOCKET) return

/* Address with the given path; the whole structure is zero first. */
static void x_addr(SOCKADDR_UN *a, const char *path)
{
    memset(a, 0, sizeof(*a));
    a->sun_family = AF_UNIX;
    strncpy(a->sun_path, path, sizeof(a->sun_path));   /* may fill all 108 bytes with no terminator */
}
/* Absolute path of a leaf in the scratch directory (ring of buffers). */
static const char *x_path(const char *leaf)
{
    static char ring[8][MAX_PATH];
    static int n;
    char *p = ring[n++ & 7];
    t_tmpfile(p, MAX_PATH, leaf);
    return p;
}
/* A path of exactly total characters inside the scratch directory (leaf padded with 'x'); NULL when the
 * scratch directory alone is too long. */
static const char *x_path_len(size_t total, const char *suffix)
{
    static char ring[4][MAX_PATH];
    static int n;
    char *p = ring[n++ & 3];
    size_t dir = strlen(t_tmpdir()), sl = strlen(suffix), pad;
    if (dir + sl + 1 > total) return NULL;
    pad = total - dir - sl;
    memcpy(p, t_tmpdir(), dir);
    memset(p + dir, 'x', pad);
    strcpy(p + dir + pad, suffix);
    return p;
}
#define X_ADDR_BASE ((int)offsetof(SOCKADDR_UN, sun_path))

static int x_bind_len(SOCKET s, const SOCKADDR_UN *a, int len) { return U(bind)(s, (const struct sockaddr *)a, len); }
static int x_bind(SOCKET s, const SOCKADDR_UN *a) { return x_bind_len(s, a, (int)sizeof(*a)); }
static int x_connect_len(SOCKET s, const SOCKADDR_UN *a, int len) { return U(connect)(s, (const struct sockaddr *)a, len); }
static int x_connect(SOCKET s, const SOCKADDR_UN *a) { return x_connect_len(s, a, (int)sizeof(*a)); }

static int x_blocking(SOCKET s, BOOL blocking) { u_long v = !blocking; return U(ioctlsocket)(s, FIONBIO, &v); }
static void x_rcvtimeo(SOCKET s, DWORD ms) { U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof(ms)); }
static void x_sndtimeo(SOCKET s, DWORD ms) { U(setsockopt)(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof(ms)); }

static int x_isset(SOCKET s, const fd_set *f)
{
    u_int i;
    for (i = 0; i < f->fd_count; i++) if (f->fd_array[i] == s) return 1;
    return 0;
}
/* select-based bounded wait; 1 when ready. */
static int x_wait(SOCKET s, int want_write, int ms)
{
    fd_set f, e;
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    FD_ZERO(&f); FD_SET(s, &f);
    FD_ZERO(&e); FD_SET(s, &e);
    return U(select)(0, want_write ? NULL : &f, want_write ? &f : NULL, &e, &tv) > 0;
}
static int x_readable(SOCKET s, int ms) { return x_wait(s, 0, ms); }
static SOCKET x_accept_wait(SOCKET lis)
{
    if (!x_readable(lis, 3000)) return INVALID_SOCKET;
    return U(accept)(lis, NULL, NULL);
}

/* Connected stream trio at a scratch leaf. Returns 0 and skips on failure. */
struct x_trio { SOCKET lis, cli, srv; SOCKADDR_UN addr; char path[MAX_PATH]; };
static int x_trio_open(struct x_trio *t, const char *leaf)
{
    int r;
    t->lis = t->cli = t->srv = INVALID_SOCKET;
    t->lis = x_sock();
    if (t->lis == INVALID_SOCKET) return 0;
    t->cli = x_sock();
    x_addr(&t->addr, x_path(leaf));
    strcpy(t->path, t->addr.sun_path);
    if (t->cli == INVALID_SOCKET || x_bind(t->lis, &t->addr) || U(listen)(t->lis, 4)) goto fail;
    x_blocking(t->cli, FALSE);
    r = x_connect(t->cli, &t->addr);
    if (r != 0 && x_err() != WSAEWOULDBLOCK) goto fail;
    t->srv = x_accept_wait(t->lis);
    if (t->srv == INVALID_SOCKET) goto fail;
    x_blocking(t->cli, TRUE);
    x_rcvtimeo(t->cli, 3000); x_rcvtimeo(t->srv, 3000);
    x_sndtimeo(t->cli, 3000); x_sndtimeo(t->srv, 3000);
    return 1;
fail:
    t_skip("cannot create AF_UNIX connection");
    if (t->cli != INVALID_SOCKET) U(closesocket)(t->cli);
    U(closesocket)(t->lis);
    DeleteFileA(t->path);
    t->lis = t->cli = INVALID_SOCKET;
    return 0;
}
static void x_trio_close(struct x_trio *t)
{
    if (t->srv != INVALID_SOCKET) U(closesocket)(t->srv);
    if (t->cli != INVALID_SOCKET) U(closesocket)(t->cli);
    if (t->lis != INVALID_SOCKET) U(closesocket)(t->lis);
    DeleteFileA(t->path);
    t->srv = t->cli = t->lis = INVALID_SOCKET;
}
#define TRIO(t, leaf) struct x_trio t; if (!x_trio_open(&t, leaf)) return

static int x_send_all(SOCKET s, const char *p, int n)
{
    int off = 0;
    while (off < n) {
        int r = U(send)(s, p + off, n - off, 0);
        if (r <= 0) return -1;
        off += r;
    }
    return off;
}
static int x_recv_n(SOCKET s, char *p, int n)
{
    int off = 0;
    while (off < n) {
        int r = U(recv)(s, p + off, n - off, 0);
        if (r <= 0) return off ? off : r;
        off += r;
    }
    return off;
}
static int x_exists(const char *p) { return GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES; }
/* Working-directory guard: relative socket names resolve against the process working directory, so tests that
 * bind or connect through short names run inside the scratch directory and always restore the old directory. */
static char x_saved_cwd[MAX_PATH];
static void x_cd_scratch(void)
{
    GetCurrentDirectoryA(sizeof x_saved_cwd, x_saved_cwd);
    SetCurrentDirectoryA(t_tmpdir());
}
static void x_cd_restore(void) { if (x_saved_cwd[0]) SetCurrentDirectoryA(x_saved_cwd); x_saved_cwd[0] = 0; }
/* Delete every file (socket files included) directly inside dir, then the directory itself. */
static void x_rmtree_flat(const char *dir)
{
    char pat[MAX_PATH], f[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    snprintf(pat, sizeof pat, "%s\\*", dir);
    h = FindFirstFileA(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
            snprintf(f, sizeof f, "%s\\%s", dir, fd.cFileName);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) RemoveDirectoryA(f);
            else DeleteFileA(f);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryA(dir);
}
/* A scratch subdirectory path (no trailing separator). */
static const char *x_sub(const char *leaf)
{
    static char ring[4][MAX_PATH];
    static int n;
    char *p = ring[n++ & 3];
    snprintf(p, MAX_PATH, "%s%s", t_tmpdir(), leaf);
    return p;
}
/* Connect (nonblocking) to a path and report whether the listener lis accepts it; *err gets the connect error. */
static int x_try_connect(SOCKET lis, const char *path, int *err)
{
    SOCKADDR_UN a;
    SOCKET c = x_sock();
    int r, e, acc = 0;
    x_addr(&a, path);
    x_blocking(c, FALSE);
    r = x_connect(c, &a);
    e = r ? x_err() : 0;
    if ((r == 0 || e == WSAEWOULDBLOCK) && lis != INVALID_SOCKET && x_readable(lis, 1500)) {
        SOCKET sv = U(accept)(lis, NULL, NULL);
        if (sv != INVALID_SOCKET) { acc = 1; U(closesocket)(sv); }
    }
    if (err) *err = (r == 0) ? 0 : e;
    U(closesocket)(c);
    return acc;
}
#endif
