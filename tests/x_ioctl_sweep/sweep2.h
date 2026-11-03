/* Engine for the state-aware sweeps (sweep2.c): the same one-call-per-fresh-socket idea as sweep.h, but the
 * socket under test is first put into a state (listening, connected to a loopback peer, bound datagram,
 * connected datagram, IPv6) and the call may be any control code or any option of any level.
 * Everything runs over loopback with ephemeral ports; every socket a cell opens is closed before it returns. */
#ifndef SWEEP2_H
#define SWEEP2_H
#include "sweep.h"

enum { ST_TCP4_LISTEN = 0, ST_TCP4_CONN, ST_UDP4_BOUND, ST_UDP4_CONN, ST_TCP6, ST_UDP6, ST_TCP4, ST_UDP4, ST_COUNT };
static const char *const sw2_state_name[ST_COUNT] = {
    "tcp4_listen", "tcp4_conn", "udp4_bound", "udp4_conn", "tcp6", "udp6", "tcp4", "udp4" };

enum { API_IOCTL = 0, API_GET = 1, API_SET = 2 };
static const char *const sw2_api_name[3] = { "WSAIoctl", "getsockopt", "setsockopt" };

#define SW2_SHAPES6 {{0,0},{0,4},{0,64},{4,4},{16,64},{28,1024}}
#define SW2_GETLENS {0,1,4,8,16}
#define SW2_SETSHAPES {{0,0},{1,1},{2,1},{4,0},{4,1},{8,1}}
#define SWF2_VAL 1
#define SWF2_PRIV 2

typedef struct { unsigned char st, api, shape, flags; unsigned level, lo, hi; int ret, err; unsigned len, val; int sret, serr; } sw2_row;
typedef struct { int ret; int err; unsigned len; unsigned val; } sw2_res;

typedef struct { SOCKET s, a, b; } sw2_ctx;

/* Control codes that never complete or that fault on the first non-NULL buffer; no cell ever issues them. */
static int sw2_code_barred(unsigned code) { return code == 0x28000017u || code == 0xC8000020u; }

static int sw2_is6(int st) { return st == ST_TCP6 || st == ST_UDP6; }

static void sw2_abort_close(SOCKET s)
{
    struct linger lg = { 1, 0 };
    int t = 0, n = sizeof t;
    /* stream sockets are closed with a reset so that thousands of cells do not pile up in TIME_WAIT and exhaust the ephemeral ports */
    if (U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&t, &n) == 0 && t == SOCK_STREAM)
        U(setsockopt)(s, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
    U(closesocket)(s);
}

static void sw2_close(sw2_ctx *c)
{
    if (c->s != INVALID_SOCKET) sw2_abort_close(c->s);
    if (c->a != INVALID_SOCKET) sw2_abort_close(c->a);
    if (c->b != INVALID_SOCKET) sw2_abort_close(c->b);
    c->s = c->a = c->b = INVALID_SOCKET;
}

static void sw2_loop4(struct sockaddr_in *sa)
{
    memset(sa, 0, sizeof *sa);
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = U(htonl)(INADDR_LOOPBACK);
}

/* Build the socket for the state; returns 0 when the state cannot be built (IPv6 missing, setup failure). */
static int sw2_open(int st, sw2_ctx *c)
{
    struct sockaddr_in sa, pa;
    int n = sizeof sa;
    c->s = c->a = c->b = INVALID_SOCKET;
    switch (st) {
    case ST_TCP4:  c->s = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP); return c->s != INVALID_SOCKET;
    case ST_UDP4:  c->s = U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP); return c->s != INVALID_SOCKET;
    case ST_TCP6:  c->s = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP); return c->s != INVALID_SOCKET;
    case ST_UDP6:  c->s = U(socket)(AF_INET6, SOCK_DGRAM, IPPROTO_UDP); return c->s != INVALID_SOCKET;
    case ST_TCP4_LISTEN:
        c->s = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (c->s == INVALID_SOCKET) return 0;
        sw2_loop4(&sa);
        if (U(bind)(c->s, (struct sockaddr *)&sa, sizeof sa) || U(listen)(c->s, 1)) { sw2_close(c); return 0; }
        return 1;
    case ST_TCP4_CONN:
        c->a = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        c->s = U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (c->a == INVALID_SOCKET || c->s == INVALID_SOCKET) { sw2_close(c); return 0; }
        sw2_loop4(&sa);
        if (U(bind)(c->a, (struct sockaddr *)&sa, sizeof sa) || U(listen)(c->a, 1) ||
            U(getsockname)(c->a, (struct sockaddr *)&sa, &n) ||
            U(connect)(c->s, (struct sockaddr *)&sa, sizeof sa)) { sw2_close(c); return 0; }
        c->b = U(accept)(c->a, NULL, NULL);
        if (c->b == INVALID_SOCKET) { sw2_close(c); return 0; }
        return 1;
    case ST_UDP4_BOUND:
    case ST_UDP4_CONN:
        c->s = U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (c->s == INVALID_SOCKET) return 0;
        sw2_loop4(&sa);
        if (U(bind)(c->s, (struct sockaddr *)&sa, sizeof sa)) { sw2_close(c); return 0; }
        if (st == ST_UDP4_CONN) {
            c->a = U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (c->a == INVALID_SOCKET) { sw2_close(c); return 0; }
            sw2_loop4(&pa);
            if (U(bind)(c->a, (struct sockaddr *)&pa, sizeof pa) || U(getsockname)(c->a, (struct sockaddr *)&pa, &n) ||
                U(connect)(c->s, (struct sockaddr *)&pa, sizeof pa)) { sw2_close(c); return 0; }
        }
        return 1;
    }
    return 0;
}

static sw2_res sw2_fail(int ret) { sw2_res r; r.ret = ret; r.err = 0; r.len = 0; r.val = 0; return r; }

static sw2_res sw2_ioctl(int st, unsigned code, sw_ishape sh)
{
    sw2_res r; sw2_ctx c; unsigned char in[2048], out[2048];
    DWORD n = SW_UNSET; int rc;
    if (!sw2_open(st, &c)) return sw2_fail(SW_NOSOCK);
    memset(in, 0, sizeof in); memset(out, 0xCC, sizeof out);
    U(WSASetLastError)(0);
    snprintf(sw_last, sizeof sw_last, "WSAIoctl %s %08x in=%u out=%u", sw2_state_name[st], code, sh.in, sh.out);
    sw_arm(c.s);
    { jmp_buf jb; sw_jb = &jb; if (setjmp(jb)) { sw_disarm(); sw2_close(&c); return sw2_fail(SW_EXC); }
    rc = U(WSAIoctl)(c.s, code, sh.in ? in : NULL, sh.in, sh.out ? out : NULL, sh.out, &n, NULL, NULL); sw_jb = NULL; }
    r.err = U(WSAGetLastError)();
    if (sw_disarm()) { c.s = INVALID_SOCKET; sw2_close(&c); return sw2_fail(SW_BLOCKED); }
    r.ret = rc; r.len = n; r.val = 0;
    sw2_close(&c);
    return r;
}

static sw2_res sw2_getopt(int st, int level, int opt, unsigned len)
{
    sw2_res r; sw2_ctx c; unsigned char buf[256]; int l = (int)len, rc;
    if (!sw2_open(st, &c)) return sw2_fail(SW_NOSOCK);
    memset(buf, 0xCC, sizeof buf);
    U(WSASetLastError)(0);
    snprintf(sw_last, sizeof sw_last, "getsockopt %s lvl=%d %04x len=%u", sw2_state_name[st], level, opt, len);
    sw_arm(c.s);
    { jmp_buf jb; sw_jb = &jb; if (setjmp(jb)) { sw_disarm(); sw2_close(&c); return sw2_fail(SW_EXC); }
    rc = U(getsockopt)(c.s, level, opt, (char *)buf, &l); sw_jb = NULL; }
    r.err = U(WSAGetLastError)();
    if (sw_disarm()) { c.s = INVALID_SOCKET; sw2_close(&c); return sw2_fail(SW_BLOCKED); }
    r.ret = rc; r.len = (unsigned)l; r.val = 0;
    if (rc == 0 && l >= 4 && len >= 4) memcpy(&r.val, buf, 4);
    else if (rc == 0 && l >= 1 && len >= 1) r.val = buf[0] | 0xAA000000u;
    sw2_close(&c);
    return r;
}

static sw2_res sw2_setopt(int st, int level, int opt, sw_oshape sh)
{
    sw2_res r; sw2_ctx c; unsigned char buf[256]; int rc;
    if (!sw2_open(st, &c)) return sw2_fail(SW_NOSOCK);
    memset(buf, 0, sizeof buf); memcpy(buf, &sh.val, 4);
    U(WSASetLastError)(0);
    snprintf(sw_last, sizeof sw_last, "setsockopt %s lvl=%d %04x len=%u val=%u", sw2_state_name[st], level, opt, sh.len, sh.val);
    sw_arm(c.s);
    { jmp_buf jb; sw_jb = &jb; if (setjmp(jb)) { sw_disarm(); sw2_close(&c); return sw2_fail(SW_EXC); }
    rc = U(setsockopt)(c.s, level, opt, (const char *)buf, (int)sh.len); sw_jb = NULL; }
    r.err = U(WSAGetLastError)();
    if (sw_disarm()) { c.s = INVALID_SOCKET; sw2_close(&c); return sw2_fail(SW_BLOCKED); }
    r.ret = rc; r.len = 0; r.val = 0;
    /* the thread-wide default for overlapped creation lives behind this option: put it back before the next socket */
    if (level == SOL_SOCKET && opt == 0x7008) { int z = 0; U(setsockopt)(c.s, SOL_SOCKET, 0x7008, (char *)&z, 4); }
    sw2_close(&c);
    return r;
}
#endif
