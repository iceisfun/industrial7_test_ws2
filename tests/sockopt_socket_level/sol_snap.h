/* Table-driven runner for the sockopt_socket_level matrices.
 * A table row names an operation on one fresh socket and the exact outcome of that operation:
 *   gN     getsockopt into an N-byte buffer pre-filled with 0xaa (g0 = zero length, gneg = length -1,
 *          gnullbuf = NULL buffer, gnulllen = NULL length pointer)
 *   sV     setsockopt of the 4-byte value V; sVlN = value V passed with length N; snull = NULL value
 * The outcome string lists return value, last error, resulting length and the leading bytes (reads), or
 * the set result followed by a read-back of the option through a 4-byte int. "v=*" ends a pattern that
 * ignores the value (defaults that depend on system tuning). */
#ifndef SOL_SNAP_H
#define SOL_SNAP_H
#include "sol.h"

struct snap_row { const char *op; const char *want; };

static void snap_hex(const unsigned char *b, int n, char *o)
{
    int i;
    if (n > 12) n = 12;
    for (i = 0; i < n; i++) sprintf(o + 2 * i, "%02x", b[i]);
    o[2 * n] = 0;
}

/* Run one operation on socket s; writes the outcome string. */
static void snap_do(SOCKET s, int opt, const char *op, char *out, size_t cap)
{
    unsigned char buf[704], hx[40];
    int r, e, len;

    if (op[0] == 'g') {
        int blen = 4, nullbuf = 0, nulllen = 0;
        if      (!strcmp(op, "g1")) blen = 1;
        else if (!strcmp(op, "g2")) blen = 2;
        else if (!strcmp(op, "g4")) blen = 4;
        else if (!strcmp(op, "g8")) blen = 8;
        else if (!strcmp(op, "g0")) blen = 0;
        else if (!strcmp(op, "gneg")) blen = -1;
        else if (!strcmp(op, "gnullbuf")) nullbuf = 1;
        else if (!strcmp(op, "gnulllen")) nulllen = 1;
        memset(buf, 0xaa, sizeof buf);
        len = blen;
        wset(0);
        r = U(getsockopt)(s, SOL_SOCKET, opt, nullbuf ? NULL : (char *)buf, nulllen ? NULL : &len);
        e = r ? werr() : 0;
        snap_hex(buf, blen > 0 ? blen : 4, (char *)hx);
        snprintf(out, cap, "r=%d e=%d len=%d v=%s", r ? -1 : 0, e, nulllen ? -9 : len, hx);
    } else {
        int val = 0, vlen = 4, nullval = 0, v2 = 0x5a5a5a5a, l2 = 4, r2;
        unsigned char b[8];
        const char *p = op + 1;
        if (!strcmp(op, "snull")) { nullval = 1; val = 1; }
        else {
            val = (int)strtol(p, (char **)&p, 16);
            if (p[0] == 'l') vlen = atoi(p + 1);
        }
        memcpy(b, &val, 4); memset(b + 4, 0xee, 4);
        wset(0);
        r = U(setsockopt)(s, SOL_SOCKET, opt, nullval ? NULL : (const char *)b, vlen);
        e = r ? werr() : 0;
        r2 = U(getsockopt)(s, SOL_SOCKET, opt, (char *)&v2, &l2);
        snprintf(out, cap, "r=%d e=%d | back r=%d len=%d v=%x", r ? -1 : 0, e, r2 ? -1 : 0, l2, v2);
    }
}

static int snap_match(const char *got, const char *want)
{
    const char *star = strstr(want, "v=*");
    if (!star) return !strcmp(got, want);
    return !strncmp(got, want, (size_t)(star - want)) && strstr(got, "v=") != NULL;
}

/* Run all rows of one table against sockets produced by mkfn(ctx, &peer, &extra); peer is closed afterwards. */
typedef SOCKET (*snap_mk)(int arg, SOCKET *peer);
static void snap_run(const char *label, snap_mk mkfn, int arg, int opt, const struct snap_row *rows, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        SOCKET peer = INVALID_SOCKET, s = mkfn(arg, &peer);
        char got[160];
        if (s == INVALID_SOCKET) { t_skip("%s: cannot build the socket", label); return; }
        snap_do(s, opt, rows[i].op, got, sizeof got);
        t_check(snap_match(got, rows[i].want), __FILE__, __LINE__, "outcome matches", "%s %s: got [%s] want [%s]", label, rows[i].op, got, rows[i].want);
        cls(s);
        if (peer != INVALID_SOCKET) cls(peer);
    }
}

/* ---- socket builders ---- */
static SOCKET mk_fresh(int kind, SOCKET *peer)
{
    (void)peer;
    return mk_kind(kind);
}
enum { ST_T_BOUND, ST_T_LISTEN, ST_T_CLIENT, ST_T_ACCEPTED, ST_T_SHUT, ST_U_BOUND, ST_U_CONNECTED };
static const char *const st_name[] = { "tcp-bound", "tcp-listening", "tcp-client", "tcp-accepted", "tcp-shutdown", "udp-bound", "udp-connected" };
static SOCKET mk_state(int st, SOCKET *peer)
{
    struct sockaddr_in a; int n = sizeof a;
    SOCKET c, sv, s;
    lo4(&a, 0);
    switch (st) {
    case ST_T_BOUND:
    case ST_T_LISTEN:
        s = mk(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (U(bind)(s, (struct sockaddr *)&a, sizeof a)) { cls(s); return INVALID_SOCKET; }
        if (st == ST_T_LISTEN && U(listen)(s, 1)) { cls(s); return INVALID_SOCKET; }
        return s;
    case ST_T_CLIENT: case ST_T_ACCEPTED: case ST_T_SHUT:
        if (!make_pair(&c, &sv)) return INVALID_SOCKET;
        if (st == ST_T_ACCEPTED) { *peer = c; return sv; }
        *peer = sv;
        if (st == ST_T_SHUT) U(shutdown)(c, SD_BOTH);
        return c;
    case ST_U_BOUND:
        s = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (U(bind)(s, (struct sockaddr *)&a, sizeof a)) { cls(s); return INVALID_SOCKET; }
        return s;
    default:
        s = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        *peer = mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (U(bind)(*peer, (struct sockaddr *)&a, sizeof a) || U(getsockname)(*peer, (struct sockaddr *)&a, &n) ||
            U(connect)(s, (struct sockaddr *)&a, sizeof a)) { cls(s); cls(*peer); *peer = INVALID_SOCKET; return INVALID_SOCKET; }
        return s;
    }
}
#endif
