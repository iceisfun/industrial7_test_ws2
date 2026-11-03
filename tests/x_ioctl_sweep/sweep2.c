/* State-aware sweeps: WSAIoctl control codes and getsockopt/setsockopt options at the IP, TCP, UDP and IPv6
 * levels, plus SOL_SOCKET options on sockets that are not fresh.
 *
 * sweep.c-style tables cover a socket straight out of socket(). Windows answers some codes and options
 * differently once the socket is listening, connected, bound or an IPv6 socket, and answers the IPPROTO_*
 * levels with an option space of its own; the tables in sweep2_data.h record those answers, measured on
 * Windows 10 22H2. Each cell builds the socket state over loopback (ephemeral ports), makes one call with
 * one buffer shape, and compares the return value, the WSA error on failure, the byte count or length, and
 * where the value was stable across repeated measurements the first four value bytes.
 * Elevation: a row marked as privilege dependent carries the answer for an unelevated token as well. */
#include "sweep2.h"
#ifndef SW2_EMIT
#include "sweep2_data.h"
#endif

#define NELEM(a) (sizeof(a) / sizeof((a)[0]))

#ifndef SW2_EMIT
static int sw2_ready(int st)
{
    sw2_ctx c;
    if (!sw_up()) { t_skip("WSAStartup failed"); return 0; }
    if (!sw2_open(st, &c)) { t_skip("%s socket state cannot be built here", sw2_state_name[st]); return 0; }
    sw2_close(&c);
    return 1;
}

static void sw2_cmp(const sw2_row *w, unsigned level, unsigned code, sw2_res r, unsigned a, unsigned b)
{
    int priv = (w->flags & SWF2_PRIV) && !sw_elevated();
    int wret = priv ? w->sret : w->ret, werr = priv ? w->serr : w->err;
    const char *fn = sw2_api_name[w->api];
    CHECKF(r.ret == wret, "%s %s lvl=%u code=%x a=%u b=%u: ret %d want %d", fn, sw2_state_name[w->st], level, code, a, b, r.ret, wret);
    if (r.ret != wret) return;
    if (wret != 0) {
        CHECKF(r.err == werr, "%s %s lvl=%u code=%x a=%u b=%u: err %d want %d", fn, sw2_state_name[w->st], level, code, a, b, r.err, werr);
        return;
    }
    if (priv) return;
    if (w->api != API_SET)
        CHECKF(r.len == w->len, "%s %s lvl=%u code=%x a=%u b=%u: len %u want %u", fn, sw2_state_name[w->st], level, code, a, b, r.len, w->len);
    if ((w->flags & SWF2_VAL) && w->api == API_GET)
        CHECKF(r.val == w->val, "%s %s lvl=%u code=%x a=%u b=%u: value %08x want %08x", fn, sw2_state_name[w->st], level, code, a, b, r.val, w->val);
}

static int sw2_skip_row(const sw2_row *w) { return w->ret == SW_BLOCKED || w->ret == SW_EXC || w->ret == SW_NOSOCK; }

static void sw2_replay(int st, int api, unsigned shape)
{
    static const sw_ishape ish[] = SW2_SHAPES6;
    static const unsigned glen[] = SW2_GETLENS;
    static const sw_oshape sset[] = SW2_SETSHAPES;
    unsigned i, c;
    if (!sw2_ready(st)) return;
    for (i = 0; i < NELEM(sw2_rows); ++i) {
        const sw2_row *w = &sw2_rows[i];
        if (w->st != st || w->api != api || w->shape != shape || sw2_skip_row(w)) continue;
        for (c = w->lo; ; ++c) {
            sw2_res r; unsigned a, b;
            if (api == API_IOCTL) {
                if (sw2_code_barred(c)) { if (c == w->hi) break; continue; }
                r = sw2_ioctl(st, c, ish[shape]); a = ish[shape].in; b = ish[shape].out;
            } else if (api == API_GET) {
                r = sw2_getopt(st, (int)w->level, (int)c, glen[shape]); a = glen[shape]; b = 0;
            } else {
                r = sw2_setopt(st, (int)w->level, (int)c, sset[shape]); a = sset[shape].len; b = sset[shape].val;
            }
            sw2_cmp(w, w->level, c, r, a, b);
            if (c == w->hi) break;
        }
    }
}

#define S2_IOC(st, n) TEST(state_wsaioctl_##n) { sw2_replay(st, API_IOCTL, 0); sw2_replay(st, API_IOCTL, 1); \
    sw2_replay(st, API_IOCTL, 2); sw2_replay(st, API_IOCTL, 3); sw2_replay(st, API_IOCTL, 4); sw2_replay(st, API_IOCTL, 5); }
#define S2_GET(st, n, sh) TEST(state_getsockopt_##n##_len##sh) { sw2_replay(st, API_GET, sh); }
#define S2_SET(st, n, sh) TEST(state_setsockopt_##n##_shape##sh) { sw2_replay(st, API_SET, sh); }
#define S2_ALL(st, n) S2_IOC(st, n) \
    S2_GET(st, n, 0) S2_GET(st, n, 1) S2_GET(st, n, 2) S2_GET(st, n, 3) S2_GET(st, n, 4) \
    S2_SET(st, n, 0) S2_SET(st, n, 1) S2_SET(st, n, 2) S2_SET(st, n, 3) S2_SET(st, n, 4) S2_SET(st, n, 5)
S2_ALL(ST_TCP4_LISTEN, tcp4_listen)
S2_ALL(ST_TCP4_CONN, tcp4_conn)
S2_ALL(ST_UDP4_BOUND, udp4_bound)
S2_ALL(ST_UDP4_CONN, udp4_conn)
S2_ALL(ST_TCP6, tcp6)
S2_ALL(ST_UDP6, udp6)
S2_ALL(ST_TCP4, tcp4)
S2_ALL(ST_UDP4, udp4)
#endif /* !SW2_EMIT */

/* ---- measurement side (built with -DSW2_EMIT -DSW_PROBE to regenerate sweep2_data.h) ------------------ */
#ifdef SW2_EMIT
static int em_pass;
static struct { int on, api, st; unsigned level, shape, lo, hi; sw2_res r; } em;

static void em_flush(void)
{
    if (!em.on) return;
    printf("  NOTE Q%d %d %d %u %u %x %x %d %d %u %08x\n", em_pass, em.api, em.st, em.level, em.shape, em.lo, em.hi, em.r.ret, em.r.err, em.r.len, em.r.val);
    fflush(stdout);
    em.on = 0;
}

static void em_cell(int api, int st, unsigned level, unsigned shape, unsigned code, sw2_res r)
{
    SW_HEAPCHECK();
    if (em.on && em.api == api && em.st == st && em.level == level && em.shape == shape && em.hi + 1 == code &&
        em.r.ret == r.ret && em.r.err == r.err && em.r.len == r.len && em.r.val == r.val) { em.hi = code; return; }
    em_flush();
    em.on = 1; em.api = api; em.st = st; em.level = level; em.shape = shape; em.lo = em.hi = code; em.r = r;
}

static void em_ioctl_range(int st, unsigned lo, unsigned hi, unsigned shape)
{
    static const sw_ishape ish[] = SW2_SHAPES6;
    unsigned c;
    for (c = lo; ; ++c) {
        if (!sw2_code_barred(c)) em_cell(API_IOCTL, st, 0, shape, c, sw2_ioctl(st, c, ish[shape]));
        if (c == hi) break;
    }
}

static const unsigned em_docs[] = {
    0x28000002,0x28000004,0x4004667f,0x40047307,0x4004747f,0x48000003,0x48000005,0x48000016,0x48000018,0x4800001b,0x4800001c,
    0x4800001d,0x4800001e,0x48000020,0x48000021,0x48000022,0x48000023,0x48000025,0x48000026,0x58000024,0x58000025,0x8004667d,
    0x8004667e,0x88000001,0x88000009,0x8800000a,0x8800000b,0x8800000c,0x88000015,0x88000019,0x88000026,0x98000001,0x98000002,
    0x98000003,0x98000004,0x98000005,0x98000006,0x98000007,0x9800000c,0x9800000f,0x98000010,0x98000011,0x98000012,0x98000013,
    0x98000014,0x9800012c,0x980000de,0xc8000006,0xc8000007,0xc8000008,0xc800000d,0xc8000014,0xc8000019 };
static const unsigned em_classes[] = {
    0x28000000, 0x48000000, 0x58000000, 0x88000000, 0x98000000, 0xC8000000, 0x40046600, 0x80046600, 0x40047300, 0x80047300 };

static void em_ioctl_state(int st)
{
    unsigned i, sh, k;
    for (sh = 0; sh < 6; ++sh)
        for (i = 0; i < NELEM(em_docs); ++i) em_ioctl_range(st, em_docs[i], em_docs[i], sh);
    for (k = 0; k < NELEM(em_classes); ++k) {
        em_ioctl_range(st, em_classes[k], em_classes[k] + 0xFF, 0);
        em_ioctl_range(st, em_classes[k], em_classes[k] + 0xFF, 2);
    }
    em_flush();
}

static void em_opt_range(int st, int level, unsigned lo, unsigned hi)
{
    static const unsigned glen[] = SW2_GETLENS;
    static const sw_oshape sset[] = SW2_SETSHAPES;
    unsigned o, k;
    for (k = 0; k < 5; ++k)
        for (o = lo; o <= hi; ++o) em_cell(API_GET, st, (unsigned)level, k, o, sw2_getopt(st, level, (int)o, glen[k]));
    em_flush();
    for (k = 0; k < 6; ++k)
        for (o = lo; o <= hi; ++o) em_cell(API_SET, st, (unsigned)level, k, o, sw2_setopt(st, level, (int)o, sset[k]));
    em_flush();
}

static void em_opt_state(int st)
{
    static const int lv[] = { 0, 6, 17, 41 };
    unsigned i;
    for (i = 0; i < 4; ++i) em_opt_range(st, lv[i], 0, 0xFF);
    /* levels that are not protocol levels of the socket: a few option numbers each */
    { static const int odd[] = { 1, 2, 3, 4, 58, 255, 256, 0x7FFF, 0xFFFE }; for (i = 0; i < NELEM(odd); ++i) em_opt_range(st, odd[i], 0, 0x3F); }
    if (st != ST_TCP4 && st != ST_UDP4) {
        em_opt_range(st, SOL_SOCKET, 0, 0x1FF);
        em_opt_range(st, SOL_SOCKET, 0x1000, 0x10FF);
        em_opt_range(st, SOL_SOCKET, 0x2000, 0x20FF);
        em_opt_range(st, SOL_SOCKET, 0x3000, 0x30FF);
        em_opt_range(st, SOL_SOCKET, 0x7000, 0x70FF);
    }
}

#define EM_T(st, n) TEST(emit_ioctl_##n) { if (!sw_up()) { t_skip("no startup"); return; } em_ioctl_state(st); } \
    TEST(emit_opt_##n) { if (!sw_up()) { t_skip("no startup"); return; } em_opt_state(st); }
EM_T(ST_TCP4_LISTEN, tcp4_listen) EM_T(ST_TCP4_CONN, tcp4_conn) EM_T(ST_UDP4_BOUND, udp4_bound) EM_T(ST_UDP4_CONN, udp4_conn)
EM_T(ST_TCP6, tcp6) EM_T(ST_UDP6, udp6) EM_T(ST_TCP4, tcp4) EM_T(ST_UDP4, udp4)
#endif
