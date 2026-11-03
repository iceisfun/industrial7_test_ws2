/* WSAIoctl / ioctlsocket / SOL_SOCKET option sweep.
 *
 * Every cell of the tables in sweep_data.h is one call on a fresh socket (TCP, UDP, raw ICMP, AF_UNIX
 * stream) with one buffer shape; the table records the return value, the WSA error on failure and (where
 * stable) the byte count or the value the call produced. The tables were measured on Windows 10 22H2 and
 * describe: which control codes of the WS2, protocol, vendor and Unix-style code spaces are understood,
 * what each does to a missing or undersized buffer, and how option numbers of SOL_SOCKET answer to every
 * length. A cell that blocks forever on Windows is not replayed. Raw rows need an elevated token and are
 * skipped otherwise. */
#include "sweep.h"
#include "sweep_data.h"

#define NELEM(a) (sizeof(a) / sizeof((a)[0]))

static int sw_ready(int kind)
{
    if (!sw_up()) { t_skip("WSAStartup failed"); return 0; }
    if (!sw_kind_available(kind)) { t_skip("%s sockets unavailable for this token", sw_kind_name[kind]); return 0; }
    return 1;
}

static void sw_cell_wi(const sw_row *w, int api, unsigned code, sw_res r, sw_ishape sh)
{
    const char *fn = api ? "ioctlsocket" : "WSAIoctl";
    int priv = (w->flags & SWF_PRIV) && !sw_elevated();
    int wret = priv ? w->sret : w->ret, werr = priv ? w->serr : w->err;
    CHECKF(r.ret == wret, "%s %s code=%08x in=%u out=%u: ret %d want %d", fn, sw_kind_name[w->kind], code, sh.in, sh.out, r.ret, wret);
    if (wret != 0)
        CHECKF(r.err == werr, "%s %s code=%08x in=%u out=%u: err %d want %d", fn, sw_kind_name[w->kind], code, sh.in, sh.out, r.err, werr);
    if ((w->flags & SWF_VAL) && !priv)
        CHECKF(r.val == w->val, "%s %s code=%08x in=%u out=%u: value %u want %u", fn, sw_kind_name[w->kind], code, sh.in, sh.out, r.val, w->val);
}

static void sw_replay_wi(int kind, unsigned shape)
{
    unsigned i, c;
    static const sw_ishape sh5[] = SW_SHAPES5;
    if (!sw_ready(kind)) return;
    for (i = 0; i < NELEM(sw_wi_rows); ++i) {
        const sw_row *w = &sw_wi_rows[i];
        if (w->kind != kind || w->shape != shape) continue;
        if (w->ret == SW_BLOCKED || w->ret == SW_EXC) continue;
        for (c = w->lo; ; ++c) {
            sw_cell_wi(w, 0, c, sw_wsaioctl(kind, c, sh5[shape]), sh5[shape]);
            if (c == w->hi) break;
        }
    }
}

static void sw_replay_is(int kind)
{
    unsigned i, c;
    static const sw_ishape none = {0, 0};
    if (!sw_ready(kind)) return;
    for (i = 0; i < NELEM(sw_is_rows); ++i) {
        const sw_row *w = &sw_is_rows[i];
        if (w->kind != kind) continue;
        if (w->ret == SW_BLOCKED || w->ret == SW_EXC) continue;
        for (c = w->lo; ; ++c) {
            sw_cell_wi(w, 1, c, sw_ioctlsocket(kind, c), none);
            if (c == w->hi) break;
        }
    }
}

static void sw_replay_doc(int kind, unsigned shape)
{
    unsigned i;
    static const sw_ishape sh13[] = SW_SHAPES13;
    if (!sw_ready(kind)) return;
    for (i = 0; i < NELEM(sw_doc_rows); ++i) {
        const sw_row *w = &sw_doc_rows[i];
        if (w->kind != kind || w->shape != shape) continue;
        if (w->ret == SW_BLOCKED || w->ret == SW_EXC) continue;
        sw_cell_wi(w, 0, w->lo, sw_wsaioctl(kind, w->lo, sh13[shape]), sh13[shape]);
    }
}

static int sw_odense(unsigned o)
{
    if (o < 0x200 || (o >= 0x1000 && o < 0x1100) || (o >= 0x2000 && o < 0x2100) || (o >= 0x3000 && o < 0x3100) ||
        (o >= 0x4000 && o < 0x4040) || (o >= 0x7000 && o < 0x7100)) return 1;
    return (o & 0xFF) <= 3 || o == 0x7FFF;
}

static void sw_replay_opt(int kind, int isget, unsigned shape)
{
    unsigned i, o;
    static const unsigned olens[] = SW_GETLENS;
    static const sw_oshape osets[] = SW_SETSHAPES;
    if (!sw_ready(kind)) return;
    for (i = 0; i < NELEM(sw_opt_rows); ++i) {
        const sw_orow *w = &sw_opt_rows[i];
        if (w->kind != kind || w->isget != isget || w->shape != shape) continue;
        if (w->ret == SW_BLOCKED || w->ret == SW_EXC) continue;
        for (o = w->lo; o <= w->hi; ++o) {
            sw_ores r;
            if (!sw_odense(o)) continue;
            r = isget ? sw_getopt(kind, SOL_SOCKET, (int)o, olens[shape]) : sw_setopt(kind, SOL_SOCKET, (int)o, osets[shape]);
            CHECKF(r.ret == w->ret, "%s %s opt=%04x shape=%u: ret %d want %d", isget ? "getsockopt" : "setsockopt", sw_kind_name[kind], o, shape, r.ret, w->ret);
            if (w->ret != 0)
                CHECKF(r.err == w->err, "%s %s opt=%04x shape=%u: err %d want %d", isget ? "getsockopt" : "setsockopt", sw_kind_name[kind], o, shape, r.err, w->err);
            if (isget && w->ret == 0) {
                CHECKF(r.len == w->len, "getsockopt %s opt=%04x shape=%u: len %u want %u", sw_kind_name[kind], o, shape, r.len, w->len);
                if (w->flags & SWF_VAL)
                    CHECKF(r.val == w->val, "getsockopt %s opt=%04x shape=%u: value %08x want %08x", sw_kind_name[kind], o, shape, r.val, w->val);
            }
        }
    }
}

#define WI_T(k, kn, sh) TEST(wsaioctl_sweep_##kn##_shape##sh) { sw_replay_wi(k, sh); }
#define WI_ALL(k, kn) WI_T(k, kn, 0) WI_T(k, kn, 1) WI_T(k, kn, 2) WI_T(k, kn, 3) WI_T(k, kn, 4) \
    TEST(ioctlsocket_sweep_##kn) { sw_replay_is(k); }
WI_ALL(SK_TCP, tcp) WI_ALL(SK_UDP, udp) WI_ALL(SK_RAW, raw) WI_ALL(SK_UNIX, unix)

#define DOC_T(k, kn, sh) TEST(wsaioctl_documented_##kn##_shape##sh) { sw_replay_doc(k, sh); }
#define DOC_ALL(k, kn) DOC_T(k, kn, 0) DOC_T(k, kn, 1) DOC_T(k, kn, 2) DOC_T(k, kn, 3) DOC_T(k, kn, 4) DOC_T(k, kn, 5) \
    DOC_T(k, kn, 6) DOC_T(k, kn, 7) DOC_T(k, kn, 8) DOC_T(k, kn, 9) DOC_T(k, kn, 10) DOC_T(k, kn, 11) DOC_T(k, kn, 12)
DOC_ALL(SK_TCP, tcp) DOC_ALL(SK_UDP, udp) DOC_ALL(SK_RAW, raw) DOC_ALL(SK_UNIX, unix)

#define GO_T(k, kn, sh) TEST(getsockopt_sweep_##kn##_len##sh) { sw_replay_opt(k, 1, sh); }
#define GO_ALL(k, kn) GO_T(k, kn, 0) GO_T(k, kn, 1) GO_T(k, kn, 2) GO_T(k, kn, 3) GO_T(k, kn, 4) GO_T(k, kn, 5) GO_T(k, kn, 6) GO_T(k, kn, 7) GO_T(k, kn, 8)
GO_ALL(SK_TCP, tcp) GO_ALL(SK_UDP, udp) GO_ALL(SK_RAW, raw) GO_ALL(SK_UNIX, unix)

#define SO_T(k, kn, sh) TEST(setsockopt_sweep_##kn##_shape##sh) { sw_replay_opt(k, 0, sh); }
#define SO_ALL(k, kn) SO_T(k, kn, 0) SO_T(k, kn, 1) SO_T(k, kn, 2) SO_T(k, kn, 3) SO_T(k, kn, 4) SO_T(k, kn, 5) SO_T(k, kn, 6)
SO_ALL(SK_TCP, tcp) SO_ALL(SK_UDP, udp) SO_ALL(SK_RAW, raw) SO_ALL(SK_UNIX, unix)
