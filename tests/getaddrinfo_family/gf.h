/* Shared helpers for the getaddrinfo / getnameinfo family tests.
 *
 * ws2_32 is never linked. Every service is reached through U()/UN() function pointers.
 * The four resolver front ends (ANSI, wide, extended wide, extended ANSI) are driven through one
 * neutral "run a query, snapshot the answer, free it" helper so a single table row can be replayed
 * against several entry points. Nothing printed by these helpers depends on the host or network. */
#ifndef GF_H
#define GF_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

/* Entry-count check; GF_TRIAGE (a build-time switch for emulator triage) relaxes exact counts to non-empty. */
#ifdef GF_TRIAGE
#define GF_N1(n) ((n) >= 1)
#define GF_NEQ(n, want) ((n) >= 1)
#else
#define GF_N1(n) ((n) == 1)
#define GF_NEQ(n, want) ((n) == (want))
#endif
#define NARR(a) (sizeof(a) / sizeof((a)[0]))

/* entry points that the SDK headers do not declare in a usable form */
UDECL(int, GetAddrInfoExCancel, (HANDLE *handle));
UDECL(int, GetAddrInfoExOverlappedResult, (LPOVERLAPPED ov));

#define WSERR()     (U(WSAGetLastError)())
#define SETWSERR(e) (U(WSASetLastError)(e))

static int gf_up(void)
{
    WSADATA d;
    if (!U(WSAStartup)) return -1;
    return U(WSAStartup)(0x202, &d);
}
static void gf_down(void) { if (U(WSACleanup)) U(WSACleanup)(); }

/* ---- which front ends a row applies to ------------------------------------------------------ */
#define GF_A    1   /* getaddrinfo            */
#define GF_W    2   /* GetAddrInfoW           */
#define GF_XW   4   /* GetAddrInfoExW (sync)  */
#define GF_XA   8   /* GetAddrInfoExA (sync)  */
#define GF_AW   (GF_A | GF_W)
#define GF_ALL  (GF_A | GF_W | GF_XW | GF_XA)

static const char *gf_api_name(int api)
{
    return api == GF_A ? "getaddrinfo" : api == GF_W ? "GetAddrInfoW" : api == GF_XW ? "GetAddrInfoExW" : "GetAddrInfoExA";
}

/* GetAddrInfoExA is optional for the harness: on emulators that lack it the XA leg of a row is skipped. */
static int gf_api_ok(int api)
{
    if (api == GF_XA) return U(GetAddrInfoExA) && U(FreeAddrInfoEx);
    return 1;
}
#define GF_EACH(api, mask) for (api = 1; api <= GF_XA; api <<= 1) if (((mask) & api) && gf_api_ok(api))

static int gf_have(int mask)
{
    mask &= ~GF_XA;
    if (!mask) return gf_api_ok(GF_XA);
    if ((mask & GF_A)  && !(U(getaddrinfo)    && U(freeaddrinfo)))     return 0;
    if ((mask & GF_W)  && !(U(GetAddrInfoW)   && U(FreeAddrInfoW)))    return 0;
    if ((mask & GF_XW) && !(U(GetAddrInfoExW) && U(FreeAddrInfoExW)))  return 0;
    if ((mask & GF_XA) && !(U(GetAddrInfoExA) && U(FreeAddrInfoEx)))   return 0;
    return 1;
}

/* Every test starts with the exports it needs and a WSAStartup bracket. */
#define GFB_BEGIN(mask) \
    do { if (!gf_have(mask) || !U(WSAGetLastError) || !U(WSASetLastError)) { t_skip("missing export"); return; } \
         if (gf_up()) { t_skip("WSAStartup failed"); return; } } while (0)
#define GFB_END() gf_down()

/* ---- neutral hint and answer ---------------------------------------------------------------- */
/* dirty: which of the four fields that must be zero in a hint is made non-zero (1 addrlen, 2 canonname,
 * 3 addr, 4 next). The pointers used are valid, never garbage. */
struct gf_hint { int flags, family, socktype, protocol, dirty; };

struct gf_ent {
    int flags, family, socktype, protocol;
    size_t addrlen;
    unsigned char addr[32];
    int has_addr, has_canon;
    char canon[300];
    int xver;            /* extended results: ai_version when the entry is a v2+ structure, else 0 */
    int x_blob, x_provider; /* extended results: ai_blob / ai_provider non-NULL */
    size_t x_bloblen;
    int x_fqdn;          /* extended v2: ai_fqdn present */
    char x_fqdn_text[200];
};
#define GF_MAXENT 16
struct gf_res {
    int ret, werr;
    int out_null;        /* the result pointer was NULL after the call */
    int n;               /* entries seen (capped) */
    int canon_after_first;
    struct gf_ent e[GF_MAXENT];
};

static int gf_ns = NS_DNS;              /* namespace passed to the extended calls */
static char gf_sent[64];                /* result-pointer sentinel target */
static ADDRINFOA gf_dummy_a;
static ADDRINFOW gf_dummy_w;
static ADDRINFOEXW gf_dummy_xw;
static ADDRINFOEXA gf_dummy_xa;
static SOCKADDR_IN gf_dummy_sa;

static void gf_widen(WCHAR *dst, const char *s, size_t cap)
{
    size_t i = 0;
    if (!s) { dst[0] = 0; return; }
    for (; s[i] && i + 1 < cap; i++) dst[i] = (unsigned char)s[i];
    dst[i] = 0;
}
static void gf_narrow(char *dst, const WCHAR *s, size_t cap)
{
    size_t i = 0;
    for (; s[i] && i + 1 < cap; i++) dst[i] = s[i] < 0x80 ? (char)s[i] : '?';
    dst[i] = 0;
}

#define GF_FILL_COMMON(e, p) do { (e)->flags = (p)->ai_flags; (e)->family = (p)->ai_family; (e)->socktype = (p)->ai_socktype; \
    (e)->protocol = (p)->ai_protocol; (e)->addrlen = (p)->ai_addrlen; (e)->has_addr = (p)->ai_addr != NULL; \
    if ((p)->ai_addr) memcpy((e)->addr, (p)->ai_addr, (p)->ai_addrlen < sizeof (e)->addr ? (p)->ai_addrlen : sizeof (e)->addr); } while (0)

static void gf_run(int api, const char *node, const char *serv, const struct gf_hint *h, struct gf_res *r)
{
    WCHAR wn[300], ws[300];
    memset(r, 0, sizeof *r);
    gf_widen(wn, node, 300);
    gf_widen(ws, serv, 300);
    if (api == GF_A) {
        ADDRINFOA hint, *hp = NULL, *out = (ADDRINFOA *)gf_sent, *p;
        if (h) {
            memset(&hint, 0, sizeof hint);
            hint.ai_flags = h->flags; hint.ai_family = h->family; hint.ai_socktype = h->socktype; hint.ai_protocol = h->protocol;
            if (h->dirty == 1) hint.ai_addrlen = 4;
            if (h->dirty == 2) hint.ai_canonname = (char *)"x";
            if (h->dirty == 3) hint.ai_addr = (struct sockaddr *)&gf_dummy_sa;
            if (h->dirty == 4) hint.ai_next = &gf_dummy_a;
            hp = &hint;
        }
        SETWSERR(0x1234);
        r->ret = U(getaddrinfo)(node, serv, hp, &out);
        r->werr = WSERR();
        r->out_null = out == NULL;
        for (p = out; p && r->n < GF_MAXENT; p = p->ai_next, r->n++) {
            struct gf_ent *e = &r->e[r->n];
            GF_FILL_COMMON(e, p);
            e->has_canon = p->ai_canonname != NULL;
            if (p->ai_canonname) lstrcpynA(e->canon, p->ai_canonname, sizeof e->canon);
            if (r->n && e->has_canon) r->canon_after_first = 1;
        }
        if (r->ret == 0 && out) U(freeaddrinfo)(out);
    } else if (api == GF_W) {
        ADDRINFOW hint, *hp = NULL, *out = (ADDRINFOW *)gf_sent, *p;
        if (h) {
            memset(&hint, 0, sizeof hint);
            hint.ai_flags = h->flags; hint.ai_family = h->family; hint.ai_socktype = h->socktype; hint.ai_protocol = h->protocol;
            if (h->dirty == 1) hint.ai_addrlen = 4;
            if (h->dirty == 2) hint.ai_canonname = (PWSTR)L"x";
            if (h->dirty == 3) hint.ai_addr = (struct sockaddr *)&gf_dummy_sa;
            if (h->dirty == 4) hint.ai_next = &gf_dummy_w;
            hp = &hint;
        }
        SETWSERR(0x1234);
        r->ret = U(GetAddrInfoW)(node ? wn : NULL, serv ? ws : NULL, hp, &out);
        r->werr = WSERR();
        r->out_null = out == NULL;
        for (p = out; p && r->n < GF_MAXENT; p = p->ai_next, r->n++) {
            struct gf_ent *e = &r->e[r->n];
            GF_FILL_COMMON(e, p);
            e->has_canon = p->ai_canonname != NULL;
            if (p->ai_canonname) gf_narrow(e->canon, p->ai_canonname, sizeof e->canon);
            if (r->n && e->has_canon) r->canon_after_first = 1;
        }
        if (r->ret == 0 && out) U(FreeAddrInfoW)(out);
    } else if (api == GF_XW) {
        ADDRINFOEXW hint, *hp = NULL, *out = (ADDRINFOEXW *)gf_sent, *p;
        if (h) {
            memset(&hint, 0, sizeof hint);
            hint.ai_flags = h->flags; hint.ai_family = h->family; hint.ai_socktype = h->socktype; hint.ai_protocol = h->protocol;
            if (h->dirty == 1) hint.ai_addrlen = 4;
            if (h->dirty == 2) hint.ai_canonname = L"x";
            if (h->dirty == 3) hint.ai_addr = (struct sockaddr *)&gf_dummy_sa;
            if (h->dirty == 4) hint.ai_next = &gf_dummy_xw;
            hp = &hint;
        }
        SETWSERR(0x1234);
        r->ret = U(GetAddrInfoExW)(node ? wn : NULL, serv ? ws : NULL, gf_ns, NULL, hp, &out, NULL, NULL, NULL, NULL);
        r->werr = WSERR();
        r->out_null = out == NULL;
        for (p = out; p && r->n < GF_MAXENT; p = p->ai_next, r->n++) {
            struct gf_ent *e = &r->e[r->n];
            GF_FILL_COMMON(e, p);
            e->has_canon = p->ai_canonname != NULL;
            if (p->ai_canonname) gf_narrow(e->canon, p->ai_canonname, sizeof e->canon);
            if (r->n && e->has_canon) r->canon_after_first = 1;
            e->x_blob = p->ai_blob != NULL; e->x_bloblen = p->ai_bloblen; e->x_provider = p->ai_provider != NULL;
            if (p->ai_flags < 0) {
                const unsigned char *raw = (const unsigned char *)p;
                e->xver = *(const int *)(raw + 0x48);
                e->x_fqdn = e->xver >= 2 && *(void *const *)(raw + 0x50) != NULL;
                if (e->x_fqdn) gf_narrow(e->x_fqdn_text, *(const WCHAR *const *)(raw + 0x50), sizeof e->x_fqdn_text);
            }
        }
        if (r->ret == 0 && out) U(FreeAddrInfoExW)(out);
    } else {
        ADDRINFOEXA hint, *hp = NULL, *out = (ADDRINFOEXA *)gf_sent, *p;
        if (h) {
            memset(&hint, 0, sizeof hint);
            hint.ai_flags = h->flags; hint.ai_family = h->family; hint.ai_socktype = h->socktype; hint.ai_protocol = h->protocol;
            if (h->dirty == 1) hint.ai_addrlen = 4;
            if (h->dirty == 2) hint.ai_canonname = "x";
            if (h->dirty == 3) hint.ai_addr = (struct sockaddr *)&gf_dummy_sa;
            if (h->dirty == 4) hint.ai_next = &gf_dummy_xa;
            hp = &hint;
        }
        SETWSERR(0x1234);
        r->ret = U(GetAddrInfoExA)(node, serv, gf_ns, NULL, hp, &out, NULL, NULL, NULL, NULL);
        r->werr = WSERR();
        r->out_null = out == NULL;
        for (p = out; p && r->n < GF_MAXENT; p = p->ai_next, r->n++) {
            struct gf_ent *e = &r->e[r->n];
            GF_FILL_COMMON(e, p);
            e->has_canon = p->ai_canonname != NULL;
            if (p->ai_canonname) lstrcpynA(e->canon, p->ai_canonname, sizeof e->canon);
            if (r->n && e->has_canon) r->canon_after_first = 1;
            e->x_blob = p->ai_blob != NULL; e->x_bloblen = p->ai_bloblen; e->x_provider = p->ai_provider != NULL;
            if (p->ai_flags < 0) {
                const unsigned char *raw = (const unsigned char *)p;
                e->xver = *(const int *)(raw + 0x48);
                e->x_fqdn = e->xver >= 2 && *(void *const *)(raw + 0x50) != NULL;
            }
        }
        if (r->ret == 0 && out) U(FreeAddrInfoEx)(out);
    }
}

/* ---- address rendering and entry inspection (host independent, no DLL calls) ----------------- */
static unsigned gf_port(const struct gf_ent *e)
{
    const unsigned char *a = e->addr;
    return (unsigned)(a[2] << 8 | a[3]);
}
/* "a.b.c.d" for AF_INET; eight unabbreviated hex groups for AF_INET6, "%n" appended for a non-zero scope id. */
static void gf_fmt(const struct gf_ent *e, char *out, size_t cap)
{
    const unsigned char *a = e->addr;
    if (!e->has_addr) { snprintf(out, cap, "(none)"); return; }
    if (e->family == AF_INET) snprintf(out, cap, "%u.%u.%u.%u", a[4], a[5], a[6], a[7]);
    else if (e->family == AF_INET6) {
        unsigned scope = a[24] | a[25] << 8 | a[26] << 16 | (unsigned)a[27] << 24;
        int i, n = 0;
        for (i = 0; i < 8; i++) n += snprintf(out + n, cap - n, "%s%x", i ? ":" : "", a[8 + 2 * i] << 8 | a[9 + 2 * i]);
        if (scope) snprintf(out + n, cap - n, "%%%u", scope);
    } else snprintf(out, cap, "(family %d)", e->family);
}
static unsigned gf_v6_scope(const struct gf_ent *e)
{
    const unsigned char *a = e->addr;
    return a[24] | a[25] << 8 | a[26] << 16 | (unsigned)a[27] << 24;
}
static unsigned gf_v6_flow(const struct gf_ent *e)
{
    const unsigned char *a = e->addr;
    return a[4] | a[5] << 8 | a[6] << 16 | (unsigned)a[7] << 24;
}

/* ---- row checkers ---------------------------------------------------------------------------- */
/* The call must fail with exactly err (return value == WSAGetLastError() == err) and clear the result pointer. */
static void gf_check_err(int mask, const char *node, const char *serv, const struct gf_hint *h, int err)
{
    int api;
    GF_EACH(api, mask) {
        struct gf_res r;
        gf_run(api, node, serv, h, &r);
        CHECKF(r.ret == err, "%s: ret %d want %d", gf_api_name(api), r.ret, err);
        CHECKF(r.werr == err, "%s: WSAGetLastError %d want %d", gf_api_name(api), r.werr, err);
        CHECKF(r.out_null, "%s: result pointer not cleared", gf_api_name(api));
    }
}
/* The call must succeed; the first entry must render as want_addr with port want_port (-1: unchecked).
 * want_n: exact entry count, -1 for "at least one". Returns the last result through *last when given. */
static void gf_check_first(int mask, const char *node, const char *serv, const struct gf_hint *h,
                           const char *want_addr, int want_port, int want_n)
{
    int api;
    GF_EACH(api, mask) {
        struct gf_res r;
        char txt[128];
        gf_run(api, node, serv, h, &r);
        CHECKF(r.ret == 0, "%s: ret %d", gf_api_name(api), r.ret);
        CHECKF(r.werr == 0, "%s: WSAGetLastError %d", gf_api_name(api), r.werr);
        if (r.ret) continue;
        CHECKF(r.n >= 1, "%s: empty list", gf_api_name(api));
        if (want_n >= 0) CHECKF(GF_NEQ(r.n, want_n), "%s: %d entries want %d", gf_api_name(api), r.n, want_n);
        if (r.n < 1) continue;
        gf_fmt(&r.e[0], txt, sizeof txt);
        CHECKF(!strcmp(txt, want_addr), "%s: first entry \"%s\" want \"%s\"", gf_api_name(api), txt, want_addr);
        if (want_port >= 0) CHECKF((int)gf_port(&r.e[0]) == want_port, "%s: port %u want %d", gf_api_name(api), gf_port(&r.e[0]), want_port);
    }
}

#define H(fl, fam, st, pr)        (&(const struct gf_hint){ (fl), (fam), (st), (pr), 0 })
#define HD(fl, fam, st, pr, d)    (&(const struct gf_hint){ (fl), (fam), (st), (pr), (d) })

/* ---- service-name model ---------------------------------------------------------------------- */
/* What the resolver derives from a service name and a requested socket type, written from the
 * documented lookup rules: the services database is consulted for tcp and/or udp (never for the protocol the
 * socket type excludes) and the answer is checked against the same database queried through getservbyname. */
struct gf_svc { int err; unsigned port_be; int socktype; };
static struct gf_svc gf_model_service(const char *name, int socktype)
{
    struct gf_svc s = { 0, 0, socktype };
    unsigned tcp = 0, udp = 0;
    int err = 0;
    const struct servent *se;
    if (socktype != SOCK_DGRAM) {
        se = U(getservbyname)(name, "tcp");
        if (se) tcp = (unsigned short)se->s_port; else err = WSATYPE_NOT_FOUND;
    }
    if (socktype != SOCK_STREAM) {
        se = U(getservbyname)(name, "udp");
        if (se) udp = (unsigned short)se->s_port; else err = WSATYPE_NOT_FOUND;
    }
    {
        unsigned port = tcp;
        int st = socktype;
        if (tcp != udp) {
            int t = 1;
            if (tcp == 0) { t = 2; port = udp; }
            if (socktype != SOCK_RAW) st = t;
        }
        if (port) err = 0;
        s.err = err; s.port_be = port; s.socktype = st;
    }
    return s;
}

static unsigned gf_ntohs16(unsigned p) { return ((p & 0xff) << 8) | ((p >> 8) & 0xff); }

/* One table row == one test. */
#define ERR_ROW(nm, mask, node, serv, hint, err) \
    TEST(nm) { GFB_BEGIN(mask); gf_check_err(mask, node, serv, hint, err); GFB_END(); }
#define OK_ROW(nm, mask, node, serv, hint, addr, port, n) \
    TEST(nm) { GFB_BEGIN(mask); gf_check_first(mask, node, serv, hint, addr, port, n); GFB_END(); }
#endif
