/* Polls with many entries. Requests of a hundred entries or more with no exclusive flag take a separate,
 * cached path in the driver, so the sizes 99/100/101 and beyond are measured explicitly.
 * Measures: that every entry is reported, in submission order, at the sizes around the switch-over;
 * filtering with a mixed ready / not-ready population; one ready entry among many waiting ones; that
 * repeating the same request gives the same answer; and that a handle closed between two identical
 * requests is noticed. */
#include "ap.h"

#define MAXS 150

static SOCKET g_udp[MAXS];
static int g_nudp;

static void make_udp(int n)
{
    int i;
    g_nudp = n;
    for (i = 0; i < n; i++) g_udp[i] = ap_sock(SOCK_DGRAM);
}
static void free_udp(void)
{
    int i;
    for (i = 0; i < g_nudp; i++) ap_closeS(g_udp[i]);
    g_nudp = 0;
}

static void check_all_reported(const ap_res *r, int n, const SOCKET *h, ULONG want)
{
    int i, ok = 1;
    CHECKF(r->ret == 0 && r->ios == 0, "ret %#lx ios %#lx", (unsigned long)r->ret, (unsigned long)r->ios);
    CHECKF(r->out.n == (ULONG)n, "count %lu want %d", (unsigned long)r->out.n, n);
    CHECKF(r->info == AP_SZ(n), "information %#llx", (unsigned long long)r->info);
    for (i = 0; i < n && i < (int)r->out.n; i++)
        if (r->out.e[i].h != h[i] || r->out.e[i].ev != want || r->out.e[i].st != 0) { ok = 0; break; }
    CHECKF(ok, "entry %d differs", i);
}

TEST(apev_large_all_ready_reported_in_order)
{
    AP_BEGIN();
    static const int sizes[] = { 1, 2, 8, 64, 99, 100, 101, 128, 150 };
    size_t k; int j;
    make_udp(MAXS);
    for (k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++) {
        ULONG m[MAXS]; ap_res r; int n = sizes[k];
        for (j = 0; j < n; j++) m[j] = APE_SEND;
        ap_run((HANDLE)g_udp[0], 0, 0, n, g_udp, m, 4000, &r);
        CHECKF(!r.hung, "n=%d: hung", n);
        check_all_reported(&r, n, g_udp, APE_SEND);
    }
    free_udp();
}

/* Same request twice back to back, then from another carrier: identical answers. */
TEST(apev_large_repeat_gives_same_answer)
{
    AP_BEGIN();
    int j, rep; ULONG m[MAXS];
    make_udp(120);
    for (j = 0; j < 120; j++) m[j] = APE_SEND;
    for (rep = 0; rep < 3; rep++) {
        ap_res r;
        ap_run((HANDLE)g_udp[rep], 0, 0, 120, g_udp, m, 4000, &r);
        check_all_reported(&r, 120, g_udp, APE_SEND);
    }
    free_udp();
}

/* Alternating ready (datagram socket, send) and not-ready (idle listener, accept) entries. */
TEST(apev_large_mixed_population_filters)
{
    AP_BEGIN();
    SOCKET hs[MAXS], want[MAXS / 2]; ULONG m[MAXS]; ap_res r; int i, nw = 0, n = 110, ok = 1;
    for (i = 0; i < n; i++) {
        if (i % 2 == 0) { hs[i] = ap_sock(SOCK_DGRAM); m[i] = APE_SEND; want[nw++] = hs[i]; }
        else { hs[i] = ap_listener(NULL, 1); m[i] = APE_ACCEPT; }
    }
    ap_run((HANDLE)hs[0], 0, 0, n, hs, m, 4000, &r);
    CK_ST(r.ret, APS_SUCCESS);
    CHECK(r.out.n == (ULONG)nw);
    for (i = 0; i < nw && i < (int)r.out.n; i++) if (r.out.e[i].h != want[i] || r.out.e[i].ev != APE_SEND) ok = 0;
    CHECK(ok);
    CHECK(r.info == AP_SZ(nw));
    for (i = 0; i < n; i++) ap_closeS(hs[i]);
}

/* A hundred-plus entries waiting on listeners; one connection to one of them completes the request with
 * only that entry. */
TEST(apev_large_pending_single_ready_entry)
{
    AP_BEGIN();
    enum { N = 104, PICK = 77 };
    SOCKET hs[N]; struct sockaddr_in addrs[N]; ULONG m[N]; ap_req in, out; IO_STATUS_BLOCK io; HANDLE ev = ap_event(); int i; SOCKET cl;
    for (i = 0; i < N; i++) { hs[i] = ap_listener(&addrs[i], 1); m[i] = APE_ACCEPT; }
    ap_fill(&in, AP_REL_MS(8000), 0, N, hs, APE_ACCEPT);
    memset(&out, 0, sizeof(out));
    CK_ST(ap_submit((HANDLE)hs[0], ev, &io, &in, AP_SZ(N), &out, AP_SZ(N)), APS_PENDING);
    CHECK(WaitForSingleObject(ev, 150) == WAIT_TIMEOUT);
    cl = ap_dial(&addrs[PICK]);
    CHECK(WaitForSingleObject(ev, 4000) == WAIT_OBJECT_0);
    CK_ST(io.Status, APS_SUCCESS);
    CHECK(io.Information == AP_SZ(1));
    CHECK(out.n == 1 && out.e[0].h == hs[PICK] && out.e[0].ev == APE_ACCEPT);
    CHECK(out.to == in.to);
    ap_closeS(cl);
    for (i = 0; i < N; i++) ap_closeS(hs[i]);
    CloseHandle(ev);
}

/* A handle that went away between two identical big requests is detected by the second one. */
TEST(apev_large_closed_handle_detected_on_second_request)
{
    AP_BEGIN();
    ULONG m[MAXS]; ap_req in; int j;
    make_udp(104);
    for (j = 0; j < 104; j++) m[j] = APE_SEND;
    {
        ap_res r;
        ap_run((HANDLE)g_udp[0], 0, 0, 104, g_udp, m, 4000, &r);
        check_all_reported(&r, 104, g_udp, APE_SEND);
    }
    ap_closeS(g_udp[50]);
    ap_fill(&in, 0, 0, 104, g_udp, APE_SEND);
    CK_ST(ap_try((HANDLE)g_udp[0], &in, AP_SZ(104), AP_SZ(104)), APS_INVALID_HANDLE);
    g_udp[50] = INVALID_SOCKET;
    free_udp();
}

/* The exclusive flag with many entries is accepted too (infinite deadline) and is cancellable. */
TEST(apev_large_exclusive_is_accepted)
{
    AP_BEGIN();
    SOCKET hs[104]; ap_res r; ULONG m[104]; int i;
    for (i = 0; i < 104; i++) { hs[i] = ap_listener(NULL, 1); m[i] = APE_ACCEPT; }
    ap_run((HANDLE)hs[0], AP_INFINITE, 1, 104, hs, m, 300, &r);
    CK_ST(r.ret, APS_PENDING);
    CHECK(r.hung);
    CK_ST(r.ios, APS_CANCELLED);
    for (i = 0; i < 104; i++) ap_closeS(hs[i]);
}
