/* Socket-open contract of the helper entry points embedded in mswsock.dll (Tcpip4_/Tcpip6_ WSHOpenSocket2,
 * WSHOpenSocket) and the notification that switches the transport device mode (WSHNotify).
 *
 * Measures: which (type, protocol) pairs each family accepts and how they are normalised; the group and flag
 * restrictions per socket type; WSAEINVAL for everything else with every output left untouched; the context
 * value handed out (the address family); the notification-event mask and the empty transport device name while no
 * device mode has been requested; WSHOpenSocket as WSHOpenSocket2 with no group and no flags; and, in child
 * processes because the mode is process-wide, how WSHNotify with the stream, datagram and raw bits turns on the
 * named transport devices while every other notification value changes nothing. */
#include "gap4.h"

typedef struct { int ty, pr; GROUP grp; DWORD flags; int want_ty, want_pr; } ok_row;
typedef struct { int ty, pr; GROUP grp; DWORD flags; } bad_row;

static const ok_row ok_rows[] = {
    { 0, 6, 0, 0, 1, 6 }, { 1, 0, 0, 0, 1, 6 }, { 1, 6, 0, 0, 1, 6 }, { 1, 6, 1, 0, 1, 6 }, { 1, 6, 2, 0, 1, 6 },
    { 1, 6, 0x7fffffff, 0, 1, 6 }, { 1, 6, 0, 1, 1, 6 }, { 1, 0, 0, 1, 1, 6 },
    { 0, 17, 0, 0, 2, 17 }, { 2, 0, 0, 0, 2, 17 }, { 2, 17, 0, 0, 2, 17 }, { 2, 17, 1, 0, 2, 17 },
    { 2, 17, 0, 1, 2, 17 }, { 2, 17, 0, 4, 2, 17 }, { 2, 17, 0, 0x10, 2, 17 }, { 2, 17, 0, 0x15, 2, 17 },
    { 2, 0, 0, 0x10, 2, 17 }, { 0, 17, 0, 4, 2, 17 },
    { 3, 0, 0, 0, 3, 0 }, { 3, 0, 2, 0, 3, 0 }, { 3, 1, 0, 0, 3, 1 }, { 3, 6, 0, 0, 3, 6 }, { 3, 17, 0, 0, 3, 17 },
    { 3, 58, 0, 0, 3, 58 }, { 3, 255, 0, 0, 3, 255 }, { 3, 255, 0, 4, 3, 255 }, { 3, 255, 0, 0x10, 3, 255 },
    { 3, 255, 0, 0x15, 3, 255 }, { 3, 100, 0, 1, 3, 100 }, { 3, 100, 2, 0, 3, 100 },
};
static const bad_row bad_rows[] = {
    { 0, 0, 0, 0 }, { 0, 1, 0, 0 }, { 0, 3, 0, 0 }, { 0, 255, 0, 0 }, { 1, 17, 0, 0 }, { 1, 1, 0, 0 }, { 1, 3, 0, 0 },
    { 1, 256, 0, 0 }, { 1, 255, 0, 0 }, { 2, 6, 0, 0 }, { 2, 1, 0, 0 }, { 2, 256, 0, 0 }, { 4, 6, 0, 0 }, { 4, 0, 0, 0 },
    { 5, 6, 0, 0 }, { 5, 0, 0, 0 }, { 6, 6, 0, 0 }, { -1, 6, 0, 0 }, { 0x100, 6, 0, 0 },
    { 3, 256, 0, 0 }, { 3, 0x100, 0, 0 }, { 3, -1, 0, 0 }, { 3, 1000, 0, 0 },
    { 2, 17, 2, 0 }, { 2, 0, 2, 0 }, { 0, 17, 2, 0 },
    { 1, 6, 0, 2 }, { 1, 6, 0, 3 }, { 1, 6, 0, 4 }, { 1, 6, 0, 0x10 }, { 1, 6, 0, 0x80000000 }, { 1, 0, 0, 0x20 },
    { 2, 17, 0, 2 }, { 2, 17, 0, 8 }, { 2, 17, 0, 0x20 }, { 2, 17, 0, 0x80 }, { 2, 17, 0, 0x80000000 }, { 0, 17, 0, 0x40 },
    { 3, 255, 0, 2 }, { 3, 255, 0, 8 }, { 3, 255, 0, 0x20 }, { 3, 255, 0, 0x80 }, { 3, 0, 0, 0xffffffff },
};

#define MARK_NAME 0xCD
static void open_row(const g4_fam *fam, g4_open2_fn f, int af, int ty, int pr, GROUP grp, DWORD fl, int want_rc, int want_ty, int want_pr, const char *what)
{
    int a = af, t = ty, p = pr; UNICODE_STRING us; PVOID ctx = (PVOID)(ULONG_PTR)1; DWORD ev = 0x77; INT r;
    memset(&us, MARK_NAME, sizeof us);
    r = f(&a, &t, &p, grp, fl, &us, &ctx, &ev);
    CHECKF(r == want_rc, "%s %s: rc %d want %d", fam->tag, what, r, want_rc);
    if (want_rc == 0) {
        CHECKF(a == fam->af && t == want_ty && p == want_pr, "%s %s: out (%d,%d,%d)", fam->tag, what, a, t, p);
        CHECKF((ULONG_PTR)ctx == (ULONG_PTR)fam->af, "%s %s: context %p", fam->tag, what, ctx);
        CHECKF(ev == 0xe0000000u, "%s %s: event mask %lx", fam->tag, what, ev);
        CHECKF(us.Length == 0 && us.Buffer == NULL, "%s %s: device name not empty", fam->tag, what);
    } else {
        CHECKF(a == af && t == ty && p == pr, "%s %s: triple modified on failure (%d,%d,%d)", fam->tag, what, a, t, p);
        CHECKF(ctx == (PVOID)(ULONG_PTR)1, "%s %s: context written on failure", fam->tag, what);
        CHECKF(ev == 0x77, "%s %s: event mask written on failure", fam->tag, what);
        CHECKF(us.Length == 0xCDCD && us.MaximumLength == 0xCDCD, "%s %s: device name written on failure", fam->tag, what);
    }
}

static void accept_all(const g4_fam *fam)
{
    g4_open2_fn f = (g4_open2_fn)g4_fn(fam, "OpenSocket2"); size_t i;
    REQUIRE(f);
    for (i = 0; i < G4N(ok_rows); i++) {
        char w[80]; snprintf(w, sizeof w, "ty=%d pr=%d grp=%lx fl=%lx", ok_rows[i].ty, ok_rows[i].pr, (DWORD)ok_rows[i].grp, ok_rows[i].flags);
        open_row(fam, f, fam->af, ok_rows[i].ty, ok_rows[i].pr, ok_rows[i].grp, ok_rows[i].flags, 0, ok_rows[i].want_ty, ok_rows[i].want_pr, w);
    }
}
static void reject_all(const g4_fam *fam)
{
    g4_open2_fn f = (g4_open2_fn)g4_fn(fam, "OpenSocket2"); size_t i;
    REQUIRE(f);
    for (i = 0; i < G4N(bad_rows); i++) {
        char w[80]; snprintf(w, sizeof w, "ty=%d pr=%d grp=%lx fl=%lx", bad_rows[i].ty, bad_rows[i].pr, (DWORD)bad_rows[i].grp, bad_rows[i].flags);
        open_row(fam, f, fam->af, bad_rows[i].ty, bad_rows[i].pr, bad_rows[i].grp, bad_rows[i].flags, G4_INVAL, 0, 0, w);
    }
}
TEST(gap4_open2_v4_accepted_triples) { accept_all(&g4_v4); }
TEST(gap4_open2_v6_accepted_triples) { accept_all(&g4_v6); }
TEST(gap4_open2_v4_rejected_triples) { reject_all(&g4_v4); }
TEST(gap4_open2_v6_rejected_triples) { reject_all(&g4_v6); }

/* A family the helper does not serve is WSAEINVAL (not WSAEAFNOSUPPORT). */
static void foreign_family(const g4_fam *fam)
{
    static const int afs[] = { 0, 1, 6, 16, 26, 32, 99, -1, 0x10002, 0x10017 };
    g4_open2_fn f = (g4_open2_fn)g4_fn(fam, "OpenSocket2"); size_t i;
    REQUIRE(f);
    for (i = 0; i < G4N(afs); i++) {
        if (afs[i] == fam->af) continue;
        open_row(fam, f, afs[i], 1, 6, 0, 0, G4_INVAL, 0, 0, "foreign family stream");
        open_row(fam, f, afs[i], 2, 17, 0, 0, G4_INVAL, 0, 0, "foreign family dgram");
        open_row(fam, f, afs[i], 3, 255, 0, 0, G4_INVAL, 0, 0, "foreign family raw");
    }
}
TEST(gap4_open2_v4_foreign_family_is_invalid) { foreign_family(&g4_v4); }
TEST(gap4_open2_v6_foreign_family_is_invalid) { foreign_family(&g4_v6); }
TEST(gap4_open2_v4_rejects_the_other_ip_family) { g4_open2_fn f = (g4_open2_fn)g4_fn(&g4_v4, "OpenSocket2"); REQUIRE(f); open_row(&g4_v4, f, AF_INET6, 1, 6, 0, 0, G4_INVAL, 0, 0, "af=23"); }
TEST(gap4_open2_v6_rejects_the_other_ip_family) { g4_open2_fn f = (g4_open2_fn)g4_fn(&g4_v6, "OpenSocket2"); REQUIRE(f); open_row(&g4_v6, f, AF_INET, 1, 6, 0, 0, G4_INVAL, 0, 0, "af=2"); }

/* The family field of the incoming triple is rewritten to the helper's own value for every accepted request. */
static void af_zero_rejected(const g4_fam *fam)
{
    g4_open2_fn f = (g4_open2_fn)g4_fn(fam, "OpenSocket2");
    REQUIRE(f);
    open_row(fam, f, 0, 1, 6, 0, 0, G4_INVAL, 0, 0, "af=0");
}
TEST(gap4_open2_v4_family_zero_is_not_a_wildcard) { af_zero_rejected(&g4_v4); }
TEST(gap4_open2_v6_family_zero_is_not_a_wildcard) { af_zero_rejected(&g4_v6); }

/* Raw sockets: any protocol 0..255 is carried through unchanged; above 255 is refused. */
static void raw_protocol_sweep(const g4_fam *fam)
{
    g4_open2_fn f = (g4_open2_fn)g4_fn(fam, "OpenSocket2"); int p;
    REQUIRE(f);
    for (p = 0; p <= 255; p++) open_row(fam, f, fam->af, 3, p, 0, 0, 0, 3, p, "raw proto");
    open_row(fam, f, fam->af, 3, 256, 0, 0, G4_INVAL, 0, 0, "raw proto 256");
    open_row(fam, f, fam->af, 3, 257, 0, 0, G4_INVAL, 0, 0, "raw proto 257");
    open_row(fam, f, fam->af, 3, 0x7fffffff, 0, 0, G4_INVAL, 0, 0, "raw proto max");
}
TEST(gap4_open2_v4_raw_protocol_range) { raw_protocol_sweep(&g4_v4); }
TEST(gap4_open2_v6_raw_protocol_range) { raw_protocol_sweep(&g4_v6); }

/* Stream and datagram take the protocol only from the fixed triples. */
static void proto_sweep(const g4_fam *fam)
{
    g4_open2_fn f = (g4_open2_fn)g4_fn(fam, "OpenSocket2"); int p;
    REQUIRE(f);
    for (p = 0; p <= 40; p++) {
        int ok_s = (p == 0 || p == 6), ok_d = (p == 0 || p == 17);
        open_row(fam, f, fam->af, 1, p, 0, 0, ok_s ? 0 : G4_INVAL, 1, 6, "stream proto");
        open_row(fam, f, fam->af, 2, p, 0, 0, ok_d ? 0 : G4_INVAL, 2, 17, "dgram proto");
    }
}
TEST(gap4_open2_v4_stream_dgram_protocol_sweep) { proto_sweep(&g4_v4); }
TEST(gap4_open2_v6_stream_dgram_protocol_sweep) { proto_sweep(&g4_v6); }

/* WSHOpenSocket is WSHOpenSocket2 with group 0 and flags 0. */
static void open1(const g4_fam *fam)
{
    g4_open_fn f = (g4_open_fn)g4_fn(fam, "OpenSocket");
    int a, t, p; UNICODE_STRING us; PVOID ctx; DWORD ev;
    REQUIRE(f);
    a = fam->af; t = 1; p = 0; ctx = NULL; ev = 0; memset(&us, MARK_NAME, sizeof us);
    EXPECT_EQ(f(&a, &t, &p, &us, &ctx, &ev), 0);
    CHECK(a == fam->af && t == 1 && p == 6);
    EXPECT_EQ(ctx, fam->af); EXPECT_EQ(ev, 0xe0000000u); EXPECT_EQ(us.Length, 0); CHECK(us.Buffer == NULL);
    a = fam->af; t = 2; p = 0; ctx = NULL;
    EXPECT_EQ(f(&a, &t, &p, &us, &ctx, &ev), 0);
    CHECK(t == 2 && p == 17);
    a = fam->af; t = 3; p = 99; ctx = NULL;
    EXPECT_EQ(f(&a, &t, &p, &us, &ctx, &ev), 0);
    CHECK(t == 3 && p == 99);
}
static void open1_bad(const g4_fam *fam)
{
    g4_open_fn f = (g4_open_fn)g4_fn(fam, "OpenSocket");
    int a, t, p; UNICODE_STRING us; PVOID ctx = (PVOID)(ULONG_PTR)1; DWORD ev = 0x77;
    REQUIRE(f);
    memset(&us, MARK_NAME, sizeof us);
    a = fam->af; t = 1; p = 17;
    EXPECT_EQ(f(&a, &t, &p, &us, &ctx, &ev), G4_INVAL);
    CHECK(a == fam->af && t == 1 && p == 17 && ctx == (PVOID)(ULONG_PTR)1 && ev == 0x77 && us.Length == 0xCDCD);
    a = fam->af; t = 4; p = 0;
    EXPECT_EQ(f(&a, &t, &p, &us, &ctx, &ev), G4_INVAL);
    a = fam->af == AF_INET ? AF_INET6 : AF_INET; t = 1; p = 6;
    EXPECT_EQ(f(&a, &t, &p, &us, &ctx, &ev), G4_INVAL);
}
TEST(gap4_open1_v4_forwards_to_open2_defaults) { open1(&g4_v4); }
TEST(gap4_open1_v6_forwards_to_open2_defaults) { open1(&g4_v6); }
TEST(gap4_open1_v4_rejections) { open1_bad(&g4_v4); }
TEST(gap4_open1_v6_rejections) { open1_bad(&g4_v6); }

/* Constrained-group and flag restrictions differ per type. */
static void group_flag_matrix(const g4_fam *fam)
{
    g4_open2_fn f = (g4_open2_fn)g4_fn(fam, "OpenSocket2"); DWORD fl; int ok;
    REQUIRE(f);
    for (fl = 0; fl < 0x100; fl++) {
        ok = (fl & ~1u) == 0;
        open_row(fam, f, fam->af, 1, 6, 0, fl, ok ? 0 : G4_INVAL, 1, 6, "stream flag");
        ok = (fl & ~0x15u) == 0;
        open_row(fam, f, fam->af, 2, 17, 0, fl, ok ? 0 : G4_INVAL, 2, 17, "dgram flag");
        open_row(fam, f, fam->af, 3, 17, 0, fl, ok ? 0 : G4_INVAL, 3, 17, "raw flag");
    }
}
TEST(gap4_open2_v4_flag_matrix) { group_flag_matrix(&g4_v4); }
TEST(gap4_open2_v6_flag_matrix) { group_flag_matrix(&g4_v6); }

static void group_matrix(const g4_fam *fam)
{
    g4_open2_fn f = (g4_open2_fn)g4_fn(fam, "OpenSocket2"); GROUP g;
    REQUIRE(f);
    for (g = 0; g < 6; g++) {
        open_row(fam, f, fam->af, 1, 6, g, 0, 0, 1, 6, "stream group");
        open_row(fam, f, fam->af, 2, 17, g, 0, g == 2 ? G4_INVAL : 0, 2, 17, "dgram group");
        open_row(fam, f, fam->af, 3, 17, g, 0, 0, 3, 17, "raw group");
    }
}
TEST(gap4_open2_v4_group_matrix) { group_matrix(&g4_v4); }
TEST(gap4_open2_v6_group_matrix) { group_matrix(&g4_v6); }

/* ---- WSHNotify ---- */
/* Notification values that name no device mode: the call succeeds and the open still reports no device. These run
 * in a child process so the process-wide mode of the test executable stays untouched. */
CHILD(gap4_notify_other)
{
    int fam_n = argc > 1 ? atoi(argv[1]) : 4;
    const g4_fam *fam = fam_n == 6 ? &g4_v6 : &g4_v4;
    g4_notify_fn nf = (g4_notify_fn)g4_fn(fam, "Notify");
    g4_open2_fn of = (g4_open2_fn)g4_fn(fam, "OpenSocket2");
    static const DWORD vals[] = { 0, 1, 2, 3, 4, 8, 0x10, 0x10000000, 0xC0000000u, 0xA0000000u, 0x60000000, 0xE0000000u, 0x7fffffff, 0xffffffffu, 0x00000001u << 30 | 1 };
    DWORD rc = 0; size_t i;
    if (!nf || !of) return 100;
    for (i = 0; i < G4N(vals); i++) {
        int a = fam->af, t = 2, p = 17; UNICODE_STRING us; PVOID ctx = NULL; DWORD ev = 0;
        if (vals[i] == 0x40000000u) continue;
        if (nf((PVOID)(ULONG_PTR)fam->af, 0x1234, NULL, NULL, vals[i]) != 0) rc |= 1;
        memset(&us, MARK_NAME, sizeof us);
        if (of(&a, &t, &p, 0, 0, &us, &ctx, &ev) != 0) rc |= 2;
        if (us.Length != 0 || us.Buffer != NULL) rc |= 4;
        if (ev != 0xe0000000u) rc |= 8;
    }
    return (int)rc;
}
TEST(gap4_notify_v4_other_values_change_nothing) { EXPECT_EQ(t_run_child("gap4_notify_other", "4", 20000), 0); }
TEST(gap4_notify_v6_other_values_change_nothing) { EXPECT_EQ(t_run_child("gap4_notify_other", "6", 20000), 0); }

/* mode: s stream, d datagram, r raw. Opens each type before and after the notification. */
static int open_name(const g4_fam *fam, int ty, int pr, WCHAR *out, size_t cap, DWORD *ev)
{
    g4_open2_fn of = (g4_open2_fn)g4_fn(fam, "OpenSocket2");
    int a = fam->af, t = ty, p = pr; UNICODE_STRING us; PVOID ctx = NULL; DWORD e = 0x55; size_t n;
    memset(&us, MARK_NAME, sizeof us);
    if (of(&a, &t, &p, 0, 0, &us, &ctx, &e) != 0) return -1;
    n = us.Length / sizeof(WCHAR);
    if (n >= cap) return -2;
    if (n) memcpy(out, us.Buffer, n * sizeof(WCHAR));
    out[n] = 0;
    if (us.Buffer == NULL && us.Length != 0) return -3;
    *ev = e;
    return (int)n;
}
CHILD(gap4_notify_mode)
{
    int fam_n = argc > 1 ? atoi(argv[1]) : 4;
    char mode = argc > 2 ? argv[2][0] : 's';
    const g4_fam *fam = fam_n == 6 ? &g4_v6 : &g4_v4;
    g4_notify_fn nf = (g4_notify_fn)g4_fn(fam, "Notify");
    DWORD bit = mode == 's' ? 0x80000000u : mode == 'd' ? 0x40000000u : 0x20000000u;
    WCHAR nm[64]; DWORD ev; int rc = 0, n;
    if (!nf) return 100;
    /* before: nothing requested */
    if (open_name(fam, 1, 6, nm, 64, &ev) != 0 || ev != 0xe0000000u) rc |= 1;
    if (open_name(fam, 2, 17, nm, 64, &ev) != 0 || ev != 0xe0000000u) rc |= 2;
    if (open_name(fam, 3, 1, nm, 64, &ev) != 0 || ev != 0xe0000000u) rc |= 4;
    if (nf((PVOID)(ULONG_PTR)fam->af, 0x1234, NULL, NULL, bit) != 0) rc |= 8;
    /* after: only the requested type reports a device */
    n = open_name(fam, 1, 6, nm, 64, &ev);
    if (mode == 's') { if (n != (int)wcslen(fam->tdi_stream) || wcscmp(nm, fam->tdi_stream)) rc |= 16; if (fam_n == 4 && ev != 0) rc |= 32; }
    else if (n != 0) rc |= 16;
    n = open_name(fam, 2, 17, nm, 64, &ev);
    if (mode == 'd') { if (n != (int)wcslen(fam->tdi_dgram) || wcscmp(nm, fam->tdi_dgram) || ev != 0) rc |= 64; }
    else if (n != 0) rc |= 64;
    n = open_name(fam, 3, 255, nm, 64, &ev);
    if (mode == 'r') {
        const WCHAR *want = fam_n == 4 ? L"\\Device\\RawIp\\255" : L"\\Device\\RawIp6\\255";
        if (n != (int)wcslen(want) || wcscmp(nm, want)) rc |= 128;
        n = open_name(fam, 3, 0, nm, 64, &ev);
        want = fam_n == 4 ? L"\\Device\\RawIp\\0" : L"\\Device\\RawIp6\\0";
        if (n != (int)wcslen(want) || wcscmp(nm, want)) rc |= 256;
        n = open_name(fam, 3, 6, nm, 64, &ev);
        want = fam_n == 4 ? L"\\Device\\RawIp\\6" : L"\\Device\\RawIp6\\6";
        if (n != (int)wcslen(want) || wcscmp(nm, want)) rc |= 512;
        if (fam_n == 4 && ev != 0) rc |= 1024;
    } else if (n != 0) rc |= 128;
    /* repeating the notification is harmless */
    if (nf((PVOID)(ULONG_PTR)fam->af, 0x1234, NULL, NULL, bit) != 0) rc |= 2048;
    return rc;
}
TEST(gap4_notify_v4_stream_bit_enables_the_tcp_device) { EXPECT_EQ(t_run_child("gap4_notify_mode", "4 s", 20000), 0); }
TEST(gap4_notify_v4_datagram_bit_enables_the_udp_device) { EXPECT_EQ(t_run_child("gap4_notify_mode", "4 d", 20000), 0); }
TEST(gap4_notify_v4_raw_bit_enables_the_rawip_device) { EXPECT_EQ(t_run_child("gap4_notify_mode", "4 r", 20000), 0); }
TEST(gap4_notify_v6_stream_bit_enables_the_tcp6_device) { EXPECT_EQ(t_run_child("gap4_notify_mode", "6 s", 20000), 0); }
TEST(gap4_notify_v6_datagram_bit_enables_the_udp6_device) { EXPECT_EQ(t_run_child("gap4_notify_mode", "6 d", 20000), 0); }
TEST(gap4_notify_v6_raw_bit_enables_the_rawip6_device) { EXPECT_EQ(t_run_child("gap4_notify_mode", "6 r", 20000), 0); }

/* The two families keep separate mode flags: notifying one leaves the other helper without a device. */
CHILD(gap4_notify_isolation)
{
    int rc = 0; WCHAR nm[64]; DWORD ev;
    g4_notify_fn n4 = (g4_notify_fn)g4_fn(&g4_v4, "Notify");
    if (!n4) return 100;
    if (n4(NULL, 0, NULL, NULL, 0x80000000u) != 0) rc |= 1;
    if (open_name(&g4_v4, 1, 6, nm, 64, &ev) != (int)wcslen(L"\\Device\\Tcp")) rc |= 2;
    if (open_name(&g4_v6, 1, 6, nm, 64, &ev) != 0) rc |= 4;
    return rc;
}
TEST(gap4_notify_modes_are_per_family) { EXPECT_EQ(t_run_child("gap4_notify_isolation", "", 20000), 0); }

/* The notify call ignores the socket, handles and context entirely. */
CHILD(gap4_notify_ignores_context)
{
    g4_notify_fn n4 = (g4_notify_fn)g4_fn(&g4_v4, "Notify");
    g4_notify_fn n6 = (g4_notify_fn)g4_fn(&g4_v6, "Notify");
    int rc = 0;
    if (!n4 || !n6) return 100;
    if (n4(NULL, INVALID_SOCKET, NULL, NULL, 0x20000000u) != 0) rc |= 1;
    if (n6(NULL, INVALID_SOCKET, NULL, NULL, 0x20000000u) != 0) rc |= 2;
    if (n4(NULL, 0, NULL, NULL, 1) != 0) rc |= 4;
    return rc;
}
TEST(gap4_notify_arguments_other_than_the_event_are_ignored) { EXPECT_EQ(t_run_child("gap4_notify_ignores_context", "", 20000), 0); }
