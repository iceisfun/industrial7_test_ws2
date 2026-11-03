/* Socket-open contract of the Winsock helper DLLs (WSHOpenSocket2 / WSHOpenSocket) and the notification that
 * switches the transport device mode (WSHNotify). Measures: which (address family, socket type, protocol) triples
 * a helper accepts and how it normalises them, the flag and group restrictions, the exact error and the untouched
 * outputs on rejection, the context value handed out, the notification-event mask and the (empty) transport device
 * name; the Bluetooth helper's two transports with their device names; and, in child processes because the state is
 * process-wide, how WSHNotify with the stream, datagram and raw mode bits turns on the named transport devices. */
#include "anc.h"

typedef struct { int ty, pr; GROUP grp; DWORD flags; int want_ty, want_pr; } open_ok_row;
typedef struct { int ty, pr; GROUP grp; DWORD flags; } open_bad_row;

/* Accepted combinations of the two IP helpers. */
static const open_ok_row ip_ok[] = {
    { 0, 6, 0, 0, 1, 6 }, { 1, 0, 0, 0, 1, 6 }, { 1, 6, 0, 0, 1, 6 }, { 1, 6, 1, 0, 1, 6 }, { 1, 6, 2, 0, 1, 6 },
    { 1, 6, 0x7fffffff, 0, 1, 6 }, { 1, 6, 0, 1, 1, 6 }, { 1, 0, 0, 1, 1, 6 },
    { 0, 17, 0, 0, 2, 17 }, { 2, 0, 0, 0, 2, 17 }, { 2, 17, 0, 0, 2, 17 }, { 2, 17, 1, 0, 2, 17 },
    { 2, 17, 0, 1, 2, 17 }, { 2, 17, 0, 4, 2, 17 }, { 2, 17, 0, 0x10, 2, 17 }, { 2, 17, 0, 0x15, 2, 17 }, { 2, 0, 0, 0x10, 2, 17 }, { 0, 17, 0, 4, 2, 17 },
    { 3, 0, 0, 0, 3, 0 }, { 3, 0, 2, 0, 3, 0 }, { 3, 1, 0, 0, 3, 1 }, { 3, 3, 0, 0, 3, 3 }, { 3, 6, 0, 0, 3, 6 }, { 3, 17, 0, 0, 3, 17 },
    { 3, 58, 0, 0, 3, 58 }, { 3, 255, 0, 0, 3, 255 }, { 3, 255, 0, 4, 3, 255 }, { 3, 255, 0, 0x10, 3, 255 }, { 3, 255, 0, 0x15, 3, 255 },
    { 3, 100, 0, 1, 3, 100 }, { 3, 100, 2, 0, 3, 100 },
};
/* Rejected combinations (family is the helper's own). */
static const open_bad_row ip_bad[] = {
    { 0, 0, 0, 0 }, { 0, 1, 0, 0 }, { 0, 3, 0, 0 }, { 0, 255, 0, 0 }, { 1, 17, 0, 0 }, { 1, 1, 0, 0 }, { 1, 3, 0, 0 }, { 1, 256, 0, 0 }, { 1, 255, 0, 0 },
    { 2, 6, 0, 0 }, { 2, 1, 0, 0 }, { 2, 256, 0, 0 }, { 4, 6, 0, 0 }, { 4, 0, 0, 0 }, { 5, 6, 0, 0 }, { 5, 0, 0, 0 }, { 6, 6, 0, 0 }, { -1, 6, 0, 0 }, { 0x100, 6, 0, 0 },
    { 3, 256, 0, 0 }, { 3, 0x100, 0, 0 }, { 3, -1, 0, 0 }, { 3, 1000, 0, 0 },
    { 2, 17, 2, 0 },                                   /* constrained group on a datagram socket */
    { 2, 0, 2, 0 }, { 0, 17, 2, 0 },
    { 1, 6, 0, 2 }, { 1, 6, 0, 3 }, { 1, 6, 0, 4 }, { 1, 6, 0, 0x10 }, { 1, 6, 0, 0x80000000 }, { 1, 0, 0, 0x20 },
    { 2, 17, 0, 2 }, { 2, 17, 0, 8 }, { 2, 17, 0, 0x20 }, { 2, 17, 0, 0x80 }, { 2, 17, 0, 0x80000000 }, { 0, 17, 0, 0x40 },
    { 3, 255, 0, 2 }, { 3, 255, 0, 8 }, { 3, 255, 0, 0x20 }, { 3, 255, 0, 0x80 }, { 3, 0, 0, 0xffffffff },
};

static void open_row(const anc_wsh *h, const anc_hinfo *hi, int af, int ty, int pr, GROUP grp, DWORD fl, INT want_rc, int want_ty, int want_pr, const char *what) {
    int a = af, t = ty, p = pr; UNICODE_STRING us; PVOID ctx = (PVOID)(ULONG_PTR)1; DWORD ev = 0x77;
    memset(&us, 0xCD, sizeof us);
    INT r = h->OpenSocket2(&a, &t, &p, grp, fl, &us, &ctx, &ev);
    CHECKF(r == want_rc, "%s %s: rc %d want %d", hi->tag, what, r, want_rc);
    if (want_rc == 0) {
        CHECKF(a == hi->af && t == want_ty && p == want_pr, "%s %s: out (%d,%d,%d) want (%d,%d,%d)", hi->tag, what, a, t, p, hi->af, want_ty, want_pr);
        CHECKF(ctx != NULL && ctx != (PVOID)(ULONG_PTR)1, "%s %s: no context", hi->tag, what);
        anc_close_ctx(h, ctx);
    } else {
        CHECKF(a == af && t == ty && p == pr, "%s %s: in/out triple modified on failure (%d,%d,%d)", hi->tag, what, a, t, p);
        CHECKF(ctx == (PVOID)(ULONG_PTR)1, "%s %s: context written on failure", hi->tag, what);
        CHECKF(ev == 0x77, "%s %s: event mask written on failure", hi->tag, what);
        CHECKF(us.Length == 0xCDCD && us.MaximumLength == 0xCDCD, "%s %s: device name written on failure", hi->tag, what);
    }
}

static void ip_open_accept(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    for (size_t i = 0; i < ANC_N(ip_ok); i++) {
        char w[80]; sprintf(w, "ty=%d pr=%d grp=%lx fl=%lx", ip_ok[i].ty, ip_ok[i].pr, (DWORD)ip_ok[i].grp, ip_ok[i].flags);
        open_row(&h, hi, hi->af, ip_ok[i].ty, ip_ok[i].pr, ip_ok[i].grp, ip_ok[i].flags, 0, ip_ok[i].want_ty, ip_ok[i].want_pr, w);
    }
}
static void ip_open_reject(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    for (size_t i = 0; i < ANC_N(ip_bad); i++) {
        char w[80]; sprintf(w, "ty=%d pr=%d grp=%lx fl=%lx", ip_bad[i].ty, ip_bad[i].pr, (DWORD)ip_bad[i].grp, ip_bad[i].flags);
        open_row(&h, hi, hi->af, ip_bad[i].ty, ip_bad[i].pr, ip_bad[i].grp, ip_bad[i].flags, E_INVAL, 0, 0, w);
    }
}
TEST(open_ip_accepted_triples_wshtcpip) { ip_open_accept(&anc_tcp); }
TEST(open_ip_accepted_triples_wship6) { ip_open_accept(&anc_ip6); }
TEST(open_ip_rejected_triples_wshtcpip) { ip_open_reject(&anc_tcp); }
TEST(open_ip_rejected_triples_wship6) { ip_open_reject(&anc_ip6); }

/* A family the helper does not serve is WSAEINVAL here (the sockaddr classification says WSAEAFNOSUPPORT). */
static void open_wrong_family(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    static const int fams[] = { 0, 1, 2, 6, 17, 18, 21, 23, 24, 31, 32, 33, 0xffff, -1 };
    for (size_t i = 0; i < ANC_N(fams); i++) {
        if (fams[i] == hi->af) continue;
        char w[48]; sprintf(w, "family %d", fams[i]);
        open_row(&h, hi, fams[i], SOCK_STREAM, 6, 0, 0, E_INVAL, 0, 0, w);
        open_row(&h, hi, fams[i], SOCK_DGRAM, 17, 0, 0, E_INVAL, 0, 0, w);
        open_row(&h, hi, fams[i], SOCK_RAW, 0, 0, 0, E_INVAL, 0, 0, w);
    }
}
H3(open_foreign_family, open_wrong_family)

/* The returned context, the event mask and the transport name of a plain open. */
static void ip_open_outputs(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    static const struct { int ty, pr; } c[] = { { 1, 6 }, { 2, 17 }, { 3, 0 }, { 3, 255 } };
    for (size_t i = 0; i < ANC_N(c); i++) {
        int af = hi->af, ty = c[i].ty, pr = c[i].pr; UNICODE_STRING us; PVOID ctx = NULL; DWORD ev = 0x77;
        memset(&us, 0xCD, sizeof us);
        CHECK(h.OpenSocket2(&af, &ty, &pr, 0, 0, &us, &ctx, &ev) == 0);
        CHECKF(ev == 0xE0000000u, "%s ty=%d: event mask %lx", hi->tag, c[i].ty, ev);
        CHECKF(us.Length == 0 && us.MaximumLength == 0, "%s ty=%d: device name is not empty (%u/%u)", hi->tag, c[i].ty, us.Length, us.MaximumLength);
        CHECKF((ULONG_PTR)ctx == (ULONG_PTR)hi->af, "%s ty=%d: context %p is not the family value", hi->tag, c[i].ty, ctx);
        anc_close_ctx(&h, ctx);
    }
}
TEST(open_ip_outputs_wshtcpip) { ip_open_outputs(&anc_tcp); }
TEST(open_ip_outputs_wship6) { ip_open_outputs(&anc_ip6); }

/* WSHOpenSocket (the first-generation entry) uses flags 0 and group 0. */
static void open1(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    if (hi->af == 32) {
        int af = 32, ty = 1, pr = 0; UNICODE_STRING us; PVOID ctx = (PVOID)1; DWORD ev = 0x77; memset(&us, 0, sizeof us);
        CHECK(h.OpenSocket(&af, &ty, &pr, &us, &ctx, &ev) == E_INVAL);
        CHECK(ctx == (PVOID)1 && ev == 0x77);
        af = 32; ty = 1; pr = 3; ctx = NULL; ev = 0;
        CHECK(h.OpenSocket(&af, &ty, &pr, &us, &ctx, &ev) == 0); CHECK(ev == 0x8f && ctx != NULL && pr == 3);
        anc_close_ctx(&h, ctx);
        return;
    }
    struct { int ty, pr, wty, wpr; INT rc; } c[] = { { 1, 0, 1, 6, 0 }, { 2, 0, 2, 17, 0 }, { 3, 0, 3, 0, 0 }, { 0, 6, 1, 6, 0 }, { 1, 17, 1, 17, E_INVAL }, { 4, 6, 4, 6, E_INVAL } };
    for (size_t i = 0; i < ANC_N(c); i++) {
        int af = hi->af, ty = c[i].ty, pr = c[i].pr; UNICODE_STRING us; PVOID ctx = NULL; DWORD ev = 0; memset(&us, 0, sizeof us);
        INT r = h.OpenSocket(&af, &ty, &pr, &us, &ctx, &ev);
        CHECKF(r == c[i].rc, "%s open1 row %zu: rc %d", hi->tag, i, r);
        if (r == 0) { CHECK(af == hi->af && ty == c[i].wty && pr == c[i].wpr); CHECK(ev == 0xE0000000u); anc_close_ctx(&h, ctx); }
    }
}
H3(open_first_generation_entry, open1)

/* ---- Bluetooth helper ---- */
TEST(open_bth_transports_and_device_names) {
    anc_wsh h; if (!anc_begin(&h, &anc_bth)) return;
    static const struct { int ty, pr; int wpr; const WCHAR *dev; USHORT len, max; } c[] = {
        { 1, 256, 256, L"\\Device\\BthTdi", 28, 30 }, { 0, 256, 256, L"\\Device\\BthTdi", 28, 30 },
        { 1, 3, 3, L"\\Device\\BTHMS_RFCOMM", 40, 42 }, { 0, 3, 3, L"\\Device\\BTHMS_RFCOMM", 40, 42 } };
    PVOID seen[ANC_N(c)];
    for (size_t i = 0; i < ANC_N(c); i++) {
        int af = 32, ty = c[i].ty, pr = c[i].pr; UNICODE_STRING us; PVOID ctx = NULL; DWORD ev = 0;
        memset(&us, 0, sizeof us);
        INT r = h.OpenSocket2(&af, &ty, &pr, 0, 0, &us, &ctx, &ev);
        CHECKF(r == 0, "row %zu rc %d", i, r);
        if (r) { seen[i] = NULL; continue; }
        CHECK(af == 32); CHECK(ty == 1); CHECK(pr == c[i].wpr); CHECK(ev == 0x8f); CHECK(ctx != NULL);
        CHECKF(us.Length == c[i].len && us.MaximumLength == c[i].max, "row %zu name lengths %u/%u", i, us.Length, us.MaximumLength);
        CHECK(us.Buffer != NULL && us.Length == c[i].len && !memcmp(us.Buffer, c[i].dev, c[i].len));
        seen[i] = ctx;
    }
    for (size_t i = 0; i < ANC_N(c); i++) for (size_t j = i + 1; j < ANC_N(c); j++) CHECKF(seen[i] != seen[j] || !seen[i], "rows %zu and %zu share a context", i, j);
    for (size_t i = 0; i < ANC_N(c); i++) anc_close_ctx(&h, seen[i]);
}

TEST(open_bth_rejected_combinations) {
    anc_wsh h; if (!anc_begin(&h, &anc_bth)) return;
    static const struct { int ty, pr; GROUP g; DWORD fl; } bad[] = {
        { 1, 6, 0, 0 }, { 1, 0, 0, 0 }, { 0, 0, 0, 0 }, { 0, 17, 0, 0 }, { 1, 17, 0, 0 }, { 2, 17, 0, 0 }, { 2, 256, 0, 0 }, { 2, 3, 0, 0 }, { 3, 0, 0, 0 },
        { 3, 255, 0, 0 }, { 3, 256, 0, 0 }, { 4, 3, 0, 0 }, { 5, 256, 0, 0 }, { 1, 1, 0, 0 }, { 1, 255, 0, 0 }, { 1, 257, 0, 0 }, { 1, 2, 0, 0 }, { 1, 4, 0, 0 } };
    for (size_t i = 0; i < ANC_N(bad); i++) {
        char w[64]; sprintf(w, "ty=%d pr=%d", bad[i].ty, bad[i].pr);
        open_row(&h, &anc_bth, 32, bad[i].ty, bad[i].pr, bad[i].g, bad[i].fl, E_INVAL, 0, 0, w);
    }
    static const int fams[] = { 0, 2, 6, 17, 23, 31, 33 };
    for (size_t i = 0; i < ANC_N(fams); i++) { char w[32]; sprintf(w, "family %d", fams[i]); open_row(&h, &anc_bth, fams[i], 1, 3, 0, 0, E_INVAL, 0, 0, w); open_row(&h, &anc_bth, fams[i], 1, 256, 0, 0, E_INVAL, 0, 0, w); }
}

/* ---- notification: transport device mode (process-wide state, so each case runs in its own child) ---- */
CHILD(open_mode) {
    const char *dll = argv[1]; int mode = atoi(argv[2]);
    anc_hinfo hi = { dll, !strcmp(dll, "wship6.dll") ? AF_INET6 : AF_INET, "child" };
    anc_wsh h; int bad = 0;
    if (!anc_load_wsh(&h, dll)) return 90;
    static const DWORD bits[] = { 0, 0x80000000u, 0x40000000u, 0x20000000u, 0 };
    static const WCHAR *tcp_n[] = { L"\\Device\\Tcp", L"\\Device\\Udp", L"\\Device\\RawIp\\" };
    static const WCHAR *ip6_n[] = { L"\\Device\\Tcp6", L"\\Device\\Udp6", L"\\Device\\RawIp6\\" };
    const WCHAR **names = hi.af == AF_INET6 ? ip6_n : tcp_n;
    if (mode == 4) {   /* ordinary events must not switch anything on */
        static const DWORD evs[] = { 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x100, 0x80, 0x0fffffff };
        for (size_t i = 0; i < ANC_N(evs); i++) if (h.Notify((PVOID)(ULONG_PTR)hi.af, INVALID_SOCKET, NULL, NULL, evs[i]) != 0) bad |= 1;
    } else if (bits[mode]) {
        if (h.Notify((PVOID)(ULONG_PTR)hi.af, INVALID_SOCKET, NULL, NULL, bits[mode]) != 0) bad |= 2;
    }
    for (int t = 1; t <= 3; t++) {
        int af = hi.af, ty = t, pr = t == 1 ? 6 : (t == 2 ? 17 : 0); UNICODE_STRING us; PVOID ctx = NULL; DWORD ev = 0xdead;
        memset(&us, 0, sizeof us);
        if (h.OpenSocket2(&af, &ty, &pr, 0, 0, &us, &ctx, &ev) != 0) { bad |= 4; continue; }
        int switched = (mode >= 1 && mode <= 3 && t == mode);
        if (!switched) {
            if (ev != 0xE0000000u || us.Length != 0 || us.MaximumLength != 0) bad |= 8;
        } else {
            WCHAR want[64]; wcscpy(want, names[t - 1]);
            if (t == 3) wcscat(want, L"0");
            size_t wl = wcslen(want) * 2;
            if (ev != 0 || us.Length != wl || us.Buffer == NULL || memcmp(us.Buffer, want, wl) != 0) bad |= 16;
            if (us.MaximumLength < us.Length + 2) bad |= 32;
        }
        anc_close_ctx(&h, ctx);
    }
    if (mode == 3) {   /* raw mode appends the protocol number */
        int af = hi.af, ty = 3, pr = 255; UNICODE_STRING us; PVOID ctx = NULL; DWORD ev = 0; memset(&us, 0, sizeof us);
        if (h.OpenSocket2(&af, &ty, &pr, 0, 0, &us, &ctx, &ev) != 0) bad |= 64;
        else {
            WCHAR want[64]; wcscpy(want, names[2]); wcscat(want, L"255");
            if (us.Length != wcslen(want) * 2 || memcmp(us.Buffer, want, us.Length) != 0) bad |= 128;
            anc_close_ctx(&h, ctx);
        }
    }
    return bad;
}

static void run_mode(const char *dll, int mode) {
    char a[64];
    if (!t_module(dll)) { t_skip("%s is not present on this system", dll); return; }
    sprintf(a, "%s %d", dll, mode);
    DWORD rc = t_run_child("open_mode", a, 30000);
    CHECKF(rc == 0, "%s mode %d: child returned 0x%lx", dll, mode, rc);
}
TEST(notify_default_mode_names_no_transport_device_wshtcpip) { run_mode("wshtcpip.dll", 0); }
TEST(notify_default_mode_names_no_transport_device_wship6) { run_mode("wship6.dll", 0); }
TEST(notify_stream_bit_enables_tcp_device_wshtcpip) { run_mode("wshtcpip.dll", 1); }
TEST(notify_stream_bit_enables_tcp_device_wship6) { run_mode("wship6.dll", 1); }
TEST(notify_datagram_bit_enables_udp_device_wshtcpip) { run_mode("wshtcpip.dll", 2); }
TEST(notify_datagram_bit_enables_udp_device_wship6) { run_mode("wship6.dll", 2); }
TEST(notify_raw_bit_enables_rawip_device_wshtcpip) { run_mode("wshtcpip.dll", 3); }
TEST(notify_raw_bit_enables_rawip_device_wship6) { run_mode("wship6.dll", 3); }
TEST(notify_ordinary_events_leave_modes_off_wshtcpip) { run_mode("wshtcpip.dll", 4); }
TEST(notify_ordinary_events_leave_modes_off_wship6) { run_mode("wship6.dll", 4); }

/* Notification events return 0 whatever the state, with an invalid socket and no TDI handles. */
static void notify_returns_zero(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    PVOID ctx = anc_open_ctx(&h, hi, hi->af == 32 ? 1 : 1, hi->af == 32 ? 3 : 6);
    if (!ctx) { t_skip("could not open a helper context"); return; }
    static const DWORD evs[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x100 };
    for (size_t i = 0; i < ANC_N(evs); i++) {
        if (hi->af == 32 && (evs[i] == 1 || evs[i] == 2 || evs[i] == 4 || evs[i] == 8)) continue;   /* these reach the transport */
        CHECKF(h.Notify(ctx, INVALID_SOCKET, NULL, NULL, evs[i]) == 0, "%s event %lx", hi->tag, evs[i]);
    }
    CHECKF(h.Notify(ctx, INVALID_SOCKET, NULL, NULL, 0x80) == 0, "%s close", hi->tag);
}
H3(notify_events_return_success, notify_returns_zero)
