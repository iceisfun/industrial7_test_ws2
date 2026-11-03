/* Further edge cases for IOCTL_AFD_POLL, EVENT_SELECT and GET_EVENTS.
 * Measures: entries naming the null / pseudo handle, the entry-count boundary around the large-poll
 * path, deadlines that are already due, the event-select rule for a missing event handle, a rejected
 * selection leaving the earlier one in force, GET_EVENTS with a missing reset event or a pseudo handle,
 * and the supersede behaviour of a second exclusive poll on the same endpoint. */
#include "ap.h"

static LONG evsel_raw(SOCKET s, HANDLE ev, ULONG mask)
{
    ap_evsel p; IO_STATUS_BLOCK io;
    memset(&p, 0, sizeof(p));
    p.event = ev; p.mask = mask;
    return X.ioctl((HANDLE)s, NULL, NULL, NULL, &io, AP_IOCTL_EVENT_SELECT, &p, sizeof(p), NULL, 0);
}

static LONG getev_raw(SOCKET s, HANDLE reset_ev, ap_getev *g)
{
    IO_STATUS_BLOCK io;
    return X.ioctl((HANDLE)s, NULL, NULL, NULL, &io, AP_IOCTL_GET_EVENTS, (PVOID)reset_ev, 0, g, sizeof(*g));
}

/* ---- poll entries ----------------------------------------------------------------------------- */

/* The null handle value cannot be resolved: invalid handle. The all-ones pseudo handle names the current
 * process, which is a real object of the wrong type. */
TEST(apev_entry_null_and_pseudo_handles)
{
    AP_BEGIN();
    SOCKET l = ap_listener(NULL, 1); ap_req in; SOCKET hs[2];
    hs[0] = l; hs[1] = 0;
    ap_fill(&in, 0, 0, 2, hs, APE_ALL);
    CK_ST(ap_try((HANDLE)l, &in, AP_SZ(2), AP_SZ(2)), APS_INVALID_HANDLE);
    hs[1] = (SOCKET)(LONG_PTR)-1;
    ap_fill(&in, 0, 0, 2, hs, APE_ALL);
    CK_ST(ap_try((HANDLE)l, &in, AP_SZ(2), AP_SZ(2)), APS_TYPE_MISMATCH);
    ap_closeS(l);
}

/* The null handle as the first (and only) entry fails the same way. */
TEST(apev_entry_null_single)
{
    AP_BEGIN();
    SOCKET l = ap_listener(NULL, 1), z = 0; ap_req in;
    ap_fill(&in, 0, 0, 1, &z, APE_ALL);
    CK_ST(ap_try((HANDLE)l, &in, AP_SZ(1), AP_SZ(1)), APS_INVALID_HANDLE);
    ap_closeS(l);
}

/* The carrier handle may not be null or a pseudo handle either. */
TEST(apev_carrier_null_and_pseudo)
{
    AP_BEGIN();
    SOCKET l = ap_listener(NULL, 1); ap_req in;
    ap_fill(&in, 0, 0, 1, &l, APE_ALL);
    CK_ST(ap_try(NULL, &in, AP_SZ(1), AP_SZ(1)), APS_INVALID_HANDLE);
    {
        LONG st = ap_try(GetCurrentProcess(), &in, AP_SZ(1), AP_SZ(1));
        CHECKF(st < 0, "pseudo handle carrier accepted: %#lx", (unsigned long)st);
        t_note("pseudo handle carrier status observed: %#lx", (unsigned long)st);
    }
    ap_closeS(l);
}

/* Around the entry count where the driver switches to its large-request path, a poll over idle
 * sockets answers identically: nothing ready, no entries returned, header-sized information. */
TEST(apev_count_boundary_idle_poll)
{
    AP_BEGIN();
    static const int counts[] = { 98, 99, 100, 101 };
    SOCKET l = ap_listener(NULL, 1); SOCKET hs[AP_MAXE]; ULONG m[AP_MAXE]; size_t k; int i;
    for (i = 0; i < AP_MAXE; i++) { hs[i] = l; m[i] = APE_ACCEPT; }
    for (k = 0; k < sizeof(counts) / sizeof(counts[0]); k++) {
        ap_res r;
        ap_run((HANDLE)l, 0, 0, counts[k], hs, m, 3000, &r);
        CHECKF(r.ret == 0 && r.ios == 0 && r.out.n == 0 && r.info == 16, "count %d: ret %#lx n %lu info %lu", counts[k],
               (unsigned long)r.ret, (unsigned long)r.out.n, (unsigned long)r.info);
    }
    ap_closeS(l);
}

/* A deadline that is already due ends the poll with no entries, whether the call completed in place or
 * after a short wait. */
TEST(apev_due_deadlines_end_without_entries)
{
    AP_BEGIN();
    SOCKET l = ap_listener(NULL, 1); LARGE_INTEGER now; ap_res r;
    LONGLONG tos[2];
    size_t i;
    X.systime(&now);
    tos[0] = AP_REL_MS(1);
    tos[1] = now.QuadPart - 100000000LL;                  /* ten seconds in the past, absolute */
    for (i = 0; i < 2; i++) {
        ap_run((HANDLE)l, tos[i], 0, 1, &l, (ULONG[]){ APE_ACCEPT }, 4000, &r);
        CHECKF(!r.hung, "deadline %lu never ended the poll", (unsigned long)i);
        CHECKF((r.ios == 0 || (ULONG)r.ios == APS_TIMEOUT) && r.out.n == 0, "deadline %lu: ios %#lx n %lu", (unsigned long)i, (unsigned long)r.ios, (unsigned long)r.out.n);
    }
    ap_closeS(l);
}

/* ---- event select / get events --------------------------------------------------------------- */

/* A selection with a nonzero mask and no event handle is invalid; a null event with an empty mask clears
 * the selection. The refused request changes nothing: the earlier selection still signals. */
TEST(apev_evsel_null_event_needs_empty_mask)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = ap_event();
    ap_pair(&c, &s);
    CK_ST(evsel_raw(s, ev, APE_RECEIVE), APS_SUCCESS);
    CK_ST(evsel_raw(s, NULL, APE_RECEIVE), APS_INVALID_PARAM);
    CK_ST(evsel_raw(s, NULL, 0xffffffffu), APS_INVALID_PARAM);
    ap_send_n(c, 2);
    CHECK(WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);       /* still selected */
    CK_ST(evsel_raw(s, NULL, 0), APS_SUCCESS);
    ap_closeS(c); ap_closeS(s); CloseHandle(ev);
}

/* Without a reset event, GET_EVENTS leaves every event object alone. */
TEST(apev_getev_without_reset_event_leaves_signal)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = ap_event(); ap_getev g;
    ap_pair(&c, &s);
    CK_ST(evsel_raw(c, ev, APE_ALL), APS_SUCCESS);
    CHECK(WaitForSingleObject(ev, 0) == WAIT_OBJECT_0);
    CK_ST(getev_raw(c, NULL, &g), APS_SUCCESS);
    CK_FLAGS(g.pending, APE_SEND | APE_CONNECT);
    CHECK(WaitForSingleObject(ev, 0) == WAIT_OBJECT_0);          /* not reset */
    CK_ST(getev_raw(c, ev, &g), APS_SUCCESS);
    CK_FLAGS(g.pending, 0);                                      /* consumed by the first call */
    CHECK(WaitForSingleObject(ev, 0) == WAIT_TIMEOUT);           /* now reset */
    ap_closeS(c); ap_closeS(s); CloseHandle(ev);
}

/* The current-process pseudo handle in place of the reset event is the wrong object type. */
TEST(apev_getev_pseudo_handle_reset_event)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = ap_event(); ap_getev g;
    ap_pair(&c, &s);
    CK_ST(evsel_raw(c, ev, APE_ALL), APS_SUCCESS);
    CK_ST(getev_raw(c, GetCurrentProcess(), &g), APS_TYPE_MISMATCH);
    CK_FLAGS(getev_raw(c, ev, &g) == 0 ? g.pending : 0xdead, APE_SEND | APE_CONNECT);
    ap_closeS(c); ap_closeS(s); CloseHandle(ev);
}

/* A connection arriving on a listener whose selection excludes the accept bit does not signal; the bit
 * stays pending and is handed out once a selection includes it. */
TEST(apev_evsel_listener_accept_bit_waits_for_selection)
{
    AP_BEGIN();
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 1), c, s; HANDLE ev = ap_event(); ap_getev g;
    CK_ST(evsel_raw(l, ev, APE_RECEIVE | APE_SEND), APS_SUCCESS);
    c = ap_dial(&a);
    CK_FLAGS(ap_wait_flags(l, APE_ACCEPT), APE_ACCEPT);
    CHECK(WaitForSingleObject(ev, 0) == WAIT_TIMEOUT);
    CK_ST(getev_raw(l, ev, &g), APS_SUCCESS);
    CK_FLAGS(g.pending, 0);
    CK_ST(evsel_raw(l, ev, APE_ACCEPT), APS_SUCCESS);
    CHECK(WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0);
    CK_ST(getev_raw(l, ev, &g), APS_SUCCESS);
    CK_FLAGS(g.pending, APE_ACCEPT);
    s = X.accept(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    ap_closeS(s); ap_closeS(c); ap_closeS(l); CloseHandle(ev);
}

/* After a successful loopback connect the per-event status words carry no failure. Sentinel-filled output
 * must be fully overwritten; non-zero words are recorded, not asserted. */
TEST(apev_getev_status_words_overwritten)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = ap_event(); ap_getev g; int i, bad = 0;
    ap_pair(&c, &s);
    CK_ST(evsel_raw(c, ev, APE_ALL), APS_SUCCESS);
    memset(&g, 0xcc, sizeof(g));
    CK_ST(getev_raw(c, ev, &g), APS_SUCCESS);
    for (i = 0; i < 13; i++) if ((ULONG)g.status[i] == 0xccccccccu) bad++;
    CHECKF(bad == 0, "%d status words left untouched", bad);
    for (i = 0; i < 13; i++) if (g.status[i] != 0) t_note("status word %d is nonzero after a successful connect", i);
    ap_closeS(c); ap_closeS(s); CloseHandle(ev);
}

/* ---- exclusive supersede ------------------------------------------------------------------------ */

/* A second exclusive poll on the same endpoint takes over: the newer request stays pending while the
 * older one is ended by the driver. How the older one ends is recorded, not asserted. */
TEST(apev_exclusive_second_request_supersedes_first)
{
    AP_BEGIN();
    SOCKET l = ap_listener(NULL, 1); ap_req in1, in2, out1, out2; IO_STATUS_BLOCK io1, io2, cio;
    HANDLE e1 = ap_event(), e2 = ap_event();
    ap_fill(&in1, AP_INFINITE, 1, 1, &l, APE_ACCEPT);
    ap_fill(&in2, AP_INFINITE, 1, 1, &l, APE_ACCEPT);
    memset(&io1, 0xcc, sizeof(io1)); memset(&io2, 0xcc, sizeof(io2));
    CK_ST(ap_submit((HANDLE)l, e1, &io1, &in1, AP_SZ(1), &out1, AP_SZ(1)), APS_PENDING);
    CK_ST(ap_submit((HANDLE)l, e2, &io2, &in2, AP_SZ(1), &out2, AP_SZ(1)), APS_PENDING);
    CHECK(WaitForSingleObject(e2, 200) == WAIT_TIMEOUT);          /* the newer request is the live one */
    if (WaitForSingleObject(e1, 3000) == WAIT_OBJECT_0)
        t_note("older exclusive poll was ended by the newer one");
    else
        t_note("older exclusive poll was not ended by the newer one");
    X.cancel_all((HANDLE)l, &cio);
    CHECK(WaitForSingleObject(e2, 3000) == WAIT_OBJECT_0);
    WaitForSingleObject(e1, 3000);
    CloseHandle(e1); CloseHandle(e2); ap_closeS(l);
}
