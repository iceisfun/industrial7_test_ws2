/* IOCTL_AFD_EVENT_SELECT (0x12087) and IOCTL_AFD_GET_EVENTS (0x1208b) as a state machine, beyond the basic
 * shape checks done elsewhere.
 * Measures: the event-select input size and alignment rules, the status for event handles of the wrong
 * type / closed / lacking modify access, how the selected mask gates both signalling and the pending
 * bits returned by GET_EVENTS (bits outside the mask stay pending), that GET_EVENTS resets the event
 * handle it is given even when nothing is pending, that a failed call consumes nothing, event re-selection
 * and shared events, and the independence of AFD poll from the event-select bookkeeping. */
#include "ap.h"

static LONG evsel(SOCKET s, HANDLE ev, ULONG mask, IO_STATUS_BLOCK *io)
{
    ap_evsel p;
    memset(&p, 0, sizeof(p));
    p.event = ev; p.mask = mask;
    return X.ioctl((HANDLE)s, NULL, NULL, NULL, io, AP_IOCTL_EVENT_SELECT, &p, sizeof(p), NULL, 0);
}

/* GET_EVENTS: reset_ev is passed through the input pointer (length 0), NULL for none. */
static LONG getev(SOCKET s, HANDLE reset_ev, ap_getev *g, ULONG outlen, IO_STATUS_BLOCK *io)
{
    return X.ioctl((HANDLE)s, NULL, NULL, NULL, io, AP_IOCTL_GET_EVENTS, (PVOID)reset_ev, 0, g, outlen);
}

static ULONG take(SOCKET s, HANDLE reset_ev)
{
    ap_getev g; IO_STATUS_BLOCK io;
    memset(&g, 0xcc, sizeof(g));
    CK_ST(getev(s, reset_ev, &g, sizeof(g), &io), APS_SUCCESS);
    return g.pending;
}

static int signalled(HANDLE ev, DWORD ms) { return WaitForSingleObject(ev, ms) == WAIT_OBJECT_0; }

/* ---- EVENT_SELECT input rules -------------------------------------------------------- */

TEST(apev_evsel_input_size_boundaries)
{
    AP_BEGIN();
    static const ULONG sizes[] = { 0, 1, 8, 15 };
    SOCKET c, s; HANDLE ev = ap_event(); ap_evsel p; IO_STATUS_BLOCK io; size_t i;
    ap_pair(&c, &s);
    memset(&p, 0, sizeof(p)); p.event = ev; p.mask = APE_CONNECT;
    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        LONG st = X.ioctl((HANDLE)c, NULL, NULL, NULL, &io, AP_IOCTL_EVENT_SELECT, &p, sizes[i], NULL, 0);
        CHECKF((ULONG)st == APS_INVALID_PARAM, "input length %lu: got %#lx", (unsigned long)sizes[i], (unsigned long)st);
    }
    CK_ST(X.ioctl((HANDLE)c, NULL, NULL, NULL, &io, AP_IOCTL_EVENT_SELECT, &p, 16, NULL, 0), APS_SUCCESS);
    CK_ST(X.ioctl((HANDLE)c, NULL, NULL, NULL, &io, AP_IOCTL_EVENT_SELECT, &p, 17, NULL, 0), APS_SUCCESS);
    CK_ST(X.ioctl((HANDLE)c, NULL, NULL, NULL, &io, AP_IOCTL_EVENT_SELECT, &p, 64, NULL, 0), APS_SUCCESS);
    CloseHandle(ev); ap_closeS(c); ap_closeS(s);
}

/* The mask word is not validated: undefined bits are accepted and simply never match. */
TEST(apev_evsel_undefined_mask_bits_accepted)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = ap_event(); IO_STATUS_BLOCK io;
    ap_pair(&c, &s);
    CK_ST(evsel(c, ev, 0x7fffe000u, &io), APS_SUCCESS);
    CHECK(!signalled(ev, 0));
    CK_FLAGS(take(c, NULL), 0);
    CloseHandle(ev); ap_closeS(c); ap_closeS(s);
}

TEST(apev_evsel_event_handle_type_and_access)
{
    AP_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; HANDLE mtx, sem, file, ro = NULL, named, dead; char path[MAX_PATH]; WCHAR nm[64];
    ap_pair(&c, &s);
    mtx = CreateMutexW(NULL, FALSE, NULL);
    sem = CreateSemaphoreW(NULL, 0, 1, NULL);
    t_tmpfile(path, sizeof(path), "apev_evsel.tmp");
    file = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    wsprintfW(nm, L"apev_evsel_%lu", GetCurrentProcessId());
    named = CreateEventW(NULL, TRUE, FALSE, nm);
    ro = OpenEventW(SYNCHRONIZE, FALSE, nm);                  /* may wait but may not signal */
    dead = CreateEventW(NULL, TRUE, FALSE, NULL);
    CloseHandle(dead);
    CK_ST(evsel(c, mtx, APE_CONNECT, &io), APS_TYPE_MISMATCH);
    CK_ST(evsel(c, sem, APE_CONNECT, &io), APS_TYPE_MISMATCH);
    CK_ST(evsel(c, file, APE_CONNECT, &io), APS_TYPE_MISMATCH);
    CK_ST(evsel(c, GetCurrentProcess(), APE_CONNECT, &io), APS_TYPE_MISMATCH);
    if (ro) CK_ST(evsel(c, ro, APE_CONNECT, &io), APS_ACCESS_DENIED);
    else t_note("could not open the event with read-only access");
    CK_ST(evsel(c, dead, APE_CONNECT, &io), APS_INVALID_HANDLE);
    /* none of the failed selections registered anything */
    CK_FLAGS(take(c, NULL), 0);
    CloseHandle(mtx); CloseHandle(sem); CloseHandle(file); CloseHandle(named); if (ro) CloseHandle(ro);
    ap_closeS(c); ap_closeS(s);
}

/* The input block is read in place and must be 4-byte aligned. */
TEST(apev_evsel_misaligned_input_is_refused)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = ap_event(); IO_STATUS_BLOCK io; static UCHAR raw[64] __attribute__((aligned(8)));
    LONG st;
    ap_pair(&c, &s);
    memset(raw, 0, sizeof(raw));
    { ap_evsel p; memset(&p, 0, sizeof(p)); p.event = ev; p.mask = APE_CONNECT; memcpy(raw + 1, &p, sizeof(p)); }
    st = X.ioctl((HANDLE)c, NULL, NULL, NULL, &io, AP_IOCTL_EVENT_SELECT, raw + 1, 16, NULL, 0);
    CHECKF((ULONG)st != APS_SUCCESS, "misaligned input accepted");
    t_note("misaligned event-select input status observed: %#lx", (unsigned long)st);
    CHECK(!signalled(ev, 0));
    CloseHandle(ev); ap_closeS(c); ap_closeS(s);
}

/* ---- the pending set: mask gates both signalling and consumption -------------------------- */

/* The pending bits exist whether or not anyone selected them. An empty selection neither signals nor
 * reports; selecting a bit later signals at once and hands out exactly that bit, leaving the others. */
TEST(apev_evsel_pending_bits_wait_for_selection)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = ap_event(); IO_STATUS_BLOCK io;
    ap_pair(&c, &s);
    CK_ST(evsel(c, ev, 0, &io), APS_SUCCESS);
    CHECK(!signalled(ev, 0));
    CK_FLAGS(take(c, NULL), 0);                                  /* nothing selected, nothing consumed */
    CK_ST(evsel(c, ev, APE_CONNECT, &io), APS_SUCCESS);
    CHECK(signalled(ev, 0));                                     /* connect bit was already pending */
    CK_FLAGS(take(c, ev), APE_CONNECT);
    CHECK(!signalled(ev, 0));
    CK_ST(evsel(c, ev, APE_SEND, &io), APS_SUCCESS);
    CHECK(signalled(ev, 0));                                     /* the send bit was left behind */
    CK_FLAGS(take(c, ev), APE_SEND);
    CK_ST(evsel(c, ev, APE_ALL, &io), APS_SUCCESS);
    CHECK(!signalled(ev, 0));                                    /* both consumed */
    CK_FLAGS(take(c, NULL), 0);
    CloseHandle(ev); ap_closeS(c); ap_closeS(s);
}

TEST(apev_getev_without_selection_reports_nothing_and_keeps_state)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = ap_event(); IO_STATUS_BLOCK io;
    ap_pair(&c, &s);
    CK_FLAGS(take(c, NULL), 0);
    CK_FLAGS(take(c, NULL), 0);
    CK_ST(evsel(c, ev, APE_ALL, &io), APS_SUCCESS);
    CHECK(signalled(ev, 0));
    CK_FLAGS(take(c, ev), APE_SEND | APE_CONNECT);
    ap_closeS(c); ap_closeS(s); CloseHandle(ev);
}

/* A selection that leaves out the bit that is about to be raised stays quiet until that bit is selected. */
TEST(apev_evsel_mask_filters_new_events)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = ap_event(); IO_STATUS_BLOCK io;
    ap_pair(&c, &s);
    CK_ST(evsel(s, ev, APE_RECEIVE, &io), APS_SUCCESS);
    CHECK(!signalled(ev, 0));                                    /* only the send bit is pending on s */
    ap_send_n(c, 3);
    CK_FLAGS(ap_wait_flags(s, APE_RECEIVE), APE_RECEIVE);
    CHECK(signalled(ev, 3000));
    CK_FLAGS(take(s, ev), APE_RECEIVE);
    CHECK(!signalled(ev, 0));
    ap_closeS(c); ap_closeS(s); CloseHandle(ev);
}

TEST(apev_evsel_accept_event_on_listener)
{
    AP_BEGIN();
    struct sockaddr_in a; SOCKET l = ap_listener(&a, 1), c, s; HANDLE ev = ap_event(); IO_STATUS_BLOCK io;
    CK_ST(evsel(l, ev, APE_ACCEPT, &io), APS_SUCCESS);
    CHECK(!signalled(ev, 0));
    c = ap_dial(&a);
    CHECK(signalled(ev, 3000));
    CK_FLAGS(take(l, ev), APE_ACCEPT);
    CHECK(!signalled(ev, 0));
    s = X.accept(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    ap_closeS(s); ap_closeS(c); ap_closeS(l); CloseHandle(ev);
}

TEST(apev_evsel_datagram_arrival_and_hangup_events)
{
    AP_BEGIN();
    struct sockaddr_in a; int n = sizeof(a); SOCKET r = ap_sock(SOCK_DGRAM), w = ap_sock(SOCK_DGRAM); HANDLE ev = ap_event(); IO_STATUS_BLOCK io;
    memset(&a, 0, sizeof(a)); a.sin_family = AF_INET; a.sin_addr.s_addr = 0x0100007Fu;
    CHECK(X.bind(r, (struct sockaddr *)&a, sizeof(a)) == 0);
    CHECK(X.getsockname(r, (struct sockaddr *)&a, &n) == 0);
    CK_ST(evsel(r, ev, APE_RECEIVE, &io), APS_SUCCESS);
    CHECK(!signalled(ev, 0));
    CHECK(X.sendto(w, "dg", 2, 0, (struct sockaddr *)&a, sizeof(a)) == 2);
    CHECK(signalled(ev, 3000));
    CK_FLAGS(take(r, ev), APE_RECEIVE);
    ap_closeS(r); ap_closeS(w); CloseHandle(ev);
}

/* A new occurrence raises the event again after the previous one was fetched and the event reset. */
TEST(apev_evsel_successive_events_resignal)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = ap_event(); IO_STATUS_BLOCK io; ULONG got; char buf[8];
    ap_pair(&c, &s);
    CK_ST(evsel(s, ev, APE_RECEIVE | APE_DISCONNECT, &io), APS_SUCCESS);
    CHECK(!signalled(ev, 0));
    ap_send_n(c, 3);
    CHECK(signalled(ev, 3000));
    CK_FLAGS(take(s, ev), APE_RECEIVE);
    CHECK(X.recv(s, buf, sizeof(buf), 0) == 3);
    CHECK(X.shutdown(c, SD_SEND) == 0);
    CHECK(signalled(ev, 3000));
    got = take(s, ev);
    CHECKF((got & APE_DISCONNECT) != 0, "hang-up not delivered, got %#lx", (unsigned long)got);
    if (got != APE_DISCONNECT) t_note("hang-up delivered together with %#lx", (unsigned long)(got & ~APE_DISCONNECT));
    ap_closeS(c); ap_closeS(s); CloseHandle(ev);
}

/* ---- re-selection and shared events ---------------------------------------------------------- */

TEST(apev_evsel_reselect_replaces_event)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE e1 = ap_event(), e2 = ap_event(); IO_STATUS_BLOCK io;
    ap_pair(&c, &s);
    CK_ST(evsel(s, e1, APE_RECEIVE, &io), APS_SUCCESS);
    CK_ST(evsel(s, e2, APE_RECEIVE, &io), APS_SUCCESS);
    ap_send_n(c, 1);
    CHECK(signalled(e2, 3000));
    CHECK(!signalled(e1, 200));
    CK_FLAGS(take(s, e2), APE_RECEIVE);
    ap_closeS(c); ap_closeS(s); CloseHandle(e1); CloseHandle(e2);
}

TEST(apev_evsel_deselect_stops_signalling)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = ap_event(); IO_STATUS_BLOCK io;
    ap_pair(&c, &s);
    CK_ST(evsel(s, ev, APE_RECEIVE, &io), APS_SUCCESS);
    CK_ST(evsel(s, NULL, 0, &io), APS_SUCCESS);
    ap_send_n(c, 1);
    CK_FLAGS(ap_wait_flags(s, APE_RECEIVE), APE_RECEIVE);        /* the data has certainly arrived */
    CHECK(!signalled(ev, 0));
    ap_closeS(c); ap_closeS(s); CloseHandle(ev);
}

/* One event may serve several sockets. Fetching the events of one socket resets the shared event even
 * though that socket had nothing; the other socket's pending bit survives the reset. */
TEST(apev_getev_reset_is_per_event_not_per_socket)
{
    AP_BEGIN();
    SOCKET c1, s1, c2, s2; HANDLE ev = ap_event(); IO_STATUS_BLOCK io;
    ap_pair(&c1, &s1); ap_pair(&c2, &s2);
    CK_ST(evsel(s1, ev, APE_RECEIVE, &io), APS_SUCCESS);
    CK_ST(evsel(s2, ev, APE_RECEIVE, &io), APS_SUCCESS);
    ap_send_n(c2, 2);
    CHECK(signalled(ev, 3000));
    CK_FLAGS(take(s1, ev), 0);
    CHECK(!signalled(ev, 0));
    CK_FLAGS(take(s2, ev), APE_RECEIVE);
    ap_closeS(c1); ap_closeS(s1); ap_closeS(c2); ap_closeS(s2); CloseHandle(ev);
}

/* ---- GET_EVENTS output and failure handling -------------------------------------------------------- */

TEST(apev_getev_larger_buffer_writes_exactly_0x38)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = ap_event(); IO_STATUS_BLOCK io; UCHAR big[0x60]; IO_STATUS_BLOCK sel_io; size_t i;
    ap_pair(&c, &s);
    CK_ST(evsel(c, ev, APE_ALL, &sel_io), APS_SUCCESS);
    memset(big, 0xcc, sizeof(big)); memset(&io, 0xcc, sizeof(io));
    CK_ST(X.ioctl((HANDLE)c, NULL, NULL, NULL, &io, AP_IOCTL_GET_EVENTS, NULL, 0, big, sizeof(big)), APS_SUCCESS);
    CK_ST(io.Status, APS_SUCCESS);
    CHECK(io.Information == 0x38);
    CK_FLAGS(((ap_getev *)big)->pending, APE_SEND | APE_CONNECT);
    for (i = 0x38; i < sizeof(big); i++) if (big[i] != 0xcc) { CHECKF(0, "byte %#x was written", (unsigned)i); break; }
    CloseHandle(ev); ap_closeS(c); ap_closeS(s);
}

/* An output block below 0x38 bytes is refused before anything is touched. */
TEST(apev_getev_short_output_consumes_nothing)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = ap_event(); IO_STATUS_BLOCK io; ap_getev g;
    ap_pair(&c, &s);
    CK_ST(evsel(c, ev, APE_ALL, &io), APS_SUCCESS);
    CK_ST(getev(c, ev, &g, 0x37, &io), APS_INVALID_PARAM);
    CHECK(signalled(ev, 0));                                     /* not reset by the failed call */
    CK_FLAGS(take(c, ev), APE_SEND | APE_CONNECT);
    ap_closeS(c); ap_closeS(s); CloseHandle(ev);
}

TEST(apev_getev_bad_event_handle_consumes_nothing)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = ap_event(), mtx = CreateMutexW(NULL, FALSE, NULL), ro = NULL, dead; IO_STATUS_BLOCK io; ap_getev g; WCHAR nm[64];
    HANDLE named;
    ap_pair(&c, &s);
    wsprintfW(nm, L"apev_getev_%lu", GetCurrentProcessId());
    named = CreateEventW(NULL, TRUE, FALSE, nm);
    ro = OpenEventW(SYNCHRONIZE, FALSE, nm);
    dead = CreateEventW(NULL, TRUE, FALSE, NULL); CloseHandle(dead);
    CK_ST(evsel(c, ev, APE_ALL, &io), APS_SUCCESS);
    memset(&g, 0, sizeof(g));
    CK_ST(getev(c, mtx, &g, sizeof(g), &io), APS_TYPE_MISMATCH);
    CK_ST(getev(c, dead, &g, sizeof(g), &io), APS_INVALID_HANDLE);
    if (ro) CK_ST(getev(c, ro, &g, sizeof(g), &io), APS_ACCESS_DENIED);
    CHECK(signalled(ev, 0));
    CK_FLAGS(take(c, ev), APE_SEND | APE_CONNECT);              /* still all there */
    CloseHandle(ev); CloseHandle(mtx); CloseHandle(named); if (ro) CloseHandle(ro);
    ap_closeS(c); ap_closeS(s);
}

/* ---- independence from AFD poll -------------------------------------------------------------------- */

/* Fetching the event-select bits does not change what a poll sees: poll reports the live state. */
TEST(apev_poll_is_independent_of_getev)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = ap_event(); IO_STATUS_BLOCK io;
    ap_pair(&c, &s);
    CK_ST(evsel(s, ev, APE_RECEIVE, &io), APS_SUCCESS);
    ap_send_n(c, 4);
    CHECK(signalled(ev, 3000));
    CK_FLAGS(ap_now_flags(s, APE_RECEIVE), APE_RECEIVE);
    CK_FLAGS(take(s, ev), APE_RECEIVE);
    CK_FLAGS(ap_now_flags(s, APE_RECEIVE), APE_RECEIVE);        /* data still queued, poll still sees it */
    CK_FLAGS(take(s, ev), 0);
    ap_closeS(c); ap_closeS(s); CloseHandle(ev);
}

/* And the other way round: polling does not use up the event-select bits. */
TEST(apev_getev_independent_of_poll)
{
    AP_BEGIN();
    SOCKET c, s; HANDLE ev = ap_event(); IO_STATUS_BLOCK io;
    ap_pair(&c, &s);
    CK_ST(evsel(c, ev, APE_ALL, &io), APS_SUCCESS);
    CK_FLAGS(ap_now_flags(c, APE_ALL), APE_SEND | APE_CONNECT);
    CK_FLAGS(ap_now_flags(c, APE_ALL), APE_SEND | APE_CONNECT);
    CHECK(signalled(ev, 0));
    CK_FLAGS(take(c, ev), APE_SEND | APE_CONNECT);
    CloseHandle(ev); ap_closeS(c); ap_closeS(s);
}
