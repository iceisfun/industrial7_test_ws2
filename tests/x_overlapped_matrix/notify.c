/* Notification-suppression matrix, branch aware. The grid in matrix.c pins one observation line per case; these
 * tests instead state the documented rules as relations and apply each rule only in the branch that really ran:
 *
 *  - FILE_SKIP_COMPLETION_PORT_ON_SUCCESS suppresses the packet only when the call itself returned success.
 *    A request that returned pending still posts its packet, whatever the data state was beforehand ("data was
 *    preloaded" does not prove the immediate branch: the call's own return value decides).
 *  - The mode cannot be cleared on a handle, so every case here gets a freshly created socket (xom_setup builds
 *    all sockets anew). Providers that are not plain IFS handles may refuse the mode; the setup failure is then
 *    reported as a skip, not a failure.
 *  - A set low-order bit in OVERLAPPED.hEvent suppresses the packet for immediate and pending requests alike,
 *    while the event itself is still signalled.
 *  - An absent packet is only meaningful after the operation is known to be finished, so completion is first
 *    established through OVERLAPPED.Internal (independent of the event and of the port) before the port is read.
 * The branch actually taken is recorded with t_note for every case. */
#include "xom.h"

/* Completion evidence for a pending request that has an event: the event. A request with neither event nor routine
 * has no completion evidence besides its packet (the socket handle is not signalled once the socket is associated
 * with a port, and OVERLAPPED.Internal is only filled in when the packet is dequeued); that case is never one with an
 * expected-absent packet, so the bounded wait on the port is the evidence there. */
static int nt_wait_finished(int st, DWORD ms)
{
    return WaitForSingleObject(g.ev, ms) == WAIT_OBJECT_0;
}

static int expect_pkt_pending(int st) { return st != ST_EVLOW; }
static const int nt_styles[] = { ST_IOCP, ST_IOCPEV, ST_EVLOW, ST_SKIPOK, ST_SKIPOKNUL };
#define NT_NSTYLES ((int)(sizeof nt_styles / sizeof nt_styles[0]))

/* Run one case. mode 1: data/connection prepared before the call; mode 0: nothing prepared, pending guaranteed. */
static void nt_case(int op, int st, int mode)
{
    char name[96], pk[96], pk2[96];
    int have_early = 0, early = 0, ok, imm, e, done, n, pkts, expect, ev_set = 0, ev_before = 0;
    DWORD bytes = 0xFFFFFFFF;
    snprintf(name, sizeof name, "%s/%s/%s", xom_opname[op], xom_stname[st], mode ? "prepared" : "idle");
    if (!xom_setup(op, st, 1, mode)) { xom_free(); t_skip("%s: setup refused (mode or provider restriction)", name); return; }
    ok = xom_issue();
    e = U(WSAGetLastError)();
    imm = ok;
    if (!imm) CHECKF(e == ERROR_IO_PENDING, "%s: failure must be pending, got %d", name, e);
    t_note("%s: call returned %s", name, imm ? "immediate success" : "pending");
    if (!mode) CHECKF(!imm, "%s: an idle request must be pending", name);
    /* anything that can still be pending gets driven to completion */
    if (!imm) {
        if (!mode) {
            ev_before = xom_has_event(st) ? xom_ev_set() : 0;
            CHECKF(!ev_before, "%s: event must not be signalled while pending", name);
            xom_drive(op);
        }
    }
    if (imm) {
        done = xom_done();
        CHECKF(done, "%s: immediate success leaves the OVERLAPPED filled in", name);
        if (xom_has_event(st)) {
            ev_set = xom_ev_set();
            CHECKF(ev_set, "%s: event signalled after immediate success", name);
        }
    } else {
        if (xom_has_event(st)) {
            done = nt_wait_finished(st, 5000);
            CHECKF(done, "%s: completion of the pending request established independently of the port", name);
            if (!done) { CancelIoEx((HANDLE)g.s, &g.ov); xom_free(); return; }
        } else {
            CHECKF(expect_pkt_pending(st), "%s: a request without event always posts its packet when pending", name);
            early = xom_poll_pkts(5000, pk, sizeof pk);
            CHECKF(early == 1, "%s: pending request without event posts its packet (got %d)", name, early);
            done = early > 0;
            if (!done) { CancelIoEx((HANDLE)g.s, &g.ov); xom_free(); return; }
            have_early = 1;
        }
    }
    SetLastError(0);
    CHECKF(GetOverlappedResult((HANDLE)g.s, &g.ov, &bytes, FALSE), "%s: GetOverlappedResult succeeds", name);
    CHECKF(bytes == (op == OP_ACCEPTEX ? 0u : (op == OP_SEND ? 16u : 5u)), "%s: byte count %lu", name, bytes);
    /* the packet rule, per branch */
    if (st == ST_EVLOW) expect = 0;
    else if ((st == ST_SKIPOK || st == ST_SKIPOKNUL) && imm) expect = 0;
    else expect = 1;
    if (have_early) { pkts = early; n = xom_poll_pkts(250, pk2, sizeof pk2); CHECKF(n == 0, "%s: no second packet (got %d)", name, n); }
    else { pkts = xom_poll_pkts(250, pk, sizeof pk); }
    CHECKF(pkts == expect, "%s: %s: packets want %d got %d", name, imm ? "immediate" : "pending", expect, pkts);
    if (pkts && expect) {
        CHECKF(strstr(pk, "ok,") == pk && strstr(pk, "k=1,o=1"), "%s: packet identifies key and OVERLAPPED (%s)", name, pk);
    }
    xom_free();
}

static void nt_all(int op, int mode)
{
    int i;
    XOM_UP();
    for (i = 0; i < NT_NSTYLES; i++) nt_case(op, nt_styles[i], mode);
}

TEST(notify_recv_prepared)       { nt_all(OP_RECV, 1); }
TEST(notify_recv_idle)           { nt_all(OP_RECV, 0); }
TEST(notify_recvfrom_prepared)   { nt_all(OP_RECVFROM, 1); }
TEST(notify_recvfrom_idle)       { nt_all(OP_RECVFROM, 0); }
TEST(notify_send_prepared)       { nt_all(OP_SEND, 1); }
TEST(notify_acceptex_prepared)   { nt_all(OP_ACCEPTEX, 1); }
TEST(notify_acceptex_idle)       { nt_all(OP_ACCEPTEX, 0); }

/* Skip-on-success only matters when the call returned success: on the pending branch the packet must still come,
 * and the same socket then also delivers a later request that does succeed at once without a packet. Both
 * requests are issued on one socket here, which is a different socket from every other case. */
TEST(notify_skipok_one_socket_both_branches)
{
    int imm1, imm2, p1, p2; char pk[96];
    XOM_UP();
    if (!xom_setup(OP_RECV, ST_SKIPOKNUL, 1, 0)) { xom_free(); t_skip("setup refused"); return; }
    imm1 = xom_issue();
    CHECKF(!imm1, "first receive on an empty socket is pending");
    xom_drive(OP_RECV);
    p1 = xom_poll_pkts(5000, pk, sizeof pk);
    CHECKF(p1 == 1, "pending branch posts its packet (got %d)", p1);
    /* second request: data is waiting, so the call may return success at once */
    U(send)(g.p, "hello", 5, 0);
    CHECK(xom_readable(g.s, 3000));
    imm2 = xom_issue();
    t_note("second receive returned %s", imm2 ? "immediate success" : "pending");
    if (imm2) CHECK(xom_done());
    p2 = xom_poll_pkts(imm2 ? 250 : 5000, pk, sizeof pk);
    CHECKF(p2 == (imm2 ? 0 : 1), "second request: %s, packets got %d", imm2 ? "immediate" : "pending", p2);
    xom_free();
}
