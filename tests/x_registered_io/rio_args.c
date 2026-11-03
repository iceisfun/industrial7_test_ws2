/* Argument validation of RIOReceive / RIOSend / RIOReceiveEx / RIOSendEx, which happens before anything is queued.
 *
 * Findings, Windows 10: every call fails with FALSE and WSAEINVAL for a NULL request queue, a descriptor count
 * above one, and flag bits outside the accepted set. Receive accepts DONT_NOTIFY | DEFER | WAITALL | COMMIT_ONLY;
 * Send and SendEx accept only DONT_NOTIFY | DEFER | COMMIT_ONLY. COMMIT_ONLY must stand alone, with a NULL
 * descriptor and a count of zero. A descriptor naming no registration (RIO_INVALID_BUFFERID or NULL) is
 * WSAEINVAL at queuing time. With a count of zero the descriptor pointer is not looked at. */
#include "rio.h"

enum { OP_RECV, OP_SEND };

static BOOL do_op(PAIR *p, int op, RIO_BUF *d, ULONG count, DWORD flags)
{
    return op == OP_RECV ? p->t->Receive(p->rb, d, count, flags, RQC(1)) : p->t->Send(p->ra, d, count, flags, RQC(1));
}
static const char *opname(int op) { return op == OP_RECV ? "Receive" : "Send"; }

/* Rows that must be refused with WSAEINVAL. kind: 0 normal descriptor, 1 RIO_INVALID_BUFFERID, 2 NULL id,
 * 3 NULL descriptor pointer with count 1 is not tested (would fault), so no kind for it. */
TEST(rio_args_refused_matrix)
{
    static const struct { const char *n; int kind; ULONG count; DWORD flags; int recv, send; } m[] = {
        {"invalid buffer id", 1, 1, 0, 1, 1}, {"null buffer id", 2, 1, 0, 1, 1},
        {"count 2", 0, 2, 0, 1, 1}, {"count 3", 0, 3, 0, 1, 1}, {"count 0xffffffff", 0, 0xffffffff, 0, 1, 1},
        {"flag 0x10", 0, 1, 0x10, 1, 1}, {"flag 0x20", 0, 1, 0x20, 1, 1}, {"flag 0x100", 0, 1, 0x100, 1, 1}, {"flag 0x80000000", 0, 1, 0x80000000, 1, 1},
        {"flags 0xf", 0, 1, 0xf, 1, 1}, {"commit with descriptor", 0, 1, RIO_MSG_COMMIT_ONLY, 1, 1},
        {"commit | dont_notify", 0, 0, RIO_MSG_COMMIT_ONLY | RIO_MSG_DONT_NOTIFY, 1, 1}, {"commit | defer", 0, 0, RIO_MSG_COMMIT_ONLY | RIO_MSG_DEFER, 1, 1},
        {"commit | waitall", 0, 0, RIO_MSG_COMMIT_ONLY | RIO_MSG_WAITALL, 1, 1},
        {"waitall on a send", 0, 1, RIO_MSG_WAITALL, 0, 1}, {"waitall | defer on a send", 0, 1, RIO_MSG_WAITALL | RIO_MSG_DEFER, 0, 1},
    };
    NEED_PAIR(p, t, 4);
    for (int op = 0; op < 2; op++)
        for (unsigned i = 0; i < sizeof m / sizeof *m; i++) {
            RIO_BUF d = {p.id, PR_RECV, 8}; BOOL r;
            if (!(op == OP_RECV ? m[i].recv : m[i].send)) continue;
            if (m[i].kind == 1) d.BufferId = RIO_INVALID_BUFFERID;
            if (m[i].kind == 2) d.BufferId = NULL;
            WSASetLastError(0);
            r = do_op(&p, op, &d, m[i].count, m[i].flags);
            CHECKF(!r, "%s: %s accepted", opname(op), m[i].n);
            EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
        }
    pair_close(&p);
}
TEST(rio_args_commit_only_forms)
{
    NEED_PAIR(p, t, 4);
    for (int op = 0; op < 2; op++) {
        WSASetLastError(0);
        CHECKF(do_op(&p, op, NULL, 0, RIO_MSG_COMMIT_ONLY), "%s commit-only", opname(op));
    }
    pair_close(&p);
}
TEST(rio_args_accepted_flag_forms)
{
    static const struct { const char *n; DWORD flags; int recv, send; } m[] = {
        {"none", 0, 1, 1}, {"dont_notify", RIO_MSG_DONT_NOTIFY, 1, 1}, {"defer", RIO_MSG_DEFER, 1, 1}, {"dont_notify | defer", RIO_MSG_DONT_NOTIFY | RIO_MSG_DEFER, 1, 1},
        {"waitall", RIO_MSG_WAITALL, 1, 0}, {"waitall | dont_notify", RIO_MSG_WAITALL | RIO_MSG_DONT_NOTIFY, 1, 0},
    };
    for (int op = 0; op < 2; op++)
        for (unsigned i = 0; i < sizeof m / sizeof *m; i++) {
            NEED_PAIR(p, t, 4);
            RIO_BUF d = {p.id, PR_SEND, 4};
            if (op == OP_RECV ? m[i].recv : m[i].send) CHECKF(do_op(&p, op, &d, 1, m[i].flags), "%s: %s refused (err %d)", opname(op), m[i].n, WSAGetLastError());
            pair_close(&p);
        }
}
TEST(rio_args_count_zero_ignores_the_descriptor_pointer)
{
    NEED_PAIR(p, t, 4);
    RIO_BUF junk = {RIO_INVALID_BUFFERID, 0xffff, 0xffff};
    CHECK(do_op(&p, OP_RECV, &junk, 0, 0));
    CHECK(do_op(&p, OP_RECV, NULL, 0, 0));
    CHECK(do_op(&p, OP_SEND, &junk, 0, 0));
    CHECK(do_op(&p, OP_SEND, NULL, 0, 0));
    pair_close(&p);
}
TEST(rio_args_null_request_queue_is_einval)
{
    NEED_RIO(t);
    RIO_BUF d = {NULL, 0, 0}, ad = {NULL, 0, 28};
    WSASetLastError(0); CHECK(!t->Receive(NULL, NULL, 0, 0, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    WSASetLastError(0); CHECK(!t->Send(NULL, NULL, 0, 0, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    WSASetLastError(0); CHECK(!t->ReceiveEx(NULL, NULL, 0, NULL, NULL, NULL, NULL, 0, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    WSASetLastError(0); CHECK(!t->SendEx(NULL, NULL, 0, NULL, NULL, NULL, NULL, 0, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    WSASetLastError(0); CHECK(!t->Receive(NULL, NULL, 0, RIO_MSG_COMMIT_ONLY, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    (void)d; (void)ad;
}
TEST(rio_args_ex_variants_share_the_flag_rules)
{
    NEED_PAIR(p, t, 4);
    RIO_BUF d = {p.id, PR_RECV, 8}, to = {p.id, PR_TOB, 28}, ad = {p.id, PR_LOC, 28};
    WSASetLastError(0); CHECK(!t->ReceiveEx(p.rb, &d, 2, NULL, NULL, NULL, NULL, 0, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    WSASetLastError(0); CHECK(!t->ReceiveEx(p.rb, &d, 1, NULL, NULL, NULL, NULL, 0x10, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    WSASetLastError(0); CHECK(!t->ReceiveEx(p.rb, &d, 1, NULL, NULL, NULL, NULL, RIO_MSG_COMMIT_ONLY, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    WSASetLastError(0); CHECK(!t->SendEx(p.ra, &d, 2, NULL, &to, NULL, NULL, 0, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    WSASetLastError(0); CHECK(!t->SendEx(p.ra, &d, 1, NULL, &to, NULL, NULL, RIO_MSG_WAITALL, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    WSASetLastError(0); CHECK(!t->SendEx(p.ra, &d, 1, NULL, &to, NULL, NULL, RIO_MSG_COMMIT_ONLY, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    WSASetLastError(0); CHECK(!t->SendEx(p.ra, &d, 1, &ad, &to, NULL, NULL, 0, NULL)); EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    CHECK(t->SendEx(p.ra, NULL, 0, NULL, NULL, NULL, NULL, RIO_MSG_COMMIT_ONLY, NULL));
    CHECK(t->ReceiveEx(p.rb, NULL, 0, NULL, NULL, NULL, NULL, RIO_MSG_COMMIT_ONLY, NULL));
    pair_close(&p);
}
TEST(rio_args_failed_calls_consume_no_queue_slot)
{
    NEED_PAIR(p, t, 2);
    for (int i = 0; i < 20; i++) { RIO_BUF d = {p.id, PR_RECV, 8}; CHECK(!t->Receive(p.rb, &d, 2, 0, NULL)); CHECK(!t->Receive(p.rb, &d, 1, 0x10, NULL)); }
    CHECK(pair_recv(&p, PR_RECV, 8, RQV(1), 0)); CHECK(pair_recv(&p, PR_RECV + 0x100, 8, RQV(2), 0));
    pair_close(&p);
}
TEST(rio_args_success_leaves_error_state_alone)
{
    NEED_PAIR(p, t, 4);
    WSASetLastError(0x1234);
    CHECK(pair_recv(&p, PR_RECV, 8, RQV(1), 0));
    EXPECT_EQ(WSAGetLastError(), 0x1234);
    pair_close(&p);
}
