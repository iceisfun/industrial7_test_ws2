/* Completion notification: RIONotify arming, event and I/O completion port delivery, NotifyReset, and
 * RIO_MSG_DONT_NOTIFY.
 *
 * Measured on Windows 10. A queue created with a notification descriptor signals nothing until RIONotify arms it.
 * Arming a queue that already holds entries fires at once; arming an empty queue fires on the next completion
 * that was not posted with RIO_MSG_DONT_NOTIFY. One arming gives one notification, however many completions
 * follow, and RIONotify arms again only after it fired (WSAEALREADY while still armed). With NotifyReset the
 * event is cleared by the RIONotify call itself, otherwise left as it was. For a port the notification is one
 * packet with the descriptor's key and OVERLAPPED and a byte count of zero. */
#include "rio.h"

typedef struct { PAIR p; RIO_TABLE *t; HANDLE ev; RIO_CQ cq; RIO_RQ ra, rb; } NF;

/* Receiver side b uses `cq` (notified); a's completions go to p.cqa (polling) so sends never mix in. */
static int nf_open(NF *n, RIO_TABLE *t, BOOL reset)
{
    RIO_NOTIF d;
    memset(n, 0, sizeof *n); n->t = t;
    if (!pair_open2(&n->p, t, 4, 0)) return 0;
    n->ev = CreateEventA(NULL, TRUE, FALSE, NULL);       /* manual reset: observations do not consume the signal */
    memset(&d, 0, sizeof d); d.Type = RIO_EVENT_COMPLETION; d.u.Event.EventHandle = n->ev; d.u.Event.NotifyReset = reset;
    n->cq = t->CreateCompletionQueue(8, &d);
    if (!n->cq) return 0;
    n->rb = t->CreateRequestQueue(n->p.b, 2, 1, 2, 1, n->cq, n->cq, (PVOID)(ULONG_PTR)CTX_B);
    return n->rb != NULL;
}
static void nf_close(NF *n)
{
    pair_close(&n->p);
    if (n->cq) n->t->CloseCompletionQueue(n->cq);
    if (n->ev) CloseHandle(n->ev);
}
#define NEED_NF(n, t, reset) NF n; RIO_TABLE *t; NEED_NET(); t = rio_tbl(); if (!t) { t_skip("RIO unavailable"); return; } \
    if (!nf_open(&n, t, reset)) { nf_close(&n); t_skip("fixture unavailable"); return; }
static int signaled(HANDLE e, DWORD ms) { return WaitForSingleObject(e, ms) == WAIT_OBJECT_0; }
/* one datagram a -> b, receive posted on the notified queue */
static void one_datagram(NF *n, ULONGLONG id, DWORD rflags)
{
    CHECK(n->t->Receive(n->rb, &(RIO_BUF){n->p.id, PR_RECV, 16}, 1, rflags, (PVOID)(ULONG_PTR)(0x1100000000ULL + id)));
    CHECK(pair_send(&n->p, PR_SEND, 3, RQV(100 + id), 0));
}

TEST(rio_notify_nothing_fires_before_arming)
{
    NEED_NF(n, t, TRUE);
    one_datagram(&n, 1, 0);
    rio_settle();
    CHECK(!signaled(n.ev, 0));
    nf_close(&n);
}
TEST(rio_notify_arming_a_queue_with_entries_fires_at_once)
{
    RIORES r[2];
    NEED_NF(n, t, TRUE);
    one_datagram(&n, 1, 0);
    rio_settle();
    EXPECT_EQ(t->Notify(n.cq), 0);
    CHECK(signaled(n.ev, 2000));
    EXPECT_EQ(t->DequeueCompletion(n.cq, r, 2), 1);
    nf_close(&n);
}
TEST(rio_notify_armed_empty_queue_fires_on_next_completion)
{
    RIORES r[2];
    NEED_NF(n, t, TRUE);
    EXPECT_EQ(t->Notify(n.cq), 0);
    CHECK(!signaled(n.ev, 0));
    one_datagram(&n, 1, 0);
    CHECK(signaled(n.ev, 2000));
    EXPECT_EQ(rio_wait(t, n.cq, r, 2, 1), 1);
    nf_close(&n);
}
TEST(rio_notify_one_arming_gives_one_notification)
{
    RIORES r[4];
    NEED_NF(n, t, FALSE);
    EXPECT_EQ(t->Notify(n.cq), 0);
    one_datagram(&n, 1, 0);
    CHECK(signaled(n.ev, 2000));
    ResetEvent(n.ev);
    one_datagram(&n, 2, 0);                       /* second completion, queue not re-armed */
    rio_settle();
    CHECK(!signaled(n.ev, 0));
    EXPECT_EQ(t->DequeueCompletion(n.cq, r, 4), 2);   /* both are there to be dequeued anyway */
    EXPECT_EQ(r[0].RequestContext, RQV(1)); EXPECT_EQ(r[1].RequestContext, RQV(2));
    nf_close(&n);
}
TEST(rio_notify_rearm_after_fire_succeeds)
{
    NEED_NF(n, t, FALSE);
    EXPECT_EQ(t->Notify(n.cq), 0);
    one_datagram(&n, 1, 0);
    CHECK(signaled(n.ev, 2000));
    ResetEvent(n.ev);
    EXPECT_EQ(t->Notify(n.cq), 0);                   /* not WSAEALREADY: the first arming was used up */
    CHECK(signaled(n.ev, 2000));                     /* and the entry that is still queued fires it again */
    nf_close(&n);
}
TEST(rio_notify_dont_notify_completion_stays_quiet)
{
    RIORES r[4];
    NEED_NF(n, t, FALSE);
    EXPECT_EQ(t->Notify(n.cq), 0);
    one_datagram(&n, 1, RIO_MSG_DONT_NOTIFY);
    rio_settle();
    CHECK(!signaled(n.ev, 0));                        /* still armed, nothing fired */
    EXPECT_EQ(t->DequeueCompletion(n.cq, r, 4), 1);   /* but the entry is in the queue */
    EXPECT_EQ(r[0].RequestContext, RQV(1));
    one_datagram(&n, 2, 0);
    CHECK(signaled(n.ev, 2000));                      /* the armed notification is still there for a normal completion */
    EXPECT_EQ(rio_wait(t, n.cq, r, 4, 1), 1);
    nf_close(&n);
}
TEST(rio_notify_reset_flag_clears_the_event_in_riotify)
{
    for (int reset = 0; reset < 2; reset++) {
        NEED_NF(n, t, reset);
        SetEvent(n.ev);
        EXPECT_EQ(t->Notify(n.cq), 0);
        CHECKF(signaled(n.ev, 0) == !reset, "NotifyReset=%d", reset);
        nf_close(&n);
    }
}
TEST(rio_notify_dequeue_does_not_disarm)
{
    RIORES r[2];
    NEED_NF(n, t, FALSE);
    EXPECT_EQ(t->Notify(n.cq), 0);
    EXPECT_EQ(t->DequeueCompletion(n.cq, r, 2), 0);
    EXPECT_EQ(t->Notify(n.cq), WSAEALREADY);
    one_datagram(&n, 1, 0);
    CHECK(signaled(n.ev, 2000));
    nf_close(&n);
}

/* I/O completion port notification */
TEST(rio_notify_iocp_packet_shape)
{
    RIORES r[4]; RIO_NOTIF d; DWORD nb = 77; ULONG_PTR key = 0; OVERLAPPED *po = NULL; RIO_CQ cq; RIO_RQ rb;
    OVERLAPPED ov; HANDLE cp;
    PAIR p; RIO_TABLE *t;
    NEED_NET(); t = rio_tbl(); if (!t) { t_skip("RIO unavailable"); return; }
    if (!pair_open2(&p, t, 4, 0)) { pair_close(&p); t_skip("fixture unavailable"); return; }
    cp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    memset(&ov, 0, sizeof ov); memset(&d, 0, sizeof d);
    d.Type = RIO_IOCP_COMPLETION; d.u.Iocp.IocpHandle = cp; d.u.Iocp.CompletionKey = (PVOID)0x1234; d.u.Iocp.Overlapped = &ov;
    cq = t->CreateCompletionQueue(8, &d);
    rb = t->CreateRequestQueue(p.b, 2, 1, 2, 1, cq, cq, (PVOID)(ULONG_PTR)CTX_B);
    CHECK(cq && rb);
    CHECK(t->Receive(rb, &(RIO_BUF){p.id, PR_RECV, 16}, 1, 0, RQC(1)));
    CHECK(pair_send(&p, PR_SEND, 3, RQV(2), 0));
    rio_settle();
    CHECK(!GetQueuedCompletionStatus(cp, &nb, &key, &po, 0));   /* a completion alone posts nothing */
    EXPECT_EQ(GetLastError(), WAIT_TIMEOUT);
    EXPECT_EQ(t->Notify(cq), 0);                                 /* entries are queued: the packet is posted now */
    CHECK(GetQueuedCompletionStatus(cp, &nb, &key, &po, 3000));
    EXPECT_EQ(nb, 0); EXPECT_EQ(key, 0x1234); CHECK(po == &ov);
    CHECK(!GetQueuedCompletionStatus(cp, &nb, &key, &po, 200));  /* exactly one packet */
    EXPECT_EQ(t->DequeueCompletion(cq, r, 4), 1);
    /* arm on empty, then complete */
    EXPECT_EQ(t->Notify(cq), 0);
    CHECK(t->Receive(rb, &(RIO_BUF){p.id, PR_RECV, 16}, 1, 0, RQC(3)));
    CHECK(pair_send(&p, PR_SEND, 3, RQV(4), 0));
    CHECK(GetQueuedCompletionStatus(cp, &nb, &key, &po, 3000));
    EXPECT_EQ(key, 0x1234); CHECK(po == &ov);
    EXPECT_EQ(rio_wait(t, cq, r, 4, 1), 1);
    t->CloseCompletionQueue(cq); CloseHandle(cp); pair_close(&p);
}
