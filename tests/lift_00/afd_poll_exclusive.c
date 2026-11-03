/* Exclusive AFD polls: a request flagged exclusive terminates the earlier "main" request queued on the
 * same carrier handle for the same socket set, while non-exclusive requests accumulate undisturbed.
 * Measures which request is terminated (its event signals) and which stays pending, for polls on the
 * same handle, different handles, different sockets, another thread and overlapping socket sets. */
#include "afd_common.h"

#define NREQ 4

typedef struct {
    SOCKET ctl, socks[NREQ];
    HANDLE ev[NREQ];
    IO_STATUS_BLOCK io[NREQ];
    pollbuf_t in, out[NREQ];
    ULONG size;
} excl_t;

static void ex_init(excl_t *x)
{
    int i;
    memset(x, 0, sizeof(*x));
    x->ctl = mk_tcp();
    for (i = 0; i < NREQ; i++) { x->socks[i] = mk_tcp(); x->ev[i] = mk_event(); }
    x->size = (ULONG)POLL_BYTES(1);
    x->in.req.timeout = _I64_MAX;           /* never expires on its own */
    x->in.req.count = 1;
    x->in.req.sockets[0].socket = x->socks[0];
    x->in.req.sockets[0].flags = ~0u;
}

static void ex_done(excl_t *x)
{
    int i;
    sock_close(x->ctl);
    for (i = 0; i < NREQ; i++) { sock_close(x->socks[i]); CloseHandle(x->ev[i]); }
}

/* Issue request n on handle h with the current template and exclusivity; it must stay pending. */
static void ex_poll(excl_t *x, int n, SOCKET h, ULONG exclusive)
{
    LONG st;
    x->in.req.exclusive = exclusive;
    memset(&x->out[n], 0, sizeof(x->out[n]));
    st = afd_poll((HANDLE)h, x->ev[n], &x->io[n], &x->in, x->size, &x->out[n], x->size);
    CHECKF(st == AS_PENDING, "request %d: got %#lx", n, (unsigned long)st);
}

static void ex_ended(excl_t *x, int n)  { CHECKF(WaitForSingleObject(x->ev[n], 1000) == WAIT_OBJECT_0, "request %d should have terminated", n); }
static void ex_alive(excl_t *x, int n)  { CHECKF(WaitForSingleObject(x->ev[n], 150) == WAIT_TIMEOUT, "request %d should still pend", n); }

/* Cancel what this thread has outstanding on h and let the cancelled requests finish before the
 * buffers go away. */
static void ex_cancel(excl_t *x, SOCKET h, int upto)
{
    int i;
    CancelIo((HANDLE)h);
    for (i = 0; i < upto; i++) WaitForSingleObject(x->ev[i], 1000);
}

TEST(afdpx_exclusive_ends_on_cancel)
{
    excl_t x; NEED_AFD(); ex_init(&x);
    ex_poll(&x, 0, x.ctl, 1);
    ex_alive(&x, 0);
    CancelIo((HANDLE)x.ctl);
    ex_ended(&x, 0);
    ex_done(&x);
}

TEST(afdpx_two_nonexclusive_both_stay)
{
    excl_t x; NEED_AFD(); ex_init(&x);
    ex_poll(&x, 0, x.ctl, 0);
    ex_poll(&x, 1, x.ctl, 0);
    ex_alive(&x, 0); ex_alive(&x, 1);
    ex_cancel(&x, x.ctl, 2);
    ex_done(&x);
}

TEST(afdpx_exclusive_terminates_earlier_exclusive)
{
    excl_t x; NEED_AFD(); ex_init(&x);
    ex_poll(&x, 0, x.ctl, 1);
    ex_poll(&x, 1, x.ctl, 1);
    ex_ended(&x, 0);
    ex_alive(&x, 1);
    ex_cancel(&x, x.ctl, 2);
    ex_done(&x);
}

TEST(afdpx_nonexclusive_main_survives_later_exclusives)
{
    excl_t x; NEED_AFD(); ex_init(&x);
    ex_poll(&x, 0, x.ctl, 0);
    ex_poll(&x, 1, x.ctl, 1);
    ex_poll(&x, 2, x.ctl, 1);
    ex_alive(&x, 0); ex_alive(&x, 1); ex_alive(&x, 2);
    ex_cancel(&x, x.ctl, 3);
    ex_done(&x);
}

/* A request becomes the main one when nothing else is queued at the time it is issued. */
TEST(afdpx_first_exclusive_after_empty_queue_is_main)
{
    excl_t x; NEED_AFD(); ex_init(&x);
    ex_poll(&x, 0, x.socks[0], 0);
    CancelIo((HANDLE)x.socks[0]);
    ex_ended(&x, 0);
    ex_poll(&x, 1, x.ctl, 1);
    ex_poll(&x, 2, x.ctl, 1);
    ex_ended(&x, 1);
    ex_alive(&x, 2);
    ex_cancel(&x, x.ctl, 3);
    ex_done(&x);
}

/* The exclusive check runs when a request is issued, not again when the main one later ends. */
TEST(afdpx_check_not_repeated_when_main_ends)
{
    excl_t x; NEED_AFD(); ex_init(&x);
    ex_poll(&x, 0, x.socks[0], 0);
    ex_poll(&x, 1, x.ctl, 1);
    CancelIo((HANDLE)x.socks[0]);
    ex_ended(&x, 0);
    ex_poll(&x, 2, x.ctl, 1);
    ex_alive(&x, 1);
    ex_alive(&x, 2);
    ex_cancel(&x, x.ctl, 3);
    ex_done(&x);
}

/* Once the main request is gone, the next request issued becomes the main and can be terminated. */
TEST(afdpx_new_main_after_previous_main_gone)
{
    excl_t x; NEED_AFD(); ex_init(&x);
    ex_poll(&x, 0, x.socks[0], 0);
    ex_poll(&x, 1, x.ctl, 1);
    CancelIo((HANDLE)x.socks[0]);
    ex_ended(&x, 0);
    ex_poll(&x, 2, x.ctl, 1);
    ex_poll(&x, 3, x.ctl, 1);
    ex_alive(&x, 1);
    ex_ended(&x, 2);
    ex_alive(&x, 3);
    ex_cancel(&x, x.ctl, 4);
    ex_done(&x);
}

TEST(afdpx_different_sockets_do_not_terminate_each_other)
{
    excl_t x; NEED_AFD(); ex_init(&x);
    x.in.req.sockets[0].socket = x.socks[0];
    ex_poll(&x, 0, x.ctl, 1);
    x.in.req.sockets[0].socket = x.socks[1];
    ex_poll(&x, 1, x.ctl, 1);
    ex_alive(&x, 0); ex_alive(&x, 1);
    ex_cancel(&x, x.ctl, 2);
    ex_done(&x);
}

/* ---- another thread issues the second exclusive request ------------------- */
typedef struct { excl_t *x; LONG submit; DWORD wait_result; } thr_t;

static DWORD WINAPI thread_exclusive(void *p)
{
    thr_t *t = p;
    excl_t *x = t->x;
    x->in.req.exclusive = 1;
    memset(&x->out[1], 0, sizeof(x->out[1]));
    t->submit = afd_poll((HANDLE)x->ctl, x->ev[1], &x->io[1], &x->in, x->size, &x->out[1], x->size);
    t->wait_result = WaitForSingleObject(x->ev[1], 150);
    return 0;
}

TEST(afdpx_exclusive_from_other_thread_terminates_main)
{
    excl_t x; thr_t t; HANDLE th; NEED_AFD(); ex_init(&x);
    x.in.req.sockets[0].socket = x.ctl;
    ex_poll(&x, 0, x.ctl, 1);
    t.x = &x; t.submit = 0; t.wait_result = 0;
    th = CreateThread(NULL, 0, thread_exclusive, &t, 0, NULL);
    CHECK(th != NULL);
    if (th) { CHECK(WaitForSingleObject(th, 5000) == WAIT_OBJECT_0); CloseHandle(th); }
    CHECK(t.submit == AS_PENDING);
    CHECK(t.wait_result == WAIT_TIMEOUT);
    ex_ended(&x, 0);
    ex_cancel(&x, x.ctl, 2);
    ex_done(&x);
}

/* Two exclusive polls whose socket sets overlap in one member: the later one terminates the earlier. */
TEST(afdpx_overlapping_socket_sets_terminate)
{
    excl_t x; SOCKET a[2]; ULONG fl[2] = { ~0u, ~0u }; NEED_AFD(); ex_init(&x);
    x.size = (ULONG)POLL_BYTES(2);
    a[0] = x.ctl; a[1] = x.socks[0];
    fill_poll(&x.in, _I64_MAX, 1, 2, a, fl);
    ex_poll(&x, 0, x.ctl, 1);
    a[0] = x.ctl; a[1] = x.socks[1];
    fill_poll(&x.in, _I64_MAX, 1, 2, a, fl);
    ex_poll(&x, 1, x.ctl, 1);
    ex_ended(&x, 0);
    ex_alive(&x, 1);
    ex_cancel(&x, x.ctl, 2);
    ex_done(&x);
}
