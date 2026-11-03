/* Which outstanding AcceptEx takes which connection.  Pending requests are served newest-first (the request posted last
 * takes the first arriving connection); connections that were already queued are handed to requests in the order the
 * requests are posted.  Tags on the connections tell the cases apart. */
#include "fx.h"

#define MAXREQ 3

struct req { SOCKET acc; OVERLAPPED ov; unsigned char buf[FXC_BUF]; DWORD n; };

static void req_init(struct req *r, int af) { memset(r, 0, sizeof *r); r->acc = fx_stream(af); r->ov.hEvent = fx_event(); }
static void req_done(struct req *r) { if (r->acc != INVALID_SOCKET) fx_closesocket(r->acc); CloseHandle(r->ov.hEvent); }
static int req_post(struct fx *f, struct req *r, DWORD rl) { return fx_post(f, r->acc, r->buf, rl, f->slot, f->slot, &r->n, &r->ov); }

/* Post k requests (receive length rl), connect k clients one after another (each sends its index as a tag), then see
 * which tag each accept socket's request received.  pre != 0 connects first and posts afterwards.  Returns 1 when all
 * completed; owner[i] = index of the client whose connection request i took. */
static int run(int af, int k, DWORD rl, int pre, int owner[MAXREQ])
{
    struct fx f; struct req r[MAXREQ]; SOCKET cl[MAXREQ]; int i, ok = 1; fx_addr dummy; (void)dummy;
    if (!fx_open(&f, af)) return -1;
    for (i = 0; i < k; i++) req_init(&r[i], af);
    if (pre) for (i = 0; i < k; i++) { char t = (char)('1' + i); cl[i] = fx_client(&f); fx_send(cl[i], &t, 1, 0); }
    if (pre) Sleep(100);
    for (i = 0; i < k; i++) if (req_post(&f, &r[i], rl) != WSA_IO_PENDING) ok = 0;
    if (!pre) for (i = 0; i < k; i++) { char t = (char)('1' + i); cl[i] = fx_client(&f); fx_send(cl[i], &t, 1, 0); }
    for (i = 0; i < k; i++) {
        owner[i] = -1;
        if (WaitForSingleObject(r[i].ov.hEvent, 3000) != WAIT_OBJECT_0) { ok = 0; continue; }
        if (rl) owner[i] = r[i].buf[0] - '1';
        else {
            char t = 0;
            if (fx_recv_n(r[i].acc, &t, 1, 2000) == 1) owner[i] = t - '1';
        }
    }
    for (i = 0; i < k; i++) { fx_closesocket(cl[i]); req_done(&r[i]); }
    fx_shut(&f);
    return ok;
}

#define ORDER_CASE(name, af, k, rl, pre, e0, e1, e2) \
    TEST(name) { int o[MAXREQ] = {-9, -9, -9}; int r = run(af, k, rl, pre, o); \
        if (r < 0) { t_skip("fixture unavailable"); return; } \
        CHECK(r == 1); EXPECT_EQ(o[0], e0); EXPECT_EQ(o[1], e1); if (k > 2) EXPECT_EQ(o[2], e2); }

/* Pending requests, zero-length receive: the last request posted gets the first connection. */
ORDER_CASE(order_pending_zero_length_newest_first_v4, AF_INET, 2, 0, 0, 1, 0, 0)
ORDER_CASE(order_pending_zero_length_newest_first_v6, AF_INET6, 2, 0, 0, 1, 0, 0)
/* Pending requests, one-byte receive. */
ORDER_CASE(order_pending_one_byte_newest_first_v4, AF_INET, 2, 1, 0, 1, 0, 0)
ORDER_CASE(order_pending_one_byte_newest_first_v6, AF_INET6, 2, 1, 0, 1, 0, 0)
/* Three pending requests. */
ORDER_CASE(order_three_pending_requests_reverse_v4, AF_INET, 3, 0, 0, 2, 1, 0)
ORDER_CASE(order_three_pending_requests_reverse_v6, AF_INET6, 3, 0, 0, 2, 1, 0)
/* Connections queued before the requests exist: handed out in the order the requests are posted. */
ORDER_CASE(order_queued_zero_length_posting_order_v4, AF_INET, 2, 0, 1, 0, 1, 0)
ORDER_CASE(order_queued_zero_length_posting_order_v6, AF_INET6, 2, 0, 1, 0, 1, 0)
ORDER_CASE(order_queued_one_byte_posting_order_v4, AF_INET, 2, 1, 1, 0, 1, 0)
ORDER_CASE(order_queued_one_byte_posting_order_v6, AF_INET6, 2, 1, 1, 0, 1, 0)
ORDER_CASE(order_three_queued_requests_posting_order_v4, AF_INET, 3, 0, 1, 0, 1, 2)
ORDER_CASE(order_three_queued_requests_posting_order_v6, AF_INET6, 3, 0, 1, 0, 1, 2)

/* A request cancelled before the connection arrives is skipped; the older one takes it. */
FX_BOTH(order_cancelled_newest_request_is_skipped)
{
    struct fx f; struct req a, b; SOCKET cl; char t = 0; DWORD got;
    if (!fx_up() || !fx_open(&f, af)) { t_skip("fixture unavailable"); return; }
    req_init(&a, af); req_init(&b, af);
    FX_EQ(req_post(&f, &a, 0), WSA_IO_PENDING);
    FX_EQ(req_post(&f, &b, 0), WSA_IO_PENDING);
    CHECK(CancelIoEx((HANDLE)f.lst, &b.ov));
    FX_EQ(WaitForSingleObject(b.ov.hEvent, 3000), WAIT_OBJECT_0);
    EXPECT_EQ((ULONG)b.ov.Internal, FX_STATUS_CANCELLED);
    cl = fx_client(&f);
    fx_send(cl, "Y", 1, 0);
    FX_EQ(WaitForSingleObject(a.ov.hEvent, 3000), WAIT_OBJECT_0);
    FX_EQ(fx_recv_n(a.acc, &t, 1, 2000), 1);
    EXPECT_EQ(t, 'Y');
    (void)got;
    fx_closesocket(cl);
    req_done(&a); req_done(&b);
    fx_shut(&f);
}
