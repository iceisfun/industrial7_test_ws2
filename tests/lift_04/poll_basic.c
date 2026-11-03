/* lift_04: WSAPoll on freshly connected loopback sockets, and the helper paths used by the
 * other tests (blocking-mode switch, close-with-reset). Measures the revents reported for a
 * quiet connection, for a connection with pending data, a poll that waits in another thread,
 * and the zero-timeout poll result. */
#include "l4.h"

static int poll_one(SOCKET s, short mask, short *revents, int ms)
{
    WSAPOLLFD p;
    int r;
    p.fd = s; p.events = mask; p.revents = (short)0xdead;
    r = U(WSAPoll)(&p, 1, ms);
    *revents = p.revents;
    return r;
}

#define MASK_ALL (POLLRDNORM | POLLRDBAND | POLLWRNORM)

TEST(poll_quiet_connection_is_writable_only)
{
    SOCKET a, b; short rev; int r;
    if (!ws_up()) return;
    if (!make_pair(&a, &b, WSA_FLAG_OVERLAPPED)) { CHECK(0); ws_down(); return; }
    r = poll_one(a, MASK_ALL, &rev, 1000);
    EQ(r, 1);
    EQ(rev, POLLWRNORM);
    r = poll_one(b, MASK_ALL, &rev, 1000);
    EQ(r, 1);
    EQ(rev, POLLWRNORM);
    cl(a); cl(b); ws_down();
}

TEST(poll_pending_data_adds_readable)
{
    SOCKET a, b; short rev; int r;
    if (!ws_up()) return;
    if (!make_pair(&a, &b, WSA_FLAG_OVERLAPPED)) { CHECK(0); ws_down(); return; }
    EQ(U(send)(a, "x", 1, 0), 1);
    EQ(wait_readable(b, 5000), 1);
    r = poll_one(b, MASK_ALL, &rev, 1000);
    EQ(r, 1);
    EQ(rev, POLLRDNORM | POLLWRNORM);
    cl(a); cl(b); ws_down();
}

TEST(poll_read_only_mask_on_quiet_socket_times_out)
{
    SOCKET a, b; short rev; int r;
    if (!ws_up()) return;
    if (!make_pair(&a, &b, 0)) { CHECK(0); ws_down(); return; }
    r = poll_one(a, POLLRDNORM, &rev, 0);   /* zero timeout: immediate answer */
    EQ(r, 0);
    EQ(rev, 0);
    cl(a); cl(b); ws_down();
}

TEST(poll_works_on_non_overlapped_pair)
{
    SOCKET a, b; short rev; int r;
    if (!ws_up()) return;
    if (!make_pair(&a, &b, 0)) { CHECK(0); ws_down(); return; }
    r = poll_one(a, MASK_ALL, &rev, 1000);
    EQ(r, 1);
    EQ(rev, POLLWRNORM);
    cl(a); cl(b); ws_down();
}

struct pollarg { WSAPOLLFD p; int ret; };
static DWORD WINAPI poll_thread(LPVOID v)
{
    struct pollarg *a = v;
    a->ret = U(WSAPoll)(&a->p, 1, 5000);
    return 0;
}

/* A poll blocked in one thread wakes when another thread makes data available. */
TEST(poll_wakes_when_peer_sends)
{
    SOCKET a, b; struct pollarg arg; HANDLE h; DWORD id;
    if (!ws_up()) return;
    if (!make_pair(&a, &b, WSA_FLAG_OVERLAPPED)) { CHECK(0); ws_down(); return; }
    arg.p.fd = b; arg.p.events = POLLRDNORM; arg.p.revents = 0; arg.ret = -5;
    h = CreateThread(NULL, 0, poll_thread, &arg, 0, &id);
    CHECK(h != NULL);
    Sleep(100);
    EQ(U(send)(a, "y", 1, 0), 1);
    if (h) {
        EQ(WaitForSingleObject(h, 10000), WAIT_OBJECT_0);
        CloseHandle(h);
    }
    EQ(arg.ret, 1);
    EQ(arg.p.revents, POLLRDNORM);
    cl(a); cl(b); ws_down();
}

TEST(poll_after_peer_close_reports_readable_eof)
{
    SOCKET a, b; short rev; int r; char c;
    if (!ws_up()) return;
    if (!make_pair(&a, &b, WSA_FLAG_OVERLAPPED)) { CHECK(0); ws_down(); return; }
    cl(a);
    EQ(wait_readable(b, 5000), 1);
    r = poll_one(b, POLLRDNORM, &rev, 1000);
    EQ(r, 1);
    CHECK(rev & POLLRDNORM || rev & POLLHUP);
    EQ(U(recv)(b, &c, 1, 0), 0);     /* graceful close reads as zero bytes */
    cl(b); ws_down();
}

TEST(blocking_mode_switch_roundtrip)
{
    SOCKET a, b; char c; int r;
    if (!ws_up()) return;
    if (!make_pair(&a, &b, 0)) { CHECK(0); ws_down(); return; }
    EQ(nonblock(a, 1), 0);
    r = U(recv)(a, &c, 1, 0);
    EQ(r, SOCKET_ERROR);
    EQ(lerr(), WSAEWOULDBLOCK);
    EQ(nonblock(a, 0), 0);
    cl(a); cl(b); ws_down();
}
