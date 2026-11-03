/* Measures FD_READ notification through WSAEventSelect and WSAAsyncSelect: edge-triggering on arrival,
 * re-arming by a partial recv(), a failed recv(), per-byte draining, data arriving while not selected,
 * WSAPoll not consuming notifications, and a pending overlapped WSARecv absorbing the data. */
#include "lift07.h"

struct rd_poll { SOCKET s; short events; short revents; };
static DWORD WINAPI rd_poll_thread(void *arg)
{
    struct rd_poll *p = arg;
    WSAPOLLFD f;
    f.fd = p->s; f.events = p->events; f.revents = 0;
    U(WSAPoll)(&f, 1, 500);
    p->revents = f.revents;
    return 0;
}

L7EVTEST(l07_read_arrival_and_reselect)
{
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    l7_select(c, sv, L7_NO_WRITE);
    L7_NONE(c);
    CHECK(U(send)(cl, "data", 5, 0) == 5);
    l7_expect(c, FD_READ, 0, 1000);
    L7_NONE(c);
    l7_select(c, sv, L7_NO_WRITE);
    if (c->is_message) l7_expect(c, FD_READ, 0, 1000);
    L7_NONE(c);
    l7_select(c, sv, 0);
    l7_select(c, sv, L7_NO_WRITE);
    if (c->is_message) l7_expect(c, FD_READ, 0, 1000);
    L7_NONE(c);
    l7_close(cl); l7_close(sv);
}

L7EVTEST(l07_read_second_arrival_with_unread_data)
{
    /* More data on top of unread data: an event object is signalled again, a message queue is not. */
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    l7_select(c, sv, L7_NO_WRITE);
    CHECK(U(send)(cl, "data", 5, 0) == 5);
    l7_expect(c, FD_READ, 0, 1000);
    CHECK(U(send)(cl, "data", 5, 0) == 5);
    if (!c->is_message) l7_expect(c, FD_READ, 0, 1000);
    L7_NONE(c);
    l7_close(cl); l7_close(sv);
}

L7EVTEST(l07_read_partial_recv_rearms)
{
    char rx[16];
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    l7_select(c, sv, L7_NO_WRITE);
    CHECK(U(send)(cl, "data", 5, 0) == 5);
    CHECK(U(send)(cl, "data", 5, 0) == 5);
    l7_expect(c, FD_READ, 0, 1000);
    L7_NONE(c);
    CHECK(U(recv)(sv, rx, 2, 0) == 2);
    l7_expect(c, FD_READ, 0, 1000);
    L7_NONE(c);
    l7_close(cl); l7_close(sv);
}

L7EVTEST(l07_read_failed_recv_with_negative_length)
{
    /* recv with an impossible length fails (WSAEFAULT; older systems said WSAENOBUFS).  With unread data
     * the failed call re-posts FD_READ to a window but leaves an event object quiet. */
    char rx[16]; int r;
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    l7_select(c, sv, L7_NO_WRITE);
    CHECK(U(send)(cl, "data", 5, 0) == 5);
    l7_expect(c, FD_READ, 0, 1000);
    r = U(recv)(sv, rx, -1, 0);
    CHECKF(r == -1 && (l7_err() == WSAEFAULT || l7_err() == WSAENOBUFS), "r=%d err=%d", r, l7_err());
    if (c->is_message) l7_expect(c, FD_READ, 0, 1000);
    L7_NONE(c);
    l7_close(cl); l7_close(sv);
}

L7EVTEST(l07_read_byte_by_byte_drain)
{
    char rx[16]; int i;
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    l7_select(c, sv, L7_NO_WRITE);
    CHECK(U(send)(cl, "12345678", 8, 0) == 8);
    l7_expect(c, FD_READ, 0, 1000);
    for (i = 0; i < 8; ++i) {
        CHECKF(l7_sync_recv(sv, rx, 1) == 1, "byte %d", i);
        if (i < 7) l7_expect(c, FD_READ, 0, 1000);
        L7_NONE(c);
    }
    l7_close(cl); l7_close(sv);
}

L7EVTEST(l07_read_data_while_not_selecting)
{
    char rx[16];
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    l7_select(c, sv, 0);
    CHECK(U(send)(cl, "data", 5, 0) == 5);
    l7_select(c, sv, L7_NO_WRITE);
    l7_expect(c, FD_READ, 0, 1000);
    CHECK(U(recv)(sv, rx, 5, 0) == 5);
    l7_close(cl); l7_close(sv);
}

L7EVTEST(l07_read_data_consumed_while_not_selecting)
{
    /* Data that came and went entirely while unselected raises nothing on selection. */
    char rx[16];
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    l7_select(c, sv, 0);
    CHECK(U(send)(cl, "data", 5, 0) == 5);
    CHECK(l7_sync_recv(sv, rx, 5) == 5);
    l7_select(c, sv, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ);
    l7_expect(c, 0, 0, 200);
    l7_close(cl); l7_close(sv);
}

L7EVTEST(l07_read_poll_does_not_consume_notification)
{
    /* Data arriving while another thread polls for it (and the socket is not selected for FD_READ) is
     * reported to WSAPoll but left for a later selection; enumerating events must not clear it. */
    char rx[16]; struct rd_poll p; HANDLE th;
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    p.s = sv; p.events = POLLIN; p.revents = 0;
    th = CreateThread(NULL, 0, rd_poll_thread, &p, 0, NULL);
    l7_select(c, sv, 0);
    CHECK(U(send)(cl, "data", 5, 0) == 5);
    CHECK(WaitForSingleObject(th, 3000) == WAIT_OBJECT_0);
    CloseHandle(th);
    L7_NONE(c);
    l7_select(c, sv, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    l7_expect(c, FD_READ, FD_WRITE, 1000);
    L7_NONE(c);
    CHECK(l7_sync_recv(sv, rx, 5) == 5);
    l7_close(cl); l7_close(sv);
}

L7EVTEST(l07_read_pending_wsarecv_absorbs_data)
{
    OVERLAPPED ov = {0}; WSABUF wb; char rx[4]; DWORD flags = 0, size = 0; int r;
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    l7_select(c, sv, L7_NO_WRITE);
    wb.buf = rx; wb.len = 1;
    r = U(WSARecv)(sv, &wb, 1, NULL, &flags, (LPWSAOVERLAPPED)&ov, NULL);
    CHECKF(r == -1 && l7_err() == ERROR_IO_PENDING, "r=%d err=%d", r, l7_err());
    CHECK(U(send)(cl, "a", 1, 0) == 1);
    CHECK(WaitForSingleObject(ov.hEvent, 2000) == WAIT_OBJECT_0);
    r = GetOverlappedResult((HANDLE)sv, &ov, &size, FALSE);
    CHECKF(r && size == 1, "result r=%d size=%lu", r, size);
    L7_NONE(c);
    CHECK(U(send)(cl, "a", 1, 0) == 1);
    l7_expect(c, FD_READ, 0, 1000);
    L7_NONE(c);
    l7_close(cl); l7_close(sv);
    CloseHandle(ov.hEvent);
}
