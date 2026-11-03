/* Measures FD_WRITE notification on connected stream sockets through WSAEventSelect and WSAAsyncSelect:
 * the initial writable report, edge behaviour (sending does not re-arm it, only a full send buffer that
 * drains does), selecting a subset first and sending right after selecting. */
#include "lift07.h"

L7EVTEST(l07_write_initial_report_and_reselect)
{
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    l7_select(c, sv, L7_ALL_EV);
    l7_expect(c, FD_WRITE, 0, 1000);
    L7_NONE(c);
    l7_select(c, sv, L7_ALL_EV);
    if (c->is_message) l7_expect(c, FD_WRITE, 0, 1000);
    L7_NONE(c);
    l7_select(c, sv, 0);
    l7_select(c, sv, L7_ALL_EV);
    if (c->is_message) l7_expect(c, FD_WRITE, 0, 1000);
    L7_NONE(c);
    l7_close(cl); l7_close(sv);
}

L7EVTEST(l07_write_small_send_is_silent)
{
    char rx[16];
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    l7_select(c, sv, L7_ALL_EV);
    l7_expect(c, FD_WRITE, 0, 1000);
    CHECK(U(send)(sv, "data", 5, 0) == 5);
    L7_NONE(c);
    CHECK(l7_sync_recv(cl, rx, sizeof(rx)) == 5);
    L7_NONE(c);
    l7_close(cl); l7_close(sv);
}

L7EVTEST(l07_write_rearmed_after_buffer_full_then_drained)
{
    /* A send that fails with WSAEWOULDBLOCK arms FD_WRITE; once the peer drains, it is reported. */
    enum { SZ = 1024 * 1024 };
    char *buf = malloc(SZ); int r, iter = 0;
    L7_PAIR(cl, sv);
    REQUIRE(buf);
    l7_nonblock(cl, 1);
    l7_select(c, sv, L7_ALL_EV);
    l7_expect(c, FD_WRITE, 0, 1000);
    {
        int partial = 0;
        while ((r = U(send)(sv, buf, SZ, 0)) > 0 && ++iter < 4096)
            if (r != SZ) ++partial;
        CHECKF(partial == 0, "%d partial sends", partial);
    }
    CHECK(r == -1);
    CHECK(l7_err() == WSAEWOULDBLOCK);
    /* The sender may still be moving queued bytes when the first drain pass sees nothing; keep draining
     * until the notification shows up (bounded) instead of assuming one pass empties the pipe. */
    for (iter = 0; iter < 60; ++iter) {
        while (U(recv)(cl, buf, SZ, 0) > 0) {}
        if (l7_err() != WSAEWOULDBLOCK) iter = 1000;
        if (c->is_message) r = (MsgWaitForMultipleObjects(0, NULL, FALSE, 100, QS_POSTMESSAGE) == WAIT_OBJECT_0);
        else r = (WaitForSingleObject(c->event, 100) == WAIT_OBJECT_0);
        if (r) break;
    }
    CHECK(iter < 1000);   /* every drain pass ended on WSAEWOULDBLOCK */
    l7_expect(c, FD_WRITE, 0, 2000);
    L7_NONE(c);
    l7_select(c, sv, 0);
    l7_select(c, sv, L7_ALL_EV);
    if (c->is_message) l7_expect(c, FD_WRITE, 0, 1000);
    L7_NONE(c);
    l7_close(cl); l7_close(sv); free(buf);
}

L7EVTEST(l07_write_subset_without_write_first)
{
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    CHECK(U(send)(cl, "data", 5, 0) == 5);
    l7_select(c, cl, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ);
    if (!c->is_message) l7_expect(c, FD_CONNECT, 0, 1000);
    L7_NONE(c);
    l7_select(c, cl, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    l7_expect(c, FD_WRITE, 0, 1000);
    L7_NONE(c);
    l7_close(cl); l7_close(sv);
}

L7EVTEST(l07_write_send_does_not_clear_pending_write)
{
    /* Unlike FD_ACCEPT and FD_READ, calling send() before collecting the notification does not
     * consume FD_WRITE. */
    L7_PAIR(cl, sv);
    l7_select(c, sv, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    CHECK(U(send)(sv, "data", 5, 0) == 5);
    l7_expect(c, FD_WRITE, 0, 1000);
    l7_close(sv); l7_close(cl);
}
