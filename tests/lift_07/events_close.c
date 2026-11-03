/* Measures FD_CLOSE notification through WSAEventSelect and WSAAsyncSelect: orderly close and
 * half-close by the peer, shutdown directions that raise nothing, the interplay with unread data, selecting
 * after the close, and the error code carried by an abortive close. */
#include "lift07.h"

L7EVTEST(l07_close_peer_closesocket)
{
    char rx[8];
    L7_PAIR(cl, sv);
    l7_select(c, sv, L7_NO_WRITE);
    l7_close(cl);
    l7_expect(c, FD_CLOSE, 0, 2000);
    L7_NONE(c);
    l7_select(c, sv, L7_NO_WRITE);
    if (c->is_message) l7_expect(c, FD_CLOSE, 0, 1000);
    L7_NONE(c);
    l7_select(c, sv, 0);
    l7_select(c, sv, L7_NO_WRITE);
    if (c->is_message) l7_expect(c, FD_CLOSE, 0, 1000);
    L7_NONE(c);
    CHECK(U(recv)(sv, rx, 5, 0) == 0);
    L7_NONE(c);
    l7_close(sv);
}

L7EVTEST(l07_close_peer_shutdown_send)
{
    L7_PAIR(cl, sv);
    l7_select(c, sv, L7_NO_WRITE);
    U(shutdown)(cl, SD_SEND);
    l7_expect(c, FD_CLOSE, 0, 2000);
    L7_NONE(c);
    l7_close(cl);
    L7_NONE(c);
    l7_close(sv);
}

L7EVTEST(l07_close_other_shutdowns_are_silent)
{
    L7_PAIR(cl, sv);
    l7_select(c, sv, L7_NO_WRITE);
    U(shutdown)(cl, SD_RECEIVE);
    U(shutdown)(sv, SD_BOTH);
    l7_expect(c, 0, 0, 200);
    /* but the peer's later SD_SEND is a close indication */
    U(shutdown)(cl, SD_SEND);
    l7_expect(c, FD_CLOSE, 0, 1000);
    L7_NONE(c);
    l7_close(sv); l7_close(cl);
}

L7EVTEST(l07_close_after_data_defers_until_read)
{
    /* Unread data in front of the FIN: FD_READ first, FD_CLOSE after the peer closes; reading part of the
     * data re-arms FD_READ; draining the rest raises nothing more. */
    char rx[8];
    L7_PAIR(cl, sv);
    l7_select(c, sv, L7_NO_WRITE);
    CHECK(U(send)(cl, "data", 5, 0) == 5);
    l7_expect(c, FD_READ, 0, 1000);
    l7_close(cl);
    l7_expect(c, FD_CLOSE, 0, 1000);
    CHECK(U(recv)(sv, rx, 3, 0) == 3);
    l7_expect(c, FD_READ, 0, 1000);
    CHECK(U(recv)(sv, rx, 5, 0) == 2);
    l7_expect(c, 0, 0, 0);
    l7_close(sv);
}

L7EVTEST(l07_close_then_select)
{
    L7_PAIR(cl, sv);
    l7_close(cl);
    l7_select(c, sv, L7_NO_WRITE);
    l7_expect(c, FD_CLOSE, 0, 2000);
    l7_close(sv);
}

L7EVTEST(l07_close_select_subset_without_close_first)
{
    L7_PAIR(cl, sv);
    l7_select(c, sv, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ);
    l7_close(cl);
    l7_expect(c, 0, 0, 200);
    l7_select(c, sv, L7_NO_WRITE);
    l7_expect(c, FD_CLOSE, 0, 1000);
    l7_close(sv);
}

L7EVTEST(l07_close_abortive_reports_connaborted)
{
    L7_PAIR(cl, sv);
    l7_select(c, sv, L7_NO_WRITE);
    l7_rst_close(cl);
    l7_expect(c, MAKELONG(FD_CLOSE, WSAECONNABORTED), 0, 2000);
    L7_NONE(c);
    l7_select(c, sv, L7_NO_WRITE);
    if (c->is_message) l7_expect(c, MAKELONG(FD_CLOSE, WSAECONNABORTED), 0, 1000);
    L7_NONE(c);
    l7_select(c, sv, 0);
    l7_select(c, sv, L7_NO_WRITE);
    if (c->is_message) l7_expect(c, MAKELONG(FD_CLOSE, WSAECONNABORTED), 0, 1000);
    L7_NONE(c);
    l7_close(sv);
}
