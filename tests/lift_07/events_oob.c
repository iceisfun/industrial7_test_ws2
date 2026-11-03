/* Measures FD_OOB notification (urgent data) through WSAEventSelect and WSAAsyncSelect: arrival,
 * re-selection, a second urgent byte, re-arming by reading urgent data, and urgent data arriving while
 * unselected. */
#include "lift07.h"

L7EVTEST(l07_oob_arrival_and_reselect)
{
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    l7_select(c, sv, L7_NO_WRITE);
    L7_NONE(c);
    CHECK(U(send)(cl, "a", 1, MSG_OOB) == 1);
    l7_expect(c, FD_OOB, 0, 1000);
    L7_NONE(c);
    l7_select(c, sv, L7_NO_WRITE);
    if (c->is_message) l7_expect(c, FD_OOB, 0, 1000);
    L7_NONE(c);
    l7_select(c, sv, 0);
    l7_select(c, sv, L7_NO_WRITE);
    if (c->is_message) l7_expect(c, FD_OOB, 0, 1000);
    L7_NONE(c);
    l7_close(cl); l7_close(sv);
}

L7EVTEST(l07_oob_second_byte_and_reads)
{
    /* Two urgent bytes: an event object is signalled for the second while the first is unread, a window
     * is not; reading one urgent byte re-arms FD_OOB while another remains; both bytes are readable. */
    char rx[2];
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    l7_select(c, sv, L7_NO_WRITE);
    CHECK(U(send)(cl, "a", 1, MSG_OOB) == 1);
    l7_expect(c, FD_OOB, 0, 1000);
    CHECK(U(send)(cl, "b", 1, MSG_OOB) == 1);
    if (!c->is_message) l7_expect(c, FD_OOB, 0, 1000);
    L7_NONE(c);
    CHECK(U(recv)(sv, rx, 1, MSG_OOB) == 1);
    l7_expect(c, FD_OOB, 0, 1000);
    L7_NONE(c);
    CHECK(U(recv)(sv, rx, 1, MSG_OOB) == 1);
    L7_NONE(c);
    l7_close(cl); l7_close(sv);
}

L7EVTEST(l07_oob_arrival_while_not_selecting)
{
    char rx[2];
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    l7_select(c, sv, 0);
    CHECK(U(send)(cl, "a", 1, MSG_OOB) == 1);
    l7_select(c, sv, L7_NO_WRITE);
    l7_expect(c, FD_OOB, 0, 1000);
    CHECK(U(recv)(sv, rx, 1, MSG_OOB) == 1);
    l7_close(cl); l7_close(sv);
}
