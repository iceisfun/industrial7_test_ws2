/* Measures FD_ACCEPT notification on a listening socket, delivered either through an event object
 * (WSAEventSelect) or window messages (WSAAsyncSelect): edge-triggering while connections are pending,
 * re-arming by accept(), re-selection behaviour, inheritance of the selection by accepted sockets and the
 * effect of a pending AcceptEx. */
#include "lift07.h"

static SOCKET acc_connect(const struct sockaddr_in *a)
{
    SOCKET c = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECKF(c != INVALID_SOCKET, "socket failed");
    CHECKF(U(connect)(c, (const struct sockaddr *)a, sizeof(*a)) == 0, "connect failed (%d)", l7_err());
    return c;
}
static void acc_accept_close(SOCKET l)
{
    SOCKET s = U(accept)(l, NULL, NULL);
    CHECKF(s != INVALID_SOCKET, "accept failed (%d)", l7_err());
    if (s != INVALID_SOCKET) l7_close(s);
}
#define ACC_SETUP \
    struct sockaddr_in addr; SOCKET lst = l7_listener(&addr, 2); \
    if (lst == INVALID_SOCKET) { t_skip("no listener"); return; }

L7EVTEST(l07_accept_quiet_before_connection)
{
    ACC_SETUP
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    L7_NONE(c);
    l7_close(lst);
}

L7EVTEST(l07_accept_signalled_by_pending_connection)
{
    SOCKET cl;
    ACC_SETUP
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    cl = acc_connect(&addr);
    l7_expect(c, FD_ACCEPT, 0, 1000);
    L7_NONE(c);
    l7_close(cl); l7_close(lst);
}

L7EVTEST(l07_accept_reselect_semantics)
{
    /* Re-selecting while a connection is still queued: window messages are re-posted, an event object is
     * not re-signalled; the same holds after clearing the selection first. */
    SOCKET cl;
    ACC_SETUP
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    cl = acc_connect(&addr);
    l7_expect(c, FD_ACCEPT, 0, 1000);
    L7_NONE(c);
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    if (c->is_message) l7_expect(c, FD_ACCEPT, 0, 1000);
    L7_NONE(c);
    l7_select(c, lst, 0);
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    if (c->is_message) l7_expect(c, FD_ACCEPT, 0, 1000);
    L7_NONE(c);
    l7_close(cl); l7_close(lst);
}

L7EVTEST(l07_accept_two_pending_connections)
{
    SOCKET c1, c2;
    ACC_SETUP
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    c1 = acc_connect(&addr);
    l7_expect(c, FD_ACCEPT, 0, 1000);
    L7_NONE(c);

    c2 = acc_connect(&addr);
    /* a second connection re-signals an event object but not a message queue */
    if (!c->is_message) l7_expect(c, FD_ACCEPT, 0, 1000);
    L7_NONE(c);

    acc_accept_close(lst);                    /* one left: accept() re-arms the notification */
    l7_expect(c, FD_ACCEPT, 0, 1000);
    L7_NONE(c);
    acc_accept_close(lst);                    /* queue empty: nothing more */
    L7_NONE(c);
    l7_close(c2); l7_close(c1); l7_close(lst);
}

L7EVTEST(l07_accept_peer_gone_after_accept)
{
    SOCKET cl;
    ACC_SETUP
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    cl = acc_connect(&addr);
    l7_expect(c, FD_ACCEPT, 0, 1000);
    acc_accept_close(lst);
    l7_close(cl);
    l7_expect(c, 0, 0, 200);
    l7_close(lst);
}

L7EVTEST(l07_accept_connect_before_select)
{
    SOCKET cl;
    ACC_SETUP
    cl = acc_connect(&addr);
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    l7_expect(c, FD_ACCEPT, 0, 1000);
    acc_accept_close(lst);
    l7_close(cl); l7_close(lst);
}

L7EVTEST(l07_accept_event_object_subset_reselect)
{
    /* Event objects only: a pending connection keeps the event set across re-selecting without FD_ACCEPT,
     * and ResetEvent plus a selection without FD_ACCEPT does not signal. */
    SOCKET cl;
    int r;
    ACC_SETUP
    if (c->is_message) { l7_close(lst); t_skip("event-object mode only"); return; }
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    cl = acc_connect(&addr);
    CHECK(WaitForSingleObject(c->event, 1000) == WAIT_OBJECT_0);
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB);
    CHECK(WaitForSingleObject(c->event, 0) == WAIT_OBJECT_0);
    ResetEvent(c->event);
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB);
    r = WaitForSingleObject(c->event, 0);
    CHECKF(r == WAIT_TIMEOUT, "signalled without FD_ACCEPT selected");
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    CHECK(WaitForSingleObject(c->event, 0) == WAIT_OBJECT_0);
    l7_expect(c, FD_ACCEPT, 0, 0);
    acc_accept_close(lst);
    l7_close(cl); l7_close(lst);
}

L7EVTEST(l07_accept_select_without_accept_first)
{
    SOCKET cl;
    ACC_SETUP
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB);
    cl = acc_connect(&addr);
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    l7_expect(c, FD_ACCEPT, 0, 1000);
    acc_accept_close(lst);
    l7_close(cl); l7_close(lst);
}

L7EVTEST(l07_accept_consumed_before_select)
{
    SOCKET cl, sv;
    ACC_SETUP
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB);
    cl = acc_connect(&addr);
    Sleep(200);                                   /* let the connection reach the accept queue */
    sv = U(accept)(lst, NULL, NULL);
    CHECK(sv != INVALID_SOCKET);
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    l7_expect(c, 0, 0, 200);
    if (sv != INVALID_SOCKET) l7_close(sv);
    l7_close(cl); l7_close(lst);
}

L7EVTEST(l07_accept_selection_inherited_by_accepted_socket)
{
    /* The accepted socket carries the listener's selection: FD_WRITE (selected on the listener) shows up
     * for it right away. */
    SOCKET cl, sv;
    ACC_SETUP
    cl = acc_connect(&addr);
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT | FD_WRITE);
    l7_expect(c, FD_ACCEPT, 0, 1000);
    sv = U(accept)(lst, NULL, NULL);
    CHECK(sv != INVALID_SOCKET);
    c->socket = sv;
    l7_expect(c, FD_WRITE, 0, 1000);
    L7_NONE(c);
    if (sv != INVALID_SOCKET) l7_close(sv);
    l7_close(cl); l7_close(lst);
}

L7EVTEST(l07_accept_pending_acceptex_consumes_connection)
{
    /* A connection taken by a pending AcceptEx raises no FD_ACCEPT; a later one does. */
    GUID g = WSAID_ACCEPTEX; LPFN_ACCEPTEX acceptex = NULL; DWORD size; char buf[32];
    OVERLAPPED ov = {0}; SOCKET as, c1, c2; BOOL r; int ir;
    ACC_SETUP
    ir = l7_ioctl(lst, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof(g), &acceptex, sizeof(acceptex), &size, NULL, NULL);
    if (ir || !acceptex) { l7_close(lst); t_skip("AcceptEx unavailable"); return; }
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    l7_select(c, lst, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    as = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    r = acceptex(lst, as, buf, 0, 0, sizeof(buf), NULL, &ov);
    CHECKF(!r && l7_err() == ERROR_IO_PENDING, "AcceptEx r=%d err=%d", r, l7_err());
    c1 = acc_connect(&addr);
    CHECK(WaitForSingleObject(ov.hEvent, 2000) == WAIT_OBJECT_0);
    r = GetOverlappedResult((HANDLE)lst, &ov, &size, FALSE);
    CHECKF(r && size == 0, "AcceptEx result r=%d size=%lu", r, size);
    L7_NONE(c);
    l7_close(as); l7_close(c1);

    c2 = acc_connect(&addr);
    l7_expect(c, FD_ACCEPT, 0, 1000);
    L7_NONE(c);
    acc_accept_close(lst);
    l7_close(c2); l7_close(lst);
    CloseHandle(ov.hEvent);
}
