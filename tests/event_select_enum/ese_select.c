/* Measures WSAEventSelect argument handling and its side effects: bad sockets (WSAENOTSOCK), the
 * 0x3ff mask boundary (WSAEINVAL above it), NULL / closed / wrong-type event handles, per-bit masks,
 * replacing and cancelling a selection, the forced non-blocking mode and how to undo it, one event
 * shared by several sockets, and one socket moving between events. */
#include "ese.h"

#define SOCKET_FOR(ev, s, mask) U(WSAEventSelect)((s), (ev), (mask))

/* ---- bad sockets --------------------------------------------------------------------------------------- */
ESTEST(ese_select_invalid_socket_value)
{
    HANDLE ev = es_ev(); int r;
    REQUIRE(ev);
    U(WSASetLastError)(0);
    r = U(WSAEventSelect)(INVALID_SOCKET, ev, FD_READ);
    CHECK(r == SOCKET_ERROR);
    ES_EQ(es_err(), WSAENOTSOCK);
    U(WSACloseEvent)(ev);
}
ESTEST(ese_select_zero_socket_value)
{
    HANDLE ev = es_ev(); int r;
    REQUIRE(ev);
    U(WSASetLastError)(0);
    r = U(WSAEventSelect)(0, ev, FD_READ);
    CHECK(r == SOCKET_ERROR);
    ES_EQ(es_err(), WSAENOTSOCK);
    U(WSACloseEvent)(ev);
}
ESTEST(ese_select_non_socket_handle)
{
    HANDLE ev = es_ev(), other = es_ev(); int r;
    REQUIRE(ev && other);
    U(WSASetLastError)(0);
    r = U(WSAEventSelect)((SOCKET)other, ev, FD_READ);
    CHECK(r == SOCKET_ERROR);
    ES_EQ(es_err(), WSAENOTSOCK);
    U(WSACloseEvent)(ev); U(WSACloseEvent)(other);
}
ESTEST(ese_select_closed_socket)
{
    HANDLE ev = es_ev(); SOCKET s = es_sock(SOCK_STREAM); int r;
    REQUIRE(ev && s != INVALID_SOCKET);
    es_close(s);
    U(WSASetLastError)(0);
    r = U(WSAEventSelect)(s, ev, FD_READ);
    CHECK(r == SOCKET_ERROR);
    ES_EQ(es_err(), WSAENOTSOCK);
    U(WSACloseEvent)(ev);
}
ESTEST(ese_select_bad_socket_wins_over_bad_mask)
{
    HANDLE ev = es_ev(); int r;
    REQUIRE(ev);
    U(WSASetLastError)(0);
    r = U(WSAEventSelect)(INVALID_SOCKET, ev, 0xFFFFFFFF);
    CHECK(r == SOCKET_ERROR);
    ES_EQ(es_err(), WSAENOTSOCK);
    U(WSACloseEvent)(ev);
}
ESTEST(ese_select_bad_socket_with_null_event_zero_mask)
{
    int r;
    U(WSASetLastError)(0);
    r = U(WSAEventSelect)(INVALID_SOCKET, NULL, 0);
    CHECK(r == SOCKET_ERROR);
    ES_EQ(es_err(), WSAENOTSOCK);
}
ESTEST(ese_select_success_returns_zero_not_count)
{
    SOCKET s = es_sock(SOCK_STREAM); HANDLE ev = es_ev();
    REQUIRE(s != INVALID_SOCKET && ev);
    ES_EQ(U(WSAEventSelect)(s, ev, FD_READ | FD_WRITE | FD_CLOSE), 0);
    es_close(s); U(WSACloseEvent)(ev);
}

/* ---- masks --------------------------------------------------------------------------------------------- */
static const LONG es_single_bits[] = { FD_READ, FD_WRITE, FD_OOB, FD_ACCEPT, FD_CONNECT, FD_CLOSE, FD_QOS,
                                       FD_GROUP_QOS, FD_ROUTING_INTERFACE_CHANGE, FD_ADDRESS_LIST_CHANGE };
static void es_mask_table(int type)
{
    SOCKET s = es_sock(type); HANDLE ev = es_ev(); int i;
    REQUIRE(s != INVALID_SOCKET && ev);
    for (i = 0; i < 10; ++i) {
        int r = U(WSAEventSelect)(s, ev, es_single_bits[i]);
        CHECKF(r == 0, "bit %#lx err %d", es_single_bits[i], es_err());
    }
    for (i = 0; i < 10; ++i) {
        int r = U(WSAEventSelect)(s, ev, FD_ALL_EVENTS & ~es_single_bits[i]);
        CHECKF(r == 0, "all-but %#lx err %d", es_single_bits[i], es_err());
    }
    ES_EQ(U(WSAEventSelect)(s, ev, FD_ALL_EVENTS), 0);
    ES_EQ(U(WSAEventSelect)(s, ev, 0), 0);
    es_close(s); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_each_valid_bit_tcp)  { es_mask_table(SOCK_STREAM); }
ESTEST(ese_select_each_valid_bit_udp)  { es_mask_table(SOCK_DGRAM); }

static const unsigned long es_bad_masks[] = { 0x400, 0x800, 0x1000, 0x8000, 0x10000, 0x100000, 0x01000000,
                                              0x80000000, 0xFFFFFFFF, 0x3ff | 0x400, 0xFFFFFC00, 0x40000000 };
ESTEST(ese_select_mask_above_all_events_is_einval)
{
    SOCKET s = es_sock(SOCK_STREAM); HANDLE ev = es_ev(); unsigned i;
    REQUIRE(s != INVALID_SOCKET && ev);
    for (i = 0; i < sizeof(es_bad_masks) / sizeof(es_bad_masks[0]); ++i) {
        int r;
        U(WSASetLastError)(0);
        r = U(WSAEventSelect)(s, ev, (long)es_bad_masks[i]);
        CHECKF(r == SOCKET_ERROR, "mask %#lx accepted", es_bad_masks[i]);
        CHECKF(es_err() == WSAEINVAL, "mask %#lx err %d", es_bad_masks[i], es_err());
    }
    es_close(s); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_bad_mask_with_null_event_is_einval)
{
    SOCKET s = es_sock(SOCK_STREAM); int r;
    REQUIRE(s != INVALID_SOCKET);
    U(WSASetLastError)(0);
    r = U(WSAEventSelect)(s, NULL, 0x400);
    CHECK(r == SOCKET_ERROR);
    ES_EQ(es_err(), WSAEINVAL);
    es_close(s);
}
ESTEST(ese_select_bad_mask_then_good_mask)
{
    SOCKET s = es_sock(SOCK_STREAM); HANDLE ev = es_ev();
    REQUIRE(s != INVALID_SOCKET && ev);
    CHECK(U(WSAEventSelect)(s, ev, 0x400) == SOCKET_ERROR);
    ES_EQ(U(WSAEventSelect)(s, ev, FD_READ), 0);
    es_close(s); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_bad_mask_forces_nonblocking_observed)
{
    /* The mode switch happens before the mask is validated; record what this system does. */
    HANDLE ev; int e;
    ES_PAIR(c, v);
    ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, 0x400) == SOCKET_ERROR);
    e = es_empty_recv_error(c);
    t_note("after rejected mask the socket is %s", e == WSAEWOULDBLOCK ? "non-blocking" : "blocking");
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}

/* ---- event handle -------------------------------------------------------------------------------------- */
ESTEST(ese_select_null_event_nonzero_mask_is_einval)
{
    SOCKET s = es_sock(SOCK_STREAM); int r;
    REQUIRE(s != INVALID_SOCKET);
    U(WSASetLastError)(0);
    r = U(WSAEventSelect)(s, NULL, FD_READ);
    CHECK(r == SOCKET_ERROR);
    ES_EQ(es_err(), WSAEINVAL);
    es_close(s);
}
ESTEST(ese_select_null_event_all_valid_bits_is_einval)
{
    SOCKET s = es_sock(SOCK_STREAM); int r, i;
    REQUIRE(s != INVALID_SOCKET);
    for (i = 0; i < 10; ++i) {
        U(WSASetLastError)(0);
        r = U(WSAEventSelect)(s, NULL, es_single_bits[i]);
        CHECKF(r == SOCKET_ERROR && es_err() == WSAEINVAL, "bit %#lx r=%d err=%d", es_single_bits[i], r, es_err());
    }
    es_close(s);
}
ESTEST(ese_select_null_event_zero_mask_succeeds)
{
    SOCKET s = es_sock(SOCK_STREAM);
    REQUIRE(s != INVALID_SOCKET);
    ES_EQ(U(WSAEventSelect)(s, NULL, 0), 0);
    ES_EQ(U(WSAEventSelect)(s, NULL, 0), 0);
    es_close(s);
}
ESTEST(ese_select_event_with_zero_mask_succeeds)
{
    SOCKET s = es_sock(SOCK_STREAM); HANDLE ev = es_ev();
    REQUIRE(s != INVALID_SOCKET && ev);
    ES_EQ(U(WSAEventSelect)(s, ev, 0), 0);
    es_close(s); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_closed_event_handle_with_mask_fails)
{
    SOCKET s = es_sock(SOCK_STREAM); HANDLE ev = es_ev(); int r;
    REQUIRE(s != INVALID_SOCKET && ev);
    U(WSACloseEvent)(ev);
    U(WSASetLastError)(0);
    r = U(WSAEventSelect)(s, ev, FD_READ);
    CHECK(r == SOCKET_ERROR);
    t_note("closed event handle rejected with error class %s",
           es_err() == WSAEINVAL ? "einval" : es_err() == WSAENOTSOCK ? "enotsock" : "other");
    es_close(s);
}
ESTEST(ese_select_closed_event_handle_with_zero_mask)
{
    SOCKET s = es_sock(SOCK_STREAM); HANDLE ev = es_ev(); int r;
    REQUIRE(s != INVALID_SOCKET && ev);
    U(WSACloseEvent)(ev);
    r = U(WSAEventSelect)(s, ev, 0);
    t_note("closed event handle with empty mask %s", r == 0 ? "accepted" : "rejected");
    es_close(s);
}
ESTEST(ese_select_wrong_object_type_as_event)
{
    SOCKET s = es_sock(SOCK_STREAM); HANDLE m = CreateMutexW(NULL, FALSE, NULL); int r;
    REQUIRE(s != INVALID_SOCKET && m);
    U(WSASetLastError)(0);
    r = U(WSAEventSelect)(s, m, FD_READ);
    t_note("mutex handle as event object %s", r == 0 ? "accepted" : "rejected");
    if (r == 0) U(WSAEventSelect)(s, NULL, 0);
    es_close(s); CloseHandle(m);
}
ESTEST(ese_select_auto_reset_event_object_is_accepted)
{
    SOCKET s = es_sock(SOCK_STREAM); HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    REQUIRE(s != INVALID_SOCKET && ev);
    ES_EQ(U(WSAEventSelect)(s, ev, FD_READ), 0);
    es_close(s); CloseHandle(ev);
}
ESTEST(ese_select_pseudo_handle_as_event_observed)
{
    SOCKET s = es_sock(SOCK_STREAM); int r;
    REQUIRE(s != INVALID_SOCKET);
    r = U(WSAEventSelect)(s, GetCurrentProcess(), FD_READ);
    t_note("process pseudo-handle as event %s", r == 0 ? "accepted" : "rejected");
    if (r == 0) U(WSAEventSelect)(s, NULL, 0);
    es_close(s);
}

/* ---- non-blocking side effect ------------------------------------------------------------------------- */
ESTEST(ese_select_makes_socket_nonblocking)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    ES_EQ(es_empty_recv_error(c), WSAETIMEDOUT);          /* blocking before */
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    ES_EQ(es_empty_recv_error(c), WSAEWOULDBLOCK);        /* non-blocking after */
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_cancel_keeps_socket_nonblocking)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(U(WSAEventSelect)(c, NULL, 0) == 0);
    ES_EQ(es_empty_recv_error(c), WSAEWOULDBLOCK);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_cancel_with_event_keeps_socket_nonblocking)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(U(WSAEventSelect)(c, ev, 0) == 0);
    ES_EQ(es_empty_recv_error(c), WSAEWOULDBLOCK);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_undo_nonblocking_after_cancel_via_ioctl)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); u_long blocking = 0;
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(U(WSAEventSelect)(c, NULL, 0) == 0);
    ES_EQ(U(ioctlsocket)(c, FIONBIO, &blocking), 0);
    ES_EQ(es_empty_recv_error(c), WSAETIMEDOUT);          /* blocking again */
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_ioctl_blocking_refused_while_selected)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); u_long blocking = 0; int r;
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ | FD_CLOSE) == 0);
    U(WSASetLastError)(0);
    r = U(ioctlsocket)(c, FIONBIO, &blocking);
    CHECK(r == SOCKET_ERROR);
    ES_EQ(es_err(), WSAEINVAL);
    ES_EQ(es_empty_recv_error(c), WSAEWOULDBLOCK);        /* still non-blocking */
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_ioctl_blocking_after_zero_mask_with_event)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); u_long blocking = 0;
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(U(WSAEventSelect)(c, ev, 0) == 0);
    ES_EQ(U(ioctlsocket)(c, FIONBIO, &blocking), 0);
    ES_EQ(es_empty_recv_error(c), WSAETIMEDOUT);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_ioctl_nonblocking_stays_after_cancel)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    es_nonblock(c, 1);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(U(WSAEventSelect)(c, NULL, 0) == 0);
    ES_EQ(es_empty_recv_error(c), WSAEWOULDBLOCK);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_reselect_after_unblock_restores_nonblocking)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); u_long blocking = 0;
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(U(WSAEventSelect)(c, NULL, 0) == 0);
    CHECK(U(ioctlsocket)(c, FIONBIO, &blocking) == 0);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    ES_EQ(es_empty_recv_error(c), WSAEWOULDBLOCK);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_zero_mask_on_fresh_socket_blocking_mode_observed)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, NULL, 0) == 0);
    t_note("empty selection on a blocking socket leaves it %s",
           es_empty_recv_error(c) == WSAEWOULDBLOCK ? "non-blocking" : "blocking");
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_listener_accept_after_select_is_nonblocking)
{
    struct sockaddr_in a; SOCKET l = es_listener(&a, 1), r; HANDLE ev = es_ev();
    REQUIRE(l != INVALID_SOCKET && ev);
    CHECK(U(WSAEventSelect)(l, ev, FD_ACCEPT) == 0);
    U(WSASetLastError)(0);
    r = U(accept)(l, NULL, NULL);                    /* nothing pending: must not block */
    CHECK(r == INVALID_SOCKET);
    ES_EQ(es_err(), WSAEWOULDBLOCK);
    es_close(l); U(WSACloseEvent)(ev);
}

/* ---- replacing and cancelling ------------------------------------------------------------------------- */
ESTEST(ese_select_reselect_other_event_moves_notifications)
{
    ES_PAIR(c, v);
    HANDLE e1 = es_ev(), e2 = es_ev();
    REQUIRE(e1 && e2);
    CHECK(U(WSAEventSelect)(c, e1, FD_READ) == 0);
    CHECK(U(WSAEventSelect)(c, e2, FD_READ) == 0);
    CHECK(es_send_all(v, "x", 1) == 1);
    CHECK(es_wait(e2, 2000));
    CHECK(!es_signalled(e1));
    es_close(c); es_close(v); U(WSACloseEvent)(e1); U(WSACloseEvent)(e2);
}
ESTEST(ese_select_reselect_other_event_leaves_old_event_state)
{
    /* A signalled old event stays signalled when the socket moves away from it. */
    ES_PAIR(c, v);
    HANDLE e1 = es_ev(), e2 = es_ev();
    REQUIRE(e1 && e2);
    CHECK(U(WSAEventSelect)(c, e1, FD_READ | FD_WRITE) == 0);
    CHECK(es_signalled(e1) || es_wait(e1, 1000));
    CHECK(U(WSAEventSelect)(c, e2, FD_READ) == 0);
    CHECK(es_signalled(e1));
    es_close(c); es_close(v); U(WSACloseEvent)(e1); U(WSACloseEvent)(e2);
}
ESTEST(ese_select_mask_replaced_not_merged)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(U(WSAEventSelect)(c, ev, FD_CLOSE) == 0);
    CHECK(es_send_all(v, "x", 1) == 1);
    CHECK(!es_wait(ev, 200));                        /* FD_READ no longer selected */
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_cancel_stops_notifications)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(U(WSAEventSelect)(c, NULL, 0) == 0);
    CHECK(es_send_all(v, "x", 1) == 1);
    CHECK(!es_wait(ev, 200));
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_cancel_does_not_reset_signalled_event)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(es_send_all(v, "x", 1) == 1);
    CHECK(es_wait(ev, 2000));
    CHECK(U(WSAEventSelect)(c, NULL, 0) == 0);
    CHECK(es_signalled(ev));
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_cancel_discards_recorded_events)
{
    /* Events recorded before the cancel are not available afterwards. */
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(es_send_all(v, "x", 1) == 1);
    CHECK(es_wait(ev, 2000));
    CHECK(U(WSAEventSelect)(c, NULL, 0) == 0);
    t_note("pending FD_READ after cancel: mask %ld", es_mask(c, NULL));
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_same_selection_twice_is_idempotent)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ | FD_CLOSE) == 0);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ | FD_CLOSE) == 0);
    CHECK(es_send_all(v, "x", 1) == 1);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_mask(c, ev), FD_READ);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_survives_enum)
{
    /* Enumerating does not cancel the selection: the next arrival signals the event again. */
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); char b[4];
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(es_send_all(v, "x", 1) == 1);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_mask(c, ev), FD_READ);
    CHECK(U(recv)(c, b, 4, 0) == 1);
    CHECK(es_send_all(v, "y", 1) == 1);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_mask(c, ev), FD_READ);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_event_survives_event_close_and_replace)
{
    /* Close the first event, move the selection to a new one: the socket keeps working. */
    ES_PAIR(c, v);
    HANDLE e1 = es_ev(), e2 = es_ev();
    REQUIRE(e1 && e2);
    CHECK(U(WSAEventSelect)(c, e1, FD_READ) == 0);
    CHECK(U(WSACloseEvent)(e1));
    CHECK(U(WSAEventSelect)(c, e2, FD_READ) == 0);
    CHECK(es_send_all(v, "x", 1) == 1);
    CHECK(es_wait(e2, 2000));
    es_close(c); es_close(v); U(WSACloseEvent)(e2);
}

/* ---- several sockets, one event ------------------------------------------------------------------------ */
ESTEST(ese_select_one_event_two_sockets_either_signals)
{
    ES_PAIR(a, av);
    ES_PAIR(b, bv);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(a, ev, FD_READ) == 0);
    CHECK(U(WSAEventSelect)(b, ev, FD_READ) == 0);
    CHECK(es_send_all(bv, "x", 1) == 1);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_mask(a, NULL), 0);
    ES_EQ(es_mask(b, NULL), FD_READ);
    es_close(a); es_close(av); es_close(b); es_close(bv); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_one_event_enum_of_one_socket_resets_for_both)
{
    ES_PAIR(a, av);
    ES_PAIR(b, bv);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(a, ev, FD_READ) == 0);
    CHECK(U(WSAEventSelect)(b, ev, FD_READ) == 0);
    CHECK(es_send_all(av, "x", 1) == 1);
    CHECK(es_send_all(bv, "y", 1) == 1);
    CHECK(es_wait(ev, 2000));
    Sleep(50);
    ES_EQ(es_mask(a, ev), FD_READ);
    CHECK(!es_signalled(ev));                           /* reset although b still has a record */
    ES_EQ(es_mask(b, NULL), FD_READ);                   /* but b's record is intact */
    es_close(a); es_close(av); es_close(b); es_close(bv); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_two_sockets_two_events_independent)
{
    ES_PAIR(a, av);
    ES_PAIR(b, bv);
    HANDLE ea = es_ev(), eb = es_ev();
    REQUIRE(ea && eb);
    CHECK(U(WSAEventSelect)(a, ea, FD_READ) == 0);
    CHECK(U(WSAEventSelect)(b, eb, FD_READ) == 0);
    CHECK(es_send_all(bv, "x", 1) == 1);
    CHECK(es_wait(eb, 2000));
    CHECK(!es_signalled(ea));
    es_close(a); es_close(av); es_close(b); es_close(bv); U(WSACloseEvent)(ea); U(WSACloseEvent)(eb);
}
ESTEST(ese_select_cancel_one_socket_leaves_other)
{
    ES_PAIR(a, av);
    ES_PAIR(b, bv);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(a, ev, FD_READ) == 0);
    CHECK(U(WSAEventSelect)(b, ev, FD_READ) == 0);
    CHECK(U(WSAEventSelect)(a, NULL, 0) == 0);
    CHECK(es_send_all(av, "x", 1) == 1);
    CHECK(!es_wait(ev, 150));
    CHECK(es_send_all(bv, "y", 1) == 1);
    CHECK(es_wait(ev, 2000));
    es_close(a); es_close(av); es_close(b); es_close(bv); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_socket_pair_halves_have_separate_selections)
{
    ES_PAIR(c, v);
    HANDLE ec = es_ev(), ev = es_ev();
    REQUIRE(ec && ev);
    CHECK(U(WSAEventSelect)(c, ec, FD_READ) == 0);
    CHECK(es_send_all(c, "x", 1) == 1);                 /* data for v only */
    CHECK(!es_wait(ec, 150));
    CHECK(U(WSAEventSelect)(v, ev, FD_READ) == 0);
    CHECK(es_wait(ev, 2000));
    es_close(c); es_close(v); U(WSACloseEvent)(ec); U(WSACloseEvent)(ev);
}

/* ---- other socket kinds ------------------------------------------------------------------------------- */
ESTEST(ese_select_listener_all_events)
{
    struct sockaddr_in a; SOCKET l = es_listener(&a, 2); HANDLE ev = es_ev();
    REQUIRE(l != INVALID_SOCKET && ev);
    ES_EQ(U(WSAEventSelect)(l, ev, FD_ALL_EVENTS), 0);
    es_close(l); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_accepted_socket_inherits_nothing_by_hand)
{
    /* A fresh WSASocket without the overlapped flag accepts a selection like any other. */
    SOCKET s = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0); HANDLE ev = es_ev();
    REQUIRE(s != INVALID_SOCKET && ev);
    ES_EQ(U(WSAEventSelect)(s, ev, FD_CONNECT | FD_CLOSE), 0);
    es_close(s); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_overlapped_flag_socket)
{
    SOCKET s = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED); HANDLE ev = es_ev();
    REQUIRE(s != INVALID_SOCKET && ev);
    ES_EQ(U(WSAEventSelect)(s, ev, FD_CONNECT | FD_CLOSE), 0);
    es_close(s); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_ipv6_loopback_socket)
{
    SOCKET s = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP); HANDLE ev = es_ev();
    if (s == INVALID_SOCKET) { t_skip("no IPv6 socket support"); return; }
    REQUIRE(ev);
    ES_EQ(U(WSAEventSelect)(s, ev, FD_READ | FD_WRITE | FD_CONNECT | FD_CLOSE), 0);
    es_close(s); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_raw_icmp_socket_if_permitted)
{
    SOCKET s = U(socket)(AF_INET, SOCK_RAW, IPPROTO_ICMP); HANDLE ev = es_ev();
    if (s == INVALID_SOCKET) { t_skip("raw sockets not available"); return; }
    REQUIRE(ev);
    ES_EQ(U(WSAEventSelect)(s, ev, FD_READ | FD_WRITE), 0);
    es_close(s); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_unix_stream_socket_if_supported)
{
    SOCKET s = U(socket)(AF_UNIX, SOCK_STREAM, 0); HANDLE ev = es_ev();
    if (s == INVALID_SOCKET) { t_skip("AF_UNIX not available"); return; }
    REQUIRE(ev);
    ES_EQ(U(WSAEventSelect)(s, ev, FD_ACCEPT | FD_READ | FD_CLOSE), 0);
    es_close(s); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_after_shutdown_both)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(shutdown)(c, SD_BOTH) == 0);
    ES_EQ(U(WSAEventSelect)(c, ev, FD_READ | FD_CLOSE), 0);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_select_unbound_udp_then_bind)
{
    SOCKET s = es_sock(SOCK_DGRAM), tx = es_udp(NULL); HANDLE ev = es_ev();
    struct sockaddr_in a; int len = sizeof(a);
    REQUIRE(s != INVALID_SOCKET && tx != INVALID_SOCKET && ev);
    ES_EQ(U(WSAEventSelect)(s, ev, FD_READ), 0);
    es_addr(&a, 0);
    CHECK(U(bind)(s, (struct sockaddr *)&a, sizeof(a)) == 0);
    CHECK(U(getsockname)(s, (struct sockaddr *)&a, &len) == 0);
    CHECK(es_udp_send(tx, &a, "ab", 2) == 2);
    CHECK(es_wait(ev, 2000));
    es_close(s); es_close(tx); U(WSACloseEvent)(ev);
}
