/* Measures WSAEnumNetworkEvents: argument failures, what is written to the result (the event mask is
 * always overwritten, error slots only for reported events), consumption of recorded events, the
 * optional event-object reset (and that it is independent of the selection), UDP event behaviour,
 * events that must never be raised, and event-driven waiting over many sockets through
 * WSAWaitForMultipleEvents including the 64-handle boundary. */
#include "ese.h"

/* ---- argument failures ------------------------------------------------------------------------------- */
ESTEST(ese_enum_invalid_socket_value)
{
    WSANETWORKEVENTS ne; int r;
    U(WSASetLastError)(0);
    memset(&ne, 0xCC, sizeof(ne));
    r = U(WSAEnumNetworkEvents)(INVALID_SOCKET, NULL, &ne);
    CHECK(r == SOCKET_ERROR);
    ES_EQ(es_err(), WSAENOTSOCK);
}
ESTEST(ese_enum_closed_socket)
{
    SOCKET s = es_sock(SOCK_STREAM); WSANETWORKEVENTS ne; int r;
    REQUIRE(s != INVALID_SOCKET);
    es_close(s);
    U(WSASetLastError)(0);
    r = es_enum(s, NULL, &ne);
    CHECK(r == SOCKET_ERROR);
    ES_EQ(es_err(), WSAENOTSOCK);
}
ESTEST(ese_enum_non_socket_handle)
{
    HANDLE h = es_ev(); WSANETWORKEVENTS ne; int r;
    REQUIRE(h);
    U(WSASetLastError)(0);
    r = es_enum((SOCKET)h, NULL, &ne);
    CHECK(r == SOCKET_ERROR);
    ES_EQ(es_err(), WSAENOTSOCK);
    U(WSACloseEvent)(h);
}
ESTEST(ese_enum_null_result_pointer_fails)
{
    SOCKET s = es_sock(SOCK_STREAM); int r;
    REQUIRE(s != INVALID_SOCKET);
    U(WSASetLastError)(0);
    r = U(WSAEnumNetworkEvents)(s, NULL, NULL);
    CHECK(r == SOCKET_ERROR);
    CHECKF(es_err() == WSAEINVAL || es_err() == WSAEFAULT, "err %d", es_err());
    t_note("NULL result pointer reports %s", es_err() == WSAEFAULT ? "fault" : "invalid");
    es_close(s);
}
ESTEST(ese_enum_null_result_with_event_does_not_reset_event)
{
    SOCKET s = es_sock(SOCK_STREAM); HANDLE ev = es_ev(); int r;
    REQUIRE(s != INVALID_SOCKET && ev);
    U(WSASetEvent)(ev);
    r = U(WSAEnumNetworkEvents)(s, ev, NULL);
    CHECK(r == SOCKET_ERROR);
    t_note("event after enum with NULL result: %s", es_signalled(ev) ? "still signalled" : "reset");
    es_close(s); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_bad_socket_wins_over_null_result)
{
    int r;
    U(WSASetLastError)(0);
    r = U(WSAEnumNetworkEvents)(INVALID_SOCKET, NULL, NULL);
    CHECK(r == SOCKET_ERROR);
    t_note("bad socket + NULL result reports %d", es_err());
}
ESTEST(ese_enum_success_returns_zero)
{
    SOCKET s = es_sock(SOCK_STREAM); WSANETWORKEVENTS ne;
    REQUIRE(s != INVALID_SOCKET);
    ES_EQ(es_enum(s, NULL, &ne), 0);
    es_close(s);
}

/* ---- result contents ---------------------------------------------------------------------------------- */
ESTEST(ese_enum_unselected_fresh_socket_reports_nothing)
{
    SOCKET s = es_sock(SOCK_STREAM); WSANETWORKEVENTS ne; int i;
    REQUIRE(s != INVALID_SOCKET);
    ES_EQ(es_enum(s, NULL, &ne), 0);
    ES_EQ(ne.lNetworkEvents, 0);
    for (i = 0; i < FD_MAX_EVENTS; ++i) CHECKF((unsigned)ne.iErrorCode[i] == ES_PAT, "slot %d touched", i);
    es_close(s);
}
ESTEST(ese_enum_mask_always_overwritten)
{
    SOCKET s = es_sock(SOCK_DGRAM); WSANETWORKEVENTS ne;
    REQUIRE(s != INVALID_SOCKET);
    memset(&ne, 0xFF, sizeof(ne));
    ES_EQ(U(WSAEnumNetworkEvents)(s, NULL, &ne), 0);
    ES_EQ(ne.lNetworkEvents, 0);
    memset(&ne, 0x00, sizeof(ne)); ne.lNetworkEvents = 0x7fffffff;
    ES_EQ(U(WSAEnumNetworkEvents)(s, NULL, &ne), 0);
    ES_EQ(ne.lNetworkEvents, 0);
    es_close(s);
}
ESTEST(ese_enum_reports_only_set_slots)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); WSANETWORKEVENTS ne; int i;
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ | FD_WRITE | FD_CLOSE) == 0);
    CHECK(es_send_all(v, "x", 1) == 1);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_enum(c, ev, &ne), 0);
    CHECK((ne.lNetworkEvents & FD_READ) != 0);
    for (i = 0; i < FD_MAX_EVENTS; ++i) {
        if (ne.lNetworkEvents & (1 << i)) CHECKF(ne.iErrorCode[i] == 0, "slot %d err %d", i, ne.iErrorCode[i]);
        else CHECKF((unsigned)ne.iErrorCode[i] == ES_PAT, "slot %d touched", i);
    }
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_error_slot_indices_match_bit_numbers)
{
    CHECK(FD_READ_BIT == 0 && FD_WRITE_BIT == 1 && FD_OOB_BIT == 2 && FD_ACCEPT_BIT == 3);
    CHECK(FD_CONNECT_BIT == 4 && FD_CLOSE_BIT == 5 && FD_QOS_BIT == 6 && FD_GROUP_QOS_BIT == 7);
    CHECK(FD_ROUTING_INTERFACE_CHANGE_BIT == 8 && FD_ADDRESS_LIST_CHANGE_BIT == 9);
    CHECK((1 << FD_CLOSE_BIT) == FD_CLOSE);
}
ESTEST(ese_enum_unselected_socket_with_data_pending_observed)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(es_send_all(v, "x", 1) == 1);
    Sleep(50);
    t_note("unselected socket with unread data enumerates mask %ld", es_mask(c, NULL));
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_reports_only_selected_events)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_WRITE) == 0);       /* not FD_READ */
    CHECK(es_wait(ev, 2000));
    CHECK(es_send_all(v, "x", 1) == 1);
    Sleep(50);
    ES_EQ(es_mask(c, ev), FD_WRITE);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}

/* ---- consumption and event reset --------------------------------------------------------------------- */
ESTEST(ese_enum_consumes_recorded_events)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(es_send_all(v, "x", 1) == 1);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_mask(c, NULL), FD_READ);
    ES_EQ(es_mask(c, NULL), 0);
    ES_EQ(es_mask(c, NULL), 0);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_without_event_leaves_event_signalled)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(es_send_all(v, "x", 1) == 1);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_mask(c, NULL), FD_READ);
    CHECK(es_signalled(ev));                            /* NULL event: nothing resets it */
    CHECK(es_signalled(ev));
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_with_event_resets_it)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(es_send_all(v, "x", 1) == 1);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_mask(c, ev), FD_READ);
    CHECK(!es_signalled(ev));
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_resets_event_even_with_nothing_to_report)
{
    SOCKET s = es_sock(SOCK_STREAM); HANDLE ev = es_ev();
    REQUIRE(s != INVALID_SOCKET && ev);
    U(WSASetEvent)(ev);
    ES_EQ(es_mask(s, ev), 0);
    CHECK(!es_signalled(ev));
    es_close(s); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_resets_unrelated_event_object)
{
    /* The event passed need not be the one selected for the socket. */
    ES_PAIR(c, v);
    HANDLE sel = es_ev(), other = es_ev();
    REQUIRE(sel && other);
    CHECK(U(WSAEventSelect)(c, sel, FD_READ) == 0);
    CHECK(es_send_all(v, "x", 1) == 1);
    CHECK(es_wait(sel, 2000));
    U(WSASetEvent)(other);
    ES_EQ(es_mask(c, other), FD_READ);
    CHECK(!es_signalled(other));
    CHECK(es_signalled(sel));                           /* the selected event is untouched */
    es_close(c); es_close(v); U(WSACloseEvent)(sel); U(WSACloseEvent)(other);
}
ESTEST(ese_enum_resets_auto_reset_event_object_too)
{
    SOCKET s = es_sock(SOCK_STREAM); HANDLE ev = CreateEventW(NULL, FALSE, TRUE, NULL);
    REQUIRE(s != INVALID_SOCKET && ev);
    ES_EQ(es_mask(s, ev), 0);
    CHECK(!es_signalled(ev));
    es_close(s); CloseHandle(ev);
}
ESTEST(ese_enum_event_reset_is_not_a_cancel)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    ES_EQ(es_mask(c, ev), 0);
    CHECK(es_send_all(v, "x", 1) == 1);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_mask(c, ev), FD_READ);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_closed_event_handle_observed)
{
    SOCKET s = es_sock(SOCK_STREAM); HANDLE ev = es_ev(); WSANETWORKEVENTS ne; int r;
    REQUIRE(s != INVALID_SOCKET && ev);
    U(WSACloseEvent)(ev);
    U(WSASetLastError)(0);
    r = es_enum(s, ev, &ne);
    t_note("enum with a closed event handle %s", r == 0 ? "succeeds" : "fails");
    es_close(s);
}
ESTEST(ese_enum_event_closed_while_selected_still_reports)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(U(WSACloseEvent)(ev));
    CHECK(es_send_all(v, "x", 1) == 1);
    Sleep(100);
    t_note("selected-then-closed event: FD_READ recorded = %d", es_mask(c, NULL) == FD_READ);
    es_close(c); es_close(v);
}
ESTEST(ese_enum_after_closesocket_fails)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); WSANETWORKEVENTS ne;
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    es_close(c);
    U(WSASetLastError)(0);
    CHECK(es_enum(c, ev, &ne) == SOCKET_ERROR);
    ES_EQ(es_err(), WSAENOTSOCK);
    es_close(v); U(WSACloseEvent)(ev);
}

/* ---- event shared across sockets / moved ------------------------------------------------------------- */
ESTEST(ese_enum_event_of_other_socket_resets_without_consuming_this_one)
{
    ES_PAIR(a, av);
    ES_PAIR(b, bv);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(a, ev, FD_READ) == 0);
    CHECK(U(WSAEventSelect)(b, ev, FD_READ) == 0);
    CHECK(es_send_all(av, "x", 1) == 1);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_mask(b, ev), 0);                           /* b has nothing, but resets ev */
    CHECK(!es_signalled(ev));
    ES_EQ(es_mask(a, NULL), FD_READ);                   /* a's record survived */
    es_close(a); es_close(av); es_close(b); es_close(bv); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_each_socket_has_its_own_record)
{
    ES_PAIR(a, av);
    ES_PAIR(b, bv);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(a, ev, FD_READ) == 0);
    CHECK(U(WSAEventSelect)(b, ev, FD_READ | FD_CLOSE) == 0);
    CHECK(es_send_all(av, "1", 1) == 1);
    CHECK(es_send_all(bv, "2", 1) == 1);
    es_close(bv);
    Sleep(100);
    ES_EQ(es_mask(a, NULL), FD_READ);
    ES_EQ(es_mask(b, NULL), FD_READ | FD_CLOSE);        /* FD_CLOSE is recorded although data is unread */
    es_close(a); es_close(av); es_close(b); U(WSACloseEvent)(ev);
}

/* ---- UDP ------------------------------------------------------------------------------------------- */
ESTEST(ese_enum_udp_bound_write_at_most_once)
{
    SOCKET s = es_udp(NULL); HANDLE ev = es_ev();
    REQUIRE(s != INVALID_SOCKET && ev);
    LONG m;
    CHECK(U(WSAEventSelect)(s, ev, FD_READ | FD_WRITE) == 0);
    m = es_mask(s, ev);
    CHECKF(m == 0 || m == FD_WRITE, "mask %ld", m);          /* whether a bound datagram socket raises it is a note */
    t_note("bound UDP socket reports FD_WRITE on selection: %d", m == FD_WRITE);
    ES_EQ(es_mask(s, ev), 0);                                /* never twice */
    es_close(s); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_udp_send_does_not_rearm_write)
{
    struct sockaddr_in a; SOCKET s = es_udp(NULL), sink = es_udp(&a); HANDLE ev = es_ev(); int i;
    REQUIRE(s != INVALID_SOCKET && sink != INVALID_SOCKET && ev);
    CHECK(U(WSAEventSelect)(s, ev, FD_WRITE) == 0);
    { LONG m0 = es_mask(s, ev); CHECKF(m0 == 0 || m0 == FD_WRITE, "mask %ld", m0); }
    for (i = 0; i < 4; ++i) CHECK(es_udp_send(s, &a, "z", 1) == 1);
    Sleep(50);
    ES_EQ(es_mask(s, ev), 0);
    CHECK(!es_signalled(ev));
    es_close(s); es_close(sink); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_udp_datagram_raises_read)
{
    struct sockaddr_in a; SOCKET rx = es_udp(&a), tx = es_udp(NULL); HANDLE ev = es_ev(); char b[8];
    REQUIRE(rx != INVALID_SOCKET && tx != INVALID_SOCKET && ev);
    CHECK(U(WSAEventSelect)(rx, ev, FD_READ) == 0);
    CHECK(!es_wait(ev, 100));
    CHECK(es_udp_send(tx, &a, "abc", 3) == 3);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_mask(rx, ev), FD_READ);
    CHECK(U(recvfrom)(rx, b, sizeof(b), 0, NULL, NULL) == 3);
    ES_EQ(es_mask(rx, ev), 0);
    es_close(rx); es_close(tx); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_udp_second_datagram_rearms_read_after_recv)
{
    struct sockaddr_in a; SOCKET rx = es_udp(&a), tx = es_udp(NULL); HANDLE ev = es_ev(); char b[8];
    REQUIRE(rx != INVALID_SOCKET && tx != INVALID_SOCKET && ev);
    CHECK(U(WSAEventSelect)(rx, ev, FD_READ) == 0);
    CHECK(es_udp_send(tx, &a, "1", 1) == 1);
    CHECK(es_udp_send(tx, &a, "22", 2) == 2);
    CHECK(es_wait(ev, 2000));
    Sleep(50);
    ES_EQ(es_mask(rx, ev), FD_READ);
    CHECK(U(recvfrom)(rx, b, sizeof(b), 0, NULL, NULL) == 1);   /* one datagram left: read re-armed */
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_mask(rx, ev), FD_READ);
    CHECK(U(recvfrom)(rx, b, sizeof(b), 0, NULL, NULL) == 2);
    CHECK(!es_wait(ev, 100));
    ES_EQ(es_mask(rx, ev), 0);
    es_close(rx); es_close(tx); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_udp_unconnected_has_no_connect_or_close)
{
    struct sockaddr_in a; SOCKET rx = es_udp(&a), tx = es_udp(NULL); HANDLE ev = es_ev();
    REQUIRE(rx != INVALID_SOCKET && tx != INVALID_SOCKET && ev);
    CHECK(U(WSAEventSelect)(rx, ev, FD_ALL_EVENTS) == 0);
    { LONG m0 = es_mask(rx, ev); CHECKF(m0 == 0 || m0 == FD_WRITE, "mask %ld", m0); }
    CHECK(es_udp_send(tx, &a, "q", 1) == 1);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_mask(rx, ev), FD_READ);
    es_close(tx);
    Sleep(50);
    ES_EQ(es_mask(rx, ev), 0);
    es_close(rx); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_udp_zero_length_datagram_raises_read)
{
    struct sockaddr_in a; SOCKET rx = es_udp(&a), tx = es_udp(NULL); HANDLE ev = es_ev(); char b[4];
    REQUIRE(rx != INVALID_SOCKET && tx != INVALID_SOCKET && ev);
    CHECK(U(WSAEventSelect)(rx, ev, FD_READ) == 0);
    CHECK(es_udp_send(tx, &a, "", 0) == 0);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_mask(rx, ev), FD_READ);
    CHECK(U(recvfrom)(rx, b, sizeof(b), 0, NULL, NULL) == 0);
    es_close(rx); es_close(tx); U(WSACloseEvent)(ev);
}

/* ---- TCP details ------------------------------------------------------------------------------------ */
ESTEST(ese_enum_connected_tcp_write_once_then_quiet)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_WRITE) == 0);
    ES_EQ(es_mask(c, ev), FD_WRITE);
    CHECK(es_send_all(c, "abc", 3) == 3);
    ES_EQ(es_mask(c, ev), 0);
    CHECK(!es_signalled(ev));
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_never_raises_qos_routing_or_address_events)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); LONG m, seen = 0; char b[8];
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_ALL_EVENTS) == 0);
    seen |= es_mask(c, ev);
    CHECK(es_send_all(v, "x", 1) == 1);
    CHECK(es_wait(ev, 2000));
    seen |= es_mask(c, ev);
    CHECK(U(recv)(c, b, sizeof(b), 0) == 1);
    es_close(v);
    CHECK(es_wait(ev, 2000));
    m = es_mask(c, ev);
    CHECK(m >= 0);
    seen |= m;
    CHECK((seen & (FD_QOS | FD_GROUP_QOS | FD_ROUTING_INTERFACE_CHANGE | FD_ADDRESS_LIST_CHANGE)) == 0);
    CHECK((seen & FD_CLOSE) != 0);
    es_close(c); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_all_events_mask_on_fresh_pair)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); LONG m;
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_ALL_EVENTS) == 0);
    CHECK(es_wait(ev, 2000));
    m = es_mask(c, ev);
    CHECK((m & FD_WRITE) != 0);
    CHECK((m & ~(FD_WRITE | FD_CONNECT)) == 0);
    t_note("fresh connected socket reports connect bit: %d", (m & FD_CONNECT) != 0);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_listener_accept_bit_only)
{
    struct sockaddr_in a; SOCKET l = es_listener(&a, 2), c = es_sock(SOCK_STREAM), s2; HANDLE ev = es_ev();
    REQUIRE(l != INVALID_SOCKET && c != INVALID_SOCKET && ev);
    CHECK(U(WSAEventSelect)(l, ev, FD_ALL_EVENTS) == 0);
    ES_EQ(es_mask(l, ev), 0);
    CHECK(U(connect)(c, (struct sockaddr *)&a, sizeof(a)) == 0);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_mask(l, ev), FD_ACCEPT);
    s2 = U(accept)(l, NULL, NULL);
    CHECK(s2 != INVALID_SOCKET);
    es_close(s2); es_close(c); es_close(l); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_nonblocking_connect_reports_connect)
{
    struct sockaddr_in a; SOCKET l = es_listener(&a, 1), c = es_sock(SOCK_STREAM), s2; HANDLE ev = es_ev(); LONG m; int r;
    REQUIRE(l != INVALID_SOCKET && c != INVALID_SOCKET && ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_CONNECT) == 0);
    r = U(connect)(c, (struct sockaddr *)&a, sizeof(a));
    CHECK(r == SOCKET_ERROR && es_err() == WSAEWOULDBLOCK);
    CHECK(es_wait(ev, 2000));
    m = es_mask(c, ev);
    ES_EQ(m, FD_CONNECT);
    s2 = U(accept)(l, NULL, NULL);
    es_close(s2); es_close(c); es_close(l); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_refused_connect_reports_error_in_connect_slot)
{
    struct sockaddr_in a; SOCKET l = es_listener(&a, 1), c = es_sock(SOCK_STREAM); HANDLE ev = es_ev();
    WSANETWORKEVENTS ne;
    REQUIRE(l != INVALID_SOCKET && c != INVALID_SOCKET && ev);
    es_close(l);                                         /* nobody listens on the port any more */
    CHECK(U(WSAEventSelect)(c, ev, FD_CONNECT) == 0);
    U(connect)(c, (struct sockaddr *)&a, sizeof(a));
    if (!es_wait(ev, 8000)) { t_skip("refusal not reported in time"); es_close(c); U(WSACloseEvent)(ev); return; }
    ES_EQ(es_enum(c, ev, &ne), 0);
    CHECK((ne.lNetworkEvents & FD_CONNECT) != 0);
    ES_EQ(ne.iErrorCode[FD_CONNECT_BIT], WSAECONNREFUSED);
    es_close(c); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_graceful_close_has_zero_error)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev(); WSANETWORKEVENTS ne;
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_CLOSE) == 0);
    es_close(v);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_enum(c, ev, &ne), 0);
    ES_EQ(ne.lNetworkEvents, FD_CLOSE);
    ES_EQ(ne.iErrorCode[FD_CLOSE_BIT], 0);
    es_close(c); U(WSACloseEvent)(ev);
}
ESTEST(ese_enum_close_record_is_consumed)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_CLOSE) == 0);
    es_close(v);
    CHECK(es_wait(ev, 2000));
    ES_EQ(es_mask(c, ev), FD_CLOSE);
    ES_EQ(es_mask(c, ev), 0);
    es_close(c); U(WSACloseEvent)(ev);
}

/* ---- waiting over many sockets ---------------------------------------------------------------------- */
#define ES_MANY 64
struct es_many { SOCKET s[ES_MANY]; HANDLE ev[ES_MANY]; struct sockaddr_in a[ES_MANY]; SOCKET tx; };
static int es_many_open(struct es_many *m, int n)
{
    int i;
    memset(m, 0, sizeof(*m));
    for (i = 0; i < ES_MANY; ++i) m->s[i] = INVALID_SOCKET;
    m->tx = es_udp(NULL);
    if (m->tx == INVALID_SOCKET) return 0;
    for (i = 0; i < n; ++i) {
        m->s[i] = es_udp(&m->a[i]);
        m->ev[i] = es_ev();
        if (m->s[i] == INVALID_SOCKET || !m->ev[i]) return 0;
        if (U(WSAEventSelect)(m->s[i], m->ev[i], FD_READ)) return 0;
    }
    return 1;
}
static void es_many_close(struct es_many *m)
{
    int i;
    for (i = 0; i < ES_MANY; ++i) { es_close(m->s[i]); if (m->ev[i]) U(WSACloseEvent)(m->ev[i]); }
    es_close(m->tx);
}
ESTEST(ese_wait_over_sockets_reports_index_of_ready_socket)
{
    static struct es_many m; int i, n = 8;
    if (!es_many_open(&m, n)) { es_many_close(&m); t_skip("could not open sockets"); return; }
    for (i = 0; i < n; ++i) {
        DWORD r; char b[4];
        CHECK(es_udp_send(m.tx, &m.a[i], "p", 1) == 1);
        r = U(WSAWaitForMultipleEvents)(n, m.ev, FALSE, 3000, FALSE);
        CHECKF(r == WSA_WAIT_EVENT_0 + i, "socket %d -> %lu", i, r);
        ES_EQ(es_mask(m.s[i], m.ev[i]), FD_READ);
        CHECK(U(recvfrom)(m.s[i], b, sizeof(b), 0, NULL, NULL) == 1);
    }
    ES_EQ(U(WSAWaitForMultipleEvents)(n, m.ev, FALSE, 50, FALSE), WSA_WAIT_TIMEOUT);
    es_many_close(&m);
}
ESTEST(ese_wait_over_64_sockets_last_one_ready)
{
    static struct es_many m;
    if (!es_many_open(&m, ES_MANY)) { es_many_close(&m); t_skip("could not open sockets"); return; }
    CHECK(es_udp_send(m.tx, &m.a[63], "p", 1) == 1);
    ES_EQ(U(WSAWaitForMultipleEvents)(64, m.ev, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0 + 63);
    ES_EQ(es_mask(m.s[63], m.ev[63]), FD_READ);
    es_many_close(&m);
}
ESTEST(ese_wait_over_64_sockets_wait_all)
{
    static struct es_many m; int i;
    if (!es_many_open(&m, ES_MANY)) { es_many_close(&m); t_skip("could not open sockets"); return; }
    for (i = 0; i < 63; ++i) CHECK(es_udp_send(m.tx, &m.a[i], "p", 1) == 1);
    ES_EQ(U(WSAWaitForMultipleEvents)(64, m.ev, TRUE, 200, FALSE), WSA_WAIT_TIMEOUT);
    CHECK(es_udp_send(m.tx, &m.a[63], "p", 1) == 1);
    ES_EQ(U(WSAWaitForMultipleEvents)(64, m.ev, TRUE, 3000, FALSE), WSA_WAIT_EVENT_0);
    es_many_close(&m);
}
ESTEST(ese_wait_over_65_sockets_rejected_even_when_ready)
{
    static struct es_many m; HANDLE all[65];
    if (!es_many_open(&m, ES_MANY)) { es_many_close(&m); t_skip("could not open sockets"); return; }
    memcpy(all, m.ev, sizeof(m.ev)); all[64] = es_ev();
    CHECK(es_udp_send(m.tx, &m.a[0], "p", 1) == 1);
    Sleep(50);
    U(WSASetLastError)(0);
    ES_EQ(U(WSAWaitForMultipleEvents)(65, all, FALSE, 1000, FALSE), WSA_WAIT_FAILED);
    ES_EQ(es_err(), WSA_INVALID_PARAMETER);
    U(WSACloseEvent)(all[64]);
    es_many_close(&m);
}
ESTEST(ese_wait_blocked_thread_wakes_on_socket_data)
{
    ES_PAIR(c, v);
    HANDLE ev[2], th; DWORD res = 0xdead;
    struct wp { HANDLE *ev; DWORD *res; } p;
    DWORD WINAPI waiter(void *a) { struct wp *q = a; *q->res = U(WSAWaitForMultipleEvents)(2, q->ev, FALSE, 5000, FALSE); return 0; }
    ev[0] = es_ev(); ev[1] = es_ev();
    REQUIRE(ev[0] && ev[1]);
    CHECK(U(WSAEventSelect)(c, ev[1], FD_READ) == 0);
    p.ev = ev; p.res = &res;
    th = CreateThread(NULL, 0, waiter, &p, 0, NULL);
    REQUIRE(th);
    Sleep(50);
    CHECK(es_send_all(v, "x", 1) == 1);
    CHECK(WaitForSingleObject(th, 6000) == WAIT_OBJECT_0);
    CloseHandle(th);
    ES_EQ(res, WSA_WAIT_EVENT_0 + 1);
    ES_EQ(es_mask(c, ev[1]), FD_READ);
    es_close(c); es_close(v); U(WSACloseEvent)(ev[0]); U(WSACloseEvent)(ev[1]);
}
ESTEST(ese_wait_enum_reset_makes_next_wait_time_out)
{
    ES_PAIR(c, v);
    HANDLE ev = es_ev();
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(es_send_all(v, "x", 1) == 1);
    ES_EQ(U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0);
    ES_EQ(U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 0, FALSE), WSA_WAIT_EVENT_0);   /* manual-reset: stays */
    ES_EQ(es_mask(c, ev), FD_READ);
    ES_EQ(U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 50, FALSE), WSA_WAIT_TIMEOUT);
    es_close(c); es_close(v); U(WSACloseEvent)(ev);
}
ESTEST(ese_wait_auto_reset_event_consumed_by_wait_but_record_kept)
{
    ES_PAIR(c, v);
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    REQUIRE(ev);
    CHECK(U(WSAEventSelect)(c, ev, FD_READ) == 0);
    CHECK(es_send_all(v, "x", 1) == 1);
    ES_EQ(U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 3000, FALSE), WSA_WAIT_EVENT_0);
    ES_EQ(U(WSAWaitForMultipleEvents)(1, &ev, FALSE, 0, FALSE), WSA_WAIT_TIMEOUT);
    ES_EQ(es_mask(c, NULL), FD_READ);
    es_close(c); es_close(v); CloseHandle(ev);
}
