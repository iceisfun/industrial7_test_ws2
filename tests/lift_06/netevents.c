/* WSAEventSelect + WSAEnumNetworkEvents on idle sockets: which events are pending right after
 * registration, that FD_WRITE is edge-reported once, and which iErrorCode slots are written. */
#include "l6.h"

/* kind 0: bound, unconnected TCP; 1: bound UDP; 2: connected TCP. use_event: pass the event to be reset. */
static void run_case(int kind, int use_event)
{
    SOCKET s = INVALID_SOCKET, peer = INVALID_SOCKET;
    WSAEVENT ev; WSANETWORKEVENTS ne;
    int j, k;
    struct sockaddr_in a = lo_addr(0);

    if (kind == 2) { CHECK(lo_pair(&s, &peer)); }
    else {
        s = w_socket(AF_INET, kind == 0 ? SOCK_STREAM : SOCK_DGRAM, 0);
        CHECK(s != INVALID_SOCKET);
        EQ(w_bind(s, &a, sizeof a), 0);
    }
    ev = U(WSACreateEvent)();
    CHECK(ev != NULL);
    for (j = 0; j < 5; j++) {
        /* Re-registering the same mask re-arms FD_WRITE on a writable socket only the first time round. */
        EQ(U(WSAEventSelect)(s, ev, FD_READ | FD_WRITE), 0);
        memset(&ne, 0xAB, sizeof ne);
        EQ(U(WSAEnumNetworkEvents)(s, use_event ? ev : NULL, &ne), 0);
        if (kind >= 1 && j == 0) EQ(ne.lNetworkEvents, FD_WRITE);
        else EQ(ne.lNetworkEvents, 0);
        for (k = 0; k < FD_MAX_EVENTS; k++) {
            if (ne.lNetworkEvents & (1 << k)) EQ(ne.iErrorCode[k], 0);
            else EQ((unsigned)ne.iErrorCode[k], 0xABABABABu);   /* untouched slots keep the fill pattern */
        }
    }
    w_close(s);
    U(WSACloseEvent)(ev);
    if (peer != INVALID_SOCKET) w_close(peer);
}
#define REQ() REQUIRE(U(WSACreateEvent)); REQUIRE(U(WSAEventSelect)); REQUIRE(U(WSAEnumNetworkEvents)); REQUIRE(U(WSACloseEvent)); NEED_WS()

TEST(lift06_enum_unconnected_tcp_event_reset)  { REQ(); run_case(0, 1); }
TEST(lift06_enum_unconnected_tcp_no_event)     { REQ(); run_case(0, 0); }
TEST(lift06_enum_bound_udp_event_reset)        { REQ(); run_case(1, 1); }
TEST(lift06_enum_bound_udp_no_event)           { REQ(); run_case(1, 0); }
TEST(lift06_enum_connected_tcp_event_reset)    { REQ(); run_case(2, 1); }
TEST(lift06_enum_connected_tcp_no_event)       { REQ(); run_case(2, 0); }
