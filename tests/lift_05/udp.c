/* UDP datagram behaviour over loopback: recvfrom() with an undersized or oversized address buffer,
 * many senders to one receiver, connected sends toward a closed port, concurrent send/select on a
 * non-blocking socket, and sends to port 0. All ports are ephemeral. */
#include "ws.h"

#define NPEERS 4

typedef struct { SOCKET s; struct sockaddr_in addr; } peer;

static int peers_open(peer *p) {
    int i;
    for (i = NPEERS - 1; i >= 0; i--) {
        struct sockaddr_in a; int n = sizeof a;
        p[i].s = w_socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(p[i].s != INVALID_SOCKET);
        memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = h32(0x7f000001u);
        CHECK(w_bind(p[i].s, &a, sizeof a) == 0);
        CHECK(w_getsockname(p[i].s, &p[i].addr, &n) == 0);
        EXPECT_EQ(n, sizeof a);
    }
    return 1;
}
static void peers_close(peer *p) { int i; for (i = 0; i < NPEERS; i++) w_close(p[i].s); }

/* getsockname() after binding port 0 reports a real port and the loopback address. */
TEST(l5_udp_bind_port_zero_assigns_port) {
    peer p[NPEERS]; int i;
    if (!ws_up()) return;
    peers_open(p);
    for (i = 0; i < NPEERS; i++) {
        CHECK(p[i].addr.sin_port != 0);
        CHECK(p[i].addr.sin_addr.s_addr == h32(0x7f000001u));
        CHECK(p[i].addr.sin_family == AF_INET);
    }
    peers_close(p);
}

/* An address buffer shorter than the peer address is rejected with WSAEFAULT, the buffer is not
 * written, and the datagram stays queued for a retry with a proper size. */
TEST(l5_udp_recvfrom_short_fromlen_fails) {
    peer p[NPEERS]; char buf[16] = "sixteen bytes!!", from[1024]; int ss, n;
    if (!ws_up()) return;
    peers_open(p);
    CHECK(w_sendto(p[1].s, buf, sizeof buf, 0, &p[0].addr, sizeof p[0].addr) == (int)sizeof buf);
    CHECK(w_readable(p[0].s, 3000));
    from[0] = 'A'; ss = 1;
    w_seterr(0);
    n = w_recvfrom(p[0].s, buf, sizeof buf, 0, from, &ss);
    CHECK(n == SOCKET_ERROR);
    EXPECT_EQ(w_err(), WSAEFAULT);
    EXPECT_EQ(from[0], 'A');
    if (n == SOCKET_ERROR) {
        /* the datagram is still queued */
        CHECK(w_readable(p[0].s, 3000));
        ss = sizeof p[0].addr;
        n = w_recvfrom(p[0].s, buf, sizeof buf, 0, from, &ss);
        EXPECT_EQ(n, sizeof buf);
    }
    peers_close(p);
}

/* A generous address buffer: only the address is written, bytes past it are untouched, and the
 * length is updated to the real address size. */
TEST(l5_udp_recvfrom_large_fromlen_untouched_tail) {
    peer p[NPEERS]; char buf[16] = {0}, from[1024]; int ss, n;
    if (!ws_up()) return;
    peers_open(p);
    CHECK(w_sendto(p[1].s, buf, sizeof buf, 0, &p[0].addr, sizeof p[0].addr) == (int)sizeof buf);
    CHECK(w_readable(p[0].s, 3000));
    from[1023] = 'B'; ss = sizeof from;
    n = w_recvfrom(p[0].s, buf, sizeof buf, 0, from, &ss);
    EXPECT_EQ(n, sizeof buf);
    EXPECT_EQ(from[1023], 'B');
    EXPECT_EQ(ss, sizeof(struct sockaddr_in));
    peers_close(p);
}

/* Several sockets send to one receiver; every datagram reports the sender port it carries. */
TEST(l5_udp_many_senders_identify_peers) {
    peer p[NPEERS]; char buf[16]; int i, ss;
    if (!ws_up()) return;
    peers_open(p);
    for (i = 1; i < NPEERS; i++) {
        memset(buf, 0, sizeof buf);
        memcpy(buf, &p[i].addr.sin_port, sizeof(unsigned short));
        CHECK(w_sendto(p[i].s, buf, sizeof buf, 0, &p[0].addr, sizeof p[0].addr) == (int)sizeof buf);
    }
    for (i = 1; i < NPEERS; i++) {
        struct sockaddr_in from; int n;
        CHECK(w_readable(p[0].s, 3000));
        ss = sizeof from;
        n = w_recvfrom(p[0].s, buf, sizeof buf, 0, &from, &ss);
        EXPECT_EQ(n, sizeof buf);
        CHECK(!memcmp(&from.sin_port, buf, sizeof(unsigned short)));
    }
    peers_close(p);
}

/* A connected datagram socket keeps sending although the port it targets has no listener. */
TEST(l5_udp_connected_send_to_closed_port_succeeds) {
    SOCKET dead, s; struct sockaddr_in a; int n = sizeof a, i; char buf[16] = {0};
    if (!ws_up()) return;
    dead = w_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = h32(0x7f000001u);
    CHECK(w_bind(dead, &a, sizeof a) == 0);
    CHECK(w_getsockname(dead, &a, &n) == 0);
    w_close(dead);                       /* port is now unused */
    s = w_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    CHECK(w_connect(s, &a, sizeof a) == 0);
    for (i = 0; i < 10; i++)
        CHECK(w_send(s, buf, sizeof buf, 0) == (int)sizeof buf);
    w_close(s);
}

struct sender { SOCKET s; HANDLE start; int bad; };
static DWORD WINAPI sender_thread(void *arg) {
    struct sender *p = arg; char buf[256]; int i;
    memset(buf, 0, sizeof buf);
    WaitForSingleObject(p->start, 10000);
    for (i = 0; i < 256; i++) {
        fd_set w; fds_one(&w, p->s);
        if (w_select(NULL, &w, NULL, 0) != 1) p->bad++;
        if (w_send(p->s, buf, sizeof buf, 0) != (int)sizeof buf) p->bad++;
    }
    return 0;
}

/* One thread sends and polls writability while another does the same on the same non-blocking
 * datagram socket: every send completes in full and select always reports it writable. */
TEST(l5_udp_concurrent_send_select_nonblocking) {
    SOCKET dead, s; struct sockaddr_in a; int n = sizeof a, i, bad = 0; char buf[256] = {0};
    struct sender sd; HANDLE th;
    if (!ws_up()) return;
    dead = w_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = h32(0x7f000001u);
    CHECK(w_bind(dead, &a, sizeof a) == 0);
    CHECK(w_getsockname(dead, &a, &n) == 0);
    w_close(dead);                       /* nobody listens on this port any more */
    s = w_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    CHECK(w_connect(s, &a, sizeof a) == 0);
    CHECK(w_nonblock(s, 1) == 0);
    sd.s = s; sd.bad = 0; sd.start = CreateEventW(NULL, FALSE, FALSE, NULL);
    th = CreateThread(NULL, 0, sender_thread, &sd, 0, NULL);
    SetEvent(sd.start);
    for (i = 0; i < 256; i++) {
        fd_set w;
        if (w_send(s, buf, sizeof buf, 0) != (int)sizeof buf) bad++;
        fds_one(&w, s);
        if (w_select(NULL, &w, NULL, 0) != 1) bad++;
    }
    CHECK(WaitForSingleObject(th, 10000) == WAIT_OBJECT_0);
    EXPECT_EQ(bad, 0);
    EXPECT_EQ(sd.bad, 0);
    CloseHandle(th); CloseHandle(sd.start);
    w_close(s);
}

/* sendto() with destination port 0 is accepted by the stack for IPv4 loopback. */
TEST(l5_udp_sendto_port_zero_v4) {
    SOCKET s; struct sockaddr_in a; char buf[16] = {0};
    if (!ws_up()) return;
    s = w_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = h32(0x7f000001u);
    CHECK(w_sendto(s, buf, sizeof buf, 0, &a, sizeof a) == (int)sizeof buf);
    w_close(s);
}

TEST(l5_udp_sendto_port_zero_v6) {
    SOCKET s; struct sockaddr_storage a; int l; char buf[16] = {0};
    if (!ws_up()) return;
    if (!v6_usable()) { t_skip("IPv6 loopback unusable"); return; }
    s = w_socket(AF_INET6, SOCK_DGRAM, 0);
    l = mk_addr(&a, AF_INET6, A_LOOP, 0);
    CHECK(w_sendto(s, buf, sizeof buf, 0, &a, l) == (int)sizeof buf);
    w_close(s);
}
