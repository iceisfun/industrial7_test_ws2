/* WSARecvMsg (obtained through SIO_GET_EXTENSION_FUNCTION_POINTER) with control data:
 * IP_PKTINFO delivery, truncated control buffers (synchronous, event overlapped and APC
 * completion), and the IPv4/IPv6 control messages enabled by IP_RECVTTL, IP_PKTINFO,
 * IP_RECVTOS, IPV6_HOPLIMIT, IPV6_PKTINFO and IPV6_RECVTCLASS. Loopback and ephemeral ports only. */
#include "ws.h"

static const char PAYLOAD[] = "HELLO";                 /* 6 bytes with the terminator */
#define PKTINFO_LEN (sizeof(WSACMSGHDR) + WSA_CMSGDATA_ALIGN(sizeof(struct in_pktinfo)))

typedef struct { SOCKET srv, cli; struct sockaddr_in dst; LPFN_WSARECVMSG recvmsg; } pair4;

/* server bound to `bind_addr` (host order) on an ephemeral port, client aimed at 127.0.0.1:<that port> */
static int pair4_open(pair4 *p, unsigned bind_addr) {
    struct sockaddr_in a; int n = sizeof a;
    GUID g = WSAID_WSARECVMSG; DWORD got = 0;
    memset(p, 0, sizeof *p);
    p->srv = w_socket(AF_INET, SOCK_DGRAM, 0);
    p->cli = w_socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(p->srv != INVALID_SOCKET && p->cli != INVALID_SOCKET);
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = h32(bind_addr);
    CHECK(w_bind(p->srv, &a, sizeof a) == 0);
    CHECK(w_getsockname(p->srv, &p->dst, &n) == 0);
    p->dst.sin_addr.s_addr = h32(0x7f000001u);
    CHECK(U(WSAIoctl)(p->srv, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &p->recvmsg, sizeof p->recvmsg,
                      &got, NULL, NULL) == 0);
    if (!p->recvmsg) { t_skip("WSARecvMsg unavailable"); return 0; }
    return 1;
}
static void pair4_close(pair4 *p) { w_close(p->srv); w_close(p->cli); }
static void send6(pair4 *p) { CHECK(w_sendto(p->cli, PAYLOAD, sizeof PAYLOAD, 0, &p->dst, sizeof p->dst) == (int)sizeof PAYLOAD); }
static void pktinfo_on(SOCKET s) { DWORD one = 1; CHECK(w_setsockopt(s, IPPROTO_IP, IP_PKTINFO, &one, sizeof one) == 0); }

static const unsigned bind_addrs[2] = {0x7f000001u, 0};      /* loopback, wildcard */
#define EACH_BIND(i) for (i = 0; i < 2; i++)

typedef struct { char data[16]; WSABUF buf; char ctl[512] __attribute__((aligned(8))); WSAMSG m; struct sockaddr_in from; } rm;
static void rm_init(rm *r, ULONG ctl_len, int with_ctl) {
    memset(r, 0, sizeof *r);
    r->buf.buf = r->data; r->buf.len = sizeof r->data;
    r->m.name = (LPSOCKADDR)&r->from; r->m.namelen = sizeof r->from;
    r->m.lpBuffers = &r->buf; r->m.dwBufferCount = 1;
    r->m.Control.buf = with_ctl ? r->ctl : NULL; r->m.Control.len = ctl_len;
}

/* With IP_PKTINFO still off, an empty NULL control buffer is accepted and the payload arrives. */
TEST(l5_recvmsg_no_control_requested_ok) {
    int i; if (!ws_up()) return;
    EACH_BIND(i) {
        pair4 p; rm r; DWORD got = 0;
        if (!pair4_open(&p, bind_addrs[i])) return;
        rm_init(&r, 0, 0);
        send6(&p);
        CHECK(w_readable(p.srv, 3000));
        CHECK(p.recvmsg(p.srv, &r.m, &got, NULL, NULL) == 0);
        EXPECT_EQ(got, sizeof PAYLOAD);
        CHECK(!memcmp(r.data, PAYLOAD, sizeof PAYLOAD));
        pair4_close(&p);
    }
}

/* A control buffer that is too small for the enabled IP_PKTINFO truncates: the call fails with
 * WSAEMSGSIZE, the byte count of the payload is still reported, and MSG_CTRUNC is set. */
TEST(l5_recvmsg_short_control_sync) {
    int i; if (!ws_up()) return;
    EACH_BIND(i) {
        pair4 p; rm r; DWORD got = 0xdeadbeef;
        if (!pair4_open(&p, bind_addrs[i])) return;
        pktinfo_on(p.srv);
        rm_init(&r, 1, 1);
        send6(&p);
        CHECK(w_readable(p.srv, 3000));
        w_seterr(0);
        CHECK(p.recvmsg(p.srv, &r.m, &got, NULL, NULL) == SOCKET_ERROR);
        EXPECT_EQ(w_err(), WSAEMSGSIZE);
        EXPECT_EQ(got, sizeof PAYLOAD);
        EXPECT_EQ(r.m.dwFlags, MSG_CTRUNC);
        pair4_close(&p);
    }
}

/* Same truncation through an event-signalled overlapped receive: the operation completes with
 * STATUS_BUFFER_OVERFLOW, the byte count in InternalHigh, and leaves Offset/OffsetHigh alone. */
TEST(l5_recvmsg_short_control_overlapped_event) {
    int i; if (!ws_up()) return;
    EACH_BIND(i) {
        pair4 p; rm r; WSAOVERLAPPED ov; DWORD got = 0, fl = 0xdeadbeef, wr; int rc;
        if (!pair4_open(&p, bind_addrs[i])) return;
        pktinfo_on(p.srv);
        rm_init(&r, 1, 1);
        memset(&ov, 0, sizeof ov);
        ov.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
        ov.Internal = 0xdead1; ov.InternalHigh = 0xdead2; ov.Offset = 0xdead3; ov.OffsetHigh = 0xdead4;
        w_seterr(0);
        rc = p.recvmsg(p.srv, &r.m, NULL, &ov, NULL);
        CHECK(rc != 0);
        EXPECT_EQ(w_err(), WSA_IO_PENDING);
        send6(&p);
        wr = WaitForSingleObject(ov.hEvent, 3000);
        EXPECT_EQ(wr, WAIT_OBJECT_0);
        EXPECT_EQ((NTSTATUS)ov.Internal, (NTSTATUS)0x80000005);        /* STATUS_BUFFER_OVERFLOW */
        EXPECT_EQ(ov.InternalHigh, sizeof PAYLOAD);
        EXPECT_EQ(ov.Offset, 0xdead3);
        EXPECT_EQ(ov.OffsetHigh, 0xdead4);
        w_seterr(0);
        CHECK(U(WSAGetOverlappedResult)(p.srv, &ov, &got, FALSE, &fl) == FALSE);
        EXPECT_EQ(w_err(), WSAEMSGSIZE);
        EXPECT_EQ(got, sizeof PAYLOAD);
        EXPECT_EQ(fl, 0xdeadbeef);                         /* flags out-parameter is not written on failure */
        EXPECT_EQ(r.m.dwFlags, MSG_CTRUNC);
        CloseHandle(ov.hEvent);
        pair4_close(&p);
    }
}

static volatile LONG apc_calls;
static DWORD apc_err, apc_size, apc_flags;
static void CALLBACK apc_cb(DWORD error, DWORD size, LPWSAOVERLAPPED ov, DWORD flags) {
    apc_err = error; apc_size = size; apc_flags = flags; InterlockedIncrement(&apc_calls);
}

/* Truncation with a completion routine: the call reports pending, the APC runs once with
 * WSAEMSGSIZE and the payload size, and MSG_CTRUNC is set in the message. */
TEST(l5_recvmsg_short_control_apc) {
    int i; if (!ws_up()) return;
    EACH_BIND(i) {
        pair4 p; rm r; WSAOVERLAPPED ov; DWORD res;
        if (!pair4_open(&p, bind_addrs[i])) return;
        pktinfo_on(p.srv);
        rm_init(&r, 1, 1);
        memset(&ov, 0, sizeof ov);
        apc_calls = 0; apc_err = apc_size = apc_flags = 0xff;
        send6(&p);
        w_seterr(0);
        CHECK(p.recvmsg(p.srv, &r.m, NULL, &ov, apc_cb) == SOCKET_ERROR);
        EXPECT_EQ(w_err(), ERROR_IO_PENDING);
        res = SleepEx(3000, TRUE);
        EXPECT_EQ(res, WAIT_IO_COMPLETION);
        EXPECT_EQ(apc_calls, 1);
        EXPECT_EQ(apc_err, WSAEMSGSIZE);
        EXPECT_EQ(apc_size, sizeof PAYLOAD);
        EXPECT_EQ(apc_flags, 0);
        EXPECT_EQ(r.m.dwFlags, MSG_CTRUNC);
        pair4_close(&p);
    }
}

/* A large enough control buffer: the pending receive does not touch Control.len up front, and on
 * completion it holds exactly one IP_PKTINFO message whose destination is the address we sent to. */
TEST(l5_recvmsg_pktinfo_overlapped_content) {
    int i; if (!ws_up()) return;
    EACH_BIND(i) {
        pair4 p; rm r; WSAOVERLAPPED ov; DWORD got = 0, wr; WSACMSGHDR *c; int found = 0;
        if (!pair4_open(&p, bind_addrs[i])) return;
        pktinfo_on(p.srv);
        rm_init(&r, sizeof r.ctl, 1);
        memset(&ov, 0, sizeof ov);
        ov.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
        w_seterr(0);
        CHECK(p.recvmsg(p.srv, &r.m, &got, &ov, NULL) != 0);
        EXPECT_EQ(w_err(), WSA_IO_PENDING);
        EXPECT_EQ(r.m.Control.len, sizeof r.ctl);
        send6(&p);
        wr = WaitForSingleObject(ov.hEvent, 3000);
        EXPECT_EQ(wr, WAIT_OBJECT_0);
        { DWORD fl = 0; CHECK(U(WSAGetOverlappedResult)(p.srv, &ov, &got, FALSE, &fl)); }
        EXPECT_EQ(got, sizeof PAYLOAD);
        CHECK(!memcmp(r.data, PAYLOAD, sizeof PAYLOAD));
        EXPECT_EQ(r.m.Control.len, PKTINFO_LEN);
        for (c = WSA_CMSG_FIRSTHDR(&r.m); c; c = WSA_CMSG_NXTHDR(&r.m, c)) {
            if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo *pi = (struct in_pktinfo *)WSA_CMSG_DATA(c);
                CHECK(pi->ipi_addr.s_addr == p.dst.sin_addr.s_addr);
                found = 1;
            }
        }
        CHECK(found);
        CloseHandle(ov.hEvent);
        pair4_close(&p);
    }
}

/* ---- control messages on a connected loopback pair ---- */
/* ancillary-data receiver over a connected datagram pair; returns 0 after skipping */
typedef struct { SOCKET srv, cli; LPFN_WSARECVMSG rm; } cpair;
static int cpair_open(cpair *c, int af) {
    struct sockaddr_storage a; int l, n = sizeof a;
    GUID g = WSAID_WSARECVMSG; DWORD got;
    c->srv = w_socket(af, SOCK_DGRAM, IPPROTO_UDP);
    c->cli = w_socket(af, SOCK_DGRAM, IPPROTO_UDP);
    CHECK(c->srv != INVALID_SOCKET && c->cli != INVALID_SOCKET);
    l = mk_addr(&a, af, A_LOOP, 0);
    CHECK(w_bind(c->srv, &a, l) == 0);
    CHECK(w_getsockname(c->srv, &a, &n) == 0);
    CHECK(w_connect(c->cli, &a, n) == 0);
    CHECK(U(WSAIoctl)(c->srv, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &c->rm, sizeof c->rm, &got, NULL, NULL) == 0);
    if (!c->rm) { t_skip("WSARecvMsg unavailable"); return 0; }
    return 1;
}
static void cpair_close(cpair *c) { w_close(c->srv); w_close(c->cli); }

/* Enables option `opt` at `level`, checks it reads back as 1, receives one datagram and returns
 * the first control header through hdr_out (copy into ctl). Returns received byte count or -1. */
static int recv_with_option(cpair *c, int level, int opt, char *ctl, ULONG ctl_cap, WSACMSGHDR **hdr_out) {
    static char payload[] = "HELLO";
    WSABUF pb = {sizeof payload, payload};
    WSAMSG m; DWORD on = 1, state = 0, got = 0; int n = sizeof state;
    memset(&m, 0, sizeof m);
    memset(ctl, 0, ctl_cap);
    m.lpBuffers = &pb; m.dwBufferCount = 1; m.Control.buf = ctl; m.Control.len = ctl_cap;
    CHECK(w_setsockopt(c->srv, level, opt, &on, sizeof on) == 0);
    CHECK(w_getsockopt(c->srv, level, opt, &state, &n) == 0);
    EXPECT_EQ(state, 1);
    CHECK(w_send(c->cli, payload, sizeof payload, 0) == (int)sizeof payload);
    if (!w_readable(c->srv, 3000)) return -1;
    if (c->rm(c->srv, &m, &got, NULL, NULL) != 0) return -1;
    *hdr_out = (WSACMSGHDR *)ctl;
    return (int)got;
}
static void option_off(cpair *c, int level, int opt) {
    DWORD off = 0; CHECK(w_setsockopt(c->srv, level, opt, &off, sizeof off) == 0);
}

TEST(l5_cmsg_v4_recvttl) {
    cpair c; char ctl[100] __attribute__((aligned(8))); WSACMSGHDR *h; int n;
    if (!ws_up()) return;
    if (!cpair_open(&c, AF_INET)) return;
    n = recv_with_option(&c, IPPROTO_IP, IP_RECVTTL, ctl, sizeof ctl, &h);
    EXPECT_EQ(n, 6);
    if (n == 6) {
        EXPECT_EQ(h->cmsg_level, IPPROTO_IP);
        EXPECT_EQ(h->cmsg_type, IP_TTL);
        EXPECT_EQ(h->cmsg_len, sizeof(*h) + sizeof(INT));
        CHECK(*(INT *)WSA_CMSG_DATA(h) >= 32);
    }
    option_off(&c, IPPROTO_IP, IP_RECVTTL);
    cpair_close(&c);
}

TEST(l5_cmsg_v4_pktinfo) {
    cpair c; char ctl[100] __attribute__((aligned(8))); WSACMSGHDR *h; int n;
    if (!ws_up()) return;
    if (!cpair_open(&c, AF_INET)) return;
    n = recv_with_option(&c, IPPROTO_IP, IP_PKTINFO, ctl, sizeof ctl, &h);
    EXPECT_EQ(n, 6);
    if (n == 6) {
        IN_PKTINFO *pi = (IN_PKTINFO *)WSA_CMSG_DATA(h);
        EXPECT_EQ(h->cmsg_level, IPPROTO_IP);
        EXPECT_EQ(h->cmsg_type, IP_PKTINFO);
        EXPECT_EQ(h->cmsg_len, sizeof(*h) + sizeof(IN_PKTINFO));
        CHECK(pi->ipi_addr.s_addr == h32(0x7f000001u));
    }
    option_off(&c, IPPROTO_IP, IP_PKTINFO);
    cpair_close(&c);
}

TEST(l5_cmsg_v4_recvtos) {
    cpair c; char ctl[100] __attribute__((aligned(8))); WSACMSGHDR *h; int n;
    if (!ws_up()) return;
    if (!cpair_open(&c, AF_INET)) return;
    n = recv_with_option(&c, IPPROTO_IP, IP_RECVTOS, ctl, sizeof ctl, &h);
    EXPECT_EQ(n, 6);
    if (n == 6) {
        EXPECT_EQ(h->cmsg_level, IPPROTO_IP);
        EXPECT_EQ(h->cmsg_type, IP_TOS);
        EXPECT_EQ(h->cmsg_len, sizeof(*h) + sizeof(INT));
        EXPECT_EQ(*(INT *)WSA_CMSG_DATA(h), 0);
    }
    option_off(&c, IPPROTO_IP, IP_RECVTOS);
    cpair_close(&c);
}

TEST(l5_cmsg_v6_hoplimit) {
    cpair c; char ctl[100] __attribute__((aligned(8))); WSACMSGHDR *h; int n;
    if (!ws_up()) return;
    if (!v6_usable()) { t_skip("IPv6 loopback unusable"); return; }
    if (!cpair_open(&c, AF_INET6)) return;
    n = recv_with_option(&c, IPPROTO_IPV6, IPV6_HOPLIMIT, ctl, sizeof ctl, &h);
    EXPECT_EQ(n, 6);
    if (n == 6) {
        EXPECT_EQ(h->cmsg_level, IPPROTO_IPV6);
        EXPECT_EQ(h->cmsg_type, IPV6_HOPLIMIT);
        EXPECT_EQ(h->cmsg_len, sizeof(*h) + sizeof(INT));
        CHECK(*(INT *)WSA_CMSG_DATA(h) >= 32);
    }
    option_off(&c, IPPROTO_IPV6, IPV6_HOPLIMIT);
    cpair_close(&c);
}

TEST(l5_cmsg_v6_pktinfo) {
    cpair c; char ctl[100] __attribute__((aligned(8))); WSACMSGHDR *h; int n;
    if (!ws_up()) return;
    if (!v6_usable()) { t_skip("IPv6 loopback unusable"); return; }
    if (!cpair_open(&c, AF_INET6)) return;
    n = recv_with_option(&c, IPPROTO_IPV6, IPV6_PKTINFO, ctl, sizeof ctl, &h);
    EXPECT_EQ(n, 6);
    if (n == 6) {
        IN6_PKTINFO *pi = (IN6_PKTINFO *)WSA_CMSG_DATA(h);
        struct sockaddr_storage lo; mk_addr(&lo, AF_INET6, A_LOOP, 0);
        EXPECT_EQ(h->cmsg_level, IPPROTO_IPV6);
        EXPECT_EQ(h->cmsg_type, IPV6_PKTINFO);
        EXPECT_EQ(h->cmsg_len, sizeof(*h) + sizeof(IN6_PKTINFO));
        CHECK(!memcmp(&pi->ipi6_addr, &((struct sockaddr_in6 *)&lo)->sin6_addr, 16));
    }
    option_off(&c, IPPROTO_IPV6, IPV6_PKTINFO);
    cpair_close(&c);
}

TEST(l5_cmsg_v6_recvtclass) {
    cpair c; char ctl[100] __attribute__((aligned(8))); WSACMSGHDR *h; int n;
    if (!ws_up()) return;
    if (!v6_usable()) { t_skip("IPv6 loopback unusable"); return; }
    if (!cpair_open(&c, AF_INET6)) return;
    n = recv_with_option(&c, IPPROTO_IPV6, IPV6_RECVTCLASS, ctl, sizeof ctl, &h);
    EXPECT_EQ(n, 6);
    if (n == 6) {
        EXPECT_EQ(h->cmsg_level, IPPROTO_IPV6);
        EXPECT_EQ(h->cmsg_type, IPV6_TCLASS);
        EXPECT_EQ(h->cmsg_len, sizeof(*h) + sizeof(INT));
        EXPECT_EQ(*(INT *)WSA_CMSG_DATA(h), 0);
    }
    option_off(&c, IPPROTO_IPV6, IPV6_RECVTCLASS);
    cpair_close(&c);
}
