/* IOCTL_AFD_BIND and IOCTL_AFD_GETSOCKNAME on the raw handle.
 *
 * BIND input is a 4-byte word followed by the address with no explicit length: the address length is the
 * input length minus four. Failures in the shape of the input are reported synchronously (INVALID_ADDRESS
 * for a bad family or a length that does not fit the family, INVALID_PARAMETER when the input cannot even
 * hold the family field or the output block is too small). A request that is well formed completes
 * "pending" with the event already signalled; its status block carries the real outcome and, on success,
 * the output buffer receives the bound name (size = the address size of the family). */
#include "afdx.h"

typedef struct { ULONG word; BYTE addr[sizeof(struct sockaddr_in6)]; } BP;

static void bp_set(BP *p, const void *sa, size_t len) { memset(p, 0, sizeof *p); memcpy(p->addr, sa, len); }
static LONG do_bind(SOCKET s, HANDLE ev, IO_STATUS_BLOCK *io, BP *p, ULONG insz, void *out, ULONG outsz) {
    return X.ioctl((HANDLE)s, ev, NULL, NULL, io, AX_IOCTL_BIND, p, insz, out, outsz);
}
static LONG do_name(SOCKET s, HANDLE ev, IO_STATUS_BLOCK *io, void *out, ULONG outsz) {
    return X.ioctl((HANDLE)s, ev, NULL, NULL, io, AX_IOCTL_GETSOCKNAME, NULL, 0, out, outsz);
}
#define IN4 (AX_BIND_ADDR_OFF + sizeof(struct sockaddr_in))
#define IN6 (AX_BIND_ADDR_OFF + sizeof(struct sockaddr_in6))
#define SA_DATA_OFF 2           /* offset of the data after the family field */

static struct sockaddr_in lo4(void) { struct sockaddr_in a; afdx_fill_sin(&a, LO4, 0); return a; }
static struct sockaddr_in6 lo6(void) { struct sockaddr_in6 a; memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1; return a; }

typedef struct { HANDLE ev; SOCKET s; BP p; IO_STATUS_BLOCK io; } BC;
static void bc_open(BC *b, int af, int type) {
    memset(b, 0, sizeof *b);
    b->ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    b->s = afdx_socket(af, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP, WSA_FLAG_OVERLAPPED);
}
static void bc_close(BC *b) { afdx_close(b->s); CloseHandle(b->ev); }

/* ---- IPv4 ---- */
TEST(afdbind_v4_bad_family) {
    AFDX_BEGIN();
    BC b; bc_open(&b, AF_INET, SOCK_STREAM); struct sockaddr_in a, out;
    memset(&a, 0, sizeof a); a.sin_family = 0xdead;
    bp_set(&b.p, &a, sizeof a);
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, IN4, &out, sizeof out), AX_STATUS_INVALID_ADDRESS);
    bc_close(&b);
}
TEST(afdbind_v4_input_one_byte_short) {
    AFDX_BEGIN();
    BC b; bc_open(&b, AF_INET, SOCK_STREAM); struct sockaddr_in a = lo4(), out;
    bp_set(&b.p, &a, sizeof a);
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, IN4 - 1, &out, sizeof out), AX_STATUS_INVALID_ADDRESS);
    bc_close(&b);
}
TEST(afdbind_v4_input_holds_family_only) {
    AFDX_BEGIN();
    BC b; bc_open(&b, AF_INET, SOCK_STREAM); struct sockaddr_in a = lo4(), out;
    bp_set(&b.p, &a, sizeof a);
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, AX_BIND_ADDR_OFF + SA_DATA_OFF, &out, sizeof out), AX_STATUS_INVALID_ADDRESS);
    bc_close(&b);
}
TEST(afdbind_v4_input_too_short_for_family) {
    AFDX_BEGIN();
    BC b; bc_open(&b, AF_INET, SOCK_STREAM); struct sockaddr_in a = lo4(), out;
    bp_set(&b.p, &a, sizeof a);
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, AX_BIND_ADDR_OFF + SA_DATA_OFF - 1, &out, sizeof out), AX_STATUS_INVALID_PARAMETER);
    bc_close(&b);
}
TEST(afdbind_v4_non_local_address_fails_asynchronously) {
    AFDX_BEGIN();
    BC b; bc_open(&b, AF_INET, SOCK_STREAM); struct sockaddr_in a = lo4(), out;
    a.sin_addr.s_addr = AX_HTONL(0xc0000200);           /* 192.0.2.0, reserved documentation network: never assigned locally */
    bp_set(&b.p, &a, sizeof a);
    FILL_IOSB(b.io, 0xcc);
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, IN4, &out, sizeof out), AX_STATUS_PENDING);
    CHECK(WaitForSingleObject(b.ev, 0) == WAIT_OBJECT_0);   /* already complete when the call returns */
    CHECK_ST(b.io.Status, AX_STATUS_INVALID_ADDRESS_COMPONENT);
    bc_close(&b);
}
TEST(afdbind_v4_output_one_byte_short) {
    AFDX_BEGIN();
    BC b; bc_open(&b, AF_INET, SOCK_STREAM); struct sockaddr_in a = lo4(), out;
    bp_set(&b.p, &a, sizeof a);
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, IN4, &out, sizeof out - 1), AX_STATUS_INVALID_PARAMETER);
    bc_close(&b);
}

static void v4_bind_ok(int type, ULONG host_addr) {
    BC b; bc_open(&b, AF_INET, type); struct sockaddr_in a, out, again;
    afdx_fill_sin(&a, host_addr, 0);
    bp_set(&b.p, &a, sizeof a);
    FILL_IOSB(b.io, 0xcc); memset(&out, 0xcc, sizeof out);
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, IN4, &out, sizeof out), AX_STATUS_PENDING);
    CHECK(WaitForSingleObject(b.ev, 0) == WAIT_OBJECT_0);
    CHECK_IOSB(b.io, 0, sizeof out);
    CHECK(out.sin_family == AF_INET);
    CHECK(out.sin_addr.s_addr == AX_HTONL(host_addr));
    CHECK(out.sin_port != 0);                        /* an ephemeral port was assigned */
    /* the name is also available through the socket-name request */
    memset(&again, 0xcc, sizeof again);
    CHECK_ST(do_name(b.s, b.ev, &b.io, &again, sizeof again), AX_STATUS_SUCCESS);
    CHECK(!memcmp(&out, &again, sizeof out));
    if (type == SOCK_STREAM) {
        /* binding twice is refused synchronously; another socket on the same name collides asynchronously */
        CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, IN4, &out, sizeof out), AX_STATUS_ADDRESS_ALREADY_ASSOCIATED);
        BC c; bc_open(&c, AF_INET, SOCK_STREAM);
        bp_set(&c.p, &again, sizeof again);
        FILL_IOSB(c.io, 0xcc); memset(&out, 0xcc, sizeof out);
        CHECK_ST(do_bind(c.s, c.ev, &c.io, &c.p, IN4, &out, sizeof out), AX_STATUS_PENDING);
        CHECK(WaitForSingleObject(c.ev, 0) == WAIT_OBJECT_0);
        CHECK_IOSB(c.io, AX_STATUS_SHARING_VIOLATION, 0);
        bc_close(&c);
    }
    bc_close(&b);
}
TEST(afdbind_v4_tcp_loopback_assigns_port_and_collides) { AFDX_BEGIN(); v4_bind_ok(SOCK_STREAM, LO4); }
TEST(afdbind_v4_udp_loopback_assigns_port) { AFDX_BEGIN(); v4_bind_ok(SOCK_DGRAM, LO4); }
TEST(afdbind_v4_udp_other_loopback_address_is_echoed) { AFDX_BEGIN(); v4_bind_ok(SOCK_DGRAM, 0x7f000002UL); }

/* ---- IPv6 ---- */
static int have_v6(void) {
    SOCKET s = X.WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) { t_skip("IPv6 sockets unavailable"); return 0; }
    X.closesocket(s);
    return 1;
}
TEST(afdbind_v6_bad_family) {
    AFDX_BEGIN(); if (!have_v6()) return;
    BC b; bc_open(&b, AF_INET6, SOCK_STREAM); struct sockaddr_in6 a, out;
    memset(&a, 0, sizeof a); a.sin6_family = 0xdead;
    bp_set(&b.p, &a, sizeof a);
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, IN6, &out, sizeof out), AX_STATUS_INVALID_ADDRESS);
    bc_close(&b);
}
TEST(afdbind_v6_input_shape_errors) {
    AFDX_BEGIN(); if (!have_v6()) return;
    BC b; bc_open(&b, AF_INET6, SOCK_STREAM); struct sockaddr_in6 a = lo6(), out;
    bp_set(&b.p, &a, sizeof a);
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, IN6 - 1, &out, sizeof out), AX_STATUS_INVALID_ADDRESS);
    /* the pre-scope-id layout (24 bytes) is not accepted for an IPv6 name either */
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, AX_BIND_ADDR_OFF + AX_SOCKADDR_IN6_OLD_SIZE, &out, sizeof out), AX_STATUS_INVALID_ADDRESS);
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, AX_BIND_ADDR_OFF + SA_DATA_OFF, &out, sizeof out), AX_STATUS_INVALID_ADDRESS);
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, AX_BIND_ADDR_OFF + SA_DATA_OFF - 1, &out, sizeof out), AX_STATUS_INVALID_PARAMETER);
    bc_close(&b);
}
TEST(afdbind_v6_output_size_errors) {
    AFDX_BEGIN(); if (!have_v6()) return;
    BC b; bc_open(&b, AF_INET6, SOCK_STREAM); struct sockaddr_in6 a = lo6(), out;
    bp_set(&b.p, &a, sizeof a);
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, IN6, &out, sizeof out - 1), AX_STATUS_INVALID_PARAMETER);
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, IN6, &out, AX_SOCKADDR_IN6_OLD_SIZE), AX_STATUS_INVALID_PARAMETER);
    /* both sizes wrong: the input is judged first */
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, IN6 - 1, &out, sizeof out - 1), AX_STATUS_INVALID_ADDRESS);
    bc_close(&b);
}
TEST(afdbind_v6_non_local_address_fails_asynchronously) {
    AFDX_BEGIN(); if (!have_v6()) return;
    BC b; bc_open(&b, AF_INET6, SOCK_STREAM); struct sockaddr_in6 a, out;
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[0] = 0x01;    /* 100::, the discard prefix */
    bp_set(&b.p, &a, sizeof a);
    FILL_IOSB(b.io, 0xcc);
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, IN6, &out, sizeof out), AX_STATUS_PENDING);
    CHECK(WaitForSingleObject(b.ev, 0) == WAIT_OBJECT_0);
    CHECK_ST(b.io.Status, AX_STATUS_INVALID_ADDRESS_COMPONENT);
    bc_close(&b);
}
TEST(afdbind_v6_loopback_assigns_port_and_collides) {
    AFDX_BEGIN(); if (!have_v6()) return;
    BC b; bc_open(&b, AF_INET6, SOCK_STREAM); struct sockaddr_in6 a = lo6(), out, again;
    bp_set(&b.p, &a, sizeof a);
    FILL_IOSB(b.io, 0xcc); memset(&out, 0xcc, sizeof out);
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, IN6, &out, sizeof out), AX_STATUS_PENDING);
    CHECK(WaitForSingleObject(b.ev, 0) == WAIT_OBJECT_0);
    if ((ULONG)b.io.Status == AX_STATUS_INVALID_ADDRESS_COMPONENT) { t_skip("no IPv6 loopback address on this system"); bc_close(&b); return; }
    CHECK_IOSB(b.io, 0, sizeof out);
    CHECK(out.sin6_family == AF_INET6);
    CHECK(!memcmp(&out.sin6_addr, &a.sin6_addr, sizeof a.sin6_addr));
    CHECK(out.sin6_flowinfo == 0);
    CHECK(out.sin6_port != 0);
    memset(&again, 0xcc, sizeof again);
    CHECK_ST(do_name(b.s, b.ev, &b.io, &again, sizeof again), AX_STATUS_SUCCESS);
    CHECK(!memcmp(&out, &again, sizeof out));
    CHECK_ST(do_bind(b.s, b.ev, &b.io, &b.p, IN6, &out, sizeof out), AX_STATUS_ADDRESS_ALREADY_ASSOCIATED);
    BC c; bc_open(&c, AF_INET6, SOCK_STREAM);
    bp_set(&c.p, &again, sizeof again);
    FILL_IOSB(c.io, 0xcc); memset(&out, 0xcc, sizeof out);
    CHECK_ST(do_bind(c.s, c.ev, &c.io, &c.p, IN6, &out, sizeof out), AX_STATUS_PENDING);
    CHECK(WaitForSingleObject(c.ev, 0) == WAIT_OBJECT_0);
    CHECK_IOSB(c.io, AX_STATUS_SHARING_VIOLATION, 0);
    bc_close(&c); bc_close(&b);
}

/* ---- IOCTL_AFD_GETSOCKNAME ---- */
TEST(afdname_connected_output_too_small) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; struct sockaddr a;
    afdx_pair(&c, &s, WSA_FLAG_OVERLAPPED);
    CHECK_ST(do_name(c, NULL, &io, &a, sizeof a - 1), AX_STATUS_BUFFER_TOO_SMALL);
    afdx_close(c); afdx_close(s);
}
TEST(afdname_connected_matches_getsockname) {
    AFDX_BEGIN();
    SOCKET c, s, both[2]; IO_STATUS_BLOCK io; struct sockaddr a, b; int len;
    afdx_pair(&c, &s, WSA_FLAG_OVERLAPPED);
    both[0] = c; both[1] = s;
    for (int i = 0; i < 2; i++) {                    /* client and accepted socket alike */
        memset(&a, 0xcc, sizeof a); FILL_IOSB(io, 0xcc);
        CHECK_ST(do_name(both[i], NULL, &io, &a, sizeof a), AX_STATUS_SUCCESS);
        CHECK_IOSB(io, 0, sizeof a);
        len = sizeof b;
        CHECK(X.getsockname(both[i], &b, &len) == 0);
        CHECK(!memcmp(&a, &b, sizeof a));
    }
    afdx_close(c); afdx_close(s);
}
TEST(afdname_unbound_socket_is_invalid_parameter) {
    AFDX_BEGIN();
    SOCKET s = afdx_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSA_FLAG_OVERLAPPED);
    IO_STATUS_BLOCK io; struct sockaddr a;
    CHECK_ST(do_name(s, NULL, &io, &a, sizeof a), AX_STATUS_INVALID_PARAMETER);
    CHECK_ST(do_name(s, NULL, &io, &a, sizeof a - 1), AX_STATUS_INVALID_PARAMETER);   /* state is judged before size */
    afdx_close(s);
}
TEST(afdname_after_winsock_bind) {
    AFDX_BEGIN();
    SOCKET s = afdx_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSA_FLAG_OVERLAPPED);
    IO_STATUS_BLOCK io; struct sockaddr a, b; struct sockaddr_in in = lo4(); int len = sizeof b;
    CHECK(X.bind(s, (struct sockaddr *)&in, sizeof in) == 0);
    memset(&a, 0xcc, sizeof a); FILL_IOSB(io, 0xcc);
    CHECK_ST(do_name(s, NULL, &io, &a, sizeof a), AX_STATUS_SUCCESS);
    CHECK_IOSB(io, 0, sizeof a);
    CHECK(X.getsockname(s, &b, &len) == 0);
    CHECK(!memcmp(&a, &b, sizeof a));
    afdx_close(s);
}
