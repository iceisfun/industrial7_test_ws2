/* The wait-for-listen requests (the FIFO code and its LIFO sibling).
 *
 * Issued on a listening endpoint, the request completes when a connection is waiting to be accepted and
 * returns a sequence number (the handle for the later accept request) followed by the peer's socket
 * address. The output needs at least twelve bytes; on this stack the address that follows the sequence
 * number is an ordinary socket address, so a loopback IPv4 answer is twenty bytes long. A request issued
 * while nothing is waiting stays pending until a connection arrives, the request is cancelled or the
 * endpoint is closed. The LIFO code differs only in where a waiting request is queued.
 */
#include "abl.h"

typedef struct { ULONG seq; struct sockaddr_in addr; } WFL4;       /* 20 bytes */
static const ULONG k_codes[2] = { IO_WAIT_FOR_LISTEN, IO_WAIT_LISTEN_LIFO };

/* queue a connection and wait until the listener has it (readable) */
static SOCKET queue_conn(SOCKET l, const struct sockaddr_in *a) {
    SOCKET c = abl_client_to(a);
    CHECK(abl_wait_readable(l, WAIT_MS));
    return c;
}

TEST(ablw_output_length_table) {
    ABL_BEGIN();
    for (int k = 0; k < 2; k++) {
        for (ULONG n = 0; n < 12; n++) {
            struct sockaddr_in a; SOCKET l = abl_listener(&a); BYTE out[64]; IO_STATUS_BLOCK io; LONG first;
            LONG st = abl_ctl(l, k_codes[k], NULL, 0, n ? out : NULL, n, &io, &first);
            t_check((ULONG)st == NS_INVALID_PARAMETER && (ULONG)first == NS_INVALID_PARAMETER, __FILE__, __LINE__, "short output refused",
                    "code 0x%lx out %lu: st 0x%08lx first 0x%08lx", (unsigned long)k_codes[k], (unsigned long)n, (unsigned long)st, (unsigned long)first);
            abl_close(l);
        }
    }
}
TEST(ablw_short_output_does_not_consume_connection) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); BYTE out[64]; IO_STATUS_BLOCK io;
    SOCKET c = queue_conn(l, &a);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, out, 11, &io, NULL), NS_INVALID_PARAMETER);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, out, sizeof out, &io, NULL), NS_SUCCESS);
    abl_close(c); abl_close(l);
}
TEST(ablw_not_listening_refused) {
    ABL_BEGIN();
    for (int k = 0; k < 2; k++) {
        SOCKET c, s; BYTE out[64]; IO_STATUS_BLOCK io; LONG first;
        SOCKET fresh = abl_tcp(), bound = abl_bound(SOCK_STREAM, NULL), udp = abl_bound(SOCK_DGRAM, NULL), udp0 = abl_udp();
        SOCKET all[4] = { fresh, bound, udp, udp0 };
        for (int i = 0; i < 4; i++) {
            LONG st = abl_ctl(all[i], k_codes[k], NULL, 0, out, sizeof out, &io, &first);
            t_check((ULONG)st == NS_INVALID_PARAMETER && (ULONG)first == NS_INVALID_PARAMETER, __FILE__, __LINE__, "non-listener refused", "kind %d code 0x%lx: 0x%08lx", i, (unsigned long)k_codes[k], (unsigned long)st);
            abl_close(all[i]);
        }
        abl_pair(&c, &s);
        CHECK_NS(abl_ctl(c, k_codes[k], NULL, 0, out, sizeof out, &io, NULL), NS_INVALID_PARAMETER);
        CHECK_NS(abl_ctl(s, k_codes[k], NULL, 0, out, sizeof out, &io, NULL), NS_INVALID_PARAMETER);
        abl_close(c); abl_close(s);
    }
}
TEST(ablw_state_checked_before_length) {
    ABL_BEGIN();
    SOCKET b = abl_bound(SOCK_STREAM, NULL); BYTE out[64]; IO_STATUS_BLOCK io;
    /* both failures use the same status, so only the combination "listening + long enough" can succeed */
    CHECK_NS(abl_ctl(b, IO_WAIT_FOR_LISTEN, NULL, 0, out, 64, &io, NULL), NS_INVALID_PARAMETER);
    CHECK_NS(abl_ctl(b, IO_WAIT_FOR_LISTEN, NULL, 0, out, 0, &io, NULL), NS_INVALID_PARAMETER);
    abl_close(b);
}

/* ---- pending behaviour -------------------------------------------------------------------------- */
TEST(ablw_idle_listener_pends_until_cancelled) {
    ABL_BEGIN();
    for (int k = 0; k < 2; k++) {
        struct sockaddr_in a; SOCKET l = abl_listener(&a); BYTE out[64]; IO_STATUS_BLOCK io;
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        FILL_IO(io, 0xcc); memset(out, 0xcc, sizeof out);
        CHECK_NS(abl_submit(l, ev, k_codes[k], NULL, 0, out, sizeof out, &io), NS_PENDING);
        CHECK(WaitForSingleObject(ev, 300) == WAIT_TIMEOUT);
        CHECK(abl_wait(l, ev, &io, 0) == WAIT_TIMEOUT);          /* cancels the request and waits for it */
        CHECK(WaitForSingleObject(ev, 0) == WAIT_OBJECT_0);
        CHECK_NS(io.Status, NS_CANCELLED);
        CHECK_INFO(io, 0);
        for (size_t i = 0; i < sizeof out; i++) if (out[i] != 0xcc) { CHECKF(0, "output touched at %zu", i); break; }
        CloseHandle(ev); abl_close(l);
    }
}
TEST(ablw_pending_request_completes_on_arrival) {
    ABL_BEGIN();
    for (int k = 0; k < 2; k++) {
        struct sockaddr_in a, cn; int len = sizeof cn; SOCKET l = abl_listener(&a); BYTE out[64]; IO_STATUS_BLOCK io;
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        memset(out, 0xcc, sizeof out);
        CHECK_NS(abl_submit(l, ev, k_codes[k], NULL, 0, out, sizeof out, &io), NS_PENDING);
        SOCKET c = abl_client_to(&a);
        CHECK(WaitForSingleObject(ev, WAIT_MS) == WAIT_OBJECT_0);
        CHECK_NS(io.Status, NS_SUCCESS);
        CHECK_INFO(io, sizeof(WFL4));
        WFL4 *r = (WFL4 *)out;
        CHECK(r->seq != 0);
        CHECK(abl_wait_writable(c, WAIT_MS));
        CHECK(W.getsockname(c, (struct sockaddr *)&cn, &len) == 0);
        CHECK(r->addr.sin_family == AF_INET);
        CHECK(r->addr.sin_port == cn.sin_port);
        CHECK(r->addr.sin_addr.s_addr == cn.sin_addr.s_addr);
        for (int i = 0; i < 8; i++) CHECK(r->addr.sin_zero[i] == 0);
        CHECK(out[sizeof(WFL4)] == 0xcc);                       /* nothing written past the answer */
        CloseHandle(ev); abl_close(c); abl_close(l);
    }
}
TEST(ablw_queued_connection_completes_at_once) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); BYTE out[64]; IO_STATUS_BLOCK io; LONG first;
    SOCKET c = queue_conn(l, &a);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, out, sizeof out, &io, &first), NS_SUCCESS);
    CHECK_NS(first, NS_SUCCESS);                    /* answered by the submit call itself */
    CHECK_INFO(io, sizeof(WFL4));
    abl_close(c); abl_close(l);
}
TEST(ablw_exact_minimum_output_gets_sequence) {
    /* twelve bytes are enough to pass validation; the sequence number is the first word */
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); BYTE out[64]; IO_STATUS_BLOCK io;
    SOCKET c = queue_conn(l, &a);
    memset(out, 0xcc, sizeof out);
    LONG st = abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, out, 20, &io, NULL);
    CHECK_NS(st, NS_SUCCESS);
    CHECK(*(ULONG *)out != 0 && *(ULONG *)out != 0xcccccccc);
    abl_close(c); abl_close(l);
}
TEST(ablw_each_connection_reported_once_in_order) {
    ABL_BEGIN();
    struct sockaddr_in a, n1, n2; int len = sizeof n1; SOCKET l = abl_listener(&a);
    SOCKET c1 = abl_tcp(); CHECK(abl_connect(c1, &a) == 0);
    SOCKET c2 = abl_tcp(); CHECK(abl_connect(c2, &a) == 0);
    CHECK(abl_wait_readable(l, WAIT_MS));
    WFL4 r1, r2; IO_STATUS_BLOCK io;
    memset(&r1, 0, sizeof r1); memset(&r2, 0, sizeof r2);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, &r1, sizeof r1, &io, NULL), NS_SUCCESS);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, &r2, sizeof r2, &io, NULL), NS_SUCCESS);
    CHECK(r1.seq != r2.seq);
    CHECK(r2.seq == r1.seq + 1);
    CHECK(W.getsockname(c1, (struct sockaddr *)&n1, &len) == 0);
    len = sizeof n2; CHECK(W.getsockname(c2, (struct sockaddr *)&n2, &len) == 0);
    CHECK(r1.addr.sin_port == n1.sin_port);               /* oldest connection first */
    CHECK(r2.addr.sin_port == n2.sin_port);
    abl_close(c1); abl_close(c2); abl_close(l);
}
TEST(ablw_second_request_waits_for_next_connection) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); WFL4 r; IO_STATUS_BLOCK io;
    SOCKET c = queue_conn(l, &a);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, &r, sizeof r, &io, NULL), NS_SUCCESS);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL); WFL4 r2; memset(&r2, 0, sizeof r2);
    CHECK_NS(abl_submit(l, ev, IO_WAIT_FOR_LISTEN, NULL, 0, &r2, sizeof r2, &io), NS_PENDING);
    CHECK(WaitForSingleObject(ev, 300) == WAIT_TIMEOUT);       /* the first connection is not reported twice */
    SOCKET c2 = abl_client_to(&a);
    CHECK(WaitForSingleObject(ev, WAIT_MS) == WAIT_OBJECT_0);
    CHECK_NS(io.Status, NS_SUCCESS);
    CHECK(r2.seq == r.seq + 1);
    CloseHandle(ev); abl_close(c); abl_close(c2); abl_close(l);
}
TEST(ablw_input_buffer_is_ignored) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); WFL4 r; IO_STATUS_BLOCK io; BYTE junk[32];
    memset(junk, 0x7e, sizeof junk);
    SOCKET c = queue_conn(l, &a);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, junk, sizeof junk, &r, sizeof r, &io, NULL), NS_SUCCESS);
    CHECK_INFO(io, sizeof r);
    abl_close(c); abl_close(l);
}
TEST(ablw_closing_listener_cancels_waiter) {
    ABL_BEGIN();
    for (int k = 0; k < 2; k++) {
        struct sockaddr_in a; SOCKET l = abl_listener(&a); BYTE out[64]; IO_STATUS_BLOCK io;
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        CHECK_NS(abl_submit(l, ev, k_codes[k], NULL, 0, out, sizeof out, &io), NS_PENDING);
        CHECK(WaitForSingleObject(ev, 200) == WAIT_TIMEOUT);
        abl_close(l);
        CHECK(WaitForSingleObject(ev, WAIT_MS) == WAIT_OBJECT_0);
        CHECK_NS(io.Status, NS_CANCELLED);
        CloseHandle(ev);
    }
}
TEST(ablw_reset_connection_still_reported) {
    /* a peer that resets before the request is issued is still handed out (the failure shows up later) */
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); WFL4 r; IO_STATUS_BLOCK io;
    SOCKET c = queue_conn(l, &a);
    CHECK(abl_wait_writable(c, WAIT_MS));
    struct linger lg = { 1, 0 };
    CHECK(W.setsockopt(c, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof lg) == 0);
    abl_close(c);
    Sleep(200);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, &r, sizeof r, &io, NULL), NS_SUCCESS);
    CHECK_INFO(io, sizeof r);
    abl_close(l);
}
TEST(ablw_requests_served_in_submission_order) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); BYTE o1[64], o2[64]; IO_STATUS_BLOCK i1, i2;
    HANDLE e1 = CreateEventW(NULL, TRUE, FALSE, NULL), e2 = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(o1, 0, sizeof o1); memset(o2, 0, sizeof o2);
    CHECK_NS(abl_submit(l, e1, IO_WAIT_FOR_LISTEN, NULL, 0, o1, sizeof o1, &i1), NS_PENDING);
    CHECK_NS(abl_submit(l, e2, IO_WAIT_FOR_LISTEN, NULL, 0, o2, sizeof o2, &i2), NS_PENDING);
    SOCKET c1 = abl_client_to(&a);
    CHECK(WaitForSingleObject(e1, WAIT_MS) == WAIT_OBJECT_0);          /* the earlier request gets the first connection */
    CHECK(WaitForSingleObject(e2, 200) == WAIT_TIMEOUT);
    SOCKET c2 = abl_client_to(&a);
    CHECK(WaitForSingleObject(e2, WAIT_MS) == WAIT_OBJECT_0);
    CHECK(*(ULONG *)o2 == *(ULONG *)o1 + 1);
    CloseHandle(e1); CloseHandle(e2); abl_close(c1); abl_close(c2); abl_close(l);
}
TEST(ablw_lifo_request_jumps_the_queue) {
    ABL_BEGIN();
    struct sockaddr_in a; SOCKET l = abl_listener(&a); BYTE o1[64], o2[64]; IO_STATUS_BLOCK i1, i2;
    HANDLE e1 = CreateEventW(NULL, TRUE, FALSE, NULL), e2 = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(o1, 0, sizeof o1); memset(o2, 0, sizeof o2);
    CHECK_NS(abl_submit(l, e1, IO_WAIT_FOR_LISTEN, NULL, 0, o1, sizeof o1, &i1), NS_PENDING);
    CHECK_NS(abl_submit(l, e2, IO_WAIT_LISTEN_LIFO, NULL, 0, o2, sizeof o2, &i2), NS_PENDING);
    SOCKET c1 = abl_client_to(&a);
    CHECK(WaitForSingleObject(e2, WAIT_MS) == WAIT_OBJECT_0);          /* the later LIFO request is served first */
    CHECK(WaitForSingleObject(e1, 200) == WAIT_TIMEOUT);
    SOCKET c2 = abl_client_to(&a);
    CHECK(WaitForSingleObject(e1, WAIT_MS) == WAIT_OBJECT_0);
    CHECK(*(ULONG *)o1 == *(ULONG *)o2 + 1);
    CloseHandle(e1); CloseHandle(e2); abl_close(c1); abl_close(c2); abl_close(l);
}

/* ---- IPv6 -------------------------------------------------------------------------------------------- */
TEST(ablw_v6_answer_carries_v6_address) {
    ABL_BEGIN();
    if (!abl_have_v6()) { t_skip("no IPv6 loopback"); return; }
    SOCKET l = abl_sock(AF_INET6, SOCK_STREAM); struct sockaddr_in6 a = abl_lo6(0), n; IO_STATUS_BLOCK io; BYTE out[64];
    CHECK_NS(abl_raw_bind(l, 0, &a, sizeof a, &n, sizeof n, &io), NS_SUCCESS);
    CHECK_NS(abl_raw_listen(l, 5, 0), NS_SUCCESS);
    CHECK_NS(abl_raw_name(l, &n, sizeof n, &io), NS_SUCCESS);
    SOCKET c = abl_sock(AF_INET6, SOCK_STREAM);
    abl_nonblock(c, 1);
    W.connect(c, (struct sockaddr *)&n, sizeof n);
    CHECK(abl_wait_readable(l, WAIT_MS));
    memset(out, 0xcc, sizeof out);
    CHECK_NS(abl_ctl(l, IO_WAIT_FOR_LISTEN, NULL, 0, out, sizeof out, &io, NULL), NS_SUCCESS);
    CHECK_INFO(io, 4 + sizeof(struct sockaddr_in6));
    struct sockaddr_in6 *r = (struct sockaddr_in6 *)(out + 4);
    CHECK(r->sin6_family == AF_INET6);
    CHECK(r->sin6_addr.u.Byte[15] == 1);
    abl_close(c); abl_close(l);
}
