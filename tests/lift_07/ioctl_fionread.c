/* Measures the FIONREAD ("bytes ready to read") and SIOCATMARK ("is the read pointer at the urgent mark")
 * socket I/O controls issued through WSAIoctl: output-buffer and byte-count-pointer validation,
 * inline completion of overlapped requests (completion port and APC delivery), and the values reported as
 * ordinary and urgent data arrives and is consumed, including with SO_OOBINLINE. */
#include "lift07.h"

/* Query both controls and compare with the expected values. */
static void fr_expect(SOCKET s, unsigned normal, unsigned at_mark, const char *what)
{
    DWORD size = 0;
    int value, r;

    value = L7_UNSET; l7_seterr(L7_UNSET);
    r = l7_ioctl(s, FIONREAD, NULL, 0, &value, sizeof(value), &size, NULL, NULL);
    CHECKF(r == 0, "%s: FIONREAD failed (%d)", what, l7_err());
    CHECKF(value == (int)normal, "%s: FIONREAD gave %d want %u", what, value, normal);

    value = L7_UNSET; l7_seterr(L7_UNSET);
    r = l7_ioctl(s, SIOCATMARK, NULL, 0, &value, sizeof(value), &size, NULL, NULL);
    CHECKF(r == 0, "%s: SIOCATMARK failed (%d)", what, l7_err());
    CHECKF(value == (int)at_mark, "%s: SIOCATMARK gave %d want %u", what, value, at_mark);
}

static const DWORD fr_codes[] = {FIONREAD, SIOCATMARK};
static const char *const fr_names[] = {"FIONREAD", "SIOCATMARK"};

L7TEST(l07_fionread_no_bytes_returned_ptr)
{
    /* Without an overlapped structure the byte-count pointer is mandatory. */
    int v, r; unsigned i;
    L7_PAIR(cl, sv);
    for (i = 0; i < 2; ++i) {
        l7_seterr(L7_UNSET);
        r = l7_ioctl(cl, fr_codes[i], NULL, 0, &v, sizeof(v), NULL, NULL, NULL);
        CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "%s: r=%d err=%d", fr_names[i], r, l7_err());
    }
    l7_close(cl); l7_close(sv);
}

L7TEST(l07_fionread_output_too_small)
{
    int v; DWORD size; int r; unsigned i;
    L7_PAIR(cl, sv);
    for (i = 0; i < 2; ++i) {
        l7_seterr(L7_UNSET);
        size = L7_UNSET;
        r = l7_ioctl(cl, fr_codes[i], NULL, 0, &v, sizeof(v) - 1, &size, NULL, NULL);
        CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "%s: r=%d err=%d", fr_names[i], r, l7_err());
        CHECKF(size == L7_UNSET, "%s: byte count was written (%lu)", fr_names[i], size);
    }
    l7_close(cl); l7_close(sv);
}

L7TEST(l07_fionread_overlapped_needs_bytes_ptr)
{
    /* Even with a completion port attached, the byte-count pointer is checked first. */
    OVERLAPPED ov = {0}; int v; int r; unsigned i; HANDLE port;
    L7_PAIR(cl, sv);
    port = l7_port_for(cl);
    for (i = 0; i < 2; ++i) {
        r = l7_ioctl(cl, fr_codes[i], NULL, 0, &v, sizeof(v), NULL, &ov, NULL);
        CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "%s: r=%d err=%d", fr_names[i], r, l7_err());
    }
    CloseHandle(port);
    l7_close(cl); l7_close(sv);
}

L7TEST(l07_fionread_idle_connection)
{
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    fr_expect(cl, 0, TRUE, "idle");
    l7_close(cl); l7_close(sv);
}

L7TEST(l07_fionread_overlapped_inline_completion)
{
    /* Both controls complete synchronously even when an overlapped structure is given: the call returns 0,
     * the byte count is 4, the structure shows status 0 / 0 bytes and a completion packet is queued. */
    OVERLAPPED ov = {0}; HANDLE port; int v; DWORD size; int r; unsigned i;
    L7_PAIR(cl, sv);
    port = l7_port_for(cl);
    for (i = 0; i < 2; ++i) {
        l7_seterr(L7_UNSET);
        size = L7_UNSET; v = L7_UNSET;
        l7_ov_poison(&ov);
        r = l7_ioctl(cl, fr_codes[i], NULL, 0, &v, sizeof(v), &size, &ov, NULL);
        CHECKF(r == 0 && l7_err() == 0, "%s: r=%d err=%d", fr_names[i], r, l7_err());
        CHECKF(v == (i == 0 ? 0 : TRUE), "%s: value %d", fr_names[i], v);
        CHECKF(size == sizeof(v), "%s: size %lu", fr_names[i], size);
        l7_expect_packet_ok(port, &ov, fr_names[i]);
    }
    CloseHandle(port);
    l7_close(cl); l7_close(sv);
}

L7TEST(l07_fionread_counts_pending_data)
{
    char buf[8] = "data";
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    CHECK(U(send)(sv, buf, 5, 0) == 5);
    CHECK((l7_poll(cl, POLLRDNORM) & POLLRDNORM) != 0);
    fr_expect(cl, 5, TRUE, "after 5 bytes");
    l7_close(cl); l7_close(sv);
}

L7TEST(l07_fionread_oob_single_byte)
{
    /* Urgent data kept out of band: it is not counted by FIONREAD and the read pointer is not at the mark
     * while ordinary data precedes it. */
    char buf[8] = "data";
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    CHECK(U(send)(sv, buf, 5, 0) == 5);
    CHECK((l7_poll(cl, POLLRDNORM) & POLLRDNORM) != 0);
    CHECK(U(send)(sv, "a", 1, MSG_OOB) == 1);
    CHECK((l7_poll(cl, POLLRDBAND) & POLLRDBAND) != 0);
    fr_expect(cl, 5, FALSE, "ordinary data and one urgent byte");
    l7_close(cl); l7_close(sv);
}

L7TEST(l07_fionread_oob_consumption_sequence)
{
    char buf[8] = "data";
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    CHECK(U(send)(sv, buf, 5, 0) == 5);
    CHECK((l7_poll(cl, POLLRDNORM) & POLLRDNORM) != 0);
    CHECK(U(send)(sv, "a", 1, MSG_OOB) == 1);
    CHECK((l7_poll(cl, POLLRDBAND) & POLLRDBAND) != 0);
    CHECK(U(send)(sv, "a", 1, MSG_OOB) == 1);
    fr_expect(cl, 5, FALSE, "two urgent bytes sent");

    CHECK(U(recv)(cl, buf, 3, 0) == 3);
    fr_expect(cl, 2, FALSE, "3 ordinary bytes consumed");

    CHECK(U(recv)(cl, buf, 1, MSG_OOB) == 1);
    CHECK((l7_poll(cl, POLLRDBAND) & POLLRDBAND) != 0);   /* a second urgent byte remains */
    fr_expect(cl, 2, FALSE, "one urgent byte consumed");

    CHECK(U(recv)(cl, buf, 5, 0) == 2);
    fr_expect(cl, 0, FALSE, "ordinary data drained, urgent byte left");

    CHECK(U(recv)(cl, buf, 1, MSG_OOB) == 1);
    fr_expect(cl, 0, TRUE, "all urgent data consumed");
    l7_close(cl); l7_close(sv);
}

L7TEST(l07_fionread_oob_inline)
{
    int one = 1;
    char buf[4];
    L7_PAIR(cl, sv);
    l7_nonblock(cl, 1);
    CHECK(U(send)(sv, "a", 1, MSG_OOB) == 1);
    CHECK((l7_poll(cl, POLLRDBAND) & POLLRDBAND) != 0);
    CHECK(U(setsockopt)(cl, SOL_SOCKET, SO_OOBINLINE, (char *)&one, sizeof(one)) == 0);
    fr_expect(cl, 1, FALSE, "urgent byte switched to inline");
    CHECK(U(recv)(cl, buf, 1, 0) == 1);
    fr_expect(cl, 0, TRUE, "inline urgent byte read");

    /* An urgent byte arriving while inline mode is on is plain readable data. */
    CHECK(U(send)(sv, "a", 1, MSG_OOB) == 1);
    CHECK((l7_poll(cl, POLLRDNORM) & POLLRDNORM) != 0);
    fr_expect(cl, 1, TRUE, "urgent byte arriving in inline mode");
    l7_close(cl); l7_close(sv);
}

L7TEST(l07_fionread_unconnected_sockets)
{
    /* A fresh and a bound-only stream socket report nothing readable and "at mark". */
    struct sockaddr_in a;
    SOCKET s;
    if (!l7_init()) return;
    s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    fr_expect(s, 0, TRUE, "new socket");
    l7_loop_addr(&a, 0);
    CHECK(U(bind)(s, (struct sockaddr *)&a, sizeof(a)) == 0);
    fr_expect(s, 0, TRUE, "bound socket");
    l7_close(s);
}

L7TEST(l07_fionread_apc_delivery)
{
    OVERLAPPED ov = {0}; int v; DWORD size; int r; unsigned i; SOCKET s;
    s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    for (i = 0; i < 2; ++i) {
        r = l7_ioctl(s, fr_codes[i], NULL, 0, &v, sizeof(v), NULL, &ov, l7_apc);
        CHECKF(r == SOCKET_ERROR && l7_err() == WSAEFAULT, "%s without byte count: r=%d err=%d", fr_names[i], r, l7_err());
        l7_apc_reset();
        size = L7_UNSET;
        r = l7_ioctl(s, fr_codes[i], NULL, 0, &v, sizeof(v), &size, &ov, l7_apc);
        CHECKF(r == 0, "%s: r=%d err=%d", fr_names[i], r, l7_err());
        CHECKF(size == sizeof(v), "%s: size %lu", fr_names[i], size);
        l7_expect_apc(&ov, 0, fr_names[i]);
    }
    l7_close(s);
}
