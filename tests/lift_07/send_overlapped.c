/* Measures large stream sends: a blocking send much bigger than the socket buffers completing once the peer
 * drains it, and an overlapped WSASend on a socket with a zero-sized send buffer staying pending until the
 * peer reads, then reporting the full byte count. */
#include "lift07.h"

#define SEND_LEN (1024 * 1024)

static DWORD WINAPI drain_thread(LPVOID arg)
{
    SOCKET s = *(SOCKET *)arg;
    char buf[4096];
    int r;
    while ((r = U(recv)(s, buf, sizeof(buf), 0)) > 0) {}
    return 0;
}

static void fill_pattern(char *p, int n) { int i; for (i = 0; i < n; ++i) p[i] = (char)i; }

L7TEST(l07_send_blocking_larger_than_buffers)
{
    char *buf = malloc(SEND_LEN); HANDLE th; DWORD id; int r;
    L7_PAIR(cl, sv);
    REQUIRE(buf);
    fill_pattern(buf, SEND_LEN);
    th = CreateThread(NULL, 0, drain_thread, &sv, 0, &id);
    r = U(send)(cl, buf, SEND_LEN, 0);
    CHECKF(r == SEND_LEN, "send returned %d (err %d)", r, l7_err());
    l7_close(cl);                                   /* peer sees EOF, drain thread ends */
    CHECK(WaitForSingleObject(th, 5000) == WAIT_OBJECT_0);
    CloseHandle(th);
    l7_close(sv);
    free(buf);
}

L7TEST(l07_send_overlapped_zero_buffer_pends_until_read)
{
    char *buf = malloc(SEND_LEN), *rx = malloc(SEND_LEN);
    int zero = 0, r, got = 0; WSABUF wb; OVERLAPPED ov; DWORD sent = 0, flags = 0, w;
    L7_PAIR(dst, src);
    REQUIRE(buf && rx);
    fill_pattern(buf, SEND_LEN);
    CHECK(U(setsockopt)(dst, SOL_SOCKET, SO_SNDBUF, (char *)&zero, sizeof(zero)) == 0);
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    wb.buf = buf; wb.len = SEND_LEN;
    l7_seterr(12345);
    r = U(WSASend)(dst, &wb, 1, &sent, 0, (LPWSAOVERLAPPED)&ov, NULL);
    CHECKF(r == SOCKET_ERROR && l7_err() == ERROR_IO_PENDING, "r=%d err=%d", r, l7_err());

    /* read everything from the peer in chunks; data must arrive in order */
    while (got < SEND_LEN) {
        int n = U(recv)(src, rx + got, SEND_LEN - got, 0);
        if (n <= 0) break;
        got += n;
    }
    CHECKF(got == SEND_LEN, "received %d bytes", got);
    CHECK(memcmp(rx, buf, got) == 0);

    w = WaitForSingleObject(ov.hEvent, 2000);
    CHECKF(w == WAIT_OBJECT_0, "completion event not signalled");
    if (w == WAIT_OBJECT_0) {
        r = U(WSAGetOverlappedResult)(dst, (LPWSAOVERLAPPED)&ov, &sent, FALSE, &flags);
        CHECKF(r && sent == SEND_LEN, "result ok=%d bytes=%lu", r, sent);
    }
    l7_close(dst); l7_close(src);
    CloseHandle(ov.hEvent);
    free(buf); free(rx);
}

L7TEST(l07_send_overlapped_invalid_socket)
{
    char b[4] = "abc"; WSABUF wb; OVERLAPPED ov; int r;
    if (!l7_init()) return;
    memset(&ov, 0, sizeof(ov));
    wb.buf = b; wb.len = sizeof(b);
    l7_seterr(12345);
    r = U(WSASend)(INVALID_SOCKET, &wb, 1, NULL, 0, (LPWSAOVERLAPPED)&ov, NULL);
    CHECKF(r == SOCKET_ERROR && l7_err() == WSAENOTSOCK, "r=%d err=%d", r, l7_err());
}

L7TEST(l07_send_overlapped_without_byte_count_pends)
{
    /* With an overlapped structure the sent-bytes pointer may be NULL; a send that cannot complete pends.
     * The pending request is cancelled by closing the socket and drained before the structure goes away. */
    char *buf = malloc(SEND_LEN); int zero = 0, r; WSABUF wb; OVERLAPPED ov;
    L7_PAIR(dst, src);
    REQUIRE(buf);
    fill_pattern(buf, SEND_LEN);
    CHECK(U(setsockopt)(dst, SOL_SOCKET, SO_SNDBUF, (char *)&zero, sizeof(zero)) == 0);
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    wb.buf = buf; wb.len = SEND_LEN;
    l7_seterr(12345);
    r = U(WSASend)(dst, &wb, 1, NULL, 0, (LPWSAOVERLAPPED)&ov, NULL);
    CHECKF(r == SOCKET_ERROR && l7_err() == ERROR_IO_PENDING, "r=%d err=%d", r, l7_err());
    l7_close(src);
    l7_close(dst);
    CHECK(WaitForSingleObject(ov.hEvent, 3000) == WAIT_OBJECT_0);   /* aborted by the close */
    CloseHandle(ov.hEvent);
    free(buf);
}
