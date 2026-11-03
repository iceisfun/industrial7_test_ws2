/* Send-side behaviour: non-blocking send accepting oversized buffers until the stack pushes back with
 * WSAEWOULDBLOCK (including data surviving a close and a sender thread that exits first), and handle
 * validation for send-family calls (duplicated socket handles work, other kernel objects do not). */
#include "lift11.h"

#define L11_BUF_BYTES (16 * 1024 * 1024)
static const char l11_pattern[] = "abcdefg01234567";

static void l11_fill(char *p, int n)
{
    int i;
    for (i = 0; i < n; i++) p[i] = l11_pattern[i % (int)sizeof(l11_pattern)];
}

/* Send whole-buffer chunks until the socket pushes back; returns bytes accepted, -1 when it never did. */
static int l11_send_until_full(SOCKET s, const char *buf, int chunk, int *last_err, int *chunk_mismatch)
{
    int total = 0, n, iter;
    *chunk_mismatch = 0;
    for (iter = 0; iter < 64; iter++) {
        n = U(send)(s, buf, chunk, 0);
        if (n > 0) {
            if (n != chunk) *chunk_mismatch = 1;
            total += n;
            continue;
        }
        *last_err = l11_err();
        return n == SOCKET_ERROR ? total : -1;
    }
    return -1;
}

/* Drain until orderly EOF, verifying the byte pattern; returns bytes seen. */
static int l11_drain_verify(SOCKET c, char *buf, int cap, int *eof_ret, int *bad_data, int *timed_out)
{
    int seen = 0, n, i;
    ULONGLONG end = GetTickCount64() + 20000;
    *bad_data = 0; *timed_out = 0;
    for (;;) {
        n = U(recv)(c, buf, cap, 0);
        if (n > 0) {
            for (i = 0; i < n; i++)
                if (buf[i] != l11_pattern[(seen + i) % (int)sizeof(l11_pattern)]) { *bad_data = 1; break; }
            seen += n;
            continue;
        }
        if (n < 0 && l11_err() == WSAEWOULDBLOCK) {
            if (GetTickCount64() > end) { *timed_out = 1; *eof_ret = -2; return seen; }
            Sleep(1);
            continue;
        }
        *eof_ret = n;
        return seen;
    }
}

TEST(send_nonblocking_big_buffer_then_wouldblock_then_close_delivers_all)
{
    SOCKET c, s;
    char *buf;
    int sent, err = 0, mism, eof = 0, bad, to, seen;
    UP();
    PAIR(&c, &s);
    buf = malloc(L11_BUF_BYTES);
    REQUIRE(buf != NULL);
    l11_fill(buf, L11_BUF_BYTES);
    l11_blocking(c, FALSE);
    l11_blocking(s, FALSE);
    sent = l11_send_until_full(s, buf, L11_BUF_BYTES, &err, &mism);
    CHECKF(sent > 0, "sent %d", sent);
    CHECK(!mism);
    L_EQ(err, WSAEWOULDBLOCK);
    U(closesocket)(s);
    l11_seterr(0xdeadbeef);
    seen = l11_drain_verify(c, buf, L11_BUF_BYTES, &eof, &bad, &to);
    CHECK(!to);
    CHECK(!bad);
    L_EQ(eof, 0);
    L_EQ(seen, sent);
    U(closesocket)(c);
    free(buf);
}

struct l11_sender { SOCKET s; char *buf; int chunk; int sent; int err; int mism; BOOL cancelex_ok; DWORD cancelex_err; BOOL cancelio_ok; };

static DWORD WINAPI l11_sender_thread(void *arg)
{
    struct l11_sender *d = arg;
    d->sent = l11_send_until_full(d->s, d->buf, d->chunk, &d->err, &d->mism);
    SetLastError(0xdeadbeef);
    d->cancelex_ok = U(CancelIoEx)((HANDLE)d->s, NULL);
    d->cancelex_err = GetLastError();
    d->cancelio_ok = U(CancelIo)((HANDLE)d->s);
    U(shutdown)(d->s, SD_BOTH);
    U(closesocket)(d->s);
    return 0;
}

TEST(send_nonblocking_sender_thread_exits_before_data_is_read)
{
    /* Data accepted by the stack is delivered even though the sending thread has finished and closed
     * the socket; with nothing outstanding, CancelIoEx finds no I/O (ERROR_NOT_FOUND) while CancelIo
     * succeeds. */
    struct l11_sender d;
    SOCKET c, s;
    HANDLE th;
    int eof = 0, bad, to, seen;
    char *buf;
    UP();
    PAIR(&c, &s);
    buf = malloc(L11_BUF_BYTES);
    REQUIRE(buf != NULL);
    l11_fill(buf, L11_BUF_BYTES);
    l11_blocking(c, FALSE);
    l11_blocking(s, FALSE);
    memset(&d, 0, sizeof(d));
    d.s = s; d.buf = buf; d.chunk = L11_BUF_BYTES;
    th = CreateThread(NULL, 0, l11_sender_thread, &d, 0, NULL);
    REQUIRE(th != NULL);
    L_EQ(WaitForSingleObject(th, 30000), WAIT_OBJECT_0);
    CloseHandle(th);
    CHECKF(d.sent > 0, "sent %d", d.sent);
    CHECK(!d.mism);
    L_EQ(d.err, WSAEWOULDBLOCK);
    CHECK(!d.cancelex_ok);
    L_EQ(d.cancelex_err, ERROR_NOT_FOUND);
    CHECK(d.cancelio_ok);
    seen = l11_drain_verify(c, buf, L11_BUF_BYTES, &eof, &bad, &to);
    CHECK(!to);
    CHECK(!bad);
    L_EQ(eof, 0);
    L_EQ(seen, d.sent);
    U(closesocket)(c);
    free(buf);
}

/* ---- handle validation for send calls ---------------------------------- */

TEST(send_through_duplicated_socket_handle_works)
{
    /* Unlike WSAGetOverlappedResult, send-family calls accept a DuplicateHandle copy of a socket. */
    SOCKET c, s;
    HANDLE dup = NULL;
    char b[1] = {'x'};
    WSABUF wb;
    DWORD sent = 0;
    UP();
    PAIR(&c, &s);
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)c, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS));
    L_EQ(U(send)((SOCKET)dup, b, 1, 0), 1);
    L_EQ(U(sendto)((SOCKET)dup, b, 1, 0, NULL, 0), 1);
    wb.buf = b; wb.len = 1;
    L_EQ(U(WSASend)((SOCKET)dup, &wb, 1, &sent, 0, NULL, NULL), 0);
    L_EQ(sent, 1);
    L_EQ(U(closesocket)((SOCKET)dup), 0);
    U(closesocket)(c); U(closesocket)(s);
}

TEST(send_on_non_socket_handle_is_notsock)
{
    HANDLE ev;
    char b[1] = {'x'};
    WSABUF wb;
    UP();
    ev = CreateEventA(NULL, TRUE, TRUE, NULL);
    wb.buf = b; wb.len = 1;
    l11_seterr(0xdeadbeef);
    L_EQ(U(WSASend)((SOCKET)ev, &wb, 1, NULL, 0, NULL, NULL), -1);
    L_EQ(l11_err(), WSAENOTSOCK);
    l11_seterr(0xdeadbeef);
    L_EQ(U(closesocket)((SOCKET)ev), SOCKET_ERROR);
    L_EQ(l11_err(), WSAENOTSOCK);
    CHECK(CloseHandle(ev));
}

TEST(send_on_invalid_socket_value_is_notsock)
{
    char b[1] = {'x'};
    WSABUF wb;
    UP();
    wb.buf = b; wb.len = 1;
    l11_seterr(0xdeadbeef);
    L_EQ(U(WSASend)(INVALID_SOCKET, &wb, 1, NULL, 0, NULL, NULL), -1);
    L_EQ(l11_err(), WSAENOTSOCK);
}
