/* Completion-port behaviour of orderly-release paths.
 * shutdown(), WSASendDisconnect() and WSARecvDisconnect() are synchronous and post nothing to the port of the
 * socket.  DisconnectEx with an OVERLAPPED goes pending and always queues a packet (also when skip-on-success is
 * enabled) with zero bytes; with a NULL OVERLAPPED it completes synchronously and queues nothing; an OVERLAPPED
 * event handle with the low bit set suppresses the packet.
 */
#include "w.h"

struct dpair { SOCKET listener, client, server; HANDLE port; struct sockaddr_in dest; };

static int dpair_open(struct dpair *p, int skip_on_success)
{
    memset(p, 0, sizeof *p);
    p->client = p->server = INVALID_SOCKET;
    p->listener = w_listener(&p->dest, 1);
    if (p->listener == INVALID_SOCKET) return 0;
    p->client = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    p->port = w_port_for(p->client, 0);
    if (skip_on_success) SetFileCompletionNotificationModes((HANDLE)p->client, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS);
    if (p_connect(p->client, (struct sockaddr *)&p->dest, sizeof p->dest)) return 0;
    p->server = w_accept(p->listener, 3000);
    return p->server != INVALID_SOCKET;
}
static void dpair_close(struct dpair *p)
{
    if (p->server != INVALID_SOCKET) p_closesocket(p->server);
    if (p->client != INVALID_SOCKET) p_closesocket(p->client);
    if (p->port) CloseHandle(p->port);
    if (p->listener != INVALID_SOCKET) p_closesocket(p->listener);
}

TEST(lift10_shutdown_posts_no_completion)
{
    struct dpair p;
    W_BEGIN();
    CHECK(dpair_open(&p, 0));
    EXPECT_EQ(p_shutdown(p.client, SD_BOTH), 0);
    w_expect_empty(p.port, 0);
    dpair_close(&p);
}

TEST(lift10_wsa_disconnect_calls_post_no_completion)
{
    struct dpair p;
    W_BEGIN();
    CHECK(dpair_open(&p, 0));
    EXPECT_EQ(p_WSASendDisconnect(p.client, NULL), 0);
    EXPECT_EQ(p_WSARecvDisconnect(p.client, NULL), 0);
    w_expect_empty(p.port, 0);
    dpair_close(&p);
}

/* skip_on_success: set the notification mode first; it must not stop the packet of a pending DisconnectEx. */
static void disconnectex_overlapped(int skip_on_success, int low_bit)
{
    struct dpair p;
    OVERLAPPED ov;
    LPFN_DISCONNECTEX dex;
    HANDLE ev;
    DWORD size = W_SENT, w;
    struct w_cp r;
    BOOL ret;

    CHECK(dpair_open(&p, skip_on_success));
    dex = w_disconnectex(p.client);
    CHECK(dex != NULL);
    if (!dex) { dpair_close(&p); return; }
    ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = low_bit ? (HANDLE)((ULONG_PTR)ev | 1) : ev;

    p_WSASetLastError(W_SENT);
    ret = dex(p.client, &ov, 0, 0);
    CHECK(!ret);
    EXPECT_EQ(p_WSAGetLastError(), ERROR_IO_PENDING);
    w = WaitForSingleObject(ev, 3000);
    EXPECT_EQ(w, WAIT_OBJECT_0);
    CHECK(GetOverlappedResult((HANDLE)p.client, &ov, &size, TRUE));
    EXPECT_EQ(size, 0);

    if (low_bit) {
        w_expect_empty(p.port, 0);
    } else {
        r = w_dequeue(p.port, 0);
        CHECK(r.ret);
        EXPECT_EQ(r.key, 0);
        EXPECT_EQ(r.bytes, 0);
        CHECK(r.ov == &ov);
    }
    CloseHandle(ev);
    dpair_close(&p);
}

TEST(lift10_disconnectex_overlapped_queues_completion)        { W_BEGIN(); disconnectex_overlapped(1, 0); }
TEST(lift10_disconnectex_overlapped_queues_without_skip_mode) { W_BEGIN(); disconnectex_overlapped(0, 0); }
TEST(lift10_disconnectex_event_low_bit_suppresses_packet)     { W_BEGIN(); disconnectex_overlapped(0, 1); }

TEST(lift10_disconnectex_null_overlapped_is_synchronous)
{
    struct dpair p;
    LPFN_DISCONNECTEX dex;
    BOOL ret;
    W_BEGIN();
    CHECK(dpair_open(&p, 0));
    dex = w_disconnectex(p.client);
    CHECK(dex != NULL);
    if (dex) {
        SetLastError(W_SENT);
        ret = dex(p.client, NULL, 0, 0);
        CHECK(ret);
        /* success leaves the thread error either untouched or cleared, depending on the Windows build */
        CHECK(GetLastError() == 0 || GetLastError() == W_SENT);
        w_expect_empty(p.port, 0);
    }
    dpair_close(&p);
}
