/* Operations on a socket whose connection attempt is still in flight.
 * A destination that really stalls the handshake is needed, so the listener on loopback is given a backlog of one
 * and its accept queue is filled without ever accepting; the next connection attempt then stays pending.  If the
 * stack does not stall (the attempt completes or is refused) the test is skipped, never failed.
 * Measures: repeating connect() gives WSAEALREADY; ConnectEx on a socket already connecting (either way round)
 * fails with WSAEINVAL after marking the OVERLAPPED as pending without touching its byte count; getsockname works;
 * getpeername works only when the attempt was started by connect(); recv/send give WSAENOTCONN.
 */
#include "w.h"

#define NFILL 8
struct stall {
    SOCKET listener, fill[NFILL], probe;
    int nfill;
    struct sockaddr_in dest;
};

/* writable-or-error test on one socket: 1 ready, 0 not ready within ms */
static int sel_write(SOCKET s, DWORD ms, int *has_error)
{
    fd_set wr, ex;
    struct timeval tv;
    int n;
    FD_ZERO(&wr); FD_SET(s, &wr);
    FD_ZERO(&ex); FD_SET(s, &ex);
    tv.tv_sec = 0; tv.tv_usec = ms * 1000;
    n = p_select(0, NULL, &wr, &ex, &tv);
    if (has_error) *has_error = (n > 0 && ex.fd_count);
    return n > 0;
}

static void stall_close(struct stall *st)
{
    int i;
    for (i = 0; i < st->nfill; i++) p_closesocket(st->fill[i]);
    if (st->listener != INVALID_SOCKET) p_closesocket(st->listener);
}

/* Returns 1 when a following connection attempt is expected to stay pending. */
static int stall_open(struct stall *st)
{
    int i;
    memset(st, 0, sizeof *st);
    st->listener = w_listener(&st->dest, 1);
    if (st->listener == INVALID_SOCKET) return 0;
    for (i = 0; i < NFILL; i++) {
        int err = 0, rc;
        SOCKET c = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        w_set_blocking(c, 0);
        p_connect(c, (struct sockaddr *)&st->dest, sizeof st->dest);
        rc = sel_write(c, 300, &err);
        if (!rc) {                       /* still pending: the accept queue is full */
            p_closesocket(c);
            return 1;
        }
        if (err) { p_closesocket(c); return 0; }
        st->fill[st->nfill++] = c;       /* completed: keep it queued */
    }
    return 0;
}

#define STALL_BEGIN(st) struct stall st; W_BEGIN(); \
    if (!stall_open(&st)) { stall_close(&st); t_skip("loopback listener did not stall the handshake"); return; }

/* Socket that is bound to the wildcard address, non-blocking. */
static SOCKET new_client(void)
{
    struct sockaddr_in any;
    SOCKET c = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&any, 0, sizeof any);
    any.sin_family = AF_INET;
    w_set_blocking(c, 0);
    p_bind(c, (struct sockaddr *)&any, sizeof any);
    return c;
}

/* Start a connect() that must be in progress; returns 0 (and closes) if it is not. */
static int start_connect(SOCKET c, struct stall *st)
{
    int ret = p_connect(c, (struct sockaddr *)&st->dest, sizeof st->dest);
    CHECK(ret == SOCKET_ERROR);
    CHECK(p_WSAGetLastError() == WSAEWOULDBLOCK);
    return !sel_write(c, 150, NULL);
}

static OVERLAPPED g_ov1, g_ov2;     /* outlive the sockets: cancelled requests are written back after close */

static void names_and_io_fail(SOCKET c, int peer_known)
{
    struct sockaddr_in a;
    int len = sizeof a, ret;
    char buf[4];

    ret = p_getsockname(c, (struct sockaddr *)&a, &len);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(a.sin_family, AF_INET);
    CHECK(a.sin_port != 0);

    len = sizeof a;
    ret = p_getpeername(c, (struct sockaddr *)&a, &len);
    if (peer_known) {
        EXPECT_EQ(ret, 0);
    } else {
        EXPECT_EQ(ret, SOCKET_ERROR);
        EXPECT_EQ(p_WSAGetLastError(), WSAENOTCONN);
    }

    ret = p_recv(c, buf, sizeof buf, 0);
    EXPECT_EQ(ret, SOCKET_ERROR);
    EXPECT_EQ(p_WSAGetLastError(), WSAENOTCONN);
    ret = p_send(c, "data", 5, 0);
    EXPECT_EQ(ret, SOCKET_ERROR);
    EXPECT_EQ(p_WSAGetLastError(), WSAENOTCONN);
}

/* ---- the attempt was started with connect() ---------------------------- */

TEST(lift10_connecting_repeat_connect_is_ealready)
{
    SOCKET c;
    int ret;
    STALL_BEGIN(st);
    c = new_client();
    if (!start_connect(c, &st)) { t_skip("attempt did not stay pending"); }
    else {
        ret = p_connect(c, (struct sockaddr *)&st.dest, sizeof st.dest);
        EXPECT_EQ(ret, SOCKET_ERROR);
        EXPECT_EQ(p_WSAGetLastError(), WSAEALREADY);
    }
    p_closesocket(c);
    stall_close(&st);
}

TEST(lift10_connecting_connectex_after_connect_is_einval)
{
    SOCKET c;
    LPFN_CONNECTEX cex;
    DWORD size = 0;
    BOOL ret;
    STALL_BEGIN(st);
    c = new_client();
    cex = w_connectex(c);
    CHECK(cex != NULL);
    if (cex && start_connect(c, &st)) {
        g_ov1.Internal = W_SENT;
        g_ov1.InternalHigh = W_SENT;
        ret = cex(c, (struct sockaddr *)&st.dest, sizeof st.dest, NULL, 0, &size, &g_ov1);
        CHECK(!ret);
        EXPECT_EQ(p_WSAGetLastError(), WSAEINVAL);
        EXPECT_EQ((DWORD)g_ov1.Internal, (DWORD)STATUS_PENDING);
        EXPECT_EQ(g_ov1.InternalHigh, W_SENT);
    }
    p_closesocket(c);
    stall_close(&st);
}

TEST(lift10_connecting_after_connect_names_and_io)
{
    SOCKET c;
    STALL_BEGIN(st);
    c = new_client();
    if (!start_connect(c, &st)) t_skip("attempt did not stay pending");
    else names_and_io_fail(c, 1);
    p_closesocket(c);
    stall_close(&st);
}

/* ---- the attempt was started with ConnectEx ----------------------------- */

TEST(lift10_connecting_connectex_then_connect_is_einval)
{
    SOCKET c;
    LPFN_CONNECTEX cex;
    DWORD size = 0;
    int ret;
    STALL_BEGIN(st);
    c = new_client();
    cex = w_connectex(c);
    CHECK(cex != NULL);
    if (cex) {
        memset(&g_ov2, 0, sizeof g_ov2);
        ret = cex(c, (struct sockaddr *)&st.dest, sizeof st.dest, NULL, 0, &size, &g_ov2);
        CHECK(!ret);
        EXPECT_EQ(p_WSAGetLastError(), ERROR_IO_PENDING);
        if (!sel_write(c, 150, NULL)) {
            ret = p_connect(c, (struct sockaddr *)&st.dest, sizeof st.dest);
            EXPECT_EQ(ret, SOCKET_ERROR);
            EXPECT_EQ(p_WSAGetLastError(), WSAEINVAL);
        } else {
            t_skip("attempt did not stay pending");
        }
    }
    p_closesocket(c);
    stall_close(&st);
}

TEST(lift10_connecting_second_connectex_is_einval)
{
    SOCKET c;
    LPFN_CONNECTEX cex;
    DWORD size = 0;
    BOOL ret;
    STALL_BEGIN(st);
    c = new_client();
    cex = w_connectex(c);
    CHECK(cex != NULL);
    if (cex) {
        memset(&g_ov2, 0, sizeof g_ov2);
        ret = cex(c, (struct sockaddr *)&st.dest, sizeof st.dest, NULL, 0, &size, &g_ov2);
        CHECK(!ret);
        EXPECT_EQ(p_WSAGetLastError(), ERROR_IO_PENDING);
        if (!sel_write(c, 150, NULL)) {
            g_ov1.Internal = W_SENT;
            g_ov1.InternalHigh = W_SENT;
            ret = cex(c, (struct sockaddr *)&st.dest, sizeof st.dest, NULL, 0, &size, &g_ov1);
            CHECK(!ret);
            EXPECT_EQ(p_WSAGetLastError(), WSAEINVAL);
            EXPECT_EQ((DWORD)g_ov1.Internal, (DWORD)STATUS_PENDING);
            EXPECT_EQ(g_ov1.InternalHigh, W_SENT);
        } else {
            t_skip("attempt did not stay pending");
        }
    }
    p_closesocket(c);
    stall_close(&st);
}

TEST(lift10_connecting_after_connectex_names_and_io)
{
    SOCKET c;
    LPFN_CONNECTEX cex;
    DWORD size = 0;
    STALL_BEGIN(st);
    c = new_client();
    cex = w_connectex(c);
    CHECK(cex != NULL);
    if (cex) {
        memset(&g_ov2, 0, sizeof g_ov2);
        cex(c, (struct sockaddr *)&st.dest, sizeof st.dest, NULL, 0, &size, &g_ov2);
        if (!sel_write(c, 150, NULL)) names_and_io_fail(c, 0);
        else t_skip("attempt did not stay pending");
    }
    p_closesocket(c);
    stall_close(&st);
}
