/* I/O completion ports combined with WSAAsyncSelect, overlapped receives and the different ways to close a socket.
 * Measures: a completion-port overlapped WSARecv goes pending and completes with the byte count, key and OVERLAPPED
 * status 0; associating a socket with a port or issuing an overlapped receive generates no window notification, and
 * data consumed by the overlapped receive raises no FD_READ; closing a socket that has a pending receive completes
 * the receive with ERROR_CONNECTION_ABORTED / STATUS_CONNECTION_ABORTED; closesocket() sends the window no FD_CLOSE
 * but dropping the raw handle (CloseHandle, NtClose) does; an overlapped receive issued from a thread that has
 * exited stays pending (no cancellation packet) when the socket is on a port.
 * The receiver side is always an ordinary connected loopback pair.
 */
#include "w.h"

typedef LONG (NTAPI *NtClose_pfn)(HANDLE);
#define DATA "Hello World!"
#define DATA_LEN 12
#define KEY 0x12345678

struct ia {
    SOCKET src, dst;
    HWND hwnd;
    HANDLE port;
    char data[512];
    WSAOVERLAPPED ov;
    WSABUF buf;
};

static int ia_open(struct ia *a, int with_window)
{
    memset(a, 0, sizeof *a);
    a->src = a->dst = INVALID_SOCKET;
    if (!w_pair(&a->src, &a->dst)) return 0;
    if (with_window) {
        a->hwnd = CreateWindowExA(0, "static", NULL, WS_POPUP, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
        if (!a->hwnd)    /* no desktop to own a top-level window: a message-only window receives the same posts */
            a->hwnd = CreateWindowExA(0, "static", NULL, WS_POPUP, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);
        if (!a->hwnd) return 0;
    }
    a->buf.len = sizeof a->data;
    a->buf.buf = a->data;
    return 1;
}

static void ia_close(struct ia *a, int src_open)
{
    if (a->port) CloseHandle(a->port);
    if (src_open && a->src != INVALID_SOCKET) p_closesocket(a->src);
    if (a->dst != INVALID_SOCKET) p_closesocket(a->dst);
    if (a->hwnd) DestroyWindow(a->hwnd);
}

#define IA_BEGIN(a, win) struct ia a; W_BEGIN(); \
    if (!ia_open(&a, win)) { ia_close(&a, 1); t_skip(win ? "no loopback pair or window station" : "no loopback pair"); return; }

/* Wait up to ms for one WM_SOCKET message for the window. */
static int next_msg(HWND h, MSG *m, DWORD ms)
{
    DWORD t0 = GetTickCount();
    for (;;) {
        memset(m, 0, sizeof *m);
        if (PeekMessageA(m, h, WM_SOCKET, WM_SOCKET, PM_REMOVE)) return 1;
        if (GetTickCount() - t0 >= ms) return 0;
        Sleep(10);
    }
}
static void expect_no_msg(HWND h, DWORD ms)
{
    MSG m;
    int got = next_msg(h, &m, ms);
    CHECKF(!got, "unexpected message %04x wParam=%#Ix lParam=%#Ix", m.message, m.wParam, m.lParam);
}
static void expect_msg(HWND h, SOCKET s, LPARAM lparam, DWORD ms)
{
    MSG m;
    int got = next_msg(h, &m, ms);
    CHECK(got);
    if (!got) return;
    CHECK(m.hwnd == h);
    EXPECT_EQ(m.message, WM_SOCKET);
    EXPECT_EQ(m.wParam, s);
    EXPECT_EQ(m.lParam, lparam);
}

static DWORD WINAPI select_thread(void *arg)
{
    struct ia *a = arg;
    int ret = p_WSAAsyncSelect(a->src, a->hwnd, WM_SOCKET, W_FD_ALL);
    return ret == 0 ? 0 : 1;
}
static DWORD WINAPI recv_thread(void *arg)
{
    struct ia *a = arg;
    DWORD bytes = W_SENT, flags = 0;
    int ret = p_WSARecv(a->src, &a->buf, 1, &bytes, &flags, &a->ov, NULL);
    /* pack the three observations into the exit code: bit0 ret ok, bit1 error ok, bit2 bytes untouched */
    return (ret == SOCKET_ERROR) | ((p_WSAGetLastError() == ERROR_IO_PENDING) << 1) | ((bytes == W_SENT) << 2);
}
static int run_thread(LPTHREAD_START_ROUTINE fn, struct ia *a, DWORD *code)
{
    HANDLE t = CreateThread(NULL, 0, fn, a, 0, NULL);
    DWORD w;
    if (!t) return 0;
    w = WaitForSingleObject(t, 10000);
    GetExitCodeThread(t, code);
    CloseHandle(t);
    return w == WAIT_OBJECT_0;
}

/* AsyncSelect (from this thread or a helper thread), see the initial FD_WRITE, join a completion port, and see
 * that joining the port produced nothing. */
static void arm(struct ia *a, int select_in_thread)
{
    DWORD code = 0;
    if (select_in_thread) {
        CHECK(run_thread(select_thread, a, &code));
        EXPECT_EQ(code, 0);
    } else {
        int ret = p_WSAAsyncSelect(a->src, a->hwnd, WM_SOCKET, W_FD_ALL);
        EXPECT_EQ(ret, 0);
    }
    expect_msg(a->hwnd, a->src, FD_WRITE, 2000);
    a->port = w_port_for(a->src, KEY);
    CHECK(a->port != NULL);
    expect_no_msg(a->hwnd, 150);
}

static void post_recv_here(struct ia *a)
{
    DWORD bytes = W_SENT, flags = 0;
    int ret;
    memset(&a->ov, 0, sizeof a->ov);
    ret = p_WSARecv(a->src, &a->buf, 1, &bytes, &flags, &a->ov, NULL);
    EXPECT_EQ(ret, SOCKET_ERROR);
    EXPECT_EQ(p_WSAGetLastError(), ERROR_IO_PENDING);
    EXPECT_EQ(bytes, W_SENT);
}
static void post_recv_in_thread(struct ia *a)
{
    DWORD code = 0;
    memset(&a->ov, 0, sizeof a->ov);
    CHECK(run_thread(recv_thread, a, &code));
    EXPECT_EQ(code, 7);
}

/* ---- plain receives ----------------------------------------------------- */

TEST(lift10_iocp_sync_recv_returns_sent_data)
{
    IA_BEGIN(a, 0);
    char got[512];
    int ret = p_send(a.dst, DATA, DATA_LEN, 0);
    EXPECT_EQ(ret, DATA_LEN);
    memset(got, 0, sizeof got);
    ret = p_recv(a.src, got, sizeof got, 0);
    EXPECT_EQ(ret, DATA_LEN);
    CHECK(!memcmp(got, DATA, DATA_LEN));
    ia_close(&a, 1);
}

TEST(lift10_iocp_overlapped_recv_completes_with_bytes_key_and_status)
{
    IA_BEGIN(a, 0);
    struct w_cp r;
    DWORD bytes = W_SENT, flags = 0;
    int ret;
    a.port = CreateIoCompletionPort((HANDLE)a.src, NULL, KEY, 0);
    CHECK(a.port != NULL);

    SetLastError(W_SENT);
    ret = p_WSARecv(a.src, &a.buf, 1, &bytes, &flags, &a.ov, NULL);
    EXPECT_EQ(ret, SOCKET_ERROR);
    EXPECT_EQ(p_WSAGetLastError(), ERROR_IO_PENDING);
    EXPECT_EQ(bytes, W_SENT);
    w_expect_empty(a.port, 100);

    CHECK(p_send(a.dst, DATA, DATA_LEN, 0) == DATA_LEN);
    r = w_dequeue(a.port, 3000);
    CHECK(r.ret);
    EXPECT_EQ(r.bytes, DATA_LEN);
    EXPECT_EQ(r.key, KEY);
    CHECK(r.ov == &a.ov);
    if (r.ov == &a.ov) {
        EXPECT_EQ(a.ov.InternalHigh, DATA_LEN);
        EXPECT_EQ(a.ov.Internal, 0);
        CHECK(!memcmp(a.data, DATA, DATA_LEN));
    }
    w_expect_empty(a.port, 100);
    ia_close(&a, 1);
}

/* Receive issued by a helper thread that then exits: the request survives on a port-attached socket and later
 * completes normally; neither the pending receive nor the arriving data produce window notifications. */
TEST(lift10_iocp_overlapped_recv_from_exited_thread_survives_and_completes)
{
    IA_BEGIN(a, 1);
    struct w_cp r;
    arm(&a, 1);
    post_recv_in_thread(&a);
    expect_no_msg(a.hwnd, 150);
    w_expect_empty(a.port, 100);          /* the thread's exit cancelled nothing */
    expect_no_msg(a.hwnd, 150);

    CHECK(p_send(a.dst, DATA, DATA_LEN, 0) == DATA_LEN);
    expect_no_msg(a.hwnd, 150);           /* the data goes to the overlapped receive, so no FD_READ */
    r = w_dequeue(a.port, 3000);
    CHECK(r.ret);
    EXPECT_EQ(r.bytes, DATA_LEN);
    EXPECT_EQ(r.key, KEY);
    CHECK(r.ov == &a.ov);
    if (r.ov == &a.ov) {
        EXPECT_EQ(a.ov.InternalHigh, DATA_LEN);
        EXPECT_EQ(a.ov.Internal, 0);
        CHECK(!memcmp(a.data, DATA, DATA_LEN));
    }
    ia_close(&a, 1);
}

/* ---- closing a socket with a pending receive ---------------------------- */

/* how: 0 closesocket, 1 CloseHandle on the raw handle, 2 NtClose on the raw handle */
static void close_with_pending_recv(int how)
{
    IA_BEGIN(a, 1);
    struct w_cp r;
    NtClose_pfn nt_close = (NtClose_pfn)t_proc_in("ntdll.dll", "NtClose");
    if (how == 2 && !nt_close) { ia_close(&a, 1); t_skip("NtClose unavailable"); return; }

    arm(&a, 0);
    post_recv_here(&a);
    expect_no_msg(a.hwnd, 150);
    w_expect_empty(a.port, 100);
    expect_no_msg(a.hwnd, 150);

    if (how == 0) p_closesocket(a.src);
    else if (how == 1) CloseHandle((HANDLE)a.src);
    else nt_close((HANDLE)a.src);

    if (how == 0) expect_no_msg(a.hwnd, 250);          /* closesocket disables the notification first */
    else expect_msg(a.hwnd, a.src, FD_CLOSE, 2000);    /* the raw handle drop is seen as an abortive close */

    r = w_dequeue(a.port, 3000);
    CHECK(!r.ret);
    EXPECT_EQ(r.err, ERROR_CONNECTION_ABORTED);
    EXPECT_EQ(r.bytes, 0);
    EXPECT_EQ(r.key, KEY);
    CHECK(r.ov == &a.ov);
    if (r.ov == &a.ov) {
        EXPECT_EQ(a.ov.InternalHigh, 0);
        EXPECT_EQ((DWORD)a.ov.Internal, (DWORD)STATUS_CONNECTION_ABORTED);
    }
    w_expect_empty(a.port, 100);
    ia_close(&a, 0);
}

TEST(lift10_iocp_closesocket_completes_pending_recv_as_aborted)   { close_with_pending_recv(0); }
TEST(lift10_iocp_closehandle_completes_pending_recv_and_sends_fd_close) { close_with_pending_recv(1); }
TEST(lift10_iocp_ntclose_completes_pending_recv_and_sends_fd_close)     { close_with_pending_recv(2); }

/* closesocket() with nothing pending: neither a message nor a packet. */
TEST(lift10_iocp_closesocket_without_pending_io_is_silent)
{
    IA_BEGIN(a, 1);
    arm(&a, 0);
    w_expect_empty(a.port, 100);
    expect_no_msg(a.hwnd, 150);
    p_closesocket(a.src);
    expect_no_msg(a.hwnd, 150);
    w_expect_empty(a.port, 100);
    ia_close(&a, 0);
}

/* Same close, but select and receive were both issued from helper threads that have exited. */
TEST(lift10_iocp_closesocket_after_threaded_recv_completes_as_aborted)
{
    IA_BEGIN(a, 1);
    struct w_cp r;
    arm(&a, 1);
    post_recv_in_thread(&a);
    expect_no_msg(a.hwnd, 150);
    w_expect_empty(a.port, 100);
    expect_no_msg(a.hwnd, 150);

    p_closesocket(a.src);
    expect_no_msg(a.hwnd, 250);
    r = w_dequeue(a.port, 3000);
    CHECK(!r.ret);
    EXPECT_EQ(r.err, ERROR_CONNECTION_ABORTED);
    EXPECT_EQ(r.bytes, 0);
    EXPECT_EQ(r.key, KEY);
    CHECK(r.ov == &a.ov);
    if (r.ov == &a.ov) {
        EXPECT_EQ(a.ov.InternalHigh, 0);
        EXPECT_EQ((DWORD)a.ov.Internal, (DWORD)STATUS_CONNECTION_ABORTED);
    }
    w_expect_empty(a.port, 100);
    ia_close(&a, 0);
}
