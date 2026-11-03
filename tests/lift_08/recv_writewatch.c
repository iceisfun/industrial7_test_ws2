/* Receives into write-watched memory: which pages the stack touches while a receive is pending
 * and when data is delivered, for overlapped scatter receives and for blocking recv/recvfrom/
 * WSARecv/WSARecvFrom.  Page counts that depend on the Windows generation accept the documented
 * alternatives (a later generation stops tripping the watch while an operation is merely pending).
 */
#include "l8.h"

typedef UINT (WINAPI *GetWriteWatch_fn)(DWORD, LPVOID, SIZE_T, LPVOID *, ULONG_PTR *, ULONG *);

#define REGION 0x10000

struct ww {
    GetWriteWatch_fn gww;
    char *base;
    SOCKET src, dst;
    void *pages[64];
};

static int ww_open(struct ww *w)
{
    memset(w, 0, sizeof *w);
    w->gww = (GetWriteWatch_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetWriteWatch");
    if (!w->gww) return 0;
    w->base = VirtualAlloc(NULL, REGION, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE);
    CHECK(w->base != NULL);
    if (!w->base) return 0;
    l8_pair(&w->src, &w->dst, WSA_FLAG_OVERLAPPED);
    return 1;
}

static void ww_close(struct ww *w)
{
    w_closesocket(w->src);
    w_closesocket(w->dst);
    if (w->base) VirtualFree(w->base, 0, MEM_RELEASE);
}

/* Number of dirty pages; optionally resets the watch. */
static ULONG_PTR ww_count(struct ww *w, DWORD flags)
{
    ULONG_PTR n = 64;
    ULONG pg;
    UINT r = w->gww(flags, w->base, REGION, w->pages, &n, &pg);
    CHECK(r == 0);
    return n;
}

/* Dirty the whole region and clear the watch: all 16 pages must read as written. */
static void ww_dirty_all_and_reset(struct ww *w)
{
    memset(w->base, 0, REGION);
    L8_EQ(ww_count(w, WRITE_WATCH_FLAG_RESET), 16);
}

#define WW_FIXTURE(w) \
    NEED_WS(); \
    if (!ww_open(&(w))) { ww_close(&(w)); t_skip("GetWriteWatch / region unavailable"); return; }

TEST(l8_writewatch_wsarecv_overlapped_scatter)
{
    struct ww w;
    WSABUF wb[2];
    OVERLAPPED ov;
    DWORD fl = 0, got = 0;
    ULONG_PTR n;
    WW_FIXTURE(w);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    ww_dirty_all_and_reset(&w);

    wb[0].len = 5;      wb[0].buf = w.base;
    wb[1].len = 0x8000; wb[1].buf = w.base + 0x4000;
    SetLastError(0);
    L8_EQ(w_WSARecv(w.dst, wb, 2, NULL, &fl, &ov, NULL), SOCKET_ERROR);
    EXPECT_ERR(ERROR_IO_PENDING);

    /* Issuing the receive touches page 0 and the eight pages of the second buffer, or nothing at all. */
    n = ww_count(&w, WRITE_WATCH_FLAG_RESET);
    CHECK(n == 9 || n == 0);
    L8_EQ(w.base[0], 0);

    w.base[0x1000] = 1;   /* an application write to an unrelated page while the operation is in flight */
    L8_EQ(w_send(w.src, "test message", 13, 0), 13);
    L8_EQ(WaitForSingleObject(ov.hEvent, 3000), WAIT_OBJECT_0);
    CHECK(GetOverlappedResult((HANDLE)w.dst, &ov, &got, FALSE));
    L8_EQ(got, 13);
    CHECK(!memcmp(w.base, "test ", 5));
    CHECK(!memcmp(w.base + 0x4000, "message", 8));

    /* Delivery does not mark pages beyond the application's own write. */
    n = ww_count(&w, 0);
    L8_EQ(n, 1);
    if (n >= 1) L8_EQ(w.pages[0], w.base + 0x1000);

    w.base[0x2000] = 1;
    n = ww_count(&w, WRITE_WATCH_FLAG_RESET);
    L8_EQ(n, 2);
    if (n >= 2) {
        L8_EQ(w.pages[0], w.base + 0x1000);
        L8_EQ(w.pages[1], w.base + 0x2000);
    }
    CloseHandle(ov.hEvent);
    ww_close(&w);
}

TEST(l8_writewatch_wsarecvfrom_overlapped_scatter)
{
    struct ww w;
    WSABUF wb[2];
    OVERLAPPED ov;
    struct sockaddr_in from;
    int fromlen = sizeof from;
    DWORD fl = 0, got = 0;
    ULONG_PTR n;
    WW_FIXTURE(w);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    ww_dirty_all_and_reset(&w);

    wb[0].len = 5;      wb[0].buf = w.base;
    wb[1].len = 0x4000; wb[1].buf = w.base + 0x2000;
    SetLastError(0);
    L8_EQ(w_WSARecvFrom(w.dst, wb, 2, NULL, &fl, (struct sockaddr *)&from, &fromlen, &ov, NULL), SOCKET_ERROR);
    EXPECT_ERR(ERROR_IO_PENDING);

    n = ww_count(&w, WRITE_WATCH_FLAG_RESET);
    CHECK(n == 5 || n == 0);
    L8_EQ(w.base[0], 0);

    L8_EQ(w_send(w.src, "test message", 13, 0), 13);
    L8_EQ(WaitForSingleObject(ov.hEvent, 3000), WAIT_OBJECT_0);
    CHECK(GetOverlappedResult((HANDLE)w.dst, &ov, &got, FALSE));
    L8_EQ(got, 13);
    CHECK(!memcmp(w.base, "test ", 5));
    CHECK(!memcmp(w.base + 0x2000, "message", 8));

    /* Completion by itself leaves the watch clean. */
    L8_EQ(ww_count(&w, WRITE_WATCH_FLAG_RESET), 0);
    CloseHandle(ov.hEvent);
    ww_close(&w);
}

/* ---- blocking receives in a worker thread ---- */

enum { RX_RECV, RX_RECVFROM, RX_WSARECV, RX_WSARECVFROM };

struct rx_job {
    int kind;
    SOCKET sock;
    char *base;
    DWORD size;
    int ret;
    DWORD len;
    int data_ok;
};

static DWORD WINAPI rx_job_proc(void *arg)
{
    struct rx_job *j = arg;
    struct sockaddr_in from;
    int fromlen = sizeof from;
    WSABUF wb = { j->size, j->base };
    DWORD fl = 0;

    switch (j->kind) {
    case RX_RECV:
        j->ret = w_recv(j->sock, j->base, j->size, 0);
        j->len = j->ret > 0 ? j->ret : 0;
        break;
    case RX_RECVFROM:
        j->ret = w_recvfrom(j->sock, j->base, j->size, 0, (struct sockaddr *)&from, &fromlen);
        j->len = j->ret > 0 ? j->ret : 0;
        break;
    case RX_WSARECV:
        j->ret = w_WSARecv(j->sock, &wb, 1, &j->len, &fl, NULL, NULL);
        break;
    case RX_WSARECVFROM:
        j->ret = w_WSARecvFrom(j->sock, &wb, 1, &j->len, &fl, (struct sockaddr *)&from, &fromlen, NULL, NULL);
        break;
    }
    j->data_ok = !strcmp(j->base, "test message");
    return 0;
}

static void blocking_receive_case(int kind)
{
    struct ww w;
    struct rx_job job;
    HANDLE th;
    ULONG_PTR n;
    WW_FIXTURE(w);
    ww_dirty_all_and_reset(&w);

    memset(&job, 0, sizeof job);
    job.kind = kind; job.sock = w.dst; job.base = w.base; job.size = 0x7002; job.ret = -2;
    th = CreateThread(NULL, 0, rx_job_proc, &job, 0, NULL);
    Sleep(200);   /* let the receive block; the observation below only reports */

    /* While blocked, the eight pages covering the buffer are held (or none, on later generations). */
    n = ww_count(&w, WRITE_WATCH_FLAG_RESET);
    CHECK(n == 8 || n == 0);

    L8_EQ(w_send(w.src, "test message", 13, 0), 13);
    L8_EQ(WaitForSingleObject(th, 5000), WAIT_OBJECT_0);
    CloseHandle(th);
    CHECK(job.ret == 13 || job.ret == 0);
    L8_EQ(job.len, 13);
    CHECK(job.data_ok);

    /* Delivering the data into the buffer must not leave the pages marked as written. */
    L8_EQ(ww_count(&w, WRITE_WATCH_FLAG_RESET), 0);
    ww_close(&w);
}

TEST(l8_writewatch_blocking_recv)         { blocking_receive_case(RX_RECV); }
TEST(l8_writewatch_blocking_recvfrom)     { blocking_receive_case(RX_RECVFROM); }
TEST(l8_writewatch_blocking_wsarecv)      { blocking_receive_case(RX_WSARECV); }
TEST(l8_writewatch_blocking_wsarecvfrom)  { blocking_receive_case(RX_WSARECVFROM); }
