/* getservbyname (threaded) and the WSAAsyncGetServBy* family.
 * Measures: services-database lookups return the right port/proto/name, repeated lookups on one
 * thread reuse one per-thread result buffer, concurrent threads do not corrupt each other, and the
 * asynchronous variants accept any parameters at start (non-NULL handle) and then always post the
 * completion message to the window with the task handle in wParam. */
#include "l2.h"

#define N_THREADS 3
#define N_ROUNDS  125

struct serv_ctx { HANDLE start; volatile LONG bad; volatile LONG first_null; };

static DWORD WINAPI serv_worker(void *p) {
    static const struct { const char *name, *proto; int port; } q[2] = { { "domain", "udp", 53 }, { "telnet", "tcp", 23 } };
    struct serv_ctx *c = p;
    struct servent *s[2] = { NULL, NULL };
    int i, j;
    if (WaitForSingleObject(c->start, 10000) != WAIT_OBJECT_0) { InterlockedIncrement(&c->bad); return 0; }
    /* Warm-up: the per-thread buffer may be grown by the first lookups. */
    for (j = 0; j < 2; j++) s[j] = U(getservbyname)(q[j].name, q[j].proto);
    for (i = 0; i < N_ROUNDS; i++) {
        for (j = 0; j < 2; j++) {
            s[j] = U(getservbyname)(q[j].name, q[j].proto);
            if (!s[j]) { InterlockedIncrement(&c->first_null); continue; }
            if (s[j]->s_port != (short)l2_swap16((unsigned short)q[j].port)) InterlockedIncrement(&c->bad);
            if (!s[j]->s_proto || strcmp(s[j]->s_proto, q[j].proto)) InterlockedIncrement(&c->bad);
            if (!s[j]->s_name || strcmp(s[j]->s_name, q[j].name)) InterlockedIncrement(&c->bad);
        }
        /* Both lookups hand back the same per-thread buffer; it must not have been reallocated. */
        if (s[0] != s[1]) InterlockedIncrement(&c->bad);
    }
    return 0;
}

TEST(servent_getservbyname_concurrent_threads) {
    HANDLE th[N_THREADS]; struct serv_ctx c; int i;
    REQUIRE(U(getservbyname)); L2_NEED_WSA();
    c.bad = 0; c.first_null = 0;
    c.start = CreateEventW(NULL, TRUE, FALSE, NULL);
    for (i = 0; i < N_THREADS; i++) th[i] = CreateThread(NULL, 0, serv_worker, &c, 0, NULL);
    SetEvent(c.start);
    for (i = 0; i < N_THREADS; i++) {
        if (!th[i]) { CHECK(0); continue; }
        EXPECT_EQ(WaitForSingleObject(th[i], 15000), WAIT_OBJECT_0);
        CloseHandle(th[i]);
    }
    EXPECT_EQ(c.first_null, 0);
    EXPECT_EQ(c.bad, 0);
    CloseHandle(c.start);
}

TEST(servent_getservbyname_fields) {
    struct servent *s;
    REQUIRE(U(getservbyname)); L2_NEED_WSA();
    s = U(getservbyname)("domain", "udp");
    CHECK(s != NULL);
    if (s) { EXPECT_EQ((unsigned short)s->s_port, l2_swap16(53)); EXPECT_STR(s->s_proto, "udp"); EXPECT_STR(s->s_name, "domain"); }
    s = U(getservbyname)("telnet", "tcp");
    CHECK(s != NULL);
    if (s) EXPECT_EQ((unsigned short)s->s_port, l2_swap16(23));
}

/* ---- asynchronous variants: need a window to receive the completion message ---- */

#define WM_L2_ASYNC (WM_USER + 100)
typedef LRESULT (CALLBACK *wndproc_fn)(HWND, UINT, WPARAM, LPARAM);

static HWND async_window(void) {
    static ATOM cls;
    WNDCLASSEXA wc;
    HWND (WINAPI *create)(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID) =
        (void *)t_proc_in("user32.dll", "CreateWindowExA");
    ATOM (WINAPI *reg)(const WNDCLASSEXA *) = (void *)t_proc_in("user32.dll", "RegisterClassExA");
    if (!create || !reg) return NULL;
    if (!cls) {
        memset(&wc, 0, sizeof wc);
        wc.cbSize = sizeof wc;
        wc.lpfnWndProc = (wndproc_fn)t_proc_in("user32.dll", "DefWindowProcA");
        wc.hInstance = GetModuleHandleA(NULL);
        wc.lpszClassName = "l2_async_sink";
        cls = reg(&wc);
        if (!cls) return NULL;
    }
    /* Message-only window: receives posted messages without needing visible UI. */
    return create(0, "l2_async_sink", "sink", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, GetModuleHandleA(NULL), NULL);
}

/* Pump messages until WM_L2_ASYNC for hwnd arrives; returns lParam via *lp, or -1 on timeout. */
static int wait_async(HWND hwnd, HANDLE expect, LPARAM *lp, WPARAM *wp) {
    BOOL (WINAPI *peek)(LPMSG, HWND, UINT, UINT, UINT) = (void *)t_proc_in("user32.dll", "PeekMessageA");
    BOOL (WINAPI *xlat)(const MSG *) = (void *)t_proc_in("user32.dll", "TranslateMessage");
    LRESULT (WINAPI *disp)(const MSG *) = (void *)t_proc_in("user32.dll", "DispatchMessageA");
    DWORD end = GetTickCount() + 8000;
    MSG m;
    while ((long)(end - GetTickCount()) > 0) {
        while (peek(&m, NULL, 0, 0, 1 /* PM_REMOVE */)) {
            if (m.hwnd == hwnd && m.message == WM_L2_ASYNC) { *wp = m.wParam; *lp = m.lParam; return 0; }
            xlat(&m); disp(&m);
        }
        Sleep(5);
    }
    return -1;
}

static void destroy_window(HWND h) {
    BOOL (WINAPI *d)(HWND) = (void *)t_proc_in("user32.dll", "DestroyWindow");
    if (h && d) d(h);
}

TEST(servent_async_byport_null_params_still_start) {
    HWND h; HANDLE t; LPARAM lp; WPARAM wp;
    REQUIRE(U(WSAAsyncGetServByPort)); L2_NEED_WSA();
    h = async_window();
    if (!h) { t_skip("no message window"); return; }
    /* Parameters are not validated when the task starts: even a NULL window yields a handle. */
    t = U(WSAAsyncGetServByPort)(NULL, 0, 0, NULL, NULL, 0);
    CHECK(t != NULL);
    t = U(WSAAsyncGetServByPort)(h, WM_L2_ASYNC, 0, NULL, NULL, 0);
    CHECK(t != NULL);
    if (t) { CHECK(wait_async(h, t, &lp, &wp) == 0); EXPECT_EQ(wp, (WPARAM)t); }
    destroy_window(h);
}

TEST(servent_async_byport_posts_completion) {
    HWND h; HANDLE t; LPARAM lp = 0; WPARAM wp = 0; char buf[MAXGETHOSTSTRUCT];
    REQUIRE(U(WSAAsyncGetServByPort)); L2_NEED_WSA();
    h = async_window();
    if (!h) { t_skip("no message window"); return; }
    t = U(WSAAsyncGetServByPort)(h, WM_L2_ASYNC, l2_swap16(80), NULL, NULL, 0);
    CHECK(t != NULL);
    if (t) { CHECK(wait_async(h, t, &lp, &wp) == 0); EXPECT_EQ(wp, (WPARAM)t); }
    t = U(WSAAsyncGetServByPort)(h, WM_L2_ASYNC, l2_swap16(80), NULL, buf, sizeof buf);
    CHECK(t != NULL);
    if (t) { CHECK(wait_async(h, t, &lp, &wp) == 0); EXPECT_EQ(wp, (WPARAM)t); }
    destroy_window(h);
}

TEST(servent_async_byname_null_buffer_posts_completion) {
    HWND h; HANDLE t; LPARAM lp = 0; WPARAM wp = 0; char buf[MAXGETHOSTSTRUCT];
    REQUIRE(U(WSAAsyncGetServByName)); L2_NEED_WSA();
    h = async_window();
    if (!h) { t_skip("no message window"); return; }
    t = U(WSAAsyncGetServByName)(h, WM_L2_ASYNC, "", NULL, NULL, 0);
    CHECK(t != NULL);
    if (t) { CHECK(wait_async(h, t, &lp, &wp) == 0); EXPECT_EQ(wp, (WPARAM)t); }
    t = U(WSAAsyncGetServByName)(h, WM_L2_ASYNC, "", "", buf, sizeof buf);
    CHECK(t != NULL);
    if (t) { CHECK(wait_async(h, t, &lp, &wp) == 0); EXPECT_EQ(wp, (WPARAM)t); }
    destroy_window(h);
}

TEST(servent_async_byname_http_tcp) {
    HWND h; HANDLE t; LPARAM lp = 0; WPARAM wp = 0; char buf[MAXGETHOSTSTRUCT];
    REQUIRE(U(WSAAsyncGetServByName)); L2_NEED_WSA();
    h = async_window();
    if (!h) { t_skip("no message window"); return; }
    t = U(WSAAsyncGetServByName)(h, WM_L2_ASYNC, "http", NULL, NULL, 0);
    CHECK(t != NULL);
    if (t) { CHECK(wait_async(h, t, &lp, &wp) == 0); EXPECT_EQ(wp, (WPARAM)t); }
    t = U(WSAAsyncGetServByName)(h, WM_L2_ASYNC, "http", "tcp", buf, sizeof buf);
    CHECK(t != NULL);
    if (t && wait_async(h, t, &lp, &wp) == 0) {
        EXPECT_EQ(wp, (WPARAM)t);
        /* A successful lookup reports no error in the high word of lParam. */
        EXPECT_EQ((lp >> 16) & 0xffff, 0);
        {
            struct servent *s = (struct servent *)buf;
            /* The servent is laid out inside the caller's buffer; its pointers are valid there. */
            CHECK(s->s_name != NULL);
        }
    }
    destroy_window(h);
}
