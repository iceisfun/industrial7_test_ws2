/* Helpers for the async_select_messages area: tracked sockets and windows, a message log fed by one
 * window procedure, loopback socket pairs, and a bounded receive. See asm.h. */
#include "asm.h"

#define MAXLOG 8192
#define MAXTRACK 256

static CRITICAL_SECTION g_cs;
static int g_cs_init;
static asm_rec g_log[MAXLOG];
static int g_nlog;
static LONG g_seq;
static SOCKET g_socks[MAXTRACK];
static HWND g_wins[MAXTRACK];
static int g_started;
static ATOM g_atom;

int a_err(void) { return U(WSAGetLastError)(); }

static LRESULT CALLBACK a_wndproc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m >= WM_USER && m <= 0xFFFF) {
        EnterCriticalSection(&g_cs);
        if (g_nlog < MAXLOG) {
            asm_rec *r = &g_log[g_nlog++];
            r->hwnd = h; r->msg = m; r->wp = w; r->lp = l; r->tid = GetCurrentThreadId();
            r->seq = InterlockedIncrement(&g_seq); r->used = 0;
        }
        LeaveCriticalSection(&g_cs);
        return 0;
    }
    return UU(DefWindowProcA)(h, m, w, l);
}

static int a_register(void)
{
    WNDCLASSA wc;
    if (g_atom) return 1;
    memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc = a_wndproc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "asm_notify_window";
    g_atom = UU(RegisterClassA)(&wc);
    return g_atom != 0;
}

void a_log_reset(void)
{
    EnterCriticalSection(&g_cs);
    g_nlog = 0;
    LeaveCriticalSection(&g_cs);
}

static void release_tracked(void)
{
    int i;
    for (i = 0; i < MAXTRACK; ++i) {
        if (g_socks[i] != 0 && g_socks[i] != INVALID_SOCKET) U(closesocket)(g_socks[i]);
        g_socks[i] = 0;
    }
    for (i = 0; i < MAXTRACK; ++i) {
        if (g_wins[i]) UU(DestroyWindow)(g_wins[i]);
        g_wins[i] = NULL;
    }
}

int a_begin(void)
{
    WSADATA d;
    if (!g_cs_init) { InitializeCriticalSection(&g_cs); g_cs_init = 1; }
    if (!U(WSAStartup) || !U(socket) || !U(WSAAsyncSelect) || !UU(CreateWindowExA)) { t_skip("missing export"); return 0; }
    if (!g_started) {
        if (U(WSAStartup)(MAKEWORD(2, 2), &d) != 0) { t_skip("WSAStartup failed"); return 0; }
        g_started = 1;
    }
    if (!a_register()) { t_skip("window class registration failed"); return 0; }
    release_tracked();
    a_log_reset();
    return 1;
}

void a_end(void)
{
    release_tracked();
    a_pump(30);
    a_log_reset();
}

/* ---- sockets --------------------------------------------------------------------------------- */
static void track_sock(SOCKET s)
{
    int i;
    if (s == INVALID_SOCKET) return;
    for (i = 0; i < MAXTRACK; ++i) if (g_socks[i] == 0 || g_socks[i] == INVALID_SOCKET) { g_socks[i] = s; return; }
}

SOCKET a_sock(int af, int type, int proto)
{
    SOCKET s = U(socket)(af, type, proto);
    track_sock(s);
    return s;
}

void a_close(SOCKET s)
{
    int i;
    for (i = 0; i < MAXTRACK; ++i) if (g_socks[i] == s) g_socks[i] = 0;
    if (s != INVALID_SOCKET && s != 0) U(closesocket)(s);
}

int a_select(SOCKET s, HWND w, UINT m, long ev) { return U(WSAAsyncSelect)(s, w, m, ev); }

void a_loop_addr(struct sockaddr_in *a, unsigned short port_be)
{
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = ASM_LOOP_BE;
    a->sin_port = port_be;
}

SOCKET a_listener(struct sockaddr_in *addr, int backlog)
{
    struct sockaddr_in a; int len = sizeof a;
    SOCKET s = a_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return s;
    a_loop_addr(&a, 0);
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a) != 0 || U(listen)(s, backlog) != 0 ||
        U(getsockname)(s, (struct sockaddr *)&a, &len) != 0) { a_close(s); return INVALID_SOCKET; }
    if (addr) *addr = a;
    return s;
}

SOCKET a_listener6(struct sockaddr_in6 *addr, int backlog)
{
    struct sockaddr_in6 a; int len = sizeof a;
    SOCKET s = a_sock(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return s;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6;
    a.sin6_addr.s6_addr[15] = 1;
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a) != 0 || U(listen)(s, backlog) != 0 ||
        U(getsockname)(s, (struct sockaddr *)&a, &len) != 0) { a_close(s); return INVALID_SOCKET; }
    if (addr) *addr = a;
    return s;
}

int a_pair(SOCKET *cl, SOCKET *sv)
{
    struct sockaddr_in a;
    SOCKET l = a_listener(&a, 4), c, s;
    *cl = *sv = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    c = a_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c == INVALID_SOCKET || U(connect)(c, (struct sockaddr *)&a, sizeof a) != 0) { a_close(l); a_close(c); return 0; }
    s = U(accept)(l, NULL, NULL);
    track_sock(s);
    a_close(l);
    if (s == INVALID_SOCKET) { a_close(c); return 0; }
    *cl = c; *sv = s;
    return 1;
}

int a_pair6(SOCKET *cl, SOCKET *sv)
{
    struct sockaddr_in6 a;
    SOCKET l = a_listener6(&a, 4), c, s;
    *cl = *sv = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return 0;
    c = a_sock(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (c == INVALID_SOCKET || U(connect)(c, (struct sockaddr *)&a, sizeof a) != 0) { a_close(l); a_close(c); return 0; }
    s = U(accept)(l, NULL, NULL);
    track_sock(s);
    a_close(l);
    if (s == INVALID_SOCKET) { a_close(c); return 0; }
    *cl = c; *sv = s;
    return 1;
}

int a_udp_pair(SOCKET *a, SOCKET *b, struct sockaddr_in *aaddr, struct sockaddr_in *baddr)
{
    struct sockaddr_in x, y; int l = sizeof x;
    *a = a_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    *b = a_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (*a == INVALID_SOCKET || *b == INVALID_SOCKET) return 0;
    a_loop_addr(&x, 0); y = x;
    if (U(bind)(*a, (struct sockaddr *)&x, sizeof x) || U(bind)(*b, (struct sockaddr *)&y, sizeof y)) return 0;
    if (U(getsockname)(*a, (struct sockaddr *)&x, &l) || U(getsockname)(*b, (struct sockaddr *)&y, &l)) return 0;
    if (aaddr) *aaddr = x;
    if (baddr) *baddr = y;
    return 1;
}

int a_send(SOCKET s, int n)
{
    char buf[512];
    if (n > (int)sizeof buf) n = sizeof buf;
    memset(buf, 'x', n);
    return U(send)(s, buf, n, 0);
}

int a_recv(SOCKET s, int n)
{
    char buf[1024];
    if (n > (int)sizeof buf) n = sizeof buf;
    return U(recv)(s, buf, n, 0);
}

struct brecv { SOCKET s; int n; int res; int err; volatile LONG done; };
static DWORD WINAPI brecv_thread(LPVOID p)
{
    struct brecv *b = p;
    char buf[1024];
    b->res = U(recv)(b->s, buf, b->n > 1024 ? 1024 : b->n, 0);
    b->err = a_err();
    InterlockedExchange(&b->done, 1);
    return 0;
}

int a_recv_bounded(SOCKET s, int n, int *err, DWORD ms)
{
    struct brecv b;
    HANDLE th;
    DWORD t0 = GetTickCount();
    int broke = 0;
    memset(&b, 0, sizeof b);
    b.s = s; b.n = n;
    th = CreateThread(NULL, 0, brecv_thread, &b, 0, NULL);
    if (!th) return -9;
    while (!b.done && GetTickCount() - t0 < ms) Sleep(5);
    if (!b.done) { U(shutdown)(s, SD_BOTH); broke = 1; }
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
    if (err) *err = b.err;
    return broke ? -9 : b.res;
}

/* ---- windows --------------------------------------------------------------------------------- */
static HWND make_win(int kind, HWND *parent_out)
{
    HINSTANCE hi = GetModuleHandleA(NULL);
    HWND p, w = NULL;
    if (parent_out) *parent_out = NULL;
    switch (kind) {
    case ASM_WIN_MSGONLY:
        w = UU(CreateWindowExA)(0, "asm_notify_window", "m", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, hi, NULL); break;
    case ASM_WIN_POPUP:
        w = UU(CreateWindowExA)(0, "asm_notify_window", "p", WS_POPUP, 0, 0, 10, 10, NULL, NULL, hi, NULL); break;
    case ASM_WIN_OVERLAP:
        w = UU(CreateWindowExA)(0, "asm_notify_window", "o", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL, hi, NULL); break;
    case ASM_WIN_CHILD:
        p = UU(CreateWindowExA)(0, "asm_notify_window", "pp", WS_POPUP, 0, 0, 10, 10, NULL, NULL, hi, NULL);
        if (!p) return NULL;
        w = UU(CreateWindowExA)(0, "asm_notify_window", "c", WS_CHILD, 0, 0, 5, 5, p, NULL, hi, NULL);
        if (parent_out) *parent_out = p;
        break;
    }
    return w;
}

HWND a_win(int kind)
{
    HWND parent, w = make_win(kind, &parent);
    int i;
    if (parent) for (i = 0; i < MAXTRACK; ++i) if (!g_wins[i]) { g_wins[i] = parent; break; }
    if (!w) return NULL;
    for (i = 0; i < MAXTRACK; ++i) if (!g_wins[i]) { g_wins[i] = w; break; }
    return w;
}

void a_destroy(HWND w)
{
    int i;
    for (i = 0; i < MAXTRACK; ++i) if (g_wins[i] == w) g_wins[i] = NULL;
    if (w) UU(DestroyWindow)(w);
}

static DWORD WINAPI wthread_main(LPVOID p)
{
    asm_wthread *t = p;
    MSG m;
    HWND parent;
    t->hwnd = make_win(t->kind, &parent);
    t->tid = GetCurrentThreadId();
    SetEvent(t->ready);
    if (!t->hwnd) return 1;
    while (!t->stop) {
        while (UU(PeekMessageA)(&m, NULL, 0, 0, PM_REMOVE)) UU(DispatchMessageA)(&m);
        UU(MsgWaitForMultipleObjects)(0, NULL, FALSE, 20, QS_ALLINPUT);
    }
    UU(DestroyWindow)(t->hwnd);
    if (parent) UU(DestroyWindow)(parent);
    return 0;
}

int a_wthread_start(asm_wthread *t, int kind)
{
    memset(t, 0, sizeof *t);
    t->kind = kind;
    t->ready = CreateEventA(NULL, TRUE, FALSE, NULL);
    t->th = CreateThread(NULL, 0, wthread_main, t, 0, NULL);
    if (!t->th) { CloseHandle(t->ready); return 0; }
    WaitForSingleObject(t->ready, 5000);
    if (!t->hwnd) { WaitForSingleObject(t->th, 2000); CloseHandle(t->th); CloseHandle(t->ready); return 0; }
    return 1;
}

void a_wthread_stop(asm_wthread *t)
{
    InterlockedExchange(&t->stop, 1);
    WaitForSingleObject(t->th, 5000);
    CloseHandle(t->th);
    CloseHandle(t->ready);
}

/* ---- pumping and log queries ------------------------------------------------------------------ */
static void pump_once(void)
{
    MSG m;
    while (UU(PeekMessageA)(&m, NULL, 0, 0, PM_REMOVE)) UU(DispatchMessageA)(&m);
}

void a_pump(DWORD ms)
{
    DWORD t0 = GetTickCount(), el;
    for (;;) {
        pump_once();
        el = GetTickCount() - t0;
        if (el >= ms) break;
        UU(MsgWaitForMultipleObjects)(0, NULL, FALSE, ms - el < 10 ? ms - el : 10, QS_ALLINPUT);
    }
    pump_once();
}

static int match(const asm_rec *r, WPARAM wp, UINT msg, int ev)
{
    return !r->used && r->wp == wp && r->msg == msg && (ev < 0 || (int)LOWORD(r->lp) == ev);
}

static int take_locked(WPARAM wp, UINT msg, int ev, LPARAM *lp)
{
    int i;
    for (i = 0; i < g_nlog; ++i) if (match(&g_log[i], wp, msg, ev)) { g_log[i].used = 1; if (lp) *lp = g_log[i].lp; return 1; }
    return 0;
}

int a_take(WPARAM wp, UINT msg, int ev, DWORD ms, LPARAM *lp)
{
    DWORD t0 = GetTickCount(), el;
    for (;;) {
        int ok;
        pump_once();
        EnterCriticalSection(&g_cs);
        ok = take_locked(wp, msg, ev, lp);
        LeaveCriticalSection(&g_cs);
        if (ok) return 1;
        el = GetTickCount() - t0;
        if (el >= ms) return 0;
        UU(MsgWaitForMultipleObjects)(0, NULL, FALSE, ms - el < 10 ? ms - el : 10, QS_ALLINPUT);
    }
}

int a_count(WPARAM wp, UINT msg)
{
    int i, n = 0;
    EnterCriticalSection(&g_cs);
    for (i = 0; i < g_nlog; ++i) if (match(&g_log[i], wp, msg, -1)) ++n;
    LeaveCriticalSection(&g_cs);
    return n;
}

int a_total(void)
{
    int i, n = 0;
    EnterCriticalSection(&g_cs);
    for (i = 0; i < g_nlog; ++i) if (!g_log[i].used) ++n;
    LeaveCriticalSection(&g_cs);
    return n;
}

int a_quiet(DWORD ms) { a_pump(ms); return a_total(); }
int a_quiet_for(WPARAM wp, UINT msg, DWORD ms) { a_pump(ms); return a_count(wp, msg); }

void a_drain(DWORD ms)
{
    int i;
    a_pump(ms);
    EnterCriticalSection(&g_cs);
    for (i = 0; i < g_nlog; ++i) g_log[i].used = 1;
    LeaveCriticalSection(&g_cs);
}

int a_find_rec(WPARAM wp, UINT msg, int ev, asm_rec *out)
{
    int i, ok = 0;
    EnterCriticalSection(&g_cs);
    for (i = 0; i < g_nlog; ++i) if (match(&g_log[i], wp, msg, ev)) { if (out) *out = g_log[i]; ok = 1; break; }
    LeaveCriticalSection(&g_cs);
    return ok;
}

LONG a_seq_of(WPARAM wp, UINT msg, int ev)
{
    asm_rec r;
    return a_find_rec(wp, msg, ev, &r) ? r.seq : -1;
}

int a_peek_posted(HWND w, UINT msg, DWORD ms, MSG *out)
{
    MSG m;
    DWORD t0 = GetTickCount();
    for (;;) {
        if (UU(PeekMessageA)(&m, w, msg, msg, PM_NOREMOVE)) { if (out) *out = m; return 1; }
        if (GetTickCount() - t0 >= ms) return 0;
        UU(MsgWaitForMultipleObjects)(0, NULL, FALSE, 10, QS_POSTMESSAGE);
    }
}
