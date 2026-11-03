/* Observers for the readiness matrix: render one socket through each interface as a stable string. */
#include "xs.h"

#ifndef POLLRDNORM
#define POLLRDNORM 0x0100
#define POLLRDBAND 0x0200
#define POLLPRI    0x0400
#define POLLWRNORM 0x0010
#define POLLWRBAND 0x0020
#define POLLERR    0x0001
#define POLLHUP    0x0002
#define POLLNVAL   0x0004
#endif

UDECL(LONG, XsIoctl, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG));
UDECL(LONG, XsCancel, (HANDLE, PIO_STATUS_BLOCK));

const char *const xs_view_names[XV_COUNT] = {
    "sel", "poll_rw", "poll_band", "poll_rd", "poll_wr", "poll_none", "poll_all", "afd", "enum", "async"
};

static HANDLE g_ev;          /* created before any state exists so a freed socket handle is never recycled for it */
static HWND   g_wnd;
static int    g_ready;       /* 0 untried, 1 usable, -1 not */
#define WM_XS (WM_USER + 7)
static struct { unsigned ev, err; } g_msgs[64];
static int g_nmsgs;
static SOCKET g_msg_sock;

SOCKET xs_sock(int af, int type) { return U(socket)(af, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP); }
void   xs_close(SOCKET s) { if (s != INVALID_SOCKET && s != 0) U(closesocket)(s); }
int    xs_err(void) { return U(WSAGetLastError)(); }
void   xs_nb(SOCKET s, int on) { u_long v = on; U(ioctlsocket)(s, FIONBIO, &v); }
void   xs_settle(int ms) { Sleep(ms); }

int xs_sel(SOCKET s, int *r, int *w, int *x)
{
    fd_set rs, ws, xe; struct timeval tv = { 0, 0 };
    int n;
    FD_ZERO(&rs); FD_ZERO(&ws); FD_ZERO(&xe);
    rs.fd_count = ws.fd_count = xe.fd_count = 1;
    rs.fd_array[0] = ws.fd_array[0] = xe.fd_array[0] = s;
    n = U(select)(0, &rs, &ws, &xe, &tv);
    *r = rs.fd_count; *w = ws.fd_count; *x = xe.fd_count;
    if (n >= 0) { *r = rs.fd_count == 1 && rs.fd_array[0] == s; *w = ws.fd_count == 1 && ws.fd_array[0] == s; *x = xe.fd_count == 1 && xe.fd_array[0] == s; }
    return n;
}

int xs_wait(SOCKET s, char kind, int ms)
{
    DWORD t0 = GetTickCount();
    for (;;) {
        int r, w, x;
        int n = xs_sel(s, &r, &w, &x);
        if (n < 0) return 0;
        if ((kind == 'r' && r) || (kind == 'w' && w) || (kind == 'x' && x)) return 1;
        if ((int)(GetTickCount() - t0) >= ms) return 0;
        Sleep(5);
    }
}

int xs_send_n(SOCKET s, int n, int flags)
{
    char buf[64];
    memset(buf, 'q', sizeof(buf));
    if (n > (int)sizeof(buf)) n = sizeof(buf);
    return U(send)(s, buf, n, flags);
}

int xs_poll1(SOCKET s, short events, short *revents)
{
    WSAPOLLFD f;
    int n;
    f.fd = s; f.events = events; f.revents = (short)0x7777;
    n = U(WSAPoll)(&f, 1, 0);
    *revents = f.revents;
    return n;
}

const char *xs_poll_name(unsigned rev, char *buf, size_t cap)
{
    static const struct { unsigned bit; const char *n; } t[] = {
        { POLLRDNORM, "RDNORM" }, { POLLRDBAND, "RDBAND" }, { POLLPRI, "PRI" }, { POLLWRNORM, "WRNORM" },
        { POLLWRBAND, "WRBAND" }, { POLLERR, "ERR" }, { POLLHUP, "HUP" }, { POLLNVAL, "NVAL" } };
    size_t i; buf[0] = 0;
    for (i = 0; i < sizeof(t) / sizeof(t[0]); i++)
        if (rev & t[i].bit) { if (buf[0]) strncat(buf, "|", cap - strlen(buf) - 1); strncat(buf, t[i].n, cap - strlen(buf) - 1); rev &= ~t[i].bit; }
    if (rev) { char h[16]; snprintf(h, sizeof(h), "%s0x%x", buf[0] ? "|" : "", rev); strncat(buf, h, cap - strlen(buf) - 1); }
    if (!buf[0]) snprintf(buf, cap, "0");
    return buf;
}

const char *xs_fd_name(unsigned ev, char *buf, size_t cap)
{
    static const char *n[] = { "READ", "WRITE", "OOB", "ACCEPT", "CONNECT", "CLOSE", "QOS", "GROUP_QOS", "ROUTING", "ADDRLIST" };
    unsigned i; buf[0] = 0;
    for (i = 0; i < 10; i++)
        if (ev & (1u << i)) { if (buf[0]) strncat(buf, "|", cap - strlen(buf) - 1); strncat(buf, n[i], cap - strlen(buf) - 1); ev &= ~(1u << i); }
    if (ev) { char h[16]; snprintf(h, sizeof(h), "%s0x%x", buf[0] ? "|" : "", ev); strncat(buf, h, cap - strlen(buf) - 1); }
    if (!buf[0]) snprintf(buf, cap, "0");
    return buf;
}

const char *xs_afd_name(unsigned ev, char *buf, size_t cap)
{
    static const char *n[] = { "RECEIVE", "OOB", "SEND", "DISCONNECT", "ABORT", "CLOSE", "CONNECT", "ACCEPT", "CONNECT_FAIL", "QOS", "GROUP_QOS" };
    unsigned i; buf[0] = 0;
    for (i = 0; i < 11; i++)
        if (ev & (1u << i)) { if (buf[0]) strncat(buf, "|", cap - strlen(buf) - 1); strncat(buf, n[i], cap - strlen(buf) - 1); ev &= ~(1u << i); }
    if (ev) { char h[16]; snprintf(h, sizeof(h), "%s0x%x", buf[0] ? "|" : "", ev); strncat(buf, h, cap - strlen(buf) - 1); }
    if (!buf[0]) snprintf(buf, cap, "0");
    return buf;
}

/* ---- window used by the async view ------------------------------------ */
static LRESULT CALLBACK xs_wndproc(HWND h, UINT m, WPARAM wp, LPARAM lp)
{
    if (m == WM_XS) {
        if (g_nmsgs < 64 && (SOCKET)wp == g_msg_sock) { g_msgs[g_nmsgs].ev = (unsigned)(lp & 0xffff); g_msgs[g_nmsgs].err = (unsigned)((lp >> 16) & 0xffff); g_nmsgs++; }
        return 0;
    }
    return UIN("user32.dll", DefWindowProcW)(h, m, wp, lp);
}

int xs_init(void)
{
    WSADATA d;
    if (g_ready) return g_ready > 0;
    g_ready = -1;
    if (!U(WSAStartup) || !U(select) || !U(WSAPoll) || !U(WSAEventSelect) || !U(WSAEnumNetworkEvents) || !U(WSAAsyncSelect)) return 0;
    if (!t_proc_in("ntdll.dll", "NtDeviceIoControlFile") || !t_proc_in("ntdll.dll", "NtCancelIoFile")) return 0;
    if (U(WSAStartup)(MAKEWORD(2, 2), &d)) return 0;
    g_ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    {
        WNDCLASSEXW wc;
        memset(&wc, 0, sizeof(wc));
        wc.cbSize = sizeof(wc); wc.lpfnWndProc = xs_wndproc; wc.hInstance = GetModuleHandleW(NULL);
        wc.lpszClassName = L"XsMatrixWnd";
        UIN("user32.dll", RegisterClassExW)(&wc);
        g_wnd = UIN("user32.dll", CreateWindowExW)(0, L"XsMatrixWnd", L"x", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, wc.hInstance, NULL);
    }
    g_ready = g_ev ? 1 : -1;
    return g_ready > 0;
}

void xs_teardown(xs_st *st)
{
    int i;
    xs_close(st->s); xs_close(st->peer); xs_close(st->lst); xs_close(st->aux);
    for (i = 0; i < st->nextra; i++) xs_close(st->extra[i]);
    memset(st, 0, sizeof(*st));
    st->s = st->peer = st->lst = st->aux = INVALID_SOCKET;
}

/* ---- AFD poll request ---------------------------------------------------- */
typedef struct { ULONG_PTR h; ULONG ev; LONG st; } xs_aent;
typedef struct { LONGLONG to; ULONG n; UCHAR ex; UCHAR pad[3]; xs_aent e[2]; } xs_areq;
#define XS_AFD_MASK 0x1FFu    /* receive .. connect-fail: every event bit below QOS */

static void obs_afd(SOCKET s, char *out, size_t cap)
{
    xs_areq in, o; IO_STATUS_BLOCK io; LONG st; char nm[160];
    memset(&in, 0, sizeof(in)); memset(&o, 0xcc, sizeof(o));
    in.to = 0; in.n = 1; in.e[0].h = s; in.e[0].ev = XS_AFD_MASK;
    ResetEvent(g_ev);
    memset(&io, 0xcc, sizeof(io));
    st = ((XsIoctl_pfn)t_proc_in("ntdll.dll", "NtDeviceIoControlFile"))((HANDLE)s, g_ev, NULL, NULL, &io, 0x12024, &in, 32, &o, 32);
    if (st == (LONG)0x103) {
        if (WaitForSingleObject(g_ev, 2000) != WAIT_OBJECT_0) {
            IO_STATUS_BLOCK c; ((XsCancel_pfn)t_proc_in("ntdll.dll", "NtCancelIoFile"))((HANDLE)s, &c); WaitForSingleObject(g_ev, 2000);
            snprintf(out, cap, "pending-hung"); return;
        }
        st = io.Status;
    }
    if (st != 0) { snprintf(out, cap, "st=0x%08lx", (unsigned long)st); return; }
    if (o.n == 0) { snprintf(out, cap, "none"); return; }
    xs_afd_name(o.e[0].ev, nm, sizeof(nm));
    if (o.e[0].st) snprintf(out, cap, "n=%lu %s est=0x%08lx", (unsigned long)o.n, nm, (unsigned long)o.e[0].st);
    else snprintf(out, cap, "n=%lu %s", (unsigned long)o.n, nm);
}

/* ---- the views ---------------------------------------------------------- */
static void obs_sel(SOCKET s, char *out, size_t cap)
{
    int r, w, x, n = xs_sel(s, &r, &w, &x);
    if (n < 0) snprintf(out, cap, "n=-1 err=%d", xs_err());
    else snprintf(out, cap, "n=%d %s%s%s", n, r ? "R" : "-", w ? "W" : "-", x ? "X" : "-");
}

static const short k_poll_req[6] = {
    POLLRDNORM | POLLWRNORM, POLLRDBAND, POLLRDNORM, POLLWRNORM, 0, POLLRDNORM | POLLRDBAND | POLLWRNORM };

static void obs_poll(SOCKET s, int idx, char *out, size_t cap)
{
    short rev; int n; char nm[80];
    n = xs_poll1(s, k_poll_req[idx], &rev);
    if (n < 0) snprintf(out, cap, "n=-1 err=%d", xs_err());
    else snprintf(out, cap, "n=%d %s", n, xs_poll_name((unsigned short)rev, nm, sizeof(nm)));
}

static void obs_enum(SOCKET s, char *out, size_t cap)
{
    WSANETWORKEVENTS ne; int rc, i; char nm[120], tail[200]; int sig;
    tail[0] = 0;
    ResetEvent(g_ev);
    rc = U(WSAEventSelect)(s, g_ev, FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE);
    if (rc) { snprintf(out, cap, "select-err=%d", xs_err()); return; }
    sig = WaitForSingleObject(g_ev, 0) == WAIT_OBJECT_0;
    memset(&ne, 0x55, sizeof(ne));
    rc = U(WSAEnumNetworkEvents)(s, g_ev, &ne);
    if (rc) { snprintf(out, cap, "sig=%d enum-err=%d", sig, xs_err()); U(WSAEventSelect)(s, NULL, 0); return; }
    for (i = 0; i < 10; i++)
        if ((ne.lNetworkEvents & (1 << i)) && ne.iErrorCode[i]) {
            char t[40]; snprintf(t, sizeof(t), " %s=%d", xs_fd_name(1u << i, nm, sizeof(nm)), ne.iErrorCode[i]);
            strncat(tail, t, sizeof(tail) - strlen(tail) - 1);
        }
    snprintf(out, cap, "sig=%d %s%s", sig, xs_fd_name(ne.lNetworkEvents, nm, sizeof(nm)), tail);
    U(WSAEventSelect)(s, NULL, 0);
}

int xs_async_begin(SOCKET s, long mask)
{
    g_nmsgs = 0; g_msg_sock = s;
    return U(WSAAsyncSelect)(s, g_wnd, WM_XS, mask);
}

/* Pump the window for ms milliseconds and describe the messages that arrived (sorted by event bit). */
void xs_async_pump(char *out, size_t cap, int ms)
{
    MSG m; DWORD t0 = GetTickCount(); int i, j; char nm[100], t[48];
    g_nmsgs = 0;
    while ((int)(GetTickCount() - t0) < ms) {
        while (UIN("user32.dll", PeekMessageW)(&m, NULL, 0, 0, PM_REMOVE)) UIN("user32.dll", DispatchMessageW)(&m);
        Sleep(5);
    }
    out[0] = 0;
    for (i = 0; i < 16; i++)
        for (j = 0; j < g_nmsgs; j++)
            if (g_msgs[j].ev == (1u << i)) {
                if (g_msgs[j].err) snprintf(t, sizeof(t), "%s%s=%u", out[0] ? " " : "", xs_fd_name(g_msgs[j].ev, nm, sizeof(nm)), g_msgs[j].err);
                else snprintf(t, sizeof(t), "%s%s", out[0] ? " " : "", xs_fd_name(g_msgs[j].ev, nm, sizeof(nm)));
                strncat(out, t, cap - strlen(out) - 1);
            }
    if (!out[0]) snprintf(out, cap, "none");
    if (g_nmsgs > 1) { snprintf(t, sizeof(t), " (count=%d)", g_nmsgs); strncat(out, t, cap - strlen(out) - 1); }
}

void xs_async_end(SOCKET s)
{
    MSG m;
    U(WSAAsyncSelect)(s, g_wnd, 0, 0);
    while (UIN("user32.dll", PeekMessageW)(&m, NULL, 0, 0, PM_REMOVE)) UIN("user32.dll", DispatchMessageW)(&m);
}

static void obs_async(SOCKET s, char *out, size_t cap)
{
    if (xs_async_begin(s, FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE)) { snprintf(out, cap, "select-err=%d", xs_err()); return; }
    xs_async_pump(out, cap, 300);
    xs_async_end(s);
}

HANDLE xs_event(void) { return g_ev; }

void xs_observe(int view, xs_st *st, char *out, size_t cap)
{
    SOCKET s = st->s;
    switch (view) {
    case XV_SEL: obs_sel(s, out, cap); break;
    case XV_POLL_RW: case XV_POLL_BAND: case XV_POLL_RD: case XV_POLL_WR: case XV_POLL_NONE: case XV_POLL_ALL:
        obs_poll(s, view - XV_POLL_RW, out, cap); break;
    case XV_AFD: obs_afd(s, out, cap); break;
    case XV_ENUM: obs_enum(s, out, cap); break;
    case XV_ASYNC: obs_async(s, out, cap); break;
    default: snprintf(out, cap, "?");
    }
}

void xs_snap(SOCKET s, char *out, size_t cap)
{
    char a[64], b[96], c[128];
    obs_sel(s, a, sizeof(a)); obs_poll(s, 5, b, sizeof(b)); obs_afd(s, c, sizeof(c));
    snprintf(out, cap, "sel[%s] poll[%s] afd[%s]", a, b, c);
}
