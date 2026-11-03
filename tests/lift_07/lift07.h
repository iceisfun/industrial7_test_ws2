/* Shared helpers for the lift_07 area: socket I/O control codes, extension-function lookup, overlapped
 * completion (inline, completion port, APC) and the Winsock event-notification models
 * (WSAEventSelect / WSAAsyncSelect).  Everything in ws2_32 is reached through U(); the SDK headers are
 * used for type and constant definitions only. */
#ifndef LIFT07_H
#define LIFT07_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <mstcpip.h>

#ifndef SIO_BASE_HANDLE
#define SIO_BASE_HANDLE 0x48000022
#endif
#ifndef SIO_IDEAL_SEND_BACKLOG_QUERY
#define SIO_IDEAL_SEND_BACKLOG_QUERY 0x4004747b
#endif
#ifndef SIO_ENABLE_CIRCULAR_QUEUEING
#define SIO_ENABLE_CIRCULAR_QUEUEING 0x28000002
#endif
#define L7_STATUS_PENDING       ((NTSTATUS)0x00000103)
#define L7_STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BB)
#define L7_LOOPBACK_BE          0x0100007Fu       /* 127.0.0.1 in network byte order on a little-endian host */
#define L7_UNSET                0xdeadbeef

/* ---- start-up ----------------------------------------------------------- */
static int l7_init(void)
{
    static int done = -1;
    WSADATA d;
    if (done < 0) {
        done = (U(WSAStartup) && U(WSAStartup)(MAKEWORD(2, 2), &d) == 0) ? 1 : 0;
    }
    return done;
}
#define L7TEST(n) \
    static void l7body_##n(void); \
    TEST(n) { if (!l7_init()) { t_skip("WSAStartup failed"); return; } l7body_##n(); } \
    static void l7body_##n(void)

/* ---- thin call wrappers (all through GetProcAddress) -------------------- */
static int  l7_err(void)            { return U(WSAGetLastError)(); }
static void l7_seterr(int e)        { U(WSASetLastError)(e); }
static SOCKET l7_sock(int af, int type, int proto) { return U(socket)(af, type, proto); }
static int  l7_close(SOCKET s)      { return U(closesocket)(s); }
static int  l7_ioctl(SOCKET s, DWORD code, void *in, DWORD inl, void *out, DWORD outl,
                     DWORD *ret, OVERLAPPED *ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    return U(WSAIoctl)(s, code, in, inl, out, outl, ret, (LPWSAOVERLAPPED)ov, cr);
}
static void l7_loop_addr(struct sockaddr_in *a, unsigned short port_be)
{
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = L7_LOOPBACK_BE;
    a->sin_port = port_be;
}
/* Listening TCP socket on an ephemeral loopback port; *addr receives the bound address. */
static SOCKET l7_listener(struct sockaddr_in *addr, int backlog)
{
    struct sockaddr_in a;
    int len = sizeof(a);
    SOCKET s = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return s;
    l7_loop_addr(&a, 0);
    if (U(bind)(s, (struct sockaddr *)&a, sizeof(a)) || U(getsockname)(s, (struct sockaddr *)&a, &len) ||
        U(listen)(s, backlog)) {
        l7_close(s);
        return INVALID_SOCKET;
    }
    if (addr) *addr = a;
    return s;
}
/* Connected loopback TCP pair: *cli connected to *srv (accepted).  Returns FALSE (both invalid) on failure. */
static BOOL l7_pair(SOCKET *cli, SOCKET *srv)
{
    struct sockaddr_in a;
    SOCKET l = l7_listener(&a, 1);
    *cli = *srv = INVALID_SOCKET;
    if (l == INVALID_SOCKET) return FALSE;
    *cli = l7_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*cli != INVALID_SOCKET && U(connect)(*cli, (struct sockaddr *)&a, sizeof(a)) == 0)
        *srv = U(accept)(l, NULL, NULL);
    l7_close(l);
    if (*srv == INVALID_SOCKET) {
        if (*cli != INVALID_SOCKET) l7_close(*cli);
        *cli = INVALID_SOCKET;
        return FALSE;
    }
    return TRUE;
}
#define L7_PAIR(c, s) SOCKET c = INVALID_SOCKET, s = INVALID_SOCKET; \
    if (!l7_pair(&c, &s)) { t_skip("could not build a loopback connection"); return; }
static void l7_nonblock(SOCKET s, int on)
{
    u_long v = on;
    U(ioctlsocket)(s, FIONBIO, &v);
}
/* Poll one socket (bounded 1 s); returns revents. */
static short l7_poll(SOCKET s, short mask)
{
    WSAPOLLFD p;
    p.fd = s; p.events = mask; p.revents = (short)0xdead;
    U(WSAPoll)(&p, 1, 1000);
    return p.revents;
}
/* Abortive close (zero linger) -> RST on the wire. */
static void l7_rst_close(SOCKET s)
{
    struct linger l = {1, 0};
    U(setsockopt)(s, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof(l));
    l7_close(s);
}
/* Blocking-style read on a possibly non-blocking socket, via overlapped WSARecv. */
static int l7_sync_recv(SOCKET s, void *buf, int len)
{
    OVERLAPPED ov;
    WSABUF wb;
    DWORD got = 0, fl = 0;
    int r;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    wb.buf = buf; wb.len = len;
    r = U(WSARecv)(s, &wb, 1, &got, &fl, (LPWSAOVERLAPPED)&ov, NULL);
    if (r == -1 && l7_err() == ERROR_IO_PENDING) {
        if (WaitForSingleObject(ov.hEvent, 2000) != WAIT_OBJECT_0) {
            CancelIo((HANDLE)s);
            WaitForSingleObject(ov.hEvent, 1000);
            CloseHandle(ov.hEvent);
            return -2;
        }
        r = U(WSAGetOverlappedResult)(s, (LPWSAOVERLAPPED)&ov, &got, FALSE, &fl) ? 0 : -1;
    }
    CloseHandle(ov.hEvent);
    return r == 0 ? (int)got : -1;
}

/* ---- completion capture ------------------------------------------------- */
static DWORD l7_apc_error, l7_apc_size, l7_apc_flags;
static OVERLAPPED *l7_apc_ov;
static unsigned l7_apc_count;
static void WINAPI l7_apc(DWORD error, DWORD size, LPWSAOVERLAPPED ov, DWORD flags)
{
    ++l7_apc_count; l7_apc_error = error; l7_apc_size = size; l7_apc_ov = (OVERLAPPED *)ov; l7_apc_flags = flags;
}
static void l7_apc_reset(void) { l7_apc_count = 0; l7_apc_error = L7_UNSET; l7_apc_size = L7_UNSET; l7_apc_ov = NULL; }
#define L7_PORT_KEY 123
static HANDLE l7_port_for(SOCKET s) { return CreateIoCompletionPort((HANDLE)s, NULL, L7_PORT_KEY, 0); }
static void l7_ov_poison(OVERLAPPED *ov)
{
    ov->Internal = L7_UNSET; ov->InternalHigh = L7_UNSET;
}
/* Expect exactly one completion-port packet for ov: success packet, size 0, our key. */
static void l7_expect_packet_ok(HANDLE port, OVERLAPPED *ov, const char *what)
{
    DWORD size = L7_UNSET; ULONG_PTR key = 0; OVERLAPPED *got = NULL;
    BOOL r = GetQueuedCompletionStatus(port, &size, &key, &got, 0);
    CHECKF(r, "%s: no success packet (err %lu)", what, GetLastError());
    CHECKF(size == 0, "%s: packet size %lu", what, size);
    CHECKF(key == L7_PORT_KEY, "%s: packet key %Iu", what, key);
    CHECKF(got == ov, "%s: packet overlapped", what);
    CHECKF((NTSTATUS)ov->Internal == 0, "%s: status %#lx", what, (NTSTATUS)ov->Internal);
    CHECKF(ov->InternalHigh == 0, "%s: transferred %Iu", what, ov->InternalHigh);
}
static void l7_expect_packet_unsupported(HANDLE port, OVERLAPPED *ov, const char *what)
{
    DWORD size = L7_UNSET; ULONG_PTR key = 0; OVERLAPPED *got = NULL;
    BOOL r = GetQueuedCompletionStatus(port, &size, &key, &got, 0);
    DWORD e = GetLastError();
    CHECKF(!r, "%s: packet reported success", what);
    CHECKF(e == ERROR_NOT_SUPPORTED, "%s: packet error %lu", what, e);
    CHECKF(size == 0, "%s: packet size %lu", what, size);
    CHECKF(key == L7_PORT_KEY, "%s: packet key %Iu", what, key);
    CHECKF(got == ov, "%s: packet overlapped", what);
    CHECKF((NTSTATUS)ov->Internal == L7_STATUS_NOT_SUPPORTED, "%s: status %#lx", what, (NTSTATUS)ov->Internal);
    CHECKF(ov->InternalHigh == 0, "%s: transferred %Iu", what, ov->InternalHigh);
}
/* Run the pending APC (if any) and check it fired once with the given error, zero bytes. */
static void l7_expect_apc(OVERLAPPED *ov, DWORD error, const char *what)
{
    DWORD r = SleepEx(0, TRUE);
    CHECKF(r == WAIT_IO_COMPLETION, "%s: SleepEx %lu", what, r);
    CHECKF(l7_apc_count == 1, "%s: APC ran %u times", what, l7_apc_count);
    CHECKF(l7_apc_error == error, "%s: APC error %lu", what, l7_apc_error);
    CHECKF(l7_apc_size == 0, "%s: APC size %lu", what, l7_apc_size);
    CHECKF(l7_apc_ov == ov, "%s: APC overlapped", what);
    CHECKF(l7_apc_flags == 0, "%s: APC flags %#lx", what, l7_apc_flags);
}

/* ---- event notification context ----------------------------------------- */
#define L7_WM_SOCK (WM_USER)
struct l7_ectx {
    int is_message;
    SOCKET socket;
    HANDLE event;
    HWND window;
};
static void l7_select(struct l7_ectx *c, SOCKET s, LONG events)
{
    int r;
    if (c->is_message) r = U(WSAAsyncSelect)(s, c->window, L7_WM_SOCK, events);
    else               r = U(WSAEventSelect)(s, c->event, events);
    CHECKF(r == 0, "event selection failed (%d)", l7_err());
    c->socket = s;
}
/* Wait up to `timeout` ms for a notification to become available (without consuming it). */
static BOOL l7_notified(struct l7_ectx *c, DWORD timeout)
{
    MSG m;
    if (!c->is_message) return WaitForSingleObject(c->event, timeout) == WAIT_OBJECT_0;
    for (;;) {
        if (PeekMessageA(&m, c->window, L7_WM_SOCK, L7_WM_SOCK, PM_NOREMOVE)) return TRUE;
        if (MsgWaitForMultipleObjects(0, NULL, FALSE, timeout, QS_POSTMESSAGE) != WAIT_OBJECT_0) return FALSE;
    }
}
/* Expect the notification series f1, f2 (0 = none), each encoded as MAKELONG(event, error), then silence.
 * Message mode: one message per entry in order, then no further message.
 * Event mode: the event object is signalled iff any bit is expected; the enumerated set equals f1|f2 and
 * the error code of single-bit entries matches. */
static void l7_expect(struct l7_ectx *c, LONG f1, LONG f2, DWORD timeout)
{
    int r;
    if (c->is_message) {
        MSG m;
        LONG want[2]; int i;
        want[0] = f1; want[1] = f2;
        for (i = 0; i < 2; ++i) {
            if (!want[i]) continue;
            r = PeekMessageA(&m, c->window, L7_WM_SOCK, L7_WM_SOCK, PM_REMOVE);
            while (!r && MsgWaitForMultipleObjects(0, NULL, FALSE, timeout, QS_POSTMESSAGE) == WAIT_OBJECT_0)
                r = PeekMessageA(&m, c->window, L7_WM_SOCK, L7_WM_SOCK, PM_REMOVE);
            CHECKF(r, "expected message %d (event %#lx)", i, want[i]);
            if (r) {
                CHECKF(m.wParam == c->socket, "message for another socket");
                CHECKF((LONG)m.lParam == want[i], "message %d lParam %#Ix want %#lx", i, m.lParam, want[i]);
            }
        }
        MsgWaitForMultipleObjects(0, NULL, FALSE, 10, QS_POSTMESSAGE);
        r = PeekMessageA(&m, c->window, L7_WM_SOCK, L7_WM_SOCK, PM_REMOVE);
        CHECKF(!r, "unexpected extra message %#Ix", r ? m.lParam : 0);
    } else {
        WSANETWORKEVENTS ev;
        unsigned i;
        memset(&ev, 0xcc, sizeof(ev));
        r = WaitForSingleObject(c->event, timeout);
        if (f1 | f2) CHECKF(r == WAIT_OBJECT_0, "event object not signalled");
        else         CHECKF(r == WAIT_TIMEOUT, "event object signalled unexpectedly");
        r = U(WSAEnumNetworkEvents)(c->socket, c->event, &ev);
        CHECKF(r == 0, "WSAEnumNetworkEvents failed (%d)", l7_err());
        CHECKF(ev.lNetworkEvents == (LONG)LOWORD(f1 | f2), "events %#lx want %#x", ev.lNetworkEvents, LOWORD(f1 | f2));
        for (i = 0; i < FD_MAX_EVENTS; ++i) {
            LONG fl[2]; int k;
            fl[0] = f1; fl[1] = f2;
            for (k = 0; k < 2; ++k)
                if ((1u << i) == LOWORD(fl[k]) && (ev.lNetworkEvents & LOWORD(fl[k])))
                    CHECKF(ev.iErrorCode[i] == (int)HIWORD(fl[k]), "error code %d for event bit %u", ev.iErrorCode[i], i);
        }
    }
}
#define L7_NONE(c) l7_expect(c, 0, 0, 0)
static void l7_ectx_open(struct l7_ectx *c, int is_message)
{
    memset(c, 0, sizeof(*c));
    c->is_message = is_message;
    if (is_message) c->window = CreateWindowA("Message", NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);
    else            c->event = CreateEventW(NULL, TRUE, FALSE, NULL);
}
static void l7_ectx_close(struct l7_ectx *c)
{
    if (c->is_message) { if (c->window) DestroyWindow(c->window); }
    else CloseHandle(c->event);
}
/* Define a scenario run once with an event object and once with window messages. */
#define L7EVTEST(n) \
    static void l7ev_##n(struct l7_ectx *c); \
    TEST(n##_eventobj) { struct l7_ectx c; if (!l7_init()) { t_skip("WSAStartup failed"); return; } \
        l7_ectx_open(&c, 0); l7ev_##n(&c); l7_ectx_close(&c); } \
    TEST(n##_wndmsg)   { struct l7_ectx c; if (!l7_init()) { t_skip("WSAStartup failed"); return; } \
        l7_ectx_open(&c, 1); if (!c.window) { t_skip("no message window"); return; } l7ev_##n(&c); l7_ectx_close(&c); } \
    static void l7ev_##n(struct l7_ectx *c)
#define L7_ALL_EV (FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE)
#define L7_NO_WRITE (FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ)
#endif
