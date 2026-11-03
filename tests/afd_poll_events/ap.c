/* Implementation of the helpers declared in ap.h. */
#include "ap.h"

ap_fns X;
static HANDLE g_try_ev;
static int g_ready;   /* 0 untried, 1 usable, -1 unusable */

#define RN(f, n) do { X.f = (n##_pfn)t_proc_in("ntdll.dll", #n); if (!X.f) return 0; } while (0)
#define RW(n) do { X.n = U(n); if (!X.n) return 0; } while (0)

int ap_init(void)
{
    WSADATA wd;
    if (g_ready) return g_ready > 0;
    g_ready = -1;
    RN(ioctl, NtDeviceIoControlFile); RN(cancel_all, NtCancelIoFile); RN(systime, NtQuerySystemTime);
    RN(open_file, NtOpenFile);
    X.cancel_ex = (NtCancelIoFileEx_pfn)t_proc_in("ntdll.dll", "NtCancelIoFileEx");   /* optional */
    RW(WSAStartup); RW(WSAGetLastError); RW(socket); RW(WSASocketW); RW(bind); RW(listen); RW(accept);
    RW(connect); RW(getsockname); RW(send); RW(sendto); RW(recv); RW(shutdown); RW(closesocket);
    RW(setsockopt); RW(ioctlsocket);
    if (X.WSAStartup(MAKEWORD(2, 2), &wd)) return 0;
    g_try_ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_ready = 1;
    return 1;
}

SOCKET ap_sock(int type)
{
    SOCKET s = X.socket(AF_INET, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP);
    CHECKF(s != INVALID_SOCKET, "socket failed, error %d", X.WSAGetLastError());
    return s;
}

SOCKET ap_listener(struct sockaddr_in *addr, int backlog)
{
    struct sockaddr_in a;
    int len = sizeof(a);
    SOCKET s = ap_sock(SOCK_STREAM);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = 0x0100007Fu;   /* 127.0.0.1 in network order */
    CHECK(X.bind(s, (struct sockaddr *)&a, sizeof(a)) == 0);
    CHECK(X.listen(s, backlog) == 0);
    CHECK(X.getsockname(s, (struct sockaddr *)&a, &len) == 0);
    if (addr) *addr = a;
    return s;
}

SOCKET ap_dial(const struct sockaddr_in *addr)
{
    SOCKET c = ap_sock(SOCK_STREAM);
    CHECK(X.connect(c, (const struct sockaddr *)addr, sizeof(*addr)) == 0);
    return c;
}

void ap_pair(SOCKET *client, SOCKET *server)
{
    struct sockaddr_in a;
    SOCKET l = ap_listener(&a, 1);
    *client = ap_dial(&a);
    *server = X.accept(l, NULL, NULL);
    CHECK(*server != INVALID_SOCKET);
    X.closesocket(l);
}

void ap_closeS(SOCKET s) { if (s != INVALID_SOCKET) X.closesocket(s); }

void ap_rst_close(SOCKET s)
{
    struct linger lg = { 1, 0 };
    CHECK(X.setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof(lg)) == 0);
    X.closesocket(s);
}

void ap_nonblock(SOCKET s) { u_long v = 1; CHECK(X.ioctlsocket(s, FIONBIO, &v) == 0); }

HANDLE ap_event(void)
{
    HANDLE h = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(h != NULL);
    return h;
}

void ap_send_n(SOCKET s, int n)
{
    char buf[64];
    memset(buf, 'a', sizeof(buf));
    if (n > (int)sizeof(buf)) n = sizeof(buf);
    CHECK(X.send(s, buf, n, 0) == n);
}

void ap_drain(SOCKET s)
{
    char buf[256];
    u_long v = 1;
    X.ioctlsocket(s, FIONBIO, &v);
    while (X.recv(s, buf, sizeof(buf), 0) > 0) { }
    v = 0;
    X.ioctlsocket(s, FIONBIO, &v);
}

LONG ap_submit(HANDLE carrier, HANDLE ev, IO_STATUS_BLOCK *io, const void *in, ULONG inlen, void *out, ULONG outlen)
{
    return X.ioctl(carrier, ev, NULL, NULL, io, AP_IOCTL_POLL, (PVOID)in, inlen, out, outlen);
}

void ap_run(HANDLE carrier, LONGLONG to, UCHAR ex, int n, const SOCKET *h, const ULONG *mask, DWORD wait_ms, ap_res *r)
{
    ap_req in;
    IO_STATUS_BLOCK io;
    HANDLE ev = ap_event();
    int i;
    memset(&in, 0, sizeof(in));
    memset(r, 0, sizeof(*r));
    memset(&r->out, 0xcc, sizeof(r->out));
    in.to = to; in.n = n; in.ex = ex;
    for (i = 0; i < n; i++) { in.e[i].h = h[i]; in.e[i].ev = mask[i]; in.e[i].st = (LONG)0xdeadbeef; }
    memset(&io, 0xcc, sizeof(io));
    r->ret = ap_submit(carrier, ev, &io, &in, AP_SZ(n), &r->out, AP_SZ(n));
    if (r->ret == (LONG)APS_PENDING) {
        if (WaitForSingleObject(ev, wait_ms) == WAIT_OBJECT_0) r->waited = 1;
        else {
            r->hung = 1;
            { IO_STATUS_BLOCK cio; X.cancel_all(carrier, &cio); }
            WaitForSingleObject(ev, 2000);
        }
    }
    r->ios = io.Status;
    r->info = io.Information;
    CloseHandle(ev);
}

void ap_run1(SOCKET s, ULONG mask, LONGLONG to, ap_res *r)
{
    ap_run((HANDLE)s, to, 0, 1, &s, &mask, 6000, r);
}

/* Flags of entry 0 when the poll reported exactly one entry for s; 0 otherwise. */
static ULONG flags_of(const ap_res *r, SOCKET s)
{
    if (r->hung || r->ios != 0 || r->out.n != 1 || r->out.e[0].h != s) return 0;
    return r->out.e[0].ev;
}

ULONG ap_wait_flags(SOCKET s, ULONG mask)
{
    ap_res r;
    ap_run1(s, mask, AP_REL_MS(3000), &r);
    return flags_of(&r, s);
}

ULONG ap_now_flags(SOCKET s, ULONG mask)
{
    ap_res r;
    ap_run1(s, mask, 0, &r);
    return flags_of(&r, s);
}

int ap_idle(SOCKET s, ULONG mask)
{
    ap_res r;
    ap_run1(s, mask, 0, &r);
    return r.ret == 0 && r.ios == 0 && r.out.n == 0 && r.info == 16;
}

void ap_fill(ap_req *r, LONGLONG to, UCHAR ex, int n, const SOCKET *h, ULONG mask)
{
    int i;
    memset(r, 0, sizeof(*r));
    r->to = to; r->n = n; r->ex = ex;
    for (i = 0; i < n; i++) { r->e[i].h = h[i]; r->e[i].ev = mask; r->e[i].st = (LONG)0xdeadbeef; }
}

LONG ap_try(HANDLE carrier, const ap_req *in, ULONG inlen, ULONG outlen)
{
    static ap_req out[2];   /* the oversized-output rows ask for up to 2x the entries; AP_MAXE keeps it in range */
    IO_STATUS_BLOCK io;
    HANDLE ev = g_try_ev;   /* created up front: a handle freed by the caller must not be recycled for it */
    LONG st;
    memset(out, 0, sizeof(out));
    ResetEvent(ev);
    memset(&io, 0xcc, sizeof(io));
    st = ap_submit(carrier, ev, &io, in, inlen, outlen ? out : NULL, outlen);
    if (st == (LONG)APS_PENDING) {
        { IO_STATUS_BLOCK cio; X.cancel_all(carrier, &cio); }   /* separate block: never the request's own */
        WaitForSingleObject(ev, 2000);
    }
    return st;
}
