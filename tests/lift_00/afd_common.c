/* Shared helpers for the AFD poll / device-open tests (see afd_common.h). */
#include "afd_common.h"

afdfn_t F;
static int g_state; /* 0 untried, 1 ready, -1 failed */

#define RES_NT(n) do { F.n = (n##_pfn)t_proc_in("ntdll.dll", #n); if (!F.n) return 0; } while (0)
#define RES_WS(n) do { F.n = U(n); if (!F.n) return 0; } while (0)

int afd_ready(void)
{
    WSADATA wd;
    if (g_state) return g_state > 0;
    g_state = -1;
    RES_NT(NtOpenFile); RES_NT(NtDeviceIoControlFile); RES_NT(NtQueryObject);
    RES_NT(NtQuerySystemTime); RES_NT(NtRemoveIoCompletion);
    RES_WS(WSAStartup); RES_WS(WSAGetLastError); RES_WS(socket); RES_WS(bind); RES_WS(listen);
    RES_WS(accept); RES_WS(connect); RES_WS(getsockname); RES_WS(send); RES_WS(recv); RES_WS(sendto);
    RES_WS(shutdown); RES_WS(closesocket); RES_WS(setsockopt); RES_WS(ioctlsocket); RES_WS(WSAIoctl);
    RES_WS(WSARecv);
    if (F.WSAStartup(MAKEWORD(2, 2), &wd)) return 0;
    g_state = 1;
    return 1;
}

SOCKET mk_sock(int type)
{
    SOCKET s = F.socket(AF_INET, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP);
    CHECKF(s != INVALID_SOCKET, "socket failed, error %d", F.WSAGetLastError());
    return s;
}

SOCKET mk_listener(struct sockaddr_in *addr_out)
{
    struct sockaddr_in a;
    int len = sizeof(a);
    SOCKET s = mk_tcp();
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = 0x0100007Fu /* 127.0.0.1, network order */;
    CHECK(F.bind(s, (struct sockaddr *)&a, sizeof(a)) == 0);
    CHECK(F.listen(s, 1) == 0);
    CHECK(F.getsockname(s, (struct sockaddr *)&a, &len) == 0);
    if (addr_out) *addr_out = a;
    return s;
}

void mk_pair(SOCKET *client, SOCKET *server)
{
    struct sockaddr_in a;
    SOCKET l = mk_listener(&a);
    *client = mk_tcp();
    CHECK(F.connect(*client, (struct sockaddr *)&a, sizeof(a)) == 0);
    *server = F.accept(l, NULL, NULL);
    CHECK(*server != INVALID_SOCKET);
    F.closesocket(l);
}

void set_nonblock(SOCKET s, int on)
{
    u_long v = on ? 1 : 0;
    CHECK(F.ioctlsocket(s, FIONBIO, &v) == 0);
}

void close_rst(SOCKET s)
{
    struct linger lg = { 1, 0 };
    SET_ERR(0);
    CHECK(F.setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof(lg)) == 0);
    F.closesocket(s);
}

void sock_close(SOCKET s)
{
    if (s != INVALID_SOCKET) F.closesocket(s);
}

HANDLE mk_event(void)
{
    HANDLE h = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(h != NULL);
    return h;
}

HANDLE open_afd(const wchar_t *path)
{
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK io;
    HANDLE h = NULL;
    LONG st;
    us.Buffer = (PWSTR)path;
    us.Length = (USHORT)(lstrlenW(path) * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);
    InitializeObjectAttributes(&oa, &us, 0, NULL, NULL);
    memset(&io, 0, sizeof(io));
    st = F.NtOpenFile(&h, SYNCHRONIZE, &oa, &io, 0, 0);
    EXPECT_EQ((ULONG)st, 0);
    return st == 0 ? h : NULL;
}

LONG afd_poll_ex(HANDLE h, HANDLE ev, void *apc_ctx, IO_STATUS_BLOCK *io, void *in, ULONG inlen, void *out, ULONG outlen)
{
    return F.NtDeviceIoControlFile(h, ev, NULL, apc_ctx, io, AFDX_IOCTL_POLL, in, inlen, out, outlen);
}

LONG afd_poll(HANDLE h, HANDLE ev, IO_STATUS_BLOCK *io, void *in, ULONG inlen, void *out, ULONG outlen)
{
    return afd_poll_ex(h, ev, NULL, io, in, inlen, out, outlen);
}

void fill_poll(pollbuf_t *b, LONGLONG timeout, ULONG exclusive, int n, const SOCKET *socks, const ULONG *flags)
{
    int i;
    memset(b, 0, sizeof(*b));
    b->req.timeout = timeout;
    b->req.count = n;
    b->req.exclusive = exclusive;
    for (i = 0; i < n; i++) {
        b->req.sockets[i].socket = socks[i];
        b->req.sockets[i].flags = flags[i];
        b->req.sockets[i].status = (LONG)0xdeadbeef;
    }
}

void fill_poll1(pollbuf_t *b, LONGLONG timeout, SOCKET s, ULONG flags)
{
    fill_poll(b, timeout, 0, 1, &s, &flags);
}

DWORD wait_done(HANDLE ev, DWORD ms)
{
    return WaitForSingleObject(ev, ms);
}

void cancel_and_drain(HANDLE h, HANDLE ev)
{
    CancelIo(h);
    /* the request completes (cancelled) and signals its event; bounded wait only */
    WaitForSingleObject(ev, 1000);
}

void poll_one_expect(const char *file, int line, SOCKET s, HANDLE ev, ULONG mask, ULONG expect)
{
    pollreq_t in, out;
    IO_STATUS_BLOCK io;
    LONG st;
    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    memset(&io, 0, sizeof(io));
    in.timeout = REL_MS(1000);
    in.count = 1;
    in.sockets[0].socket = s;
    in.sockets[0].flags = mask;
    in.sockets[0].status = (LONG)0xdeadbeef;
    st = afd_poll((HANDLE)s, ev, &io, &in, sizeof(in), &out, sizeof(out));
    t_check(st == AS_SUCCESS || st == AS_PENDING, file, line, "poll submit", "got %#lx", (unsigned long)st);
    if (st == AS_PENDING) {
        DWORD w = WaitForSingleObject(ev, 1500);
        t_check(w == WAIT_OBJECT_0, file, line, "poll completes", "wait result %lu", (unsigned long)w);
        if (w != WAIT_OBJECT_0) { CancelIo((HANDLE)s); WaitForSingleObject(ev, 1000); return; }
    }
    t_check(io.Status == 0, file, line, "io.Status == 0", "got %#lx", (unsigned long)io.Status);
    t_check(io.Information == sizeof(out), file, line, "io.Information == one entry", "got %#llx", (unsigned long long)io.Information);
    t_check(out.timeout == in.timeout, file, line, "timeout echoed", "got %lld", (long long)out.timeout);
    t_check(out.count == 1, file, line, "count == 1", "got %lu", (unsigned long)out.count);
    t_check(out.sockets[0].socket == s, file, line, "socket echoed", "got %#llx", (unsigned long long)out.sockets[0].socket);
    t_check(out.sockets[0].flags == expect, file, line, "flags == expected", "got %#lx want %#lx", (unsigned long)out.sockets[0].flags, (unsigned long)expect);
    t_check(out.sockets[0].status == 0, file, line, "status == 0", "got %#lx", (unsigned long)out.sockets[0].status);
}
