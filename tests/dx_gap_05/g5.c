/* Helper implementation for the gap_05 area. */
#include "g5.h"

G5F W;
static int g_state;

int g5_init(void)
{
    if (g_state) return g_state > 0;
    g_state = -1;
#define R(n) do { W.n = U(n); if (!W.n) return 0; } while (0)
    R(WSAStartup); R(WSAGetLastError); R(WSASocketW); R(closesocket); R(bind); R(listen); R(connect);
    R(accept); R(getsockname); R(getpeername); R(setsockopt); R(ioctlsocket); R(send); R(recv);
    R(sendto); R(shutdown); R(select); R(WSAIoctl);
#undef R
    W.ioctl = (g5_ioctl_fn)t_proc_in("ntdll.dll", "NtDeviceIoControlFile");
    W.cancel = (void *)t_proc_in("ntdll.dll", "NtCancelIoFile");
    W.nt_close = (void *)t_proc_in("ntdll.dll", "NtClose");
    W.nt_create = (void *)t_proc_in("ntdll.dll", "NtCreateFile");
    if (!W.ioctl || !W.cancel || !W.nt_close || !W.nt_create) return 0;
    WSADATA d;
    if (W.WSAStartup(MAKEWORD(2, 2), &d)) return 0;
    g_state = 1;
    return 1;
}

void g5_timeouts(SOCKET s)
{
    DWORD ms = WAIT_MS;
    W.setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms);
    W.setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof ms);
}
SOCKET g5_sock(int af, int type)
{
    SOCKET s = W.WSASocketW(af, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
    CHECKF(s != INVALID_SOCKET, "socket creation failed, error %d", W.WSAGetLastError());
    if (s != INVALID_SOCKET) g5_timeouts(s);
    return s;
}
void g5_close(SOCKET s) { if (s != INVALID_SOCKET && s != 0) W.closesocket(s); }
struct sockaddr_in g5_lo4(USHORT port_be)
{
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = BE32(0x7f000001UL); a.sin_port = port_be;
    return a;
}
SOCKET g5_bound(int type, struct sockaddr_in *addr)
{
    struct sockaddr_in a = g5_lo4(0); int n = sizeof a;
    SOCKET s = g5_sock(AF_INET, type);
    if (s == INVALID_SOCKET) return s;
    CHECK(W.bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(W.getsockname(s, (struct sockaddr *)&a, &n) == 0);
    if (addr) *addr = a;
    return s;
}
SOCKET g5_listener(struct sockaddr_in *addr)
{
    SOCKET s = g5_bound(SOCK_STREAM, addr);
    if (s != INVALID_SOCKET) CHECK(W.listen(s, 4) == 0);
    return s;
}
static int wait_sel(SOCKET s, DWORD ms)
{
    fd_set f; struct timeval tv;
    f.fd_count = 1; f.fd_array[0] = s;
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return W.select(0, &f, NULL, NULL, &tv) > 0;
}
int g5_readable(SOCKET s, DWORD ms) { return wait_sel(s, ms); }
SOCKET g5_connect_nb(const struct sockaddr_in *to)
{
    ULONG on = 1;
    SOCKET c = g5_tcp();
    W.ioctlsocket(c, FIONBIO, &on);
    W.connect(c, (const struct sockaddr *)to, sizeof *to);      /* completes later: would-block now */
    return c;
}
void g5_pair(SOCKET *client, SOCKET *server)
{
    struct sockaddr_in a; SOCKET l = g5_listener(&a), c = g5_tcp();
    *client = *server = INVALID_SOCKET;
    if (l == INVALID_SOCKET || c == INVALID_SOCKET) { g5_close(l); g5_close(c); return; }
    CHECK(W.connect(c, (struct sockaddr *)&a, sizeof a) == 0);
    SOCKET s = g5_readable(l, WAIT_MS) ? W.accept(l, NULL, NULL) : INVALID_SOCKET;
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) g5_timeouts(s);
    g5_close(l);
    *client = c; *server = s;
}

LONG g5_submit(HANDLE h, HANDLE ev, ULONG code, void *in, ULONG inl, void *out, ULONG outl, IO_STATUS_BLOCK *io)
{
    return W.ioctl(h, ev, NULL, NULL, io, code, in, inl, out, outl);
}
LONG g5_finish(HANDLE h, HANDLE ev, IO_STATUS_BLOCK *io, DWORD ms)
{
    if (WaitForSingleObject(ev, ms) != WAIT_OBJECT_0) {
        IO_STATUS_BLOCK c;
        W.cancel(h, &c);
        WaitForSingleObject(ev, 2000);
        return ST_LOCAL_GAVE_UP;
    }
    return io->Status;
}
LONG g5_ctl(HANDLE h, ULONG code, void *in, ULONG inl, void *out, ULONG outl, IO_STATUS_BLOCK *io, LONG *first)
{
    IO_STATUS_BLOCK local;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    LONG st;
    if (!io) io = &local;
    io->Status = (LONG)0xcccccccc; io->Information = (ULONG_PTR)0xcccccccccccccccc;
    st = g5_submit(h, ev, code, in, inl, out, outl, io);
    if (first) *first = st;
    if (st == ST_PENDING) st = g5_finish(h, ev, io, WAIT_MS);
    CloseHandle(ev);
    return st;
}
LONG g5_raw_listen(SOCKET s, ULONG backlog, ULONG delayed)
{
    G5_LISTEN l; memset(&l, 0, sizeof l);
    l.backlog = backlog; l.delayed = delayed;
    return g5_ctl(S(s), C_START_LISTEN, &l, sizeof l, NULL, 0, NULL, NULL);
}
LONG g5_raw_bind4(HANDLE h, USHORT port_be)
{
    struct sockaddr_in a = g5_lo4(port_be), out; unsigned char buf[4 + sizeof a];
    ULONG share = 0;
    memcpy(buf, &share, 4); memcpy(buf + 4, &a, sizeof a);
    return g5_ctl(h, C_BIND, buf, sizeof buf, &out, sizeof out, NULL, NULL);
}
LONG g5_wait_listen(SOCKET l, ULONG code, ULONG *seq, IO_STATUS_BLOCK *io)
{
    G5_WAITRES r; IO_STATUS_BLOCK local; LONG st;
    memset(&r, 0, sizeof r);
    if (!io) io = &local;
    st = g5_ctl(S(l), code, NULL, 0, &r, sizeof r, io, NULL);
    if (seq) *seq = r.sequence;
    return st;
}

/* The open packet is the extended attribute "AfdOpenPacketXX" whose value is
 * { Flags, GroupID, Family, Type, Protocol, TransportNameBytes, TransportName[] }. */
HANDLE g5_open_ep(int kind, int legacy, LONG *stp)
{
    static const struct { ULONG flags, fam, type, proto; const WCHAR *name; } k[] = {
        { 0, 2, 1, 6, L"\\Device\\Tcp" }, { 0x11, 2, 2, 17, L"\\Device\\Udp" }, { 0, 23, 1, 6, L"\\Device\\Tcp6" },
    };
    static const char ea_name[] = "AfdOpenPacketXX";
    static const WCHAR path[] = L"\\Device\\Afd\\Endpoint";
    unsigned char buf[8 + sizeof ea_name + 24 + 64];
    ULONG *v;
    size_t nlen = legacy ? lstrlenW(k[kind].name) * 2 : 0, vlen = nlen ? 24 + nlen + 2 : 28, total;
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h = NULL; LONG st;
    if (t_is_wine()) { if (stp) *stp = (LONG)0xC0000001; return NULL; }
    memset(buf, 0, sizeof buf);
    buf[5] = (unsigned char)(sizeof ea_name - 1);
    *(USHORT *)(buf + 6) = (USHORT)vlen;
    memcpy(buf + 8, ea_name, sizeof ea_name);
    v = (ULONG *)(buf + 8 + sizeof ea_name);
    v[0] = k[kind].flags; v[1] = 0; v[2] = k[kind].fam; v[3] = k[kind].type; v[4] = k[kind].proto; v[5] = (ULONG)nlen;
    if (nlen) memcpy(v + 6, k[kind].name, nlen);
    total = 8 + (ULONG)sizeof ea_name + (ULONG)vlen;
    us.Buffer = (PWSTR)path; us.Length = sizeof path - 2; us.MaximumLength = sizeof path;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    st = W.nt_create(&h, 0xC0140000u, &oa, &io, NULL, 0, 3, 3, 0, buf, total);
    if (stp) *stp = st;
    return st >= 0 ? h : NULL;
}
void g5_close_h(HANDLE h) { if (h) W.nt_close(h); }
