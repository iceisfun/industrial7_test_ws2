/* Implementation of the helpers declared in aio.h. */
#include "aio.h"

AIOF W;
static LONG (NTAPI *p_create)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *, IO_STATUS_BLOCK *, LARGE_INTEGER *, ULONG, ULONG, ULONG, ULONG, void *, ULONG);
static LONG (NTAPI *p_close)(HANDLE);
DWORD aio_wait_ms = 3000;
static int g_state;

int aio_init(void)
{
    if (g_state) return g_state > 0;
    g_state = -1;
#define R(n) do { W.n = U(n); if (!W.n) return 0; } while (0)
    R(WSAStartup); R(WSAGetLastError); R(WSASocketW); R(closesocket); R(bind); R(listen); R(connect);
    R(accept); R(getsockname); R(send); R(recv); R(setsockopt); R(getsockopt); R(ioctlsocket); R(WSAIoctl);
    R(shutdown); R(sendto);
#undef R
    W.ioctl = (aio_ioctl_fn)t_proc_in("ntdll.dll", "NtDeviceIoControlFile");
    W.cancel = (LONG (NTAPI *)(HANDLE, PIO_STATUS_BLOCK))t_proc_in("ntdll.dll", "NtCancelIoFile");
    p_create = (void *)t_proc_in("ntdll.dll", "NtCreateFile");
    p_close = (void *)t_proc_in("ntdll.dll", "NtClose");
    if (!W.ioctl || !W.cancel || !p_create || !p_close) return 0;
    WSADATA d;
    if (W.WSAStartup(MAKEWORD(2, 2), &d)) return 0;
    g_state = 1;
    return 1;
}

SOCKET aio_sock(int af, int type, int proto)
{
    SOCKET s = W.WSASocketW(af, type, proto, NULL, 0, WSA_FLAG_OVERLAPPED);
    CHECKF(s != INVALID_SOCKET, "socket creation failed, error %d", W.WSAGetLastError());
    return s;
}
void aio_close(SOCKET s) { if (s != INVALID_SOCKET && s != 0) W.closesocket(s); }

struct sockaddr_in aio_lo4(USHORT port_be)
{
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = BE32(LO4_HOST); a.sin_port = port_be;
    return a;
}
SOCKET aio_bound(int type)
{
    SOCKET s = aio_sock(AF_INET, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP);
    struct sockaddr_in a = aio_lo4(0);
    if (s == INVALID_SOCKET) return s;
    CHECK(W.bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    return s;
}
SOCKET aio_listener(struct sockaddr_in *addr)
{
    SOCKET s = aio_bound(SOCK_STREAM);
    int n = sizeof *addr;
    if (s == INVALID_SOCKET) return s;
    CHECK(W.listen(s, 4) == 0);
    if (addr) { memset(addr, 0, sizeof *addr); CHECK(W.getsockname(s, (struct sockaddr *)addr, &n) == 0); }
    return s;
}
const char *const aio_kind_name[AK_COUNT] = { "tcp", "udp", "raw", "tcp-bound", "tcp-listening", "udp-bound", "tcp-connected" };
SOCKET aio_kind(int kind)
{
    SOCKET s = INVALID_SOCKET, peer;
    switch (kind) {
    case AK_TCP: return aio_tcp();
    case AK_UDP: return aio_udp();
    case AK_RAW: return W.WSASocketW(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
    case AK_TCP_BOUND: return aio_bound(SOCK_STREAM);
    case AK_TCP_LISTEN: return aio_listener(NULL);
    case AK_UDP_BOUND: return aio_bound(SOCK_DGRAM);
    case AK_TCP_CONN: aio_pair(&s, &peer); aio_close(peer); return s;
    }
    return s;
}
void aio_nonblock(SOCKET s, int on) { u_long v = on; W.ioctlsocket(s, FIONBIO, &v); }
void aio_pair(SOCKET *client, SOCKET *server)
{
    struct sockaddr_in a;
    SOCKET l = aio_listener(&a), c = aio_tcp(), a2;
    *client = *server = INVALID_SOCKET;
    if (l == INVALID_SOCKET || c == INVALID_SOCKET) { aio_close(l); aio_close(c); return; }
    CHECK(W.connect(c, (struct sockaddr *)&a, sizeof a) == 0);
    a2 = W.accept(l, NULL, NULL);
    CHECK(a2 != INVALID_SOCKET);
    aio_close(l);
    *client = c; *server = a2;
}

LONG aio_ctl(SOCKET s, ULONG code, void *in, ULONG inl, void *out, ULONG outl, IO_STATUS_BLOCK *io, LONG *first)
{
    IO_STATUS_BLOCK local;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    LONG st;
    if (!io) io = &local;
    io->Status = (LONG)0xcccccccc; io->Information = (ULONG_PTR)0xcccccccccccccccc;
    st = W.ioctl((HANDLE)s, ev, NULL, NULL, io, code, in, inl, out, outl);
    if (first) *first = st;
    if (st == NTS_PENDING) {
        if (WaitForSingleObject(ev, aio_wait_ms) != WAIT_OBJECT_0) {
            IO_STATUS_BLOCK c;
            W.cancel((HANDLE)s, &c);
            WaitForSingleObject(ev, 1000);
            CloseHandle(ev);
            return NTS_TIMEOUT_LOCAL;
        }
        st = io->Status;
    }
    CloseHandle(ev);
    return st;
}

LONG aio_get_info(SOCKET s, ULONG cls, aio_info_t *v)
{
    aio_info_t in, out;
    memset(&in, 0, sizeof in); memset(&out, 0, sizeof out);
    in.Class = cls;
    LONG st = aio_ctl(s, IOC_GET_INFO, &in, sizeof in, &out, sizeof out, NULL, NULL);
    if (v) *v = out;
    return st;
}
LONG aio_set_info(SOCKET s, ULONG cls, ULONGLONG val)
{
    aio_info_t in;
    memset(&in, 0, sizeof in);
    in.Class = cls; in.V.Large = (LONGLONG)val;
    return aio_ctl(s, IOC_SET_INFO, &in, sizeof in, NULL, 0, NULL, NULL);
}

/* The open packet is the single extended attribute "AfdOpenPacketXX" whose value is
 * { Flags, GroupID, Family, Type, Protocol, TransportNameBytes, TransportName[] }. */
static HANDLE open_ep(int kind, int named, LONG *stp)
{
    static const struct { ULONG flags, fam, type, proto; const WCHAR *name; } k[] = {
        { 0, 2, 1, 6, L"\\Device\\Tcp" },
        { 0x11, 2, 2, 17, L"\\Device\\Udp" },
        { 0x111, 2, 3, 1, L"\\Device\\RawIp" },
        { 0, 23, 1, 6, L"\\Device\\Tcp6" },
        { 0x11, 23, 2, 17, L"\\Device\\Udp6" },
    };
    static const char ea_name[] = "AfdOpenPacketXX";
    if (t_is_wine()) { t_skip("endpoints opened directly on the device are not emulated here"); if (stp) *stp = (LONG)0xC0000001; return NULL; }
    unsigned char buf[8 + sizeof ea_name + 24 + 64];
    ULONG *v;
    size_t nlen = named ? lstrlenW(k[kind].name) * 2 : 0, vlen = nlen ? 24 + nlen + 2 : 28, total;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK io;
    HANDLE h = NULL;
    LONG st;
    static const WCHAR path[] = L"\\Device\\Afd\\Endpoint";
    memset(buf, 0, sizeof buf);
    buf[5] = (unsigned char)(sizeof ea_name - 1);
    *(USHORT *)(buf + 6) = (USHORT)vlen;
    memcpy(buf + 8, ea_name, sizeof ea_name);
    v = (ULONG *)(buf + 8 + sizeof ea_name);
    v[0] = k[kind].flags; v[1] = 0; v[2] = k[kind].fam; v[3] = k[kind].type; v[4] = k[kind].proto; v[5] = (ULONG)nlen;
    if (nlen) memcpy(v + 6, k[kind].name, nlen);
    total = 8 + (ULONG)sizeof ea_name + (ULONG)vlen;
    us.Buffer = (PWSTR)path; us.Length = sizeof path - 2; us.MaximumLength = sizeof path;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_INHERIT, NULL, NULL);
    st = p_create(&h, 0xC0140000u, &oa, &io, NULL, 0, 3, 3, 0, buf, total);
    if (stp) *stp = st;
    return st >= 0 ? h : NULL;
}
HANDLE aio_open_raw(int kind, LONG *stp) { return open_ep(kind, 0, stp); }
HANDLE aio_open_tdi(int kind, LONG *stp) { return open_ep(kind, 1, stp); }
void aio_close_raw(HANDLE h) { if (h) p_close(h); }
