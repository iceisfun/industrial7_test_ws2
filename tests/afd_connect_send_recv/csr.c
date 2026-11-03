/* Helpers for the AFD data-path tests: function table, loopback sockets and raw request submission. */
#include "csr.h"

CSF X;
static int g_state;   /* 0 untried, 1 ready, -1 failed */

int csr_init(void) {
    if (g_state) return g_state > 0;
    g_state = -1;
#define R(n) do { X.n = U(n); if (!X.n) return 0; } while (0)
    R(WSAStartup); R(WSAGetLastError); R(WSASocketW); R(closesocket); R(bind); R(listen); R(connect); R(accept);
    R(getsockname); R(getpeername); R(send); R(recv); R(sendto); R(recvfrom); R(shutdown); R(setsockopt);
    R(getsockopt); R(ioctlsocket); R(select);
#undef R
    X.ioctl  = (NtDeviceIoControlFile_pfn)t_proc_in("ntdll.dll", "NtDeviceIoControlFile");
    X.read   = (NtReadFile_pfn)t_proc_in("ntdll.dll", "NtReadFile");
    X.write  = (NtWriteFile_pfn)t_proc_in("ntdll.dll", "NtWriteFile");
    X.cancel = (NtCancelIoFile_pfn)t_proc_in("ntdll.dll", "NtCancelIoFile");
    if (!X.ioctl || !X.read || !X.write || !X.cancel) return 0;
    WSADATA d;
    if (X.WSAStartup(MAKEWORD(2, 2), &d)) return 0;
    g_state = 1;
    return 1;
}

/* a blocking winsock call on one of our sockets gives up after a few seconds instead of hanging the run */
void cs_bound_blocking(SOCKET s) {
    DWORD ms = 4000;
    X.setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms);
    X.setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof ms);
}
SOCKET cs_sock(int af, int type) {
    SOCKET s = X.WSASocketW(af, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
    CHECKF(s != INVALID_SOCKET, "socket creation failed, error %d", X.WSAGetLastError());
    if (s != INVALID_SOCKET) cs_bound_blocking(s);
    return s;
}
void cs_close(SOCKET s) { if (s != INVALID_SOCKET && s != 0) X.closesocket(s); }

struct sockaddr_in cs_lo4(USHORT port_be) {
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = BE32(LO4); a.sin_port = port_be;
    return a;
}
void cs_bind_lo(SOCKET s, struct sockaddr_in *out) {
    struct sockaddr_in a = cs_lo4(0); int len = sizeof a;
    CHECK(X.bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(X.getsockname(s, (struct sockaddr *)&a, &len) == 0);
    if (out) *out = a;
}
SOCKET cs_listener(struct sockaddr_in *addr) {
    SOCKET s = cs_sock(AF_INET, SOCK_STREAM);
    cs_bind_lo(s, addr);
    CHECK(X.listen(s, 4) == 0);
    return s;
}
int cs_readable(SOCKET s, DWORD ms) {
    fd_set fds; FD_ZERO(&fds); FD_SET(s, &fds);
    struct timeval tv; tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return X.select(0, &fds, NULL, NULL, &tv) == 1;
}
void cs_pair(SOCKET *client, SOCKET *server) {
    struct sockaddr_in a;
    SOCKET l = cs_listener(&a);
    SOCKET c = cs_sock(AF_INET, SOCK_STREAM);
    CHECK(X.connect(c, (struct sockaddr *)&a, sizeof a) == 0);
    SOCKET s = INVALID_SOCKET;
    if (cs_readable(l, CS_WAIT)) s = X.accept(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    cs_close(l);
    if (s != INVALID_SOCKET) cs_bound_blocking(s);
    *client = c; *server = s;
}
void cs_udp_pair(SOCKET *a, SOCKET *b, struct sockaddr_in *aa, struct sockaddr_in *ba) {
    *a = cs_sock(AF_INET, SOCK_DGRAM); *b = cs_sock(AF_INET, SOCK_DGRAM);
    cs_bind_lo(*a, aa); cs_bind_lo(*b, ba);
}
void cs_rst_close(SOCKET s) {
    struct linger l = {1, 0};
    X.setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof l);
    X.closesocket(s);
}
int cs_have_v6(void) {
    static int have = -1;
    if (have < 0) {
        SOCKET s = X.WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        have = s != INVALID_SOCKET;
        if (have) {
            struct sockaddr_in6 a; memset(&a, 0, sizeof a);
            a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1;
            have = X.bind(s, (struct sockaddr *)&a, sizeof a) == 0;
            X.closesocket(s);
        }
    }
    return have;
}

/* ---- raw requests ---------------------------------------------------------------------------------------- */
LONG cs_submit(SOCKET s, HANDLE ev, CS_APC apc, void *apc_ctx, IO_STATUS_BLOCK *io, ULONG code, void *in, ULONG inl, void *out, ULONG outl) {
    return X.ioctl((HANDLE)s, ev, apc, apc_ctx, io, code, in, inl, out, outl);
}
DWORD cs_await(SOCKET s, HANDLE ev, IO_STATUS_BLOCK *io, DWORD ms) {
    DWORD w = WaitForSingleObject(ev, ms);
    if (w != WAIT_OBJECT_0) {
        IO_STATUS_BLOCK c;
        X.cancel((HANDLE)s, &c);
        WaitForSingleObject(ev, 300);
    }
    return w;
}
CS_R cs_ioctl(SOCKET s, ULONG code, void *in, ULONG inl, void *out, ULONG outl) {
    return cs_ioctl_ms(s, code, in, inl, out, outl, CS_WAIT);
}
CS_R cs_ioctl_ms(SOCKET s, ULONG code, void *in, ULONG inl, void *out, ULONG outl, DWORD ms) {
    CS_R r; memset(&r, 0, sizeof r);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&r.io, 0xAB, sizeof r.io);
    r.first = cs_submit(s, ev, NULL, NULL, &r.io, code, in, inl, out, outl);
    if ((ULONG)r.first == CS_PENDING) {
        DWORD w = cs_await(s, ev, &r.io, ms);
        r.final = (w == WAIT_OBJECT_0) ? r.io.Status : (LONG)CS_TIMEOUT;
        r.signalled = (w == WAIT_OBJECT_0);
    } else {
        r.final = r.first;
        /* an error returned by the submit call itself leaves the status block alone: present it as zero bytes */
        if (((ULONG)r.first >> 30) == 3) { r.io.Status = r.first; r.io.Information = 0; }
        r.signalled = WaitForSingleObject(ev, 0) == WAIT_OBJECT_0;
    }
    CloseHandle(ev);
    return r;
}

CS_R cs_recv(SOCKET s, void *buf, ULONG len, ULONG tdi, ULONG afd) {
    WSABUF wb = { len, (CHAR *)buf };
    CS_DATA d; memset(&d, 0, sizeof d);
    d.buf = &wb; d.count = 1; d.afd = afd; d.tdi = tdi;
    return cs_ioctl(s, CS_IOCTL_RECV, &d, sizeof d, NULL, 0);
}
CS_R cs_send(SOCKET s, const void *buf, ULONG len, ULONG tdi, ULONG afd) {
    WSABUF wb = { len, (CHAR *)buf };
    CS_DATA d; memset(&d, 0, sizeof d);
    d.buf = &wb; d.count = 1; d.afd = afd; d.tdi = tdi;
    return cs_ioctl(s, CS_IOCTL_SEND, &d, sizeof d, NULL, 0);
}
CS_R cs_connect_ms(SOCKET s, const void *sa, ULONG salen, DWORD ms) {
    UCHAR req[0x18 + 64]; memset(req, 0, sizeof req);
    if (salen > 64) salen = 64;
    memcpy(req + 0x18, sa, salen);
    return cs_ioctl_ms(s, CS_IOCTL_CONNECT, req, 0x18 + salen, NULL, 0, ms);
}
CS_R cs_connect(SOCKET s, const void *sa, ULONG salen) { return cs_connect_ms(s, sa, salen, CS_WAIT); }
CS_R cs_disc(SOCKET s, ULONG flags) {
    CS_DISC d; memset(&d, 0, sizeof d);
    d.flags = flags; d.timeout.QuadPart = -1;
    return cs_ioctl(s, CS_IOCTL_PARTIAL_DISC, &d, sizeof d, NULL, 0);
}
CS_R cs_recvfrom(SOCKET s, void *buf, ULONG len, struct sockaddr_in *from, ULONG *fromlen, ULONG tdi) {
    WSABUF wb = { len, (CHAR *)buf };
    CS_RDG d; memset(&d, 0, sizeof d);
    d.buf = &wb; d.count = 1; d.tdi = tdi; d.addr = from; d.addrlen = fromlen;
    return cs_ioctl(s, CS_IOCTL_RECV_DGRAM, &d, sizeof d, NULL, 0);
}
CS_R cs_sendto(SOCKET s, const void *buf, ULONG len, const void *to, ULONG tolen, ULONG afd) {
    WSABUF wb = { len, (CHAR *)buf };
    CS_SDG d; memset(&d, 0, sizeof d);
    d.buf = &wb; d.count = 1; d.afd = afd; d.addr = to; d.addrlen = tolen;
    return cs_ioctl(s, CS_IOCTL_SEND_DGRAM, &d, sizeof d, NULL, 0);
}
