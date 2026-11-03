/* Helpers for the AFD bind / listen / accept tests: function table, loopback sockets, raw requests. */
#include "abl.h"

ABLF W;
static LONG (NTAPI *p_cancel)(HANDLE, PIO_STATUS_BLOCK);
static int g_state;   /* 0 untried, 1 ready, -1 failed */

/* The driver's control-code table, in slot order (slot = bits 2..11 of the code). */
const unsigned abl_code_table[ABL_SLOTS] = {
    0x12003, 0x12007, 0x1200b, 0x1200c, 0x12010, 0x12017, 0x1201b, 0x1201f, 0x12023, 0x12024,
    0x1202b, 0x1202f, 0x12033, 0x12037, 0x1203b, 0x1203f, 0x12043, 0x12047, 0x1204b, 0x1204f,
    0x12053, 0x12057, 0x1205b, 0x1205f, 0x12063, 0x12067, 0x1206b, 0x1206f, 0x12073, 0x12077,
    0x1207b, 0x1207f, 0x12083, 0x12087, 0x1208b, 0x1208c, 0x12090, 0x12094, 0x12098, 0x1209f,
    0x120a0, 0x120a7, 0x120ab, 0x120ac, 0x120b3, 0x120b4, 0x120bb, 0x120bf, 0x120c3, 0x120c7,
    0x120cb, 0x120cf, 0x120d3, 0x120d7, 0x120db, 0x120df, 0x120e2, 0x120e7, 0x120eb, 0x120ef,
    0x120f3, 0x120f7, 0x120fb, 0x120ff, 0x12103, 0x12107, 0x1210b, 0x1210c, 0x12113, 0x12117,
    0x1211b, 0x1211f, 0x12123
};

int abl_init(void) {
    if (g_state) return g_state > 0;
    g_state = -1;
#define R(n) do { W.n = U(n); if (!W.n) return 0; } while (0)
    R(WSAStartup); R(WSAGetLastError); R(WSASocketW); R(socket); R(closesocket); R(bind); R(listen);
    R(connect); R(accept); R(getsockname); R(getpeername); R(setsockopt); R(getsockopt); R(ioctlsocket);
    R(send); R(recv); R(shutdown); R(select);
#undef R
    W.ioctl = (abl_ioctl_fn)t_proc_in("ntdll.dll", "NtDeviceIoControlFile");
    p_cancel = (LONG (NTAPI *)(HANDLE, PIO_STATUS_BLOCK))t_proc_in("ntdll.dll", "NtCancelIoFile");
    if (!W.ioctl || !p_cancel) return 0;
    WSADATA d;
    if (W.WSAStartup(MAKEWORD(2, 2), &d)) return 0;
    g_state = 1;
    return 1;
}

/* bound every blocking receive/send so a misbehaving stack cannot hang a test */
void abl_timeouts(SOCKET s) {
    DWORD ms = WAIT_MS;
    if (s == INVALID_SOCKET) return;
    W.setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms);
    W.setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof ms);
}
SOCKET abl_sock(int af, int type) {
    SOCKET s = W.WSASocketW(af, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
    CHECKF(s != INVALID_SOCKET, "socket creation failed, error %d", W.WSAGetLastError());
    abl_timeouts(s);
    return s;
}
void abl_close(SOCKET s) { if (s != INVALID_SOCKET && s != 0) W.closesocket(s); }

struct sockaddr_in abl_lo4(USHORT port_be) {
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = BE32(LO4); a.sin_port = port_be;
    return a;
}
struct sockaddr_in6 abl_lo6(USHORT port_be) {
    struct sockaddr_in6 a; memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1; a.sin6_port = port_be;
    return a;
}
int abl_have_v6(void) {
    static int have = -1;
    if (have < 0) {
        SOCKET s = W.WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        have = s != INVALID_SOCKET;
        if (have) {
            struct sockaddr_in6 a = abl_lo6(0);       /* the stack may exist without the loopback address */
            have = W.bind(s, (struct sockaddr *)&a, sizeof a) == 0;
            W.closesocket(s);
        }
    }
    return have;
}

SOCKET abl_bound(int type, struct sockaddr_in *addr) {
    struct sockaddr_in a = abl_lo4(0); int len = sizeof a;
    SOCKET s = abl_sock(AF_INET, type);
    CHECK(W.bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(W.getsockname(s, (struct sockaddr *)&a, &len) == 0);
    if (addr) *addr = a;
    return s;
}
SOCKET abl_listener(struct sockaddr_in *addr) {
    SOCKET s = abl_bound(SOCK_STREAM, addr);
    CHECK(W.listen(s, 4) == 0);
    return s;
}
void abl_nonblock(SOCKET s, int on) { ULONG v = on; CHECK(W.ioctlsocket(s, FIONBIO, &v) == 0); }
int abl_connect(SOCKET c, const struct sockaddr_in *to) { return W.connect(c, (const struct sockaddr *)to, sizeof *to); }
void abl_pair(SOCKET *client, SOCKET *server) {
    struct sockaddr_in a; SOCKET l = abl_listener(&a);
    *client = abl_tcp();
    CHECK(abl_connect(*client, &a) == 0);
    CHECK(abl_wait_readable(l, WAIT_MS));
    *server = W.accept(l, NULL, NULL);
    CHECK(*server != INVALID_SOCKET);
    abl_timeouts(*server);
    abl_close(l);
}
SOCKET abl_client_to(const struct sockaddr_in *to) {
    SOCKET c = abl_tcp();
    abl_nonblock(c, 1);
    W.connect(c, (const struct sockaddr *)to, sizeof *to);    /* completes with would-block */
    return c;
}
static int wait_sel(SOCKET s, DWORD ms, int write) {
    fd_set f; struct timeval tv;
    f.fd_count = 1; f.fd_array[0] = s;
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return W.select(0, write ? NULL : &f, write ? &f : NULL, NULL, &tv) > 0;
}
int abl_wait_readable(SOCKET s, DWORD ms) { return wait_sel(s, ms, 0); }
int abl_wait_writable(SOCKET s, DWORD ms) { return wait_sel(s, ms, 1); }

/* ---- raw requests ------------------------------------------------------------------------------------- */
LONG abl_submit(SOCKET s, HANDLE ev, ULONG code, void *in, ULONG inl, void *out, ULONG outl, IO_STATUS_BLOCK *io) {
    return W.ioctl((HANDLE)s, ev, NULL, NULL, io, code, in, inl, out, outl);
}
DWORD abl_wait(SOCKET s, HANDLE ev, IO_STATUS_BLOCK *io, DWORD ms) {
    DWORD r = WaitForSingleObject(ev, ms);
    if (r != WAIT_OBJECT_0) {
        IO_STATUS_BLOCK c;
        p_cancel((HANDLE)s, &c);
        WaitForSingleObject(ev, 2000);
    }
    return r;
}
LONG abl_ctl(SOCKET s, ULONG code, void *in, ULONG inl, void *out, ULONG outl, IO_STATUS_BLOCK *io, LONG *first) {
    IO_STATUS_BLOCK local;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    LONG st;
    if (!io) io = &local;
    FILL_IO(*io, 0xcc);
    st = abl_submit(s, ev, code, in, inl, out, outl, io);
    if (first) *first = st;
    if ((ULONG)st == NS_PENDING) {
        if (abl_wait(s, ev, io, WAIT_MS) != WAIT_OBJECT_0) { CloseHandle(ev); return (LONG)NS_TIMEOUT; }
        st = io->Status;
    }
    CloseHandle(ev);
    return st;
}

LONG abl_raw_bind(SOCKET s, ULONG share, const void *sa, ULONG salen, void *out, ULONG outl, IO_STATUS_BLOCK *io) {
    BYTE buf[4 + sizeof(struct sockaddr_in6) + 8];
    memset(buf, 0, sizeof buf);
    memcpy(buf, &share, 4);
    if (salen > sizeof buf - 4) salen = sizeof buf - 4;
    memcpy(buf + 4, sa, salen);
    return abl_ctl(s, IO_BIND, buf, 4 + salen, out, outl, io, NULL);
}
LONG abl_raw_bind4(SOCKET s, ULONG share, ULONG host_addr, USHORT port_be, struct sockaddr_in *out) {
    struct sockaddr_in a = abl_lo4(port_be); IO_STATUS_BLOCK io;
    a.sin_addr.s_addr = BE32(host_addr);
    memset(out, 0, sizeof *out);
    return abl_raw_bind(s, share, &a, sizeof a, out, sizeof *out, &io);
}
LONG abl_raw_listen(SOCKET s, ULONG backlog, ULONG delayed) {
    ABL_LISTEN l; memset(&l, 0, sizeof l);
    l.backlog = backlog; l.delayed = delayed;
    return abl_ctl(s, IO_START_LISTEN, &l, sizeof l, NULL, 0, NULL, NULL);
}
LONG abl_raw_name(SOCKET s, void *out, ULONG outl, IO_STATUS_BLOCK *io) {
    return abl_ctl(s, IO_GET_ADDRESS, NULL, 0, out, outl, io, NULL);
}
