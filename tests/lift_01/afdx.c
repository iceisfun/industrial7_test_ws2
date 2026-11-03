/* Helpers shared by the AFD contract tests: function table, loopback sockets, poll wait. */
#include "afdx.h"

AFDX X;
static int g_state;   /* 0 untried, 1 ready, -1 failed */

int afdx_init(void) {
    if (g_state) return g_state > 0;
    g_state = -1;
#define R(n) do { X.n = U(n); if (!X.n) return 0; } while (0)
    R(WSAStartup); R(WSAGetLastError); R(WSASocketW); R(closesocket); R(bind); R(listen); R(connect); R(accept);
    R(getsockname); R(send); R(sendto); R(shutdown); R(ioctlsocket); R(setsockopt); R(WSAEventSelect);
    R(WSAEnumNetworkEvents);
#undef R
    X.ioctl = (NtDeviceIoControlFile_pfn)t_proc_in("ntdll.dll", "NtDeviceIoControlFile");
    X.read = (NtReadFile_pfn)t_proc_in("ntdll.dll", "NtReadFile");
    X.write = (NtWriteFile_pfn)t_proc_in("ntdll.dll", "NtWriteFile");
    X.remove_completion = (NtRemoveIoCompletion_pfn)t_proc_in("ntdll.dll", "NtRemoveIoCompletion");
    if (!X.ioctl || !X.read || !X.write || !X.remove_completion) return 0;
    WSADATA d;
    if (X.WSAStartup(MAKEWORD(2, 2), &d)) return 0;
    g_state = 1;
    return 1;
}

SOCKET afdx_socket(int af, int type, int proto, DWORD flags) {
    SOCKET s = X.WSASocketW(af, type, proto, NULL, 0, flags);
    CHECKF(s != INVALID_SOCKET, "socket creation failed, error %d", X.WSAGetLastError());
    return s;
}
void afdx_close(SOCKET s) { if (s != INVALID_SOCKET && s != 0) X.closesocket(s); }

void afdx_fill_sin(struct sockaddr_in *a, ULONG host_addr, USHORT port_be) {
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = AX_HTONL(host_addr);
    a->sin_port = port_be;
}

void afdx_listener(SOCKET *l, struct sockaddr_in *addr) {
    struct sockaddr_in a; int len = sizeof a;
    afdx_fill_sin(&a, LO4, 0);
    *l = afdx_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSA_FLAG_OVERLAPPED);
    CHECK(X.bind(*l, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(X.listen(*l, 1) == 0);
    CHECK(X.getsockname(*l, (struct sockaddr *)&a, &len) == 0);
    if (addr) *addr = a;
}

void afdx_pair(SOCKET *client, SOCKET *server, DWORD flags) {
    SOCKET l; struct sockaddr_in a;
    *client = *server = INVALID_SOCKET;
    afdx_listener(&l, &a);
    *client = afdx_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, flags);
    CHECK(X.connect(*client, (struct sockaddr *)&a, sizeof a) == 0);
    *server = X.accept(l, NULL, NULL);
    CHECK(*server != INVALID_SOCKET);
    X.closesocket(l);
}

/* Both ends non-overlapped: the accepted socket takes the open mode of the listener, so the listener is
 * created without WSA_FLAG_OVERLAPPED here. */
void afdx_pair_sync(SOCKET *client, SOCKET *server) {
    SOCKET l; struct sockaddr_in a; int len = sizeof a;
    afdx_fill_sin(&a, LO4, 0);
    l = afdx_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0);
    CHECK(X.bind(l, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(X.listen(l, 1) == 0);
    CHECK(X.getsockname(l, (struct sockaddr *)&a, &len) == 0);
    *client = afdx_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0);
    CHECK(X.connect(*client, (struct sockaddr *)&a, sizeof a) == 0);
    *server = X.accept(l, NULL, NULL);
    CHECK(*server != INVALID_SOCKET);
    X.closesocket(l);
}

void afdx_set_blocking(SOCKET s, int blocking) {
    ULONG nb = !blocking;
    CHECK(X.ioctlsocket(s, FIONBIO, &nb) == 0);
}

void afdx_close_rst(SOCKET s) {
    struct linger lg = {1, 0};
    CHECK(X.setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg) == 0);
    X.closesocket(s);
}

void afdx_wait_poll(SOCKET s, HANDLE event, ULONG mask, ULONG expect, const char *file, int line) {
    AX_POLL in, out; IO_STATUS_BLOCK io; LONG st;
    memset(&in, 0, sizeof in); memset(&out, 0, sizeof out);
    in.timeout = -(LONGLONG)AX_WAIT * 10000;
    in.count = 1;
    in.sockets[0].socket = s; in.sockets[0].flags = mask; in.sockets[0].status = 0xdeadbeef;
    st = X.ioctl((HANDLE)s, event, NULL, NULL, &io, AX_IOCTL_POLL, &in, sizeof in, &out, sizeof out);
    t_check(st == 0 || (ULONG)st == AX_STATUS_PENDING, file, line, "poll submit", "status 0x%08lx", (unsigned long)st);
    if ((ULONG)st == AX_STATUS_PENDING)
        t_check(WaitForSingleObject(event, AX_WAIT) == WAIT_OBJECT_0, file, line, "poll completes", NULL);
    t_check(io.Status == 0, file, line, "poll iosb status", "0x%08lx", (unsigned long)io.Status);
    t_check(io.Information == sizeof out, file, line, "poll iosb information", "0x%llx", (unsigned long long)io.Information);
    t_check(out.count == 1 && out.sockets[0].socket == s, file, line, "poll echoes the socket", NULL);
    t_check(out.timeout == in.timeout, file, line, "poll echoes the timeout", NULL);
    t_check(out.sockets[0].flags == expect, file, line, "poll reported mask", "got 0x%lx want 0x%lx", (unsigned long)out.sockets[0].flags, (unsigned long)expect);
    t_check(out.sockets[0].status == 0, file, line, "poll entry status", "0x%08lx", (unsigned long)out.sockets[0].status);
}
