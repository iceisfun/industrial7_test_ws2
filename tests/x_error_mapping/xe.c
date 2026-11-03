/* x_error_mapping: shared helper implementations (see xe.h). */
#include "xe.h"

int xe_gle_seen, xe_wsa_seen;

static DWORD WINAPI watchdog(LPVOID p) {
    Sleep(170000);
    printf("  FAIL watchdog: a scenario blocked; terminating the run\n"); fflush(stdout);
    ExitProcess(3);
    return 0;
}
int xe_up(void) {
    static int state;
    if (state == 0) {
        WSADATA d;
        if (!t_proc_in("ws2_32.dll", "WSAStartup") || !t_proc_in("ws2_32.dll", "socket")) state = -1;
        else state = (WSAStartup(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
        if (state > 0) CreateThread(NULL, 0, watchdog, NULL, 0, NULL);
    }
    return state > 0;
}

/* Every socket gets a generous receive/send timeout so a scenario that unexpectedly blocks fails instead of hanging. */
static SOCKET guard(SOCKET s) {
    DWORD t = 4000;
    if (s != INVALID_SOCKET) { setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof t); setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&t, sizeof t); }
    return s;
}
SOCKET xe_sock(int type) { return guard(WSASocketW(AF_INET, type, 0, NULL, 0, WSA_FLAG_OVERLAPPED)); }
SOCKET xe_sock6(int type) { return guard(WSASocketW(AF_INET6, type, 0, NULL, 0, WSA_FLAG_OVERLAPPED)); }
void xe_close(SOCKET s) { if (s != INVALID_SOCKET) closesocket(s); }
struct sockaddr_in xe_lo(USHORT port_be) {
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = port_be; a.sin_addr.s_addr = 0x0100007f;
    return a;
}
void xe_bind_lo(SOCKET s, struct sockaddr_in *out) {
    struct sockaddr_in a = xe_lo(0); int n = sizeof a;
    bind(s, (struct sockaddr *)&a, sizeof a);
    getsockname(s, (struct sockaddr *)&a, &n);
    if (out) *out = a;
}
SOCKET xe_listener(struct sockaddr_in *a) {
    SOCKET s = xe_sock(SOCK_STREAM);
    xe_bind_lo(s, a);
    listen(s, 4);
    return s;
}
void xe_wait_readable(SOCKET s, DWORD ms) {
    fd_set f; struct timeval tv;
    FD_ZERO(&f); FD_SET(s, &f);
    tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    select(0, &f, NULL, NULL, &tv);
}
void xe_pair(SOCKET *c, SOCKET *s) {
    struct sockaddr_in la; SOCKET l = xe_listener(&la);
    *c = xe_sock(SOCK_STREAM);
    connect(*c, (struct sockaddr *)&la, sizeof la);
    xe_wait_readable(l, 2000);
    *s = guard(accept(l, NULL, NULL));
    xe_close(l);
}
SOCKET xe_dead_port(struct sockaddr_in *a) {
    /* bind, learn the port, close: nobody listens there afterwards */
    SOCKET s = xe_sock(SOCK_STREAM);
    xe_bind_lo(s, a);
    xe_close(s);
    return INVALID_SOCKET;
}

/* ---- raw AFD ---------------------------------------------------------------------------------------------- */
xe_r xe_afd(SOCKET s, ULONG code, void *in, ULONG inl, void *out, ULONG outl, DWORD ms) {
    xe_NtIoctl f = (xe_NtIoctl)t_proc_in("ntdll.dll", "NtDeviceIoControlFile");
    xe_NtIoctl cancel = NULL; xe_r r; IO_STATUS_BLOCK io; HANDLE ev;
    typedef LONG (NTAPI *cancel_t)(HANDLE, PIO_STATUS_BLOCK);
    cancel_t nc = (cancel_t)t_proc_in("ntdll.dll", "NtCancelIoFile");
    (void)cancel;
    r.status = (LONG)0xC0000002; r.info = 0;
    if (!f) return r;
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&io, 0xAB, sizeof io);
    r.status = f((HANDLE)s, ev, NULL, NULL, &io, code, in, inl, out, outl);
    if (r.status == 0x103) {
        if (WaitForSingleObject(ev, ms) == WAIT_OBJECT_0) { r.status = io.Status; r.info = io.Information; }
        else {
            IO_STATUS_BLOCK cio;
            if (nc) nc((HANDLE)s, &cio);
            WaitForSingleObject(ev, 2000);
            r.status = 0x102; r.info = 0;
        }
    } else if (r.status >= 0) r.info = io.Information;
    CloseHandle(ev);
    return r;
}
xe_r xe_afd_connect(SOCKET s, const struct sockaddr_in *a) {
    UCHAR req[0x18 + 32]; struct sockaddr_in any = xe_lo(0); memset(req, 0, sizeof req);
    xe_afd_bind(s, &any, sizeof any);   /* the driver needs a bound endpoint; a bound one just refuses this */
    memcpy(req + 0x18, a, sizeof *a);
    return xe_afd(s, XE_IOCTL_CONNECT, req, 0x18 + sizeof *a, NULL, 0, 3000);
}
xe_r xe_afd_bind(SOCKET s, const void *sa, ULONG salen) {
    UCHAR req[4 + 32]; UCHAR out[32]; memset(req, 0, sizeof req);
    memcpy(req + 4, sa, salen > 32 ? 32 : salen);
    return xe_afd(s, XE_IOCTL_BIND, req, 4 + salen, out, sizeof out, 3000);
}
typedef struct { WSABUF *buf; ULONG count; ULONG afd; ULONG tdi; ULONG pad; } xe_data;
xe_r xe_afd_recv(SOCKET s, void *b, ULONG n, ULONG tdi, DWORD ms) {
    WSABUF wb = { n, (CHAR *)b }; xe_data d; memset(&d, 0, sizeof d);
    d.buf = &wb; d.count = 1; d.tdi = tdi;
    return xe_afd(s, XE_IOCTL_RECV, &d, sizeof d, NULL, 0, ms);
}
xe_r xe_afd_send(SOCKET s, const void *b, ULONG n, DWORD ms) {
    WSABUF wb = { n, (CHAR *)b }; xe_data d; memset(&d, 0, sizeof d);
    d.buf = &wb; d.count = 1;
    return xe_afd(s, XE_IOCTL_SEND, &d, sizeof d, NULL, 0, ms);
}
xe_r xe_afd_disc(SOCKET s, ULONG flags) {
    struct { ULONG flags, pad; LARGE_INTEGER t; } d; memset(&d, 0, sizeof d);
    d.flags = flags; d.t.QuadPart = -1;
    return xe_afd(s, XE_IOCTL_DISC, &d, sizeof d, NULL, 0, 3000);
}
xe_r xe_afd_listen(SOCKET s) {
    struct { UCHAR use_san; UCHAR pad[3]; ULONG backlog; ULONG delayed; } d; memset(&d, 0, sizeof d);
    d.backlog = 4;
    return xe_afd(s, XE_IOCTL_LISTEN, &d, sizeof d, NULL, 0, 3000);
}
