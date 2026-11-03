/* Helper implementations for the x_tcp_info_fastopen area. */
#include "xt.h"

static int g_up;
int xt_up(void)
{
    WSADATA d;
    if (g_up) return 1;
    if (U(WSAStartup)(MAKEWORD(2, 2), &d) != 0) return 0;
    g_up = 1;
    return 1;
}
int xt_wsaerr(void) { return U(WSAGetLastError)(); }
SOCKET xt_tcp(void) { return U(socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP); }
SOCKET xt_udp(void) { return U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP); }
void xt_close(SOCKET s) { if (s != INVALID_SOCKET) U(closesocket)(s); }
static void lo(struct sockaddr_in *a, u_short port)
{
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET; a->sin_addr.s_addr = U(htonl)(INADDR_LOOPBACK); a->sin_port = port;
}
int xt_bind_lo(SOCKET s, u_short *port)
{
    struct sockaddr_in a; int l = sizeof a;
    lo(&a, port ? *port : 0);
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a)) return SOCKET_ERROR;
    if (port) {
        if (U(getsockname)(s, (struct sockaddr *)&a, &l)) return SOCKET_ERROR;
        *port = a.sin_port;
    }
    return 0;
}
int xt_listen_lo(SOCKET *l, u_short *port, int backlog)
{
    *port = 0; *l = xt_tcp();
    if (*l == INVALID_SOCKET) return 0;
    if (xt_bind_lo(*l, port) || U(listen)(*l, backlog)) { xt_close(*l); *l = INVALID_SOCKET; return 0; }
    return 1;
}
int xt_connect_lo(SOCKET c, u_short port)
{
    struct sockaddr_in a; lo(&a, port);
    return U(connect)(c, (struct sockaddr *)&a, sizeof a);
}
int xt_readable(SOCKET s, int timeout_ms)
{
    fd_set f; struct timeval tv;
    f.fd_count = 1; f.fd_array[0] = s;
    tv.tv_sec = timeout_ms / 1000; tv.tv_usec = (timeout_ms % 1000) * 1000;
    return U(select)(0, &f, NULL, NULL, &tv) == 1;
}
SOCKET xt_accept(SOCKET l) { return xt_readable(l, 5000) ? U(accept)(l, NULL, NULL) : INVALID_SOCKET; }
int xt_pair(SOCKET *c, SOCKET *a, SOCKET *l)
{
    u_short p;
    *c = *a = INVALID_SOCKET;
    if (!xt_listen_lo(l, &p, 4)) return 0;
    *c = xt_tcp();
    if (*c == INVALID_SOCKET || xt_connect_lo(*c, p)) goto bad;
    if (!xt_readable(*l, 5000)) goto bad;
    *a = xt_accept(*l);
    if (*a == INVALID_SOCKET) goto bad;
    return 1;
bad:
    xt_close(*c); xt_close(*a); xt_close(*l);
    *c = *a = *l = INVALID_SOCKET;
    return 0;
}
int xt_send(SOCKET s, const void *p, int n) { return U(send)(s, (const char *)p, n, 0); }
int xt_recv_all(SOCKET s, void *p, int n, int timeout_ms)
{
    int got = 0;
    while (got < n) {
        int r;
        if (!xt_readable(s, timeout_ms)) break;
        r = U(recv)(s, (char *)p + got, n - got, 0);
        if (r <= 0) break;
        got += r;
    }
    return got;
}
xt_res xt_io(SOCKET s, DWORD code, const void *in, DWORD inlen, void *out, DWORD outlen)
{
    xt_res r; DWORD ret = 0xCCCCCCCC;
    r.rc = U(WSAIoctl)(s, code, (void *)in, inlen, out, outlen, &ret, NULL, NULL);
    r.err = r.rc ? U(WSAGetLastError)() : 0;
    r.ret = ret;
    return r;
}
xt_res xt_so(SOCKET s, int level, int opt, const void *v, int len)
{
    xt_res r;
    r.rc = U(setsockopt)(s, level, opt, (const char *)v, len);
    r.err = r.rc ? U(WSAGetLastError)() : 0; r.ret = 0;
    return r;
}
xt_res xt_go(SOCKET s, int level, int opt, void *v, int *len)
{
    xt_res r;
    r.rc = U(getsockopt)(s, level, opt, (char *)v, len);
    r.err = r.rc ? U(WSAGetLastError)() : 0; r.ret = len ? (DWORD)*len : 0;
    return r;
}
int xt_geti(SOCKET s, int level, int opt, long long *v)
{
    DWORD d = 0; int n = 4; xt_res r = xt_go(s, level, opt, &d, &n);
    *v = r.rc ? -1 : (long long)d;
    return r.err;
}
int xt_seti(SOCKET s, int level, int opt, int v) { return xt_so(s, level, opt, &v, 4).err; }
int xt_wait_state(SOCKET s, DWORD want, int timeout_ms)
{
    int i;
    for (i = 0; i <= timeout_ms / 20; i++) {
        xt_info0 in; DWORD ver = 0; xt_res r = xt_io(s, XT_SIO_TCP_INFO, &ver, 4, &in, sizeof in);
        if (r.rc == 0 && in.State == want) return 1;
        Sleep(20);
    }
    return 0;
}
int xt_elevated(void)
{
    HANDLE t; TOKEN_ELEVATION e; DWORD n = 0; int r = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
        if (GetTokenInformation(t, TokenElevation, &e, sizeof e, &n)) r = e.TokenIsElevated != 0;
        CloseHandle(t);
    }
    return r;
}

const char *const xt_state_name[XS_COUNT] = {"fresh", "bound", "listening", "client", "accepted", "client_shut_send",
    "client_peer_closed", "udp", "accepted_peer_closed"};
int xt_is_connected_kind(int k) { return k == XS_CLIENT || k == XS_ACCEPTED || k == XS_SHUT_SEND || k == XS_PEER_CLOSED || k == XS_ACC_PEER_CLOSED; }
int xt_mkstate(int k, xt_st *st)
{
    SOCKET c, a, l; u_short p = 0;
    st->s = st->keep[0] = st->keep[1] = INVALID_SOCKET;
    switch (k) {
    case XS_FRESH: st->s = xt_tcp(); return st->s != INVALID_SOCKET;
    case XS_BOUND: st->s = xt_tcp(); return st->s != INVALID_SOCKET && xt_bind_lo(st->s, &p) == 0;
    case XS_LISTEN: return xt_listen_lo(&st->s, &p, 2);
    case XS_UDP: st->s = xt_udp(); return st->s != INVALID_SOCKET;
    default: break;
    }
    if (!xt_pair(&c, &a, &l)) return 0;
    st->keep[1] = l;
    switch (k) {
    case XS_CLIENT: st->s = c; st->keep[0] = a; return 1;
    case XS_ACCEPTED: st->s = a; st->keep[0] = c; return 1;
    case XS_SHUT_SEND: U(shutdown)(c, SD_SEND); st->s = c; st->keep[0] = a; return xt_wait_state(c, 6, 3000);
    case XS_PEER_CLOSED: xt_close(a); st->s = c; return xt_wait_state(c, 7, 3000);
    case XS_ACC_PEER_CLOSED: xt_close(c); st->s = a; return xt_wait_state(a, 7, 3000);
    }
    xt_close(c); xt_close(a); xt_close(l);
    return 0;
}
void xt_rmstate(xt_st *st) { xt_close(st->s); xt_close(st->keep[0]); xt_close(st->keep[1]); st->s = st->keep[0] = st->keep[1] = INVALID_SOCKET; }
