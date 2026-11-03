/* Helpers shared by the gap_02 tests. */
#include "g2.h"

const GUID g2_guid_throwaway = { 0x5d2c9a71, 0x0b3e, 0x4c58, { 0x8f, 0x14, 0xa6, 0x3d, 0x70, 0xe2, 0x19, 0x4b } };
const GUID g2_svc_hostname    = { 0x0002a800, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
const GUID g2_svc_addr_by_name = { 0x0002a803, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };

int g2_up(void) {
    static int state;   /* 0 unknown, 1 up, -1 failed */
    if (!state) {
        WSADATA d;
        if (!WS(WSAStartup)) state = -1;
        else state = WS(WSAStartup)(MAKEWORD(2, 2), &d) == 0 ? 1 : -1;
    }
    return state == 1;
}

static SOCKET mk(int af, int type, int proto) {
    if (!g2_up() || !WS(socket)) return INVALID_SOCKET;
    return WS(socket)(af, type, proto);
}
SOCKET g2_tcp4(void) { return mk(AF_INET, SOCK_STREAM, IPPROTO_TCP); }
SOCKET g2_udp4(void) { return mk(AF_INET, SOCK_DGRAM, IPPROTO_UDP); }
SOCKET g2_tcp6(void) { return mk(AF_INET6, SOCK_STREAM, IPPROTO_TCP); }
void g2_close(SOCKET s) { if (s != INVALID_SOCKET && WS(closesocket)) WS(closesocket)(s); }

void g2_loop4(struct sockaddr_in *sa, unsigned short port_be) {
    memset(sa, 0, sizeof *sa);
    sa->sin_family = AF_INET;
    sa->sin_port = port_be;
    sa->sin_addr.s_addr = 0x0100007f;   /* 127.0.0.1 in network order on a little-endian host */
}

int g2_bind_any4(SOCKET s) {
    struct sockaddr_in a;
    g2_loop4(&a, 0);
    return WS(bind)(s, (struct sockaddr *)&a, sizeof a);
}

SOCKET g2_listen4(unsigned short *port_be) {
    struct sockaddr_in a; int len = sizeof a;
    SOCKET s = g2_tcp4();
    if (s == INVALID_SOCKET) return s;
    if (g2_bind_any4(s) != 0 || WS(listen)(s, 8) != 0 || WS(getsockname)(s, (struct sockaddr *)&a, &len) != 0) {
        g2_close(s);
        return INVALID_SOCKET;
    }
    if (port_be) *port_be = a.sin_port;
    return s;
}

SOCKET g2_connect_accept(SOCKET lst, SOCKET cli) {
    struct sockaddr_in a; int len = sizeof a;
    fd_set rd; struct timeval tv = { 3, 0 };
    SOCKET acc;
    if (WS(getsockname)(lst, (struct sockaddr *)&a, &len) != 0) return INVALID_SOCKET;
    if (WS(connect)(cli, (struct sockaddr *)&a, sizeof a) != 0) return INVALID_SOCKET;
    FD_ZERO(&rd); FD_SET(lst, &rd);
    if (WS(select)(0, &rd, NULL, NULL, &tv) != 1) return INVALID_SOCKET;
    acc = WS(accept)(lst, NULL, NULL);
    return acc;
}

WSANAMESPACE_INFOW *g2_catalog(int *n) {
    DWORD len = 0; WSANAMESPACE_INFOW *info; int r;
    if (!g2_up() || !WS(WSAEnumNameSpaceProvidersW)) return NULL;
    WS(WSAEnumNameSpaceProvidersW)(&len, NULL);
    if (!len) return NULL;
    info = (WSANAMESPACE_INFOW *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
    if (!info) return NULL;
    r = WS(WSAEnumNameSpaceProvidersW)(&len, info);
    if (r <= 0) { HeapFree(GetProcessHeap(), 0, info); return NULL; }
    *n = r;
    return info;
}
void g2_free(void *p) { if (p) HeapFree(GetProcessHeap(), 0, p); }

int g2_provider_for(DWORD ns, GUID *id) {
    int n = 0, i, found = 0;
    WSANAMESPACE_INFOW *c = g2_catalog(&n);
    for (i = 0; c && i < n; i++)
        if (c[i].dwNameSpace == ns && c[i].fActive) { *id = c[i].NSProviderId; found = 1; break; }
    g2_free(c);
    return found;
}

int g2_is_elevated(void) {
    HANDLE tok = NULL; TOKEN_ELEVATION el; DWORD got = 0; int r = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &got)) r = el.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}

void g2_qs_w(WSAQUERYSETW *qs, LPWSTR name, const GUID *cls, DWORD ns) {
    memset(qs, 0, sizeof *qs);
    qs->dwSize = sizeof *qs;
    qs->lpszServiceInstanceName = name;
    qs->lpServiceClassId = (GUID *)cls;
    qs->dwNameSpace = ns;
}
void g2_qs_a(WSAQUERYSETA *qs, LPSTR name, const GUID *cls, DWORD ns) {
    memset(qs, 0, sizeof *qs);
    qs->dwSize = sizeof *qs;
    qs->lpszServiceInstanceName = name;
    qs->lpServiceClassId = (GUID *)cls;
    qs->dwNameSpace = ns;
}

int g2_wide_to_ansi_equal(const WCHAR *w, const char *a) {
    char buf[512];
    int n = WideCharToMultiByte(CP_ACP, 0, w, -1, buf, sizeof buf, NULL, NULL);
    return n > 0 && strcmp(buf, a) == 0;
}
