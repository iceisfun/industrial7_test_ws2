/* Helpers shared by the name-space lookup tests. */
#include "nsp.h"

const GUID nsp_svcid_hostname        = { 0x0002a800, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
const GUID nsp_svcid_addr_by_string  = { 0x0002a801, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
const GUID nsp_svcid_service_by_name = { 0x0002a802, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
const GUID nsp_svcid_addr_by_name    = { 0x0002a803, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
/* NS_NLA provider id (documented constant of the SPI). */
const GUID nsp_guid_nla = { 0x6642243a, 0x3ba8, 0x4aa6, { 0xba, 0xa5, 0x2e, 0x0b, 0xd7, 0x1f, 0xdd, 0x83 } };
/* Random id owned by this corpus; no real provider or class uses it. */
const GUID nsp_guid_throwaway = { 0x7c1e5a90, 0x3b64, 0x4f0d, { 0x9a, 0x21, 0x5e, 0x88, 0x0c, 0x6d, 0x41, 0xb7 } };

int nsp_up(void) {
    static int state; /* 0 unknown, 1 up, -1 failed */
    if (!state) {
        WSADATA d;
        if (!UIN("ws2_32.dll", WSAStartup)) { state = -1; }
        else state = UIN("ws2_32.dll", WSAStartup)(MAKEWORD(2, 2), &d) == 0 ? 1 : -1;
    }
    return state == 1;
}

void nsp_query_w(WSAQUERYSETW *qs, LPWSTR name, const GUID *cls, DWORD ns) {
    memset(qs, 0, sizeof *qs);
    qs->dwSize = sizeof *qs;
    qs->lpszServiceInstanceName = name;
    qs->lpServiceClassId = (GUID *)cls;
    qs->dwNameSpace = ns;
}

void nsp_query_a(WSAQUERYSETA *qs, LPSTR name, const GUID *cls, DWORD ns) {
    memset(qs, 0, sizeof *qs);
    qs->dwSize = sizeof *qs;
    qs->lpszServiceInstanceName = name;
    qs->lpServiceClassId = (GUID *)cls;
    qs->dwNameSpace = ns;
}

int nsp_provider_for(DWORD ns, GUID *id) {
    DWORD len = 0, i, n;
    WSANAMESPACE_INFOW *info;
    int found = 0;
    typeof(&WSAEnumNameSpaceProvidersW) en = UIN("ws2_32.dll", WSAEnumNameSpaceProvidersW);
    if (!en || !nsp_up()) return 0;
    if (en(&len, NULL) != SOCKET_ERROR || len == 0) return 0;
    info = (WSANAMESPACE_INFOW *)HeapAlloc(GetProcessHeap(), 0, len);
    if (!info) return 0;
    n = (DWORD)en(&len, info);
    if ((int)n > 0) {
        for (i = 0; i < n; i++)
            if (info[i].dwNameSpace == ns && info[i].fActive) { *id = info[i].NSProviderId; found = 1; break; }
    }
    HeapFree(GetProcessHeap(), 0, info);
    return found;
}

void nsp_buf_free(nsp_buf *b) {
    if (b->p) HeapFree(GetProcessHeap(), 0, b->p);
    b->p = NULL; b->cap = 0;
}

static int buf_grow(nsp_buf *b, DWORD want) {
    if (want < 256) want = 256;
    if (b->p) HeapFree(GetProcessHeap(), 0, b->p);
    b->p = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, want);
    b->cap = b->p ? want : 0;
    return b->p != NULL;
}

int nsp_next_w(HANDLE h, DWORD flags, nsp_buf *b, int *grew) {
    DWORD len; int err;
    if (grew) *grew = 0;
    if (!b->p && !buf_grow(b, 1024)) return -1;
    len = b->cap;
    memset(b->p, 0, b->cap);
    if (W_NEXT_W(h, flags, &len, (WSAQUERYSETW *)b->p) == 0) return 0;
    err = W_ERR();
    if (err == WSAEFAULT) {
        b->need = len;
        if (grew) *grew = 1;
        if (!buf_grow(b, len)) return -1;
        len = b->cap;
        if (W_NEXT_W(h, flags, &len, (WSAQUERYSETW *)b->p) == 0) return 0;
        err = W_ERR();
    }
    return err;
}

int nsp_next_a(HANDLE h, DWORD flags, nsp_buf *b, int *grew) {
    DWORD len; int err;
    if (grew) *grew = 0;
    if (!b->p && !buf_grow(b, 1024)) return -1;
    len = b->cap;
    memset(b->p, 0, b->cap);
    if (W_NEXT_A(h, flags, &len, (WSAQUERYSETA *)b->p) == 0) return 0;
    err = W_ERR();
    if (err == WSAEFAULT) {
        b->need = len;
        if (grew) *grew = 1;
        if (!buf_grow(b, len)) return -1;
        len = b->cap;
        if (W_NEXT_A(h, flags, &len, (WSAQUERYSETA *)b->p) == 0) return 0;
        err = W_ERR();
    }
    return err;
}

int nsp_count_w(const WSAQUERYSETW *qs, DWORD flags, int *err_begin, int *err_last) {
    HANDLE h = NULL; nsp_buf b = {0}; int n = 0, e, guard = 0;
    WSAQUERYSETW copy = *qs;
    if (err_begin) *err_begin = 0;
    if (err_last) *err_last = 0;
    if (W_BEGIN_W(&copy, flags, &h) != 0) { if (err_begin) *err_begin = W_ERR(); return -1; }
    while (guard++ < 64) {
        e = nsp_next_w(h, 0, &b, NULL);
        if (e != 0) { if (err_last) *err_last = e; break; }
        n++;
    }
    nsp_buf_free(&b);
    W_END(h);
    return n;
}

int nsp_csaddrs_loopback(const CSADDR_INFO *c, DWORD count, int *n) {
    DWORD i; int all = 1;
    *n = 0;
    for (i = 0; i < count; i++) {
        const SOCKADDR *sa = c[i].RemoteAddr.lpSockaddr ? c[i].RemoteAddr.lpSockaddr : c[i].LocalAddr.lpSockaddr;
        if (!sa) { all = 0; continue; }
        (*n)++;
        if (sa->sa_family == AF_INET) {
            all &= ((const SOCKADDR_IN *)sa)->sin_addr.S_un.S_un_b.s_b1 == 127;
        } else if (sa->sa_family == AF_INET6) {
            const BYTE *a = ((const SOCKADDR_IN6 *)sa)->sin6_addr.u.Byte; int k, z = 1;
            for (k = 0; k < 15; k++) z &= a[k] == 0;
            all &= z && a[15] == 1;
        } else all = 0;
    }
    return all;
}
