/* Helpers for the protocol_catalog area. */
#include "pc.h"
#include <stdlib.h>

const GUID pc_guid_tcpip4 = {0xE70F1AA0, 0xAB8B, 0x11CF, {0x8C, 0xA3, 0x00, 0x80, 0x5F, 0x48, 0xA1, 0x92}};
const GUID pc_guid_tcpip6 = {0xF9EAB0C0, 0x26D4, 0x11D0, {0xBB, 0xBF, 0x00, 0xAA, 0x00, 0x6C, 0x34, 0xE4}};
const GUID pc_guid_ns_dns = {0x22059D40, 0x7E9E, 0x11CF, {0xAE, 0x5A, 0x00, 0xAA, 0x00, 0xA7, 0x11, 0x2B}};
const GUID pc_guid_unknown_a = {0x5c0de0a1, 0x7a11, 0x4c0d, {0x9e, 0x01, 0x42, 0x13, 0x77, 0x00, 0xaa, 0x01}};
const GUID pc_guid_unknown_b = {0x5c0de0a1, 0x7a11, 0x4c0d, {0x9e, 0x01, 0x42, 0x13, 0x77, 0x00, 0xaa, 0x02}};

int pc_up(void)
{
    static int state; /* 0 untried, 1 ok, -1 failed */
    if (state == 0) {
        WSADATA d;
        if (!U(WSAStartup)) { state = -1; return 0; }
        state = U(WSAStartup)(0x202, &d) == 0 ? 1 : -1;
    }
    return state == 1;
}

typedef INT (WSAAPI *enum_w_fn)(LPINT, LPWSAPROTOCOL_INFOW, LPDWORD);
typedef INT (WSAAPI *enum_a_fn)(LPINT, LPWSAPROTOCOL_INFOA, LPDWORD);
typedef INT (WSPAPI *enum_c_fn)(LPINT, LPWSAPROTOCOL_INFOW, LPDWORD, LPINT);

int pc_enum_w(int which, INT *filter, pc_list *out)
{
    DWORD len = 0;
    INT err = 0, n;
    void *f;
    out->e = NULL; out->n = 0; out->bytes = 0;
    f = which == 0 ? (void *)t_proc_in("ws2_32.dll", "WSAEnumProtocolsW")
      : which == 1 ? (void *)t_proc_in("ws2_32.dll", "WSCEnumProtocols")
                   : (void *)t_proc_in("ws2_32.dll", "WSCEnumProtocols32");
    if (!f) return -1;
    for (int tries = 0; tries < 4; tries++) {
        n = which == 0 ? ((enum_w_fn)f)(filter, out->e, &len) : ((enum_c_fn)f)(filter, out->e, &len, &err);
        if (n >= 0) { out->n = n; out->bytes = len; return n; }
        if (!len) break;
        free(out->e);
        out->e = (WSAPROTOCOL_INFOW *)calloc(1, len);
        if (!out->e) return -1;
    }
    free(out->e); out->e = NULL;
    return -1;
}

int pc_enum_a(INT *filter, WSAPROTOCOL_INFOA **out)
{
    DWORD len = 0;
    INT n;
    enum_a_fn f = (enum_a_fn)t_proc_in("ws2_32.dll", "WSAEnumProtocolsA");
    *out = NULL;
    if (!f) return -1;
    for (int tries = 0; tries < 4; tries++) {
        n = f(filter, *out, &len);
        if (n >= 0) return n;
        if (!len) break;
        free(*out);
        *out = (WSAPROTOCOL_INFOA *)calloc(1, len);
        if (!*out) return -1;
    }
    free(*out); *out = NULL;
    return -1;
}

void pc_free(pc_list *l) { free(l->e); l->e = NULL; l->n = 0; l->bytes = 0; }

int pc_guid_eq(const GUID *a, const GUID *b) { return memcmp(a, b, sizeof(GUID)) == 0; }

const WSAPROTOCOL_INFOW *pc_find(const pc_list *l, int af, int type, int proto, int chain)
{
    for (int i = 0; i < l->n; i++) {
        const WSAPROTOCOL_INFOW *e = &l->e[i];
        if (e->iAddressFamily == af && e->iSocketType == type && e->iProtocol == proto &&
            (chain < 0 || e->ProtocolChain.ChainLen == chain))
            return e;
    }
    return NULL;
}

const WSAPROTOCOL_INFOW *pc_by_id(const pc_list *l, DWORD id)
{
    for (int i = 0; i < l->n; i++) if (l->e[i].dwCatalogEntryId == id) return &l->e[i];
    return NULL;
}

int pc_in_range(const WSAPROTOCOL_INFOW *e, int proto)
{
    return proto >= e->iProtocol && proto <= e->iProtocol + e->iProtocolMaxOffset;
}

int pc_wieq(const WCHAR *a, const WCHAR *b) { return lstrcmpiW(a, b) == 0; }
