/* Helpers for the gap_01 area (see g1.h). */
#include "g1.h"

const GUID g1_guid_a    = { 0x67617031, 0x0101, 0x4a01, { 0x80, 0x01, 0x77, 0x73, 0x32, 0x74, 0x00, 0x01 } };
const GUID g1_guid_b    = { 0x67617031, 0x0101, 0x4a01, { 0x80, 0x01, 0x77, 0x73, 0x32, 0x74, 0x00, 0x02 } };
const GUID g1_guid_zero = { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } };
const GUID g1_guid_ones = { 0xffffffff, 0xffff, 0xffff, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };

/* An emulation layer may abort the whole process when it reaches one of its unimplemented stubs; those exports are hidden
 * there so the area can still be checked for crashes and hangs. Windows is the authority. */
static const char *const k_emu_stubs[] = { "WSCUpdateProvider", "WSCUpdateProvider32", NULL };
void *g1_fn(const char *name)
{
    if (t_is_wine())
        for (int i = 0; k_emu_stubs[i]; i++) if (!strcmp(k_emu_stubs[i], name)) return NULL;
    return (void *)t_proc_in("ws2_32.dll", name);
}

static int g_up;
int g1_up(void)
{
    typedef int (WSAAPI *su_t)(WORD, LPWSADATA);
    if (!g_up) {
        WSADATA d; su_t f = (su_t)g1_fn("WSAStartup");
        g_up = (f && f(0x202, &d) == 0) ? 1 : -1;
    }
    return g_up == 1 ? 0 : -1;
}

int g1_elevated(void)
{
    HANDLE tok = NULL; TOKEN_ELEVATION el; DWORD n = 0; int r = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &n)) r = el.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}

void g1_fill_w(WCHAR *dst, int len, WCHAR c)
{
    for (int i = 0; i < len; i++) dst[i] = c;
    dst[len] = 0;
}

void g1_base_info(WSAPROTOCOL_INFOW *p, int af)
{
    memset(p, 0, sizeof *p);
    p->dwServiceFlags1 = XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER | XP1_GRACEFUL_CLOSE;
    p->dwCatalogEntryId = 0x12345u;
    p->iVersion = 2;
    p->iAddressFamily = af;
    p->iMaxSockAddr = 16;
    p->iMinSockAddr = 16;
    p->iSocketType = SOCK_STREAM;
    p->iProtocol = 6;
    p->ProtocolChain.ChainLen = 1;
    lstrcpyW(p->szProtocol, L"gap1 base");
}

/* ---- signatures ---- */
static void mix(unsigned long long *h, const void *p, size_t n)
{
    const unsigned char *b = (const unsigned char *)p;
    while (n--) { *h ^= *b++; *h *= 1099511628211ULL; }
}

typedef INT (WSAAPI *enum_t)(LPINT, LPWSAPROTOCOL_INFOW, LPDWORD, LPINT);
int g1_proto_sig(int wow, g1_sig *s)
{
    enum_t f = (enum_t)g1_fn(wow ? "WSCEnumProtocols32" : "WSCEnumProtocols");
    WSAPROTOCOL_INFOW *buf = NULL; DWORD len = 0; INT err = 0, n = -1;
    s->n = 0; s->h = 14695981039346656037ULL;
    if (!f) return -1;
    for (int tries = 0; tries < 4; tries++) {
        n = f(NULL, buf, &len, &err);
        if (n >= 0) break;
        if (!len) break;
        free(buf); buf = (WSAPROTOCOL_INFOW *)calloc(1, len);
        if (!buf) return -1;
    }
    if (n < 0) { free(buf); return -1; }
    s->n = n;
    for (int i = 0; i < n; i++) {
        mix(&s->h, &buf[i].dwCatalogEntryId, 4);
        mix(&s->h, &buf[i].ProviderId, sizeof(GUID));
        mix(&s->h, &buf[i].ProtocolChain.ChainLen, 4);
        mix(&s->h, &buf[i].iAddressFamily, 4);
        mix(&s->h, &buf[i].dwProviderFlags, 4);
    }
    free(buf);
    return 0;
}

typedef INT (WSAAPI *nsenum_t)(LPDWORD, LPWSANAMESPACE_INFOW);
static int ns_enum(int wow, WSANAMESPACE_INFOW **out, int *count)
{
    nsenum_t f = (nsenum_t)g1_fn(wow ? "WSCEnumNameSpaceProviders32" : "WSAEnumNameSpaceProvidersW");
    WSANAMESPACE_INFOW *buf = NULL; DWORD len = 0; INT n = -1;
    *out = NULL; *count = 0;
    if (!f) return -1;
    if (!wow && g1_up()) return -1;
    for (int tries = 0; tries < 4; tries++) {
        n = f(&len, buf);
        if (n >= 0 && n != SOCKET_ERROR) break;
        n = -1;
        if (!len) break;
        free(buf); buf = (WSANAMESPACE_INFOW *)calloc(1, len);
        if (!buf) return -1;
    }
    if (n < 0) { free(buf); return -1; }
    *out = buf; *count = n;
    return 0;
}

static void ns_hash(g1_sig *s, const WSANAMESPACE_INFOW *e, int n)
{
    s->n = n; s->h = 14695981039346656037ULL;
    for (int i = 0; i < n; i++) {
        mix(&s->h, &e[i].NSProviderId, sizeof(GUID));
        mix(&s->h, &e[i].dwNameSpace, 4);
        mix(&s->h, &e[i].fActive, 4);
        mix(&s->h, &e[i].dwVersion, 4);
        if (e[i].lpszIdentifier) mix(&s->h, e[i].lpszIdentifier, lstrlenW(e[i].lpszIdentifier) * 2);
    }
}

int g1_ns32_sig(g1_sig *s)
{
    WSANAMESPACE_INFOW *e; int n;
    s->n = 0; s->h = 0;
    if (ns_enum(1, &e, &n)) return -1;
    ns_hash(s, e, n); free(e);
    return 0;
}

CHILD(g1_nssig)
{
    WSANAMESPACE_INFOW *e; int n; g1_sig s;
    if (ns_enum(0, &e, &n)) return 0x3fffffff;
    ns_hash(&s, e, n); free(e);
    return (int)((s.h ^ (s.h >> 32)) & 0x3ffffffe);
}

int g1_ns_native_sig(unsigned *code)
{
    DWORD rc = t_run_child("g1_nssig", "", 30000);
    if (rc >= 0x40000000u) return -1;
    *code = rc;
    return 0;
}

int g1_sig_eq(const g1_sig *a, const g1_sig *b) { return a->n == b->n && a->h == b->h; }

int g1_proto_ids(int wow, GUID *out, int max)
{
    enum_t f = (enum_t)g1_fn(wow ? "WSCEnumProtocols32" : "WSCEnumProtocols");
    WSAPROTOCOL_INFOW *buf = NULL; DWORD len = 0; INT err = 0, n = -1; int k = 0;
    if (!f) return 0;
    for (int tries = 0; tries < 4; tries++) {
        n = f(NULL, buf, &len, &err);
        if (n >= 0) break;
        if (!len) break;
        free(buf); buf = (WSAPROTOCOL_INFOW *)calloc(1, len);
        if (!buf) return 0;
    }
    for (int i = 0; i < n && n >= 0; i++) {
        int dup = 0;
        for (int j = 0; j < k; j++) if (!memcmp(&out[j], &buf[i].ProviderId, sizeof(GUID))) dup = 1;
        if (!dup && k < max) out[k++] = buf[i].ProviderId;
    }
    free(buf);
    return k;
}

int g1_ns_ids(int wow, GUID *out, DWORD *ns, int max)
{
    WSANAMESPACE_INFOW *e; int n, k = 0;
    if (ns_enum(wow, &e, &n)) return 0;
    for (int i = 0; i < n && k < max; i++) { out[k] = e[i].NSProviderId; if (ns) ns[k] = e[i].dwNameSpace; k++; }
    free(e);
    return k;
}

void g1_snap(g1_snapshot *s)
{
    memset(s, 0, sizeof *s);
    g1_proto_sig(0, &s->nat);
    s->ok_wow = g1_proto_sig(1, &s->wow) == 0;
    s->ok_ns32 = g1_ns32_sig(&s->ns32) == 0;
    s->ok_nsnat = g1_ns_native_sig(&s->nsnat) == 0;
}

int g1_snap_same(const g1_snapshot *b)
{
    g1_snapshot now; int ok = 1;
    g1_snap(&now);
    if (!g1_sig_eq(&now.nat, &b->nat)) ok = 0;
    if (b->ok_wow && (!now.ok_wow || !g1_sig_eq(&now.wow, &b->wow))) ok = 0;
    if (b->ok_ns32 && (!now.ok_ns32 || !g1_sig_eq(&now.ns32, &b->ns32))) ok = 0;
    if (b->ok_nsnat && (!now.ok_nsnat || now.nsnat != b->nsnat)) ok = 0;
    return ok;
}
