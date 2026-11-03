/* Helpers for dx_provider_catalog: throwaway identities, catalog snapshots, guarded setup and full restore. */
#include "dx.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

const WCHAR dx_app_path[]  = L"C:\\ws2t_dx_catalog_dir\\dx_app_one.exe";
const WCHAR dx_app_path2[] = L"C:\\ws2t_dx_catalog_dir\\dx_app_two.exe";

#define DX_MARK1 0x77733274u   /* "ws2t" */
#define DX_MARK2 0xD0C1u

GUID dx_guid(unsigned idx)
{
    GUID g;
    g.Data1 = DX_MARK1; g.Data2 = DX_MARK2; g.Data3 = 0x0001;
    memset(g.Data4, 0, 8);
    g.Data4[0] = 0x57; g.Data4[1] = 0x41; g.Data4[2] = 0x7a; g.Data4[3] = 0x73;
    g.Data4[6] = (BYTE)(idx >> 8); g.Data4[7] = (BYTE)idx;
    return g;
}
int dx_is_ours(const GUID *g)
{
    return g->Data1 == DX_MARK1 && g->Data2 == DX_MARK2 && g->Data4[0] == 0x57 && g->Data4[1] == 0x41;
}

const WCHAR *dx_dll_path(void) { return L"%SystemRoot%\\system32\\mswsock.dll"; }

/* ---- WSA startup (needed by the API enumerations only) ---- */
static int g_wsa_rc;
static int wsa_up(void)
{
    static int st;
    if (!st) {
        WSADATA d;
        typedef int (WSAAPI *su_fn)(WORD, LPWSADATA);
        su_fn f = (su_fn)t_proc_in("ws2_32.dll", "WSAStartup");
        int rc = f ? f(0x202, &d) : -1;
        st = rc == 0 ? 1 : -1;
        g_wsa_rc = rc;
    }
    return st == 1;
}

/* ---- catalog enumeration ---- */
int dx_enum(int which, dx_list *out) { return dx_enum_f(which, NULL, out); }
int dx_enum_f(int which, INT *filter, dx_list *out)
{
    DWORD len = 0;
    INT err = 0, n;
    out->e = NULL; out->n = 0;
    if (which == 2 && !wsa_up()) return -1;
    for (int tries = 0; tries < 4; tries++) {
        if (which == 2) {
            dx_enumw_fn f = DX_FN(dx_enumw_fn, "WSAEnumProtocolsW");
            if (!f) return -1;
            n = f(filter, out->e, &len);
        } else {
            dx_enum_fn f = DX_FN(dx_enum_fn, which == 0 ? "WSCEnumProtocols" : "WSCEnumProtocols32");
            if (!f) return -1;
            n = f(filter, out->e, &len, &err);
        }
        if (n >= 0) { out->n = n; return n; }
        if (!len) break;
        free(out->e);
        out->e = (WSAPROTOCOL_INFOW *)calloc(1, len);
        if (!out->e) return -1;
    }
    free(out->e); out->e = NULL; out->n = 0;
    return -1;
}
void dx_free(dx_list *l) { free(l->e); l->e = NULL; l->n = 0; }

int dx_index_of_id(const dx_list *l, DWORD id)
{
    for (int i = 0; i < l->n; i++) if (l->e[i].dwCatalogEntryId == id) return i;
    return -1;
}
const WSAPROTOCOL_INFOW *dx_by_id(const dx_list *l, DWORD id)
{
    int i = dx_index_of_id(l, id);
    return i < 0 ? NULL : &l->e[i];
}
int dx_count_guid(const dx_list *l, const GUID *g)
{
    int c = 0;
    for (int i = 0; i < l->n; i++) if (!memcmp(&l->e[i].ProviderId, g, sizeof *g)) c++;
    return c;
}
const WSAPROTOCOL_INFOW *dx_first_guid(const dx_list *l, const GUID *g)
{
    for (int i = 0; i < l->n; i++) if (!memcmp(&l->e[i].ProviderId, g, sizeof *g)) return &l->e[i];
    return NULL;
}
int dx_has_guid(int which, const GUID *g)
{
    dx_list l; int r;
    if (which == 2) return dx_child_query("has %u", dx_guid_index(g)) == 0;
    if (dx_enum(which, &l) < 0) return 0;
    r = dx_count_guid(&l, g) > 0;
    dx_free(&l);
    return r;
}
int dx_api_wait_guid(const GUID *g, int present)
{
    return dx_child_query("has %u", dx_guid_index(g)) == (present ? 0 : 1);
}
unsigned dx_guid_index(const GUID *g) { return ((unsigned)g->Data4[6] << 8) | g->Data4[7]; }
int dx_child_query(const char *fmt, ...)
{
    char args[200]; va_list ap;
    va_start(ap, fmt); vsnprintf(args, sizeof args, fmt, ap); va_end(ap);
    return (int)t_run_child("dx_api", args, 30000);
}

/* Child side of dx_child_query: reads the API lists (WSAEnumProtocolsW/A) with fresh state.
 *   has <i>            provider #i is listed
 *   before <a> <b>     both listed and #a comes first
 *   filt <proto> <i>   provider #i is listed when the protocol filter {proto} is applied
 *   ansi <i> <proto>   the ANSI list carries provider #i with that protocol number and the standard name
 *   same <i>           the API record of #i equals the SPI record on the compared fields
 *   count <i> <n>      provider #i is listed exactly n times */
static int idx_pos(const WSAPROTOCOL_INFOW *e, int n, unsigned idx)
{
    GUID g = dx_guid(idx);
    for (int i = 0; i < n; i++) if (!memcmp(&e[i].ProviderId, &g, sizeof g)) return i;
    return -1;
}
CHILD(dx_api)
{
    dx_list l;
    if (argc < 3) return 90;
    if (!wsa_up()) return 1000 + (g_wsa_rc > 10000 ? g_wsa_rc - 10000 : 0);
    if (!strcmp(argv[1], "has")) {
        if (dx_enum(2, &l) < 0) return 92;
        return idx_pos(l.e, l.n, (unsigned)atoi(argv[2])) >= 0 ? 0 : 1;
    }
    if (!strcmp(argv[1], "count") && argc >= 4) {
        int c = 0; GUID g = dx_guid((unsigned)atoi(argv[2]));
        if (dx_enum(2, &l) < 0) return 92;
        c = dx_count_guid(&l, &g);
        return c == atoi(argv[3]) ? 0 : 1;
    }
    if (!strcmp(argv[1], "before") && argc >= 4) {
        int a, b;
        if (dx_enum(2, &l) < 0) return 92;
        a = idx_pos(l.e, l.n, (unsigned)atoi(argv[2])); b = idx_pos(l.e, l.n, (unsigned)atoi(argv[3]));
        if (a < 0 || b < 0) return 2;
        return a < b ? 0 : 1;
    }
    if (!strcmp(argv[1], "filt") && argc >= 4) {
        INT f[2]; f[0] = atoi(argv[2]); f[1] = 0;
        if (dx_enum_f(2, f, &l) < 0) return 92;
        return idx_pos(l.e, l.n, (unsigned)atoi(argv[3])) >= 0 ? 0 : 1;
    }
    if (!strcmp(argv[1], "same")) {
        dx_list s; int ia, is; unsigned idx = (unsigned)atoi(argv[2]);
        if (dx_enum(2, &l) < 0 || dx_enum(0, &s) < 0) return 92;
        ia = idx_pos(l.e, l.n, idx); is = idx_pos(s.e, s.n, idx);
        if (ia < 0 || is < 0) return 2;
        if (l.e[ia].dwCatalogEntryId != s.e[is].dwCatalogEntryId || l.e[ia].dwServiceFlags1 != s.e[is].dwServiceFlags1 ||
            l.e[ia].dwProviderFlags != s.e[is].dwProviderFlags || l.e[ia].iAddressFamily != s.e[is].iAddressFamily ||
            l.e[ia].iSocketType != s.e[is].iSocketType || l.e[ia].iProtocol != s.e[is].iProtocol ||
            l.e[ia].ProtocolChain.ChainLen != s.e[is].ProtocolChain.ChainLen || lstrcmpW(l.e[ia].szProtocol, s.e[is].szProtocol))
            return 1;
        return 0;
    }
    if (!strcmp(argv[1], "ansi") && argc >= 4) {
        typedef INT (WSAAPI *ea_fn)(LPINT, LPWSAPROTOCOL_INFOA, LPDWORD);
        ea_fn f = (ea_fn)t_proc_in("ws2_32.dll", "WSAEnumProtocolsA");
        DWORD len = 0; INT n; WSAPROTOCOL_INFOA *a; GUID g = dx_guid((unsigned)atoi(argv[2])); int rc = 1;
        if (!f) return 90;
        f(NULL, NULL, &len);
        a = (WSAPROTOCOL_INFOA *)calloc(1, len ? len : 1);
        n = f(NULL, a, &len);
        for (int i = 0; i < n; i++)
            if (!memcmp(&a[i].ProviderId, &g, sizeof g) && a[i].iProtocol == atoi(argv[3]) && !strcmp(a[i].szProtocol, "ws2t dx base")) rc = 0;
        free(a);
        return rc;
    }
    if (!strncmp(argv[1], "ns", 2)) {
        dx_nslist n; int i, rc = 1; const char *cmd = argv[1];
        if (dx_ns_enum(&n) < 0) return 92;
        if (!strcmp(cmd, "nscount")) rc = n.n == atoi(argv[2]) ? 0 : 1;
        else {
            GUID g = dx_guid((unsigned)atoi(argv[2])); const WSANAMESPACE_INFOW *e = dx_ns_by_guid(&n, &g);
            if (!strcmp(cmd, "nshas")) rc = e ? 0 : 1;
            else if (!e) rc = 2;
            else if (!strcmp(cmd, "nsfields") && argc >= 6) {
                rc = (e->dwNameSpace == (DWORD)strtoul(argv[3], NULL, 0) && e->dwVersion == (DWORD)strtoul(argv[4], NULL, 0) &&
                      (atoi(argv[5]) < 0 || (e->fActive != 0) == (atoi(argv[5]) != 0))) ? 0 : 1;
            } else if (!strcmp(cmd, "nsactive")) rc = e->fActive ? 0 : 1;
            else if (!strcmp(cmd, "nsident") && argc >= 5) {
                int len = atoi(argv[3]); WCHAR want[400]; int k;
                if (len == 0) lstrcpyW(want, L"ws2t dx namespace");
                else { for (k = 0; k < len && k < 390; k++) want[k] = (WCHAR)argv[4][0]; want[k] = 0; }
                rc = (e->lpszIdentifier && !lstrcmpW(e->lpszIdentifier, want)) ? 0 : 1;
            } else if (!strcmp(cmd, "nslast")) rc = (e == &n.e[n.n - 1]) ? 0 : 1;
            else if (!strcmp(cmd, "nsbefore") && argc >= 4) {
                GUID h = dx_guid((unsigned)atoi(argv[3])); const WSANAMESPACE_INFOW *f = dx_ns_by_guid(&n, &h);
                rc = !f ? 2 : (e < f ? 0 : 1);
            } else rc = 93;
        }
        (void)i;
        dx_ns_free(&n);
        return rc;
    }
    return 93;
}
DWORD dx_id_of(int which, const GUID *g)
{
    dx_list l; DWORD id = 0;
    if (dx_enum(which, &l) < 0) return 0;
    { const WSAPROTOCOL_INFOW *e = dx_first_guid(&l, g); if (e) id = e->dwCatalogEntryId; }
    dx_free(&l);
    return id;
}

int dx_path_of(const GUID *g, WCHAR *out, int cch)
{
    typedef INT (WSAAPI *pf)(const GUID *, WCHAR *, LPINT, LPINT);
    pf f = (pf)t_proc_in("ws2_32.dll", "WSCGetProviderPath");
    INT len = cch, err = 0;
    if (!f) return -1;
    if (f(g, out, &len, &err) == 0) return 0;
    return err ? err : -2;
}

/* ---- name-space catalog ---- */
int dx_ns_enum(dx_nslist *out)
{
    DWORD len = 0;
    INT n;
    dx_enumnsw_fn f = DX_FN(dx_enumnsw_fn, "WSAEnumNameSpaceProvidersW");
    out->e = NULL; out->n = 0;
    if (!f || !wsa_up()) return -1;
    for (int tries = 0; tries < 4; tries++) {
        n = f(&len, out->e);
        if (n >= 0 && n != SOCKET_ERROR) { out->n = n; return n; }
        if (!len) break;
        free(out->e);
        out->e = (WSANAMESPACE_INFOW *)calloc(1, len);
        if (!out->e) return -1;
    }
    free(out->e); out->e = NULL; out->n = 0;
    return -1;
}
void dx_ns_free(dx_nslist *l) { free(l->e); l->e = NULL; l->n = 0; }
const WSANAMESPACE_INFOW *dx_ns_by_guid(const dx_nslist *l, const GUID *g)
{
    for (int i = 0; i < l->n; i++) if (!memcmp(&l->e[i].NSProviderId, g, sizeof *g)) return &l->e[i];
    return NULL;
}
int dx_ns_wait_guid(const GUID *g, int present)
{
    return dx_child_query("nshas %u", dx_guid_index(g)) == (present ? 0 : 1);
}

/* ---- entry builders ---- */
static void fill_common(WSAPROTOCOL_INFOW *p, unsigned idx, const WCHAR *name)
{
    memset(p, 0, sizeof *p);
    p->dwServiceFlags1 = XP1_IFS_HANDLES | XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER | XP1_GRACEFUL_CLOSE;
    p->dwCatalogEntryId = 0xDEADBEEFu;      /* the install assigns its own id; this value must be ignored */
    p->iVersion = 2;
    p->iAddressFamily = DX_AF_BASE + (int)idx;
    p->iMaxSockAddr = 16;
    p->iMinSockAddr = 16;
    p->iSocketType = SOCK_STREAM;
    p->iProtocol = 6;
    lstrcpyW(p->szProtocol, name);
}
void dx_base_entry(WSAPROTOCOL_INFOW *p, unsigned idx)
{
    fill_common(p, idx, L"ws2t dx base");
    p->ProtocolChain.ChainLen = 1;
}
void dx_layered_entry(WSAPROTOCOL_INFOW *p, unsigned idx)
{
    fill_common(p, idx, L"ws2t dx layered");
    p->ProtocolChain.ChainLen = 0;
}
void dx_chain_entry(WSAPROTOCOL_INFOW *p, unsigned idx, DWORD layered_id, DWORD base_id)
{
    fill_common(p, idx, L"ws2t dx chain");
    p->ProtocolChain.ChainLen = 2;
    p->ProtocolChain.ChainEntries[0] = layered_id;
    p->ProtocolChain.ChainEntries[1] = base_id;
}

static int do_install(dx_install_fn f, const GUID *g, const WSAPROTOCOL_INFOW *p)
{
    INT err = 0;
    if (!f) return -1;
    if (f(g, dx_dll_path(), p, 1, &err) == 0) return 0;
    return err ? err : -2;
}
int dx_install_one(const GUID *g, const WSAPROTOCOL_INFOW *p) { return do_install(DX_INSTALL, g, p); }
int dx_install64_32_one(const GUID *g, const WSAPROTOCOL_INFOW *p) { return do_install(DX_INSTALL64_32, g, p); }

/* ---- environment ---- */
int dx_elevated(void)
{
    HANDLE tok = NULL; TOKEN_ELEVATION el; DWORD got = 0; int r = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &got)) r = el.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}

/* ---- baseline ---- */
typedef struct { DWORD id; GUID pid; DWORD chain; DWORD flags1; DWORD pflags; int af; } snap_e;
typedef struct { snap_e *e; int n; } snap;
static snap g_nat, g_wow;
static GUID *g_ns; static int g_nsn;
static int g_state;                 /* 0 none, 1 ready, -1 refused */
static char g_reason[160];
static int g_atexit;

static void snap_take(const dx_list *l, snap *s)
{
    free(s->e);
    s->e = (snap_e *)calloc(l->n ? l->n : 1, sizeof(snap_e));
    s->n = l->n;
    for (int i = 0; i < l->n; i++) {
        s->e[i].id = l->e[i].dwCatalogEntryId; s->e[i].pid = l->e[i].ProviderId;
        s->e[i].chain = l->e[i].ProtocolChain.ChainLen; s->e[i].flags1 = l->e[i].dwServiceFlags1;
        s->e[i].pflags = l->e[i].dwProviderFlags; s->e[i].af = l->e[i].iAddressFamily;
    }
}
static int snap_equal(const dx_list *l, const snap *s)
{
    if (l->n != s->n) return 0;
    for (int i = 0; i < l->n; i++) {
        if (l->e[i].dwCatalogEntryId != s->e[i].id || memcmp(&l->e[i].ProviderId, &s->e[i].pid, sizeof(GUID)) ||
            l->e[i].ProtocolChain.ChainLen != s->e[i].chain || l->e[i].dwServiceFlags1 != s->e[i].flags1 ||
            l->e[i].dwProviderFlags != s->e[i].pflags || l->e[i].iAddressFamily != s->e[i].af)
            return 0;
    }
    return 1;
}
static int matches(int which, const snap *s)
{
    dx_list l; int r;
    if (dx_enum(which, &l) < 0) return 0;
    r = snap_equal(&l, s);
    dx_free(&l);
    return r;
}
int dx_native_matches_baseline(void) { return matches(0, &g_nat); }
int dx_wow_matches_baseline(void) { return matches(1, &g_wow); }
int dx_baseline_count(void) { return g_nat.n; }
int dx_ns_matches_baseline(void)
{
    /* Read in a fresh process: the count must equal the baseline count. Order is compared in-process by the
     * restore step (the persistent list is what WSCWriteNameSpaceOrder rewrites). */
    int rc = dx_child_query("nscount %d", g_nsn);
    if (rc != 0) t_note("name-space baseline child returned %d (expected %d entries)", rc, g_nsn);
    return rc == 0;
}

/* ---- sweep and restore ---- */
static void sweep_catalog(int which)
{
    dx_deinstall_fn de = which == 0 ? DX_DEINSTALL : DX_DEINSTALL32;
    if (!de) return;
    for (int round = 0; round < 64; round++) {
        dx_list l; GUID victim; int found = 0;
        if (dx_enum(which, &l) < 0) return;
        for (int i = 0; i < l.n && !found; i++)
            if (dx_is_ours(&l.e[i].ProviderId)) { victim = l.e[i].ProviderId; found = 1; }
        dx_free(&l);
        if (!found) return;
        { INT err = 0; if (de(&victim, &err) != 0) return; }
    }
}
static void sweep_ns(void)
{
    /* The in-process list can be stale, so also try every identity the area uses. */
    for (unsigned i = 0; i <= 24; i++) {
        GUID g = dx_guid(i);
        if (DX_NSUNINSTALL) DX_NSUNINSTALL(&g);
        if (DX_NSUNINSTALL32) DX_NSUNINSTALL32(&g);
    }
    { GUID g = dx_guid(200); if (DX_NSUNINSTALL) DX_NSUNINSTALL(&g); }
    for (int round = 0; round < 64; round++) {
        dx_nslist l; GUID victim; int found = 0;
        if (dx_ns_enum(&l) < 0) return;
        for (int i = 0; i < l.n && !found; i++)
            if (dx_is_ours(&l.e[i].NSProviderId)) { victim = l.e[i].NSProviderId; found = 1; }
        dx_ns_free(&l);
        if (!found) return;
        if (!DX_NSUNINSTALL || DX_NSUNINSTALL(&victim) != 0) return;
    }
}
static void sweep_apps(void)
{
    static const WCHAR *extras[] = { NULL, L"-ws2t dx", L"one two" };
    const WCHAR *paths[2] = { dx_app_path, dx_app_path2 };
    dx_appget_fn g = DX_APPGET; dx_appset_fn s = DX_APPSET;
    if (!g || !s) return;
    for (int p = 0; p < 2; p++)
        for (int x = 0; x < 3; x++) {
            DWORD cat = 0, prev = 0; INT err = 0;
            DWORD xl = extras[x] ? (DWORD)lstrlenW(extras[x]) : 0;
            if (g(paths[p], (DWORD)lstrlenW(paths[p]), extras[x], xl, &cat, &err) == 0)
                s(paths[p], (DWORD)lstrlenW(paths[p]), extras[x], xl, 0, &prev, &err);
        }
}
void dx_sweep(void)
{
    sweep_catalog(0);
    sweep_catalog(1);
    sweep_ns();
    sweep_apps();
}

static void restore_order(int which, const snap *s)
{
    dx_list l; dx_order_fn wo = which == 0 ? DX_ORDER : DX_ORDER32;
    DWORD *ids; int k = 0;
    if (!wo || dx_enum(which, &l) < 0) return;
    if (snap_equal(&l, s)) { dx_free(&l); return; }
    ids = (DWORD *)calloc(l.n ? l.n : 1, sizeof(DWORD));
    /* Baseline order restricted to the entries that still exist. */
    for (int i = 0; i < s->n; i++) if (dx_index_of_id(&l, s->e[i].id) >= 0) ids[k++] = s->e[i].id;
    if (k == l.n) wo(ids, (DWORD)k);
    free(ids);
    dx_free(&l);
}
int dx_ns_order_dirty;
static void restore_ns_order(void)
{
    typedef INT (WSAAPI *wno_fn)(LPGUID, DWORD);
    wno_fn wo = (wno_fn)t_proc_in("ws2_32.dll", "WSCWriteNameSpaceOrder");
    /* The in-process list can be stale, so the baseline order is rewritten whenever a test touched it. */
    if (dx_ns_order_dirty && wo && g_ns && g_nsn > 0) { wo(g_ns, (DWORD)g_nsn); dx_ns_order_dirty = 0; }
}
static void restore_all(void)
{
    dx_sweep();
    restore_ns_order();
    restore_order(0, &g_nat);
    restore_order(1, &g_wow);
}
static void atexit_restore(void) { if (g_state == 1) restore_all(); }

void dx_end(void)
{
    if (g_state != 1) return;
    restore_all();
    /* After every test the catalogs must be exactly as found. */
    CHECK(dx_native_matches_baseline());
    if (g_wow.n) CHECK(dx_wow_matches_baseline());
    CHECK(dx_ns_matches_baseline());
}

int dx_wow_available(void) { return g_wow.n > 0 && DX_INSTALL64_32 && DX_DEINSTALL32 && DX_ORDER32; }

int dx_begin(void)
{
    if (g_state == 0) {
        dx_list l; int ok;
        if (t_is_wine()) {
            /* The emulator's configuration exports are partly unimplemented stubs that abort the process. */
            g_state = -1; snprintf(g_reason, sizeof g_reason, "provider catalog configuration is not available on an emulated stack");
        } else if (!DX_INSTALL || !DX_DEINSTALL || !DX_ORDER || !DX_UPDATE || !DX_NSINSTALL || !DX_NSUNINSTALL || !DX_NSENABLE) {
            g_state = -1; snprintf(g_reason, sizeof g_reason, "catalog configuration exports missing");
        } else if (!dx_elevated()) {
            g_state = -1; snprintf(g_reason, sizeof g_reason, "not elevated");
        } else {
            dx_sweep();
            ok = dx_enum(0, &l) >= 0;
            if (ok) { snap_take(&l, &g_nat); dx_free(&l); }
            if (dx_enum(1, &l) >= 0) { snap_take(&l, &g_wow); dx_free(&l); }
            { dx_nslist nl;
              if (dx_ns_enum(&nl) >= 0) {
                  g_nsn = nl.n; g_ns = (GUID *)calloc(nl.n ? nl.n : 1, sizeof(GUID));
                  for (int i = 0; i < nl.n; i++) g_ns[i] = nl.e[i].NSProviderId;
                  dx_ns_free(&nl);
              } else ok = 0;
            }
            if (!ok) { g_state = -1; snprintf(g_reason, sizeof g_reason, "catalogs cannot be enumerated"); }
            else {
                /* Probe: a throwaway base entry must install and uninstall. */
                WSAPROTOCOL_INFOW p; GUID g = dx_guid(0); int r;
                dx_base_entry(&p, 0);
                r = dx_install_one(&g, &p);
                if (r != 0) { g_state = -1; snprintf(g_reason, sizeof g_reason, "catalog mutation refused (error %d)", r); }
                else {
                    INT err = 0;
                    if (DX_DEINSTALL(&g, &err) != 0) { g_state = -1; snprintf(g_reason, sizeof g_reason, "probe entry could not be removed"); dx_sweep(); }
                    else g_state = 1;
                }
            }
            if (g_state == 1 && !g_atexit) { g_atexit = 1; atexit(atexit_restore); }
        }
    }
    if (g_state != 1) { t_skip("%s", g_reason); return 0; }
    restore_all();
    return 1;
}
