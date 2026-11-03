/* Start-up contract of the name-space provider DLLs that hold no lookup data in this environment: winrnr (directory
 * provider), napinsp (e-mail naming shim), pnrpnsp (peer name resolution), nlaapi (location awareness) and the
 * Bluetooth helper's own NSPStartup. Each case runs in a child process because the providers keep process-wide
 * reference counts. Measures: which provider GUID each start-up accepts, the error and the untouched table for a
 * wrong GUID, the table header and the set of routines it publishes, whether cbSize of the caller's table matters,
 * and that cleanup balances start-up. No lookup is started and nothing leaves the process. */
#include "anc.h"

typedef INT (WSAAPI *nspstartup_fn)(LPGUID, LPNSP_ROUTINE);
typedef INT (WSAAPI *nspcleanup_fn)(LPGUID);

static const GUID G_NLA   = { 0x6642243a, 0x3ba8, 0x4aa6, { 0xba, 0xa5, 0x2e, 0x0b, 0xd7, 0x1f, 0xdd, 0x83 } };
static const GUID G_DNS   = { 0x22059D40, 0x7E9E, 0x11CF, { 0xAE, 0x5A, 0x00, 0xAA, 0x00, 0xA7, 0x11, 0x2B } };
static const GUID G_EMAIL = { 0x964ACBA2, 0xB2BC, 0x40EB, { 0x8C, 0x6A, 0xA6, 0xDB, 0x40, 0x16, 0x1C, 0xAE } };
static const GUID G_PNRP  = { 0x03FE89CD, 0x766D, 0x4976, { 0xB9, 0xC1, 0xBB, 0x9B, 0xC4, 0x2C, 0x7B, 0x4D } };
static const GUID G_PNRPC = { 0x03FE89CE, 0x766D, 0x4976, { 0xB9, 0xC1, 0xBB, 0x9B, 0xC4, 0x2C, 0x7B, 0x4D } };
static const GUID G_BTH   = { 0x06AA63E0, 0x7D60, 0x41FF, { 0xAF, 0xB2, 0x3E, 0xE6, 0xD2, 0xD9, 0x39, 0x2D } };
static const GUID G_ZERO  = { 0 };

#define BAD(n) (1u << (n))
#define PTR_SLOT(t, i) (((void **)((BYTE *)(t) + 16))[i])

static int fn_mask(NSP_ROUTINE *t) { int m = 0; for (int i = 0; i < 9; i++) if (PTR_SLOT(t, i)) m |= 1 << i; return m; }

/* Start with a table pre-filled with fill bytes; returns the result and leaves the table for inspection. */
static INT start(nspstartup_fn f, const GUID *g, NSP_ROUTINE *t, DWORD cb, DWORD *gle) {
    memset(t, ANC_FILL, sizeof *t); t->cbSize = cb; SetLastError(0);
    INT r = f((LPGUID)g, t); *gle = GetLastError(); return r;
}
static int table_untouched(NSP_ROUTINE *t, DWORD cb) {
    NSP_ROUTINE e; memset(&e, ANC_FILL, sizeof e); e.cbSize = cb; return !memcmp(&e, t, sizeof e);
}

/* kind: 0 winrnr, 1 napinsp, 2 pnrpnsp, 3 nlaapi, 4 wshbth */
CHILD(nsp_accepts) {
    static const char *dlls[] = { "winrnr.dll", "napinsp.dll", "pnrpnsp.dll", "nlaapi.dll", "wshbth.dll" };
    int kind = atoi(argv[1]); int bad = 0; DWORD gle; NSP_ROUTINE t; INT r;
    HMODULE m = LoadLibraryA(dlls[kind]); if (!m) return 90;
    nspstartup_fn f = (nspstartup_fn)GetProcAddress(m, "NSPStartup"); if (!f) return 91;
    const GUID *all[] = { &G_NLA, &G_DNS, &G_EMAIL, &G_PNRP, &G_PNRPC, &G_BTH, &G_ZERO };
    const GUID *good[2] = { NULL, NULL }; int ngood = 0; DWORD good_cb = 0x58; DWORD good_major = 1, good_minor = 0;
    switch (kind) {
    case 1: good[ngood++] = &G_EMAIL; break;
    case 2: good[ngood++] = &G_PNRP; good[ngood++] = &G_PNRPC; break;
    case 3: good[ngood++] = &G_NLA; break;
    default: break;
    }
    for (size_t i = 0; i < ANC_N(all); i++) {
        int is_good = (kind == 0 || kind == 4); for (int k = 0; k < ngood; k++) if (good[k] == all[i]) is_good = 1;
        r = start(f, all[i], &t, 0x58, &gle);
        if (is_good) {
            if (r != 0) { bad |= BAD(0); continue; }
            if (kind == 0 || kind == 4) { good_cb = 0x50; good_major = 1; good_minor = 1; }
            if (t.cbSize != good_cb || t.dwMajorVersion != good_major || t.dwMinorVersion != good_minor) bad |= BAD(1);
            int want = (kind == 0 || kind == 4) ? 0x0ff : 0x1ff;
            if (fn_mask(&t) != want) bad |= BAD(2);
            if (GetLastError() != 0 && kind == 3) bad |= BAD(3);
            if (t.NSPCleanup) { if (((nspcleanup_fn)t.NSPCleanup)((LPGUID)all[i]) != 0) bad |= BAD(4); }
        } else {
            if (r != -1 || gle != 10108) bad |= BAD(5);
            if (!table_untouched(&t, 0x58)) bad |= BAD(6);
        }
    }
    return bad;
}

CHILD(nsp_null_args) {
    static const char *dlls[] = { "winrnr.dll", "napinsp.dll", "pnrpnsp.dll", "nlaapi.dll", "wshbth.dll" };
    int kind = atoi(argv[1]); int bad = 0; DWORD gle; NSP_ROUTINE t; INT r;
    HMODULE m = LoadLibraryA(dlls[kind]); if (!m) return 90;
    nspstartup_fn f = (nspstartup_fn)GetProcAddress(m, "NSPStartup"); if (!f) return 91;
    /* NULL provider id */
    r = start(f, NULL, &t, 0x58, &gle);
    switch (kind) {
    case 1: case 2: case 3: if (r != -1 || gle != 10108 || !table_untouched(&t, 0x58)) bad |= BAD(0); break;
    default: if (r != 0) bad |= BAD(0); else if (t.NSPCleanup) ((nspcleanup_fn)t.NSPCleanup)(NULL); break;
    }
    /* NULL table (only providers that check it before the id) */
    if (kind == 1 || kind == 3) { SetLastError(0); r = f((LPGUID)&G_NLA, NULL); if (r != -1 || GetLastError() != 10022) bad |= BAD(1); }
    if (kind == 2) { SetLastError(0); r = f((LPGUID)&G_NLA, NULL); if (r != -1 || GetLastError() != 10108) bad |= BAD(2); }
    return bad;
}

CHILD(nsp_cbsize) {
    static const char *dlls[] = { "winrnr.dll", "napinsp.dll", "pnrpnsp.dll", "nlaapi.dll", "wshbth.dll" };
    int kind = atoi(argv[1]); int bad = 0; DWORD gle; NSP_ROUTINE t; INT r;
    HMODULE m = LoadLibraryA(dlls[kind]); if (!m) return 90;
    nspstartup_fn f = (nspstartup_fn)GetProcAddress(m, "NSPStartup"); if (!f) return 91;
    static const DWORD cbs[] = { 0, 4, 0x30, 0x4f, 0x50, 0x57, 0x58, 0x59, 0x100, 0xffffffffu };
    if (kind == 0 || kind == 3) {   /* the caller's cbSize is ignored */
        const GUID *g = kind == 3 ? &G_NLA : &G_DNS;
        for (size_t i = 0; i < ANC_N(cbs); i++) {
            r = start(f, g, &t, cbs[i], &gle);
            if (r != 0) { bad |= BAD(0); continue; }
            if (t.cbSize != (kind == 0 ? 0x50u : 0x58u)) bad |= BAD(1);
            if (t.NSPCleanup) ((nspcleanup_fn)t.NSPCleanup)((LPGUID)g);
        }
    } else if (kind == 4) {         /* the Bluetooth start-up copies as much of its table as the caller says it can hold */
        for (size_t i = 0; i < ANC_N(cbs); i++) {
            r = start(f, &G_BTH, &t, cbs[i], &gle);
            if (cbs[i] < 0x50) {
                if (r != -1 || gle != 10104 || !table_untouched(&t, cbs[i])) bad |= BAD(2);
            } else {
                if (r != 0) { bad |= BAD(3); continue; }
                if (t.cbSize != 0x50 || t.dwMajorVersion != 1 || t.dwMinorVersion != 1) bad |= BAD(4);
                if (fn_mask(&t) & 0xff ? (fn_mask(&t) & 0xff) != 0xff : 1) bad |= BAD(5);
                if (cbs[i] >= 0x58) { if (PTR_SLOT(&t, 8) != NULL) bad |= BAD(6); }
                else { if (PTR_SLOT(&t, 8) != (void *)0xCCCCCCCCCCCCCCCCull) bad |= BAD(7); }
            }
        }
    }
    return bad;
}

static void run(const char *child, int kind, const char *dll) {
    char a[32];
    if (!t_module(dll)) { t_skip("%s is not present on this system", dll); return; }
    sprintf(a, "%d", kind);
    DWORD rc = t_run_child(child, a, 30000);
    CHECKF(rc == 0, "%s %s: child returned 0x%lx", dll, child, rc);
}

TEST(nsp_winrnr_startup_ignores_the_provider_id) { run("nsp_accepts", 0, "winrnr.dll"); }
TEST(nsp_napinsp_startup_accepts_only_the_email_shim_id) { run("nsp_accepts", 1, "napinsp.dll"); }
TEST(nsp_pnrpnsp_startup_accepts_only_the_two_pnrp_ids) { run("nsp_accepts", 2, "pnrpnsp.dll"); }
TEST(nsp_nlaapi_startup_accepts_only_the_nla_id) { run("nsp_accepts", 3, "nlaapi.dll"); }
TEST(nsp_wshbth_startup_ignores_the_provider_id) { run("nsp_accepts", 4, "wshbth.dll"); }
TEST(nsp_napinsp_null_arguments) { run("nsp_null_args", 1, "napinsp.dll"); }
TEST(nsp_pnrpnsp_null_arguments) { run("nsp_null_args", 2, "pnrpnsp.dll"); }
TEST(nsp_nlaapi_null_arguments) { run("nsp_null_args", 3, "nlaapi.dll"); }
TEST(nsp_winrnr_null_provider_id) { run("nsp_null_args", 0, "winrnr.dll"); }
TEST(nsp_wshbth_null_provider_id) { run("nsp_null_args", 4, "wshbth.dll"); }
TEST(nsp_winrnr_table_size_is_not_consulted) { run("nsp_cbsize", 0, "winrnr.dll"); }
TEST(nsp_nlaapi_table_size_is_not_consulted) { run("nsp_cbsize", 3, "nlaapi.dll"); }
TEST(nsp_wshbth_table_size_selects_the_copy_length) { run("nsp_cbsize", 4, "wshbth.dll"); }

/* Table layout facts the header promises, independent of any provider. */
TEST(nsp_routine_table_is_88_bytes_with_nine_slots) {
    CHECK(sizeof(NSP_ROUTINE) == 0x58);
    CHECK(offsetof(NSP_ROUTINE, NSPCleanup) == 0x10);
    CHECK(offsetof(NSP_ROUTINE, NSPIoctl) == 0x50);
}
