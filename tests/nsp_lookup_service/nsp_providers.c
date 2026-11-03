/* Name-space providers loaded directly: NSPStartup of mswsock (DNS), nlaapi (NLA), napinsp and
 * winrnr, the NSP_ROUTINE table each fills in, and the provider-side routines of the DNS and NLA
 * providers called through that table (no ws2_32 name-space dispatcher in between).
 * Measures: export presence, table layout and which routines exist, the error each provider's
 * startup/cleanup/routines give for a wrong provider id, a NULL table or a missing startup, and
 * the DNS provider's own validation of query sets, flags and handles on loopback names. */
#include "nsp.h"

typedef INT (WSAAPI *nspstartup_fn)(LPGUID, LPNSP_ROUTINE);

static nspstartup_fn startup_of(const char *dll) {
    return (nspstartup_fn)t_proc_in(dll, "NSPStartup");
}

static int load_ok(const char *dll) { return t_module(dll) != NULL; }

/* ---- the table layout the header describes matches the offsets providers write ---- */

TEST(np_routine_table_layout) {
    EXPECT_EQ(sizeof(NSP_ROUTINE), 0x58);
    EXPECT_EQ(offsetof(NSP_ROUTINE, NSPCleanup), 0x10);
    EXPECT_EQ(offsetof(NSP_ROUTINE, NSPLookupServiceBegin), 0x18);
    EXPECT_EQ(offsetof(NSP_ROUTINE, NSPLookupServiceNext), 0x20);
    EXPECT_EQ(offsetof(NSP_ROUTINE, NSPLookupServiceEnd), 0x28);
    EXPECT_EQ(offsetof(NSP_ROUTINE, NSPSetService), 0x30);
    EXPECT_EQ(offsetof(NSP_ROUTINE, NSPInstallServiceClass), 0x38);
    EXPECT_EQ(offsetof(NSP_ROUTINE, NSPRemoveServiceClass), 0x40);
    EXPECT_EQ(offsetof(NSP_ROUTINE, NSPGetServiceClassInfo), 0x48);
    EXPECT_EQ(offsetof(NSP_ROUTINE, NSPIoctl), 0x50);
}

/* ---- exports ---- */

static const struct { const char *dll; unsigned ord; } nsp_exports[] = {
    { "mswsock.dll", 17 }, { "nlaapi.dll", 3 }, { "napinsp.dll", 2 }, { "winrnr.dll", 2 },
};

TEST(np_nspstartup_exported_by_name_and_ordinal) {
    size_t i;
    for (i = 0; i < NSP_N(nsp_exports); i++) {
        FARPROC byname, byord;
        if (!load_ok(nsp_exports[i].dll)) { t_note("%s did not load", nsp_exports[i].dll); continue; }
        byname = t_proc_in(nsp_exports[i].dll, "NSPStartup");
        byord = t_proc_ord(nsp_exports[i].dll, nsp_exports[i].ord);
        CHECKF(byname != NULL, "%s: NSPStartup missing", nsp_exports[i].dll);
        CHECKF(byname == byord, "%s: ordinal %u is not NSPStartup", nsp_exports[i].dll, nsp_exports[i].ord);
    }
}

TEST(np_rasadhlp_exports_present) {
    static const char *names[] = { "AcsHlpNbConnection", "WSAttemptAutodialAddr", "WSAttemptAutodialName", "WSNoteSuccessfulHostentLookup" };
    size_t i;
    if (!load_ok("rasadhlp.dll")) { t_skip("rasadhlp.dll did not load"); return; }
    for (i = 0; i < NSP_N(names); i++) CHECKF(t_proc_in("rasadhlp.dll", names[i]) != NULL, "%s missing", names[i]);
}

TEST(np_rasadhlp_ordinals) {
    static const char *names[] = { "AcsHlpNbConnection", "WSAttemptAutodialAddr", "WSAttemptAutodialName", "WSNoteSuccessfulHostentLookup" };
    size_t i;
    if (!load_ok("rasadhlp.dll")) { t_skip("rasadhlp.dll did not load"); return; }
    for (i = 0; i < NSP_N(names); i++) CHECKF(t_proc_ord("rasadhlp.dll", (unsigned)i + 1) == t_proc_in("rasadhlp.dll", names[i]), "%s is not ordinal %zu", names[i], i + 1);
}

TEST(np_rasadhlp_helpers_null_and_unrelated_family) {
    typedef int (WINAPI *acs_fn)(LPCWSTR);
    typedef int (WINAPI *addr_fn)(const SOCKADDR *);
    typedef void (WINAPI *note_fn)(const char *, DWORD);
    acs_fn acs; addr_fn addr; note_fn note;
    SOCKADDR_IN6 s6;
    if (!load_ok("rasadhlp.dll")) { t_skip("rasadhlp.dll did not load"); return; }
    acs = (acs_fn)t_proc_in("rasadhlp.dll", "AcsHlpNbConnection");
    addr = (addr_fn)t_proc_in("rasadhlp.dll", "WSAttemptAutodialAddr");
    note = (note_fn)t_proc_in("rasadhlp.dll", "WSNoteSuccessfulHostentLookup");
    REQUIRE(acs); REQUIRE(addr); REQUIRE(note);
    EXPECT_EQ(acs(NULL), 0);                           /* nothing to connect to */
    memset(&s6, 0, sizeof s6); s6.sin6_family = AF_INET6;
    EXPECT_EQ(addr((SOCKADDR *)&s6), 0);               /* only IPv4 and NetBIOS addresses are considered */
    note(NULL, 0);                                     /* a NULL name is ignored */
    note("", 0);                                       /* so is an empty one */
}

/* ---- startup/cleanup sequences run in a child so process-wide provider state is fresh ---- */

CHILD(np_nla_sequence) {
    nspstartup_fn st = startup_of("nlaapi.dll");
    NSP_ROUTINE rt; GUID other = nsp_guid_throwaway; int bad = 0; INT r;
    if (!st) return 90;
    /* wrong ids and tables */
    memset(&rt, 0xCC, sizeof rt);
    SetLastError(0); r = st(NULL, &rt);
    if (r != -1 || GetLastError() != E_SVC_NOTFOUND) bad |= 1;
    SetLastError(0); r = st(&other, &rt);
    if (r != -1 || GetLastError() != E_SVC_NOTFOUND) bad |= 2;
    SetLastError(0); r = st((GUID *)&nsp_guid_nla, NULL);
    if (r != -1 || GetLastError() != E_INVAL) bad |= 4;
    SetLastError(0); r = st(NULL, NULL);                 /* the provider id is checked first */
    if (r != -1 || GetLastError() != E_SVC_NOTFOUND) bad |= 8;
    /* a failed startup leaves the table untouched */
    if (((BYTE *)&rt)[0] != 0xCC) bad |= 16;
    return bad;
}

TEST(np_nla_startup_rejections) {
    if (!load_ok("nlaapi.dll")) { t_skip("nlaapi.dll did not load"); return; }
    EXPECT_EQ(t_run_child("np_nla_sequence", "", 30000), 0);
}

CHILD(np_nla_table) {
    nspstartup_fn st = startup_of("nlaapi.dll");
    NSP_ROUTINE rt; int bad = 0;
    if (!st) return 90;
    memset(&rt, 0xCC, sizeof rt);
    SetLastError(0xdead);
    if (st((GUID *)&nsp_guid_nla, &rt) != 0) return 91;
    if (GetLastError() != 0) bad |= 1;                    /* success clears the error */
    if (rt.cbSize != 0x58) bad |= 2;
    if (rt.dwMajorVersion != 1) bad |= 4;
    if (rt.dwMinorVersion != 0) bad |= 8;
    if (!rt.NSPCleanup || !rt.NSPLookupServiceBegin || !rt.NSPLookupServiceNext || !rt.NSPLookupServiceEnd) bad |= 16;
    if (!rt.NSPSetService || !rt.NSPInstallServiceClass || !rt.NSPRemoveServiceClass || !rt.NSPGetServiceClassInfo) bad |= 32;
    if (!rt.NSPIoctl) bad |= 64;
    /* a second startup hands out the same routines */
    {   NSP_ROUTINE rt2;
        if (st((GUID *)&nsp_guid_nla, &rt2) != 0) bad |= 128;
        else {
            if (rt2.NSPLookupServiceBegin != rt.NSPLookupServiceBegin || rt2.NSPCleanup != rt.NSPCleanup) bad |= 256;
            if (rt2.NSPCleanup((GUID *)&nsp_guid_nla) != 0) bad |= 512;
        }
    }
    if (rt.NSPCleanup((GUID *)&nsp_guid_nla) != 0) bad |= 1024;
    return bad;
}

TEST(np_nla_startup_fills_routine_table) {
    if (!load_ok("nlaapi.dll")) { t_skip("nlaapi.dll did not load"); return; }
    EXPECT_EQ(t_run_child("np_nla_table", "", 30000), 0);
}

CHILD(np_nla_routines) {
    nspstartup_fn st = startup_of("nlaapi.dll");
    NSP_ROUTINE rt; int bad = 0; GUID other = nsp_guid_throwaway, cls = nsp_guid_throwaway;
    WSASERVICECLASSINFOW info; DWORD len = 0x80; INT r;
    if (!st) return 90;
    if (st((GUID *)&nsp_guid_nla, &rt) != 0) return 91;
    memset(&info, 0, sizeof info);
    /* InstallServiceClass: provider id first, then the class description, then "not supported". */
    SetLastError(0); r = rt.NSPInstallServiceClass(NULL, &info);
    if (r != -1 || GetLastError() != E_SVC_NOTFOUND) bad |= 1;
    SetLastError(0); r = rt.NSPInstallServiceClass(&other, &info);
    if (r != -1 || GetLastError() != E_SVC_NOTFOUND) bad |= 2;
    SetLastError(0); r = rt.NSPInstallServiceClass((GUID *)&nsp_guid_nla, NULL);
    if (r != -1 || GetLastError() != E_INVAL) bad |= 4;
    SetLastError(0); r = rt.NSPInstallServiceClass((GUID *)&nsp_guid_nla, &info);
    if (r != -1 || GetLastError() != WSAEOPNOTSUPP) bad |= 8;
    /* RemoveServiceClass: NULL checks first, then the ids. */
    SetLastError(0); r = rt.NSPRemoveServiceClass(NULL, &cls);
    if (r != -1 || GetLastError() != E_INVAL) bad |= 16;
    SetLastError(0); r = rt.NSPRemoveServiceClass((GUID *)&nsp_guid_nla, NULL);
    if (r != -1 || GetLastError() != E_INVAL) bad |= 32;
    SetLastError(0); r = rt.NSPRemoveServiceClass((GUID *)&nsp_guid_nla, &cls);
    if (r != -1 || GetLastError() != E_SVC_NOTFOUND) bad |= 64;
    SetLastError(0); r = rt.NSPRemoveServiceClass(&other, &cls);
    if (r != -1 || GetLastError() != E_SVC_NOTFOUND) bad |= 128;
    /* GetServiceClassInfo */
    SetLastError(0); r = rt.NSPGetServiceClassInfo(NULL, &len, &info);
    if (r != -1 || GetLastError() != E_SVC_NOTFOUND) bad |= 256;
    SetLastError(0); r = rt.NSPGetServiceClassInfo(&other, &len, &info);
    if (r != -1 || GetLastError() != E_SVC_NOTFOUND) bad |= 512;
    SetLastError(0); r = rt.NSPGetServiceClassInfo((GUID *)&nsp_guid_nla, NULL, &info);
    if (r != -1 || GetLastError() != E_INVAL) bad |= 1024;
    SetLastError(0); r = rt.NSPGetServiceClassInfo((GUID *)&nsp_guid_nla, &len, NULL);
    if (r != -1 || GetLastError() != E_INVAL) bad |= 2048;
    SetLastError(0); r = rt.NSPGetServiceClassInfo((GUID *)&nsp_guid_nla, &len, &info);
    if (r != -1 || GetLastError() != WSAEOPNOTSUPP) bad |= 4096;
    /* Cleanup with the wrong id keeps the provider started. */
    SetLastError(0); r = rt.NSPCleanup(&other);
    if (r != -1 || GetLastError() != E_SVC_NOTFOUND) bad |= 8192;
    SetLastError(0); r = rt.NSPCleanup(NULL);
    if (r != -1 || GetLastError() != E_SVC_NOTFOUND) bad |= 16384;
    /* No final cleanup: the provider's rejected calls keep their call reference, and the last
     * cleanup would then wait for them forever. The child simply exits. */
    return bad;
}

TEST(np_nla_routines_validate_provider_id_and_arguments) {
    if (!load_ok("nlaapi.dll")) { t_skip("nlaapi.dll did not load"); return; }
    EXPECT_EQ(t_run_child("np_nla_routines", "", 30000), 0);
}

CHILD(np_nla_after_cleanup) {
    nspstartup_fn st = startup_of("nlaapi.dll");
    NSP_ROUTINE rt; int bad = 0; INT r; WSASERVICECLASSINFOW info; DWORD len = 8;
    if (!st) return 90;
    if (st((GUID *)&nsp_guid_nla, &rt) != 0) return 91;
    if (rt.NSPCleanup((GUID *)&nsp_guid_nla) != 0) bad |= 1;
    /* With the last reference gone every routine reports WSANOTINITIALISED. */
    memset(&info, 0, sizeof info);
    SetLastError(0); r = rt.NSPCleanup((GUID *)&nsp_guid_nla);
    if (r != -1 || GetLastError() != E_NOTINIT) bad |= 2;
    SetLastError(0); r = rt.NSPInstallServiceClass((GUID *)&nsp_guid_nla, &info);
    if (r != -1 || GetLastError() != E_NOTINIT) bad |= 4;
    SetLastError(0); r = rt.NSPGetServiceClassInfo((GUID *)&nsp_guid_nla, &len, &info);
    if (r != -1 || GetLastError() != E_NOTINIT) bad |= 8;
    SetLastError(0); r = rt.NSPRemoveServiceClass((GUID *)&nsp_guid_nla, (GUID *)&nsp_guid_nla);
    if (r != -1 || GetLastError() != E_NOTINIT) bad |= 16;
    SetLastError(0); r = rt.NSPLookupServiceEnd((HANDLE)(ULONG_PTR)0x10);
    if (r != -1 || GetLastError() != E_NOTINIT) bad |= 32;
    return bad;
}

TEST(np_nla_routines_after_last_cleanup_report_not_initialised) {
    if (!load_ok("nlaapi.dll")) { t_skip("nlaapi.dll did not load"); return; }
    EXPECT_EQ(t_run_child("np_nla_after_cleanup", "", 30000), 0);
}

CHILD(np_nla_refcount) {
    nspstartup_fn st = startup_of("nlaapi.dll");
    NSP_ROUTINE a, b, c; int bad = 0; INT r;
    if (!st) return 90;
    if (st((GUID *)&nsp_guid_nla, &a) != 0 || st((GUID *)&nsp_guid_nla, &b) != 0 || st((GUID *)&nsp_guid_nla, &c) != 0) return 91;
    /* three startups need three cleanups; the fourth finds nothing started */
    if (a.NSPCleanup((GUID *)&nsp_guid_nla) != 0) bad |= 1;
    if (a.NSPCleanup((GUID *)&nsp_guid_nla) != 0) bad |= 2;
    if (a.NSPCleanup((GUID *)&nsp_guid_nla) != 0) bad |= 4;
    SetLastError(0); r = a.NSPCleanup((GUID *)&nsp_guid_nla);
    if (r != -1 || GetLastError() != E_NOTINIT) bad |= 8;
    /* the provider can be started again afterwards */
    if (st((GUID *)&nsp_guid_nla, &a) != 0) bad |= 16;
    else if (a.NSPCleanup((GUID *)&nsp_guid_nla) != 0) bad |= 32;
    return bad;
}

TEST(np_nla_startup_is_reference_counted) {
    if (!load_ok("nlaapi.dll")) { t_skip("nlaapi.dll did not load"); return; }
    EXPECT_EQ(t_run_child("np_nla_refcount", "", 30000), 0);
}

/* ---- napinsp ---- */

CHILD(np_napi_rejections) {
    nspstartup_fn st = startup_of("napinsp.dll");
    NSP_ROUTINE rt; int bad = 0; INT r;
    if (!st) return 90;
    /* The table pointer is checked before the provider id. */
    SetLastError(0); r = st(NULL, NULL);
    if (r != -1 || GetLastError() != E_INVAL) bad |= 1;
    SetLastError(0); r = st((GUID *)&nsp_guid_nla, NULL);
    if (r != -1 || GetLastError() != E_INVAL) bad |= 2;
    /* a provider id that is not the naming provider's */
    SetLastError(0); r = st((GUID *)&nsp_guid_nla, &rt);
    if (r != -1 || GetLastError() != E_SVC_NOTFOUND) bad |= 4;
    SetLastError(0); r = st(NULL, &rt);
    if (r != -1 || GetLastError() != E_SVC_NOTFOUND) bad |= 8;
    SetLastError(0); r = st((GUID *)&nsp_guid_throwaway, &rt);
    if (r != -1 || GetLastError() != E_SVC_NOTFOUND) bad |= 16;
    return bad;
}

TEST(np_napinsp_startup_rejections) {
    if (!load_ok("napinsp.dll")) { t_skip("napinsp.dll did not load"); return; }
    EXPECT_EQ(t_run_child("np_napi_rejections", "", 30000), 0);
}

TEST(np_napinsp_cleanup_without_startup_logged) {
    typedef INT (WSAAPI *cleanup_fn)(LPGUID);
    cleanup_fn cl; INT r;
    if (!load_ok("napinsp.dll")) { t_skip("napinsp.dll did not load"); return; }
    /* No NSP_ROUTINE is available without a successful startup, so the cleanup address is
     * not reachable here; only the export of the startup is exercised above. */
    (void)cl; (void)r;
    t_note("napinsp cleanup is reachable only through a started table");
}

/* ---- winrnr ---- */

CHILD(np_winrnr_table) {
    nspstartup_fn st = startup_of("winrnr.dll");
    NSP_ROUTINE rt; int bad = 0;
    if (!st) return 90;
    memset(&rt, 0, sizeof rt);
    if (st((GUID *)&nsp_guid_throwaway, &rt) != 0) return 91;   /* this provider does not look at the id */
    if (rt.cbSize < 0x50) bad |= 1;
    if (!rt.NSPCleanup || !rt.NSPLookupServiceBegin || !rt.NSPLookupServiceNext || !rt.NSPLookupServiceEnd) bad |= 2;
    if (!rt.NSPSetService || !rt.NSPInstallServiceClass || !rt.NSPRemoveServiceClass || !rt.NSPGetServiceClassInfo) bad |= 4;
    return bad;
}

TEST(np_winrnr_startup_fills_routine_table) {
    if (!load_ok("winrnr.dll")) { t_skip("winrnr.dll did not load"); return; }
    EXPECT_EQ(t_run_child("np_winrnr_table", "", 30000), 0);
}

TEST(np_winrnr_table_details_logged) {
    nspstartup_fn st = startup_of("winrnr.dll"); NSP_ROUTINE rt;
    if (!load_ok("winrnr.dll") || !st) { t_skip("winrnr.dll not available"); return; }
    memset(&rt, 0, sizeof rt);
    if (st((GUID *)&nsp_guid_throwaway, &rt) != 0) { t_note("winrnr startup failed"); return; }
    t_note("winrnr table: cbSize 0x%lx version %lu.%lu ioctl %s", (unsigned long)rt.cbSize, (unsigned long)rt.dwMajorVersion, (unsigned long)rt.dwMinorVersion, rt.NSPIoctl ? "present" : "absent");
}

/* ---- the DNS provider (mswsock) through its routine table ---- */

typedef struct { NSP_ROUTINE rt; GUID id; int ok; } dnsp;

static int dns_open(dnsp *d) {
    nspstartup_fn st = startup_of("mswsock.dll");
    memset(d, 0, sizeof *d);
    if (!st || !nsp_up()) return 0;
    if (!nsp_provider_for(NS_DNS, &d->id)) return 0;
    d->rt.cbSize = sizeof d->rt;
    if (st(&d->id, &d->rt) != 0) return 0;
    d->ok = 1;
    return 1;
}
static void dns_close(dnsp *d) { if (d->ok) d->rt.NSPCleanup(&d->id); d->ok = 0; }
#define DNS_NEED(d) do { if (!dns_open(&(d))) { t_skip("DNS provider not available"); return; } } while (0)

static HANDLE dns_begin(dnsp *d, DWORD flags, LPWSTR name) {
    WSAQUERYSETW qs; HANDLE h = NULL;
    nsp_query_w(&qs, name, &nsp_svcid_addr_by_name, NS_DNS);
    if (d->rt.NSPLookupServiceBegin(&d->id, &qs, NULL, flags, &h) != 0) return NULL;
    return h;
}

TEST(np_mswsock_startup_short_table_is_invalid_proc_table) {
    nspstartup_fn st = startup_of("mswsock.dll"); NSP_ROUTINE rt; GUID id;
    REQUIRE(st); NSP_NEED();
    if (!nsp_provider_for(NS_DNS, &id)) { t_skip("no DNS provider"); return; }
    memset(&rt, 0, sizeof rt);
    rt.cbSize = 0x10;                        /* the caller's table must be at least 0x58 bytes */
    SetLastError(0);
    EXPECT_EQ(st(&id, &rt), SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), WSAEINVALIDPROCTABLE);
    rt.cbSize = 0x57;
    SetLastError(0);
    EXPECT_EQ(st(&id, &rt), SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), WSAEINVALIDPROCTABLE);
    rt.cbSize = 0;
    SetLastError(0);
    EXPECT_EQ(st(&id, &rt), SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), WSAEINVALIDPROCTABLE);
}

TEST(np_mswsock_startup_fills_table) {
    dnsp d; DNS_NEED(d);
    EXPECT_EQ(d.rt.cbSize, 0x50);   /* the table ends before NSPIoctl */
    CHECK(d.rt.NSPIoctl == NULL);
    CHECK(d.rt.NSPCleanup && d.rt.NSPLookupServiceBegin && d.rt.NSPLookupServiceNext && d.rt.NSPLookupServiceEnd);
    CHECK(d.rt.NSPSetService && d.rt.NSPInstallServiceClass && d.rt.NSPRemoveServiceClass && d.rt.NSPGetServiceClassInfo);
    t_note("DNS provider table version %lu.%lu ioctl %s", (unsigned long)d.rt.dwMajorVersion, (unsigned long)d.rt.dwMinorVersion, d.rt.NSPIoctl ? "present" : "absent");
    dns_close(&d);
}

TEST(np_mswsock_startup_twice_gives_same_routines) {
    dnsp a, b; nspstartup_fn st = startup_of("mswsock.dll");
    DNS_NEED(a);
    memset(&b, 0, sizeof b); b.rt.cbSize = sizeof b.rt; b.id = a.id;
    EXPECT_EQ(st(&b.id, &b.rt), 0);
    CHECK(a.rt.NSPLookupServiceBegin == b.rt.NSPLookupServiceBegin);
    CHECK(a.rt.NSPLookupServiceNext == b.rt.NSPLookupServiceNext);
    CHECK(a.rt.NSPLookupServiceEnd == b.rt.NSPLookupServiceEnd);
    b.rt.NSPCleanup(&b.id);
    dns_close(&a);
}

TEST(np_mswsock_service_class_routines_not_supported) {
    dnsp d; WSASERVICECLASSINFOW info; GUID cls = nsp_guid_throwaway; DWORD len = 0;
    DNS_NEED(d);
    memset(&info, 0, sizeof info);
    SetLastError(0); EXPECT_EQ(d.rt.NSPInstallServiceClass(&d.id, &info), SOCKET_ERROR); EXPECT_EQ(GetLastError(), WSAEOPNOTSUPP);
    SetLastError(0); EXPECT_EQ(d.rt.NSPRemoveServiceClass(&d.id, &cls), SOCKET_ERROR); EXPECT_EQ(GetLastError(), WSAEOPNOTSUPP);
    SetLastError(0); EXPECT_EQ(d.rt.NSPGetServiceClassInfo(&d.id, &len, &info), SOCKET_ERROR); EXPECT_EQ(GetLastError(), WSAEOPNOTSUPP);
    dns_close(&d);
}

TEST(np_mswsock_set_service_not_supported_error) {
    dnsp d; WSAQUERYSETW qs; WCHAR nm[] = L"ws2t";
    DNS_NEED(d);
    nsp_query_w(&qs, nm, &nsp_guid_throwaway, NS_DNS);
    SetLastError(0);
    EXPECT_EQ(d.rt.NSPSetService(&d.id, NULL, &qs, RNRSERVICE_REGISTER, 0), SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), ERROR_NOT_SUPPORTED);
    dns_close(&d);
}

TEST(np_mswsock_begin_short_query_is_fault) {
    dnsp d; WSAQUERYSETW qs; WCHAR nm[] = L"localhost"; HANDLE h = NULL; DWORD sizes[] = { 0, 1, 0x40, 0x77 }; size_t i;
    DNS_NEED(d);
    for (i = 0; i < NSP_N(sizes); i++) {
        nsp_query_w(&qs, nm, &nsp_svcid_addr_by_name, NS_DNS);
        qs.dwSize = sizes[i];
        SetLastError(0);
        CHECKF(d.rt.NSPLookupServiceBegin(&d.id, &qs, NULL, 0, &h) == SOCKET_ERROR, "dwSize %lu accepted", (unsigned long)sizes[i]);
        CHECKF(GetLastError() == E_FAULT, "dwSize %lu: error %lu", (unsigned long)sizes[i], GetLastError());
    }
    dns_close(&d);
}

TEST(np_mswsock_begin_localhost_returns_handle) {
    dnsp d; HANDLE h;
    DNS_NEED(d);
    h = dns_begin(&d, 0, (LPWSTR)L"localhost");
    CHECK(h != NULL);
    if (h) EXPECT_EQ(d.rt.NSPLookupServiceEnd(h), 0);
    dns_close(&d);
}

TEST(np_mswsock_begin_without_class_is_invalid_parameter) {
    dnsp d; WSAQUERYSETW qs; WCHAR nm[] = L"localhost"; HANDLE h = NULL;
    DNS_NEED(d);
    nsp_query_w(&qs, nm, NULL, NS_DNS);
    SetLastError(0);
    EXPECT_EQ(d.rt.NSPLookupServiceBegin(&d.id, &qs, NULL, 0, &h), SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), ERROR_INVALID_PARAMETER);
    dns_close(&d);
}

TEST(np_mswsock_begin_flag_table) {
    static const struct { DWORD flags; int ok; DWORD err; } t[] = {
        { 0, 1, 0 }, { LUP_RETURN_NAME, 1, 0 }, { LUP_RETURN_ALL, 1, 0 }, { LUP_DEEP, 1, 0 }, { LUP_NOCONTAINERS, 1, 0 },
        { LUP_CONTAINERS, 0, E_NODATA },   /* a host name is not a container */
        { LUP_CONTAINERS | LUP_NOCONTAINERS, 0, E_BADPARAM }, { 0x4000, 0, E_BADPARAM }, { 0x10000, 0, E_BADPARAM },
        { 0x40000, 0, E_BADPARAM }, { 0x80000, 0, E_BADPARAM }, { 0x04000000, 0, E_BADPARAM }, { 0x08000000, 0, E_BADPARAM },
        { 0x10000000, 0, E_BADPARAM }, { 0x20000000, 0, E_BADPARAM }, { 0x40000000, 0, E_BADPARAM },
    };
    dnsp d; size_t i;
    DNS_NEED(d);
    for (i = 0; i < NSP_N(t); i++) {
        HANDLE h = dns_begin(&d, t[i].flags, (LPWSTR)L"localhost");
        if (t[i].ok) { CHECKF(h != NULL, "flags 0x%lx rejected (err %lu)", (unsigned long)t[i].flags, GetLastError()); }
        else { CHECKF(h == NULL, "flags 0x%lx accepted", (unsigned long)t[i].flags); if (!h) CHECKF(GetLastError() == t[i].err, "flags 0x%lx: error %lu want %u", (unsigned long)t[i].flags, GetLastError(), t[i].err); }
        if (h) d.rt.NSPLookupServiceEnd(h);
    }
    dns_close(&d);
}

TEST(np_mswsock_next_and_end_unknown_handle) {
    dnsp d; BYTE buf[0x200]; DWORD len = sizeof buf; HANDLE bogus = (HANDLE)(ULONG_PTR)0x1000;
    DNS_NEED(d);
    SetLastError(0);
    EXPECT_EQ(d.rt.NSPLookupServiceNext(bogus, 0, &len, (WSAQUERYSETW *)buf), SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
    SetLastError(0);
    EXPECT_EQ(d.rt.NSPLookupServiceEnd(bogus), SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
    dns_close(&d);
}

TEST(np_mswsock_next_flag_check_precedes_handle_check) {
    dnsp d; BYTE buf[0x200]; DWORD len = sizeof buf; HANDLE bogus = (HANDLE)(ULONG_PTR)0x1000;
    DNS_NEED(d);
    SetLastError(0);
    EXPECT_EQ(d.rt.NSPLookupServiceNext(bogus, 0x4000, &len, (WSAQUERYSETW *)buf), SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), ERROR_INVALID_PARAMETER);
    dns_close(&d);
}

TEST(np_mswsock_end_twice_second_is_invalid_handle) {
    dnsp d; HANDLE h;
    DNS_NEED(d);
    h = dns_begin(&d, LUP_RETURN_NAME, (LPWSTR)L"localhost");
    if (!h) { t_skip("begin failed"); dns_close(&d); return; }
    EXPECT_EQ(d.rt.NSPLookupServiceEnd(h), 0);
    SetLastError(0);
    EXPECT_EQ(d.rt.NSPLookupServiceEnd(h), SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
    dns_close(&d);
}

TEST(np_mswsock_next_after_end_is_invalid_handle) {
    dnsp d; HANDLE h; BYTE buf[0x200]; DWORD len = sizeof buf;
    DNS_NEED(d);
    h = dns_begin(&d, LUP_RETURN_NAME, (LPWSTR)L"localhost");
    if (!h) { t_skip("begin failed"); dns_close(&d); return; }
    d.rt.NSPLookupServiceEnd(h);
    SetLastError(0);
    EXPECT_EQ(d.rt.NSPLookupServiceNext(h, 0, &len, (WSAQUERYSETW *)buf), SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
    dns_close(&d);
}

TEST(np_mswsock_next_buffer_protocol_and_header) {
    dnsp d; HANDLE h; DWORD need = 0, len; BYTE *buf;
    DNS_NEED(d);
    h = dns_begin(&d, LUP_RETURN_NAME | LUP_RETURN_ADDR, (LPWSTR)L"localhost");
    if (!h) { t_skip("begin failed"); dns_close(&d); return; }
    len = 0;
    SetLastError(0);
    EXPECT_EQ(d.rt.NSPLookupServiceNext(h, 0, &len, NULL), SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), E_FAULT);
    need = len;
    CHECK(need > NSP_SZ_QS_W);
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, need);
    if (buf) {
        WSAQUERYSETW *r = (WSAQUERYSETW *)buf;
        len = need;
        EXPECT_EQ(d.rt.NSPLookupServiceNext(h, 0, &len, r), 0);
        EXPECT_EQ(r->dwSize, NSP_SZ_QS_W);
        EXPECT_EQ(r->dwNameSpace, NS_DNS);       /* the provider stamps its own name space */
        CHECK(r->lpszServiceInstanceName != NULL);
        CHECK(r->lpcsaBuffer != NULL && r->dwNumberOfCsAddrs >= 1);
        SetLastError(0);
        len = need;
        EXPECT_EQ(d.rt.NSPLookupServiceNext(h, 0, &len, r), SOCKET_ERROR);
        EXPECT_EQ(GetLastError(), E_NO_MORE);
        HeapFree(GetProcessHeap(), 0, buf);
    }
    d.rt.NSPLookupServiceEnd(h);
    dns_close(&d);
}

TEST(np_mswsock_next_small_buffer_does_not_write) {
    dnsp d; HANDLE h; BYTE buf[0x78]; DWORD len = 0x40;
    DNS_NEED(d);
    h = dns_begin(&d, LUP_RETURN_NAME | LUP_RETURN_ADDR, (LPWSTR)L"localhost");
    if (!h) { t_skip("begin failed"); dns_close(&d); return; }
    memset(buf, 0x5A, sizeof buf);
    SetLastError(0);
    EXPECT_EQ(d.rt.NSPLookupServiceNext(h, 0, &len, (WSAQUERYSETW *)buf), SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), E_FAULT);
    CHECK(len >= NSP_SZ_QS_W);
    CHECK(buf[0] == 0x5A && buf[0x30] == 0x5A);
    d.rt.NSPLookupServiceEnd(h);
    dns_close(&d);
}

TEST(np_mswsock_return_type_flag) {
    dnsp d; HANDLE h; DWORD len = 0; BYTE *buf;
    DNS_NEED(d);
    h = dns_begin(&d, LUP_RETURN_TYPE, (LPWSTR)L"localhost");
    if (!h) { t_skip("begin failed"); dns_close(&d); return; }
    d.rt.NSPLookupServiceNext(h, 0, &len, NULL);
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
    if (buf) {
        DWORD l = len; WSAQUERYSETW *r = (WSAQUERYSETW *)buf;
        if (d.rt.NSPLookupServiceNext(h, 0, &l, r) == 0) {
            CHECK(r->lpServiceClassId != NULL);
            if (r->lpServiceClassId) CHECK(IsEqualGUID(r->lpServiceClassId, &nsp_svcid_addr_by_name));
        } else CHECKF(0, "next failed (%lu)", GetLastError());
        HeapFree(GetProcessHeap(), 0, buf);
    }
    d.rt.NSPLookupServiceEnd(h);
    dns_close(&d);
}

TEST(np_mswsock_unrelated_cleanup_ids_logged) {
    dnsp d; GUID other = nsp_guid_throwaway;
    DNS_NEED(d);
    SetLastError(0);
    t_note("DNS cleanup with a foreign id: result %d error %lu", d.rt.NSPCleanup(&other), GetLastError());
    dns_close(&d);
}

/* ---- ws2_32 and the provider agree ---- */

TEST(np_direct_and_dispatched_lookup_agree_on_address_count) {
    dnsp d; HANDLE h; WSAQUERYSETW qs; WCHAR nm[] = L"localhost"; DWORD len = 0; BYTE *buf; int via_ws2, eb, el;
    DNS_NEED(d);
    nsp_query_w(&qs, nm, &nsp_svcid_addr_by_name, NS_DNS);
    via_ws2 = nsp_count_w(&qs, LUP_RETURN_NAME | LUP_RETURN_ADDR, &eb, &el);
    h = dns_begin(&d, LUP_RETURN_NAME | LUP_RETURN_ADDR, nm);
    if (!h || via_ws2 < 1) { t_skip("lookup unavailable"); if (h) d.rt.NSPLookupServiceEnd(h); dns_close(&d); return; }
    d.rt.NSPLookupServiceNext(h, 0, &len, NULL);
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
    if (buf) {
        DWORD l = len;
        if (d.rt.NSPLookupServiceNext(h, 0, &l, (WSAQUERYSETW *)buf) == 0) {
            HANDLE h2 = NULL; nsp_buf b = {0};
            if (W_BEGIN_W(&qs, LUP_RETURN_NAME | LUP_RETURN_ADDR, &h2) == 0 && nsp_next_w(h2, 0, &b, NULL) == 0)
                EXPECT_EQ(((WSAQUERYSETW *)buf)->dwNumberOfCsAddrs, ((WSAQUERYSETW *)b.p)->dwNumberOfCsAddrs);
            nsp_buf_free(&b);
            if (h2) W_END(h2);
        }
        HeapFree(GetProcessHeap(), 0, buf);
    }
    d.rt.NSPLookupServiceEnd(h);
    dns_close(&d);
}
