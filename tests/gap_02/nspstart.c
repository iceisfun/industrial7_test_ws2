/* The start-up entry point of the DNS name-space provider in mswsock (NSPStartup), called directly after
 * the library was initialised. Measures: which table sizes are refused and with what error, what is
 * written into a larger table, whether the provider id is checked, that every routine pointer points
 * into the provider's own image, and that the matching cleanup always reports success.
 * Why: the start-up routine only compares the caller's table size with the 0x58-byte routine table,
 * bumps a use count, loads the host-name strings and copies the 0x58-byte routine vector; the provider
 * id merely selects bookkeeping bits for two well-known ids and is never rejected. */
#include "g2.h"

typedef INT (WSAAPI *nspstartup_fn)(LPGUID, LPNSP_ROUTINE);
typedef INT (WSAAPI *nspcleanup_fn)(LPGUID);

/* An emulator that does not implement the provider entry point aborts the process when it is called. */
static nspstartup_fn start_fn(void) { return t_is_wine() ? NULL : (nspstartup_fn)t_proc_in("mswsock.dll", "NSPStartup"); }

static int own_image(const void *fn) {
    HMODULE m = NULL, self = t_module("mswsock.dll");
    if (!fn) return 0;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)fn, &m)) return 0;
    return m == self;
}

static void balance(NSP_ROUTINE *rt, GUID *id) {
    if (rt->NSPCleanup) ((nspcleanup_fn)rt->NSPCleanup)(id);
}

TEST(gap2_nsp_start_short_table_sizes_are_invalid_proc_table) {
    static const DWORD sizes[] = { 0, 1, 4, 0x10, 0x28, 0x50, 0x54, 0x57 };
    nspstartup_fn st = start_fn(); int i;
    REQUIRE(st); G2_NEED();
    for (i = 0; i < G2_N(sizes); i++) {
        NSP_ROUTINE rt; GUID id = g2_guid_throwaway; INT r;
        memset(&rt, 0xCD, sizeof rt); rt.cbSize = sizes[i];
        SetLastError(0);
        r = st(&id, &rt);
        CHECKF(r == SOCKET_ERROR, "cbSize 0x%lx returned %d", (unsigned long)sizes[i], r);
        CHECKF(GetLastError() == GE_INVPROCTAB, "cbSize 0x%lx error %lu", (unsigned long)sizes[i], GetLastError());
        CHECKF(rt.cbSize == sizes[i] && ((BYTE *)&rt)[8] == 0xCD, "cbSize 0x%lx: table was written", (unsigned long)sizes[i]);
    }
}

TEST(gap2_nsp_start_table_size_at_or_above_minimum_accepted) {
    static const DWORD sizes[] = { 0x58, 0x59, 0x60, 0x100, 0x10000, 0xffffffffu };
    nspstartup_fn st = start_fn(); int i;
    REQUIRE(st); G2_NEED();
    for (i = 0; i < G2_N(sizes); i++) {
        NSP_ROUTINE rt; GUID id = g2_guid_throwaway; INT r;
        memset(&rt, 0, sizeof rt); rt.cbSize = sizes[i];
        SetLastError(0);
        r = st(&id, &rt);
        CHECKF(r == 0, "cbSize 0x%lx returned %d (error %lu)", (unsigned long)sizes[i], r, GetLastError());
        if (r == 0) balance(&rt, &id);
    }
}

TEST(gap2_nsp_start_writes_exactly_the_routine_vector) {
    nspstartup_fn st = start_fn();
    struct { NSP_ROUTINE rt; BYTE tail[64]; } box; GUID id = g2_guid_throwaway; int i, bad = 0;
    REQUIRE(st); G2_NEED();
    memset(&box, 0xCD, sizeof box);
    box.rt.cbSize = sizeof box;
    EXPECT_EQ(st(&id, &box.rt), 0);
    for (i = 0; i < 64; i++) if (box.tail[i] != 0xCD) bad++;
    CHECKF(bad == 0, "%d bytes after the 0x58-byte table changed", bad);
    balance(&box.rt, &id);
}

TEST(gap2_nsp_start_reports_the_vector_size) {
    nspstartup_fn st = start_fn(); NSP_ROUTINE rt; GUID id = g2_guid_throwaway;
    REQUIRE(st); G2_NEED();
    memset(&rt, 0, sizeof rt); rt.cbSize = 0x100;
    EXPECT_EQ(st(&id, &rt), 0);
    EXPECT_EQ(rt.cbSize, 0x50);   /* the vector describes the ten-routine table without NSPIoctl */
    balance(&rt, &id);
}

TEST(gap2_nsp_start_routine_pointers_lie_in_the_provider_image) {
    nspstartup_fn st = start_fn(); NSP_ROUTINE rt; GUID id = g2_guid_throwaway;
    REQUIRE(st); G2_NEED();
    memset(&rt, 0, sizeof rt); rt.cbSize = sizeof rt;
    EXPECT_EQ(st(&id, &rt), 0);
    CHECK(own_image((void *)rt.NSPCleanup));
    CHECK(own_image((void *)rt.NSPLookupServiceBegin));
    CHECK(own_image((void *)rt.NSPLookupServiceNext));
    CHECK(own_image((void *)rt.NSPLookupServiceEnd));
    CHECK(own_image((void *)rt.NSPSetService));
    CHECK(own_image((void *)rt.NSPInstallServiceClass));
    CHECK(own_image((void *)rt.NSPRemoveServiceClass));
    CHECK(own_image((void *)rt.NSPGetServiceClassInfo));
    balance(&rt, &id);
}

TEST(gap2_nsp_start_routines_are_pairwise_distinct) {
    nspstartup_fn st = start_fn(); NSP_ROUTINE rt; GUID id = g2_guid_throwaway; FARPROC f[8]; int i, j;
    REQUIRE(st); G2_NEED();
    memset(&rt, 0, sizeof rt); rt.cbSize = sizeof rt;
    EXPECT_EQ(st(&id, &rt), 0);
    f[0] = (FARPROC)rt.NSPCleanup; f[1] = (FARPROC)rt.NSPLookupServiceBegin; f[2] = (FARPROC)rt.NSPLookupServiceNext;
    f[3] = (FARPROC)rt.NSPLookupServiceEnd; f[4] = (FARPROC)rt.NSPSetService; f[5] = (FARPROC)rt.NSPInstallServiceClass;
    f[6] = (FARPROC)rt.NSPRemoveServiceClass; f[7] = (FARPROC)rt.NSPGetServiceClassInfo;
    for (i = 0; i < 8; i++) for (j = i + 1; j < 8; j++)
        if (i == 5 && j == 6) continue;   /* the two class routines may share one body */
        else if ((i == 5 || i == 6) && j == 7) continue;
        else if (i == 4 && (j == 5 || j == 6 || j == 7)) continue;
        else CHECKF(f[i] != f[j], "routines %d and %d are the same function", i, j);
    balance(&rt, &id);
}

/* The provider id is not validated: any id, including the all-zero id, starts the provider. */
TEST(gap2_nsp_start_accepts_any_provider_id) {
    nspstartup_fn st = start_fn(); int i;
    GUID ids[3];
    REQUIRE(st); G2_NEED();
    memset(&ids[0], 0, sizeof(GUID));
    memset(&ids[1], 0xff, sizeof(GUID));
    ids[2] = g2_guid_throwaway;
    for (i = 0; i < 3; i++) {
        NSP_ROUTINE rt; INT r;
        memset(&rt, 0, sizeof rt); rt.cbSize = sizeof rt;
        r = st(&ids[i], &rt);
        CHECKF(r == 0, "id %d returned %d", i, r);
        if (r == 0) balance(&rt, &ids[i]);
    }
}

TEST(gap2_nsp_start_accepts_the_real_dns_provider_id) {
    nspstartup_fn st = start_fn(); GUID id; NSP_ROUTINE rt;
    REQUIRE(st); G2_NEED();
    if (!g2_provider_for(NS_DNS, &id)) { t_skip("no DNS provider"); return; }
    memset(&rt, 0, sizeof rt); rt.cbSize = sizeof rt;
    EXPECT_EQ(st(&id, &rt), 0);
    balance(&rt, &id);
}

/* Every start is matched by one cleanup; cleanup never fails, whatever id it gets and however often it is called. */
TEST(gap2_nsp_cleanup_always_reports_success) {
    nspstartup_fn st = start_fn(); NSP_ROUTINE rt[3]; GUID id = g2_guid_throwaway; int i;
    REQUIRE(st); G2_NEED();
    for (i = 0; i < 3; i++) { memset(&rt[i], 0, sizeof rt[i]); rt[i].cbSize = sizeof rt[i]; EXPECT_EQ(st(&id, &rt[i]), 0); }
    for (i = 0; i < 3; i++) {
        nspcleanup_fn cl = (nspcleanup_fn)rt[i].NSPCleanup;
        CHECK(cl != NULL);
        if (cl) EXPECT_EQ(cl(&id), 0);
    }
}

/* The cleanup in the table is the same function for every start, and ignores its argument. */
TEST(gap2_nsp_cleanup_ignores_its_argument) {
    nspstartup_fn st = start_fn(); NSP_ROUTINE a, b; GUID id = g2_guid_throwaway; GUID zero;
    REQUIRE(st); G2_NEED();
    memset(&zero, 0, sizeof zero);
    memset(&a, 0, sizeof a); a.cbSize = sizeof a;
    memset(&b, 0, sizeof b); b.cbSize = sizeof b;
    EXPECT_EQ(st(&id, &a), 0);
    EXPECT_EQ(st(&id, &b), 0);
    CHECK(a.NSPCleanup == b.NSPCleanup);
    EXPECT_EQ(((nspcleanup_fn)a.NSPCleanup)(&zero), 0);
    EXPECT_EQ(((nspcleanup_fn)b.NSPCleanup)(&id), 0);
}

/* The service-class and registration routines of the table answer without reaching any store. */
TEST(gap2_nsp_table_service_class_routines_refuse) {
    nspstartup_fn st = start_fn(); NSP_ROUTINE rt; GUID id = g2_guid_throwaway, cls = g2_guid_throwaway; DWORD len = 0x100; BYTE buf[0x100];
    WSASERVICECLASSINFOW sc; WSAQUERYSETW qs; static WCHAR nm[] = L"ws2t-throwaway-service";
    REQUIRE(st); G2_NEED();
    memset(&rt, 0, sizeof rt); rt.cbSize = sizeof rt;
    EXPECT_EQ(st(&id, &rt), 0);
    memset(&sc, 0, sizeof sc);
    sc.lpServiceClassId = &cls;
    SetLastError(0);
    CHECK(rt.NSPInstallServiceClass(&id, &sc) == SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), GE_OPNOTSUPP);
    SetLastError(0);
    CHECK(rt.NSPRemoveServiceClass(&id, &cls) == SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), GE_OPNOTSUPP);
    SetLastError(0);
    CHECK(rt.NSPGetServiceClassInfo(&id, &len, (LPWSASERVICECLASSINFOW)buf) == SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), GE_OPNOTSUPP);
    g2_qs_w(&qs, nm, &cls, 0x7e57);
    SetLastError(0);
    CHECK(rt.NSPSetService(&id, &sc, &qs, RNRSERVICE_REGISTER, 0) == SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), GE_NOTSUPP32);
    balance(&rt, &id);
}

/* The lookup routines of the table validate their handle argument. */
TEST(gap2_nsp_table_lookup_end_with_foreign_handle) {
    nspstartup_fn st = start_fn(); NSP_ROUTINE rt; GUID id = g2_guid_throwaway;
    REQUIRE(st); G2_NEED();
    memset(&rt, 0, sizeof rt); rt.cbSize = sizeof rt;
    EXPECT_EQ(st(&id, &rt), 0);
    SetLastError(0);
    CHECK(rt.NSPLookupServiceEnd((HANDLE)(ULONG_PTR)0x7e57e570) == SOCKET_ERROR);
    EXPECT_EQ(GetLastError(), GE_BADHANDLE);
    balance(&rt, &id);
}
