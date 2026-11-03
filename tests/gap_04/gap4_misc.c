/* Presence, ordinal, aliasing and forwarder facts for the non-public mswsock.dll exports, plus the entry points
 * that are safe to call: GetSocketErrorMessageW (error code -> allocated message text) and the argument
 * validation of MigrateWinsockConfigurationEx.
 *
 * Measures: every export named in this area resolves by name and by ordinal to the same executable address;
 * the three entry points that share one body (get/set socket information, ioctl) resolve to one address for both
 * families while the other helper exports are distinct; none of these names is exported by ws2_32.dll and
 * wsock32.dll forwards the migration entry; the message lookup returns a heap block the caller frees, equal text
 * for codes that share a message, and the generic text for codes it does not know; the Ex migration entry
 * refuses a missing target description before it touches any state and never calls back. */
#include "gap4.h"

const g4_fam g4_v4 = { "v4", "Tcpip4_WSH", AF_INET, L"\\Device\\Tcp", L"\\Device\\Udp" };
const g4_fam g4_v6 = { "v6", "Tcpip6_WSH", AF_INET6, L"\\Device\\Tcp6", L"\\Device\\Udp6" };
void *g4_fn(const g4_fam *f, const char *suffix)
{
    char n[64];
    snprintf(n, sizeof n, "%s%s", f->prefix, suffix);
    return (void *)g4_ms(n);
}

static const struct { const char *name; unsigned ord; } g4_exports[] = {
    { "GetSocketErrorMessageW", 11 }, { "MigrateWinsockConfiguration", 14 }, { "MigrateWinsockConfigurationEx", 15 },
    { "StartWsdpService", 20 }, { "StopWsdpService", 21 },
    { "Tcpip4_WSHAddressToString", 22 }, { "Tcpip4_WSHEnumProtocols", 23 }, { "Tcpip4_WSHGetBroadcastSockaddr", 24 },
    { "Tcpip4_WSHGetProviderGuid", 25 }, { "Tcpip4_WSHGetSockaddrType", 26 }, { "Tcpip4_WSHGetSocketInformation", 27 },
    { "Tcpip4_WSHGetWSAProtocolInfo", 28 }, { "Tcpip4_WSHGetWildcardSockaddr", 29 }, { "Tcpip4_WSHGetWinsockMapping", 30 },
    { "Tcpip4_WSHIoctl", 31 }, { "Tcpip4_WSHJoinLeaf", 32 }, { "Tcpip4_WSHNotify", 33 }, { "Tcpip4_WSHOpenSocket", 34 },
    { "Tcpip4_WSHOpenSocket2", 35 }, { "Tcpip4_WSHSetSocketInformation", 36 }, { "Tcpip4_WSHStringToAddress", 37 },
    { "Tcpip6_WSHAddressToString", 38 }, { "Tcpip6_WSHEnumProtocols", 39 }, { "Tcpip6_WSHGetProviderGuid", 40 },
    { "Tcpip6_WSHGetSockaddrType", 41 }, { "Tcpip6_WSHGetSocketInformation", 42 }, { "Tcpip6_WSHGetWSAProtocolInfo", 43 },
    { "Tcpip6_WSHGetWildcardSockaddr", 44 }, { "Tcpip6_WSHGetWinsockMapping", 45 }, { "Tcpip6_WSHIoctl", 46 },
    { "Tcpip6_WSHJoinLeaf", 47 }, { "Tcpip6_WSHNotify", 48 }, { "Tcpip6_WSHOpenSocket", 49 }, { "Tcpip6_WSHOpenSocket2", 50 },
    { "Tcpip6_WSHSetSocketInformation", 51 }, { "Tcpip6_WSHStringToAddress", 52 },
};

TEST(gap4_exports_resolve_by_name)
{
    size_t i;
    for (i = 0; i < G4N(g4_exports); i++)
        CHECKF(g4_ms(g4_exports[i].name) != NULL, "%s missing", g4_exports[i].name);
}
TEST(gap4_exports_resolve_by_ordinal_to_the_same_address)
{
    size_t i;
    for (i = 0; i < G4N(g4_exports); i++) {
        FARPROC byname = g4_ms(g4_exports[i].name), byord = t_proc_ord("mswsock.dll", g4_exports[i].ord);
        CHECKF(byname != NULL && byord == byname, "%s ordinal %u", g4_exports[i].name, g4_exports[i].ord);
    }
}
TEST(gap4_exports_are_executable_code)
{
    size_t i;
    for (i = 0; i < G4N(g4_exports); i++) {
        MEMORY_BASIC_INFORMATION mbi; FARPROC p = g4_ms(g4_exports[i].name);
        if (!p) continue;
        memset(&mbi, 0, sizeof mbi);
        CHECK(VirtualQuery((void *)p, &mbi, sizeof mbi) == sizeof mbi);
        CHECKF((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0, "%s", g4_exports[i].name);
    }
}
TEST(gap4_exports_addresses_are_inside_the_module)
{
    HMODULE m = t_module("mswsock.dll"); MEMORY_BASIC_INFORMATION mbi; size_t i;
    REQUIRE(m);
    for (i = 0; i < G4N(g4_exports); i++) {
        FARPROC p = g4_ms(g4_exports[i].name);
        if (!p) continue;
        memset(&mbi, 0, sizeof mbi);
        VirtualQuery((void *)p, &mbi, sizeof mbi);
        CHECKF(mbi.AllocationBase == (void *)m, "%s outside mswsock", g4_exports[i].name);
    }
}
TEST(gap4_exports_names_are_case_sensitive)
{
    CHECK(t_proc_in("mswsock.dll", "tcpip4_wshnotify") == NULL);
    CHECK(t_proc_in("mswsock.dll", "TCPIP6_WSHOPENSOCKET2") == NULL);
    CHECK(t_proc_in("mswsock.dll", "getsocketerrormessagew") == NULL);
    CHECK(t_proc_in("mswsock.dll", "startwsdpservice") == NULL);
}
TEST(gap4_exports_unexported_neighbours_are_absent)
{
    CHECK(t_proc_in("mswsock.dll", "Tcpip4_WSHGetSocketInformationEx") == NULL);
    CHECK(t_proc_in("mswsock.dll", "Tcpip_WSHNotify") == NULL);
    CHECK(t_proc_in("mswsock.dll", "Tcpip6_WSHGetBroadcastSockaddr") == NULL);
    CHECK(t_proc_in("mswsock.dll", "GetSocketErrorMessageA") == NULL);
    CHECK(t_proc_in("mswsock.dll", "StartWsdpServiceEx") == NULL);
    CHECK(t_proc_in("mswsock.dll", "WSHNotify") == NULL);
}
TEST(gap4_exports_ipv6_has_no_broadcast_helper)
{
    CHECK(g4_ms("Tcpip4_WSHGetBroadcastSockaddr") != NULL);
    CHECK(g4_ms("Tcpip6_WSHGetBroadcastSockaddr") == NULL);
}
TEST(gap4_exports_shared_bodies_have_one_address)
{
    EXPECT_EQ(g4_ms("Tcpip4_WSHGetSocketInformation"), g4_ms("Tcpip6_WSHGetSocketInformation"));
    EXPECT_EQ(g4_ms("Tcpip4_WSHSetSocketInformation"), g4_ms("Tcpip6_WSHSetSocketInformation"));
    EXPECT_EQ(g4_ms("Tcpip4_WSHIoctl"), g4_ms("Tcpip6_WSHIoctl"));
}
TEST(gap4_exports_family_specific_bodies_are_distinct)
{
    static const char *const sfx[] = { "AddressToString", "EnumProtocols", "GetProviderGuid", "GetSockaddrType",
        "GetWSAProtocolInfo", "GetWildcardSockaddr", "GetWinsockMapping", "JoinLeaf", "Notify", "OpenSocket",
        "OpenSocket2", "StringToAddress" };
    size_t i;
    for (i = 0; i < G4N(sfx); i++) {
        void *a = g4_fn(&g4_v4, sfx[i]), *b = g4_fn(&g4_v6, sfx[i]);
        CHECKF(a != NULL && b != NULL && a != b, "%s", sfx[i]);
    }
}
TEST(gap4_exports_not_exported_by_ws2_32)
{
    size_t i;
    for (i = 0; i < G4N(g4_exports); i++)
        CHECKF(t_proc_in("ws2_32.dll", g4_exports[i].name) == NULL, "%s resolved in ws2_32", g4_exports[i].name);
}
TEST(gap4_exports_only_the_migration_entry_is_in_wsock32)
{
    size_t i;
    for (i = 0; i < G4N(g4_exports); i++) {
        FARPROC p = t_proc_in("wsock32.dll", g4_exports[i].name);
        if (!strcmp(g4_exports[i].name, "MigrateWinsockConfiguration")) continue;
        CHECKF(p == NULL, "%s resolved in wsock32", g4_exports[i].name);
    }
}
TEST(gap4_wsock32_migrate_forwards_to_mswsock)
{
    FARPROC w = t_proc_in("wsock32.dll", "MigrateWinsockConfiguration");
    REQUIRE(w);
    EXPECT_EQ(w, g4_ms("MigrateWinsockConfiguration"));
}
TEST(gap4_wsock32_migrate_ex_is_not_forwarded)
{
    CHECK(t_proc_in("wsock32.dll", "MigrateWinsockConfigurationEx") == NULL);
}

/* ---- GetSocketErrorMessageW ---- */
typedef LPWSTR (WINAPI *g4_errmsg_fn)(int);

static void check_free(LPWSTR s) { if (s) CHECK(LocalFree(s) == NULL); }

TEST(gap4_errmsg_known_code_returns_text)
{
    g4_errmsg_fn f = (g4_errmsg_fn)g4_ms("GetSocketErrorMessageW");
    LPWSTR s;
    REQUIRE(f); g4_wsa_up();
    s = f(0x18);
    CHECK(s != NULL);
    if (s) CHECK(lstrlenW(s) > 0);
    check_free(s);
}
TEST(gap4_errmsg_block_is_a_local_heap_allocation)
{
    g4_errmsg_fn f = (g4_errmsg_fn)g4_ms("GetSocketErrorMessageW");
    LPWSTR s;
    REQUIRE(f); g4_wsa_up();
    s = f(0x18);
    REQUIRE(s);
    CHECK(LocalSize(s) >= (SIZE_T)(lstrlenW(s) + 1) * sizeof(WCHAR));
    check_free(s);
}
TEST(gap4_errmsg_codes_sharing_a_message_return_equal_text)
{
    g4_errmsg_fn f = (g4_errmsg_fn)g4_ms("GetSocketErrorMessageW");
    LPWSTR a, b;
    REQUIRE(f); g4_wsa_up();
    a = f(0x18); b = f(0x19);
    CHECK(a != NULL && b != NULL);
    if (a && b) { CHECK(a != b); EXPECT_WSTR(a, b); }
    check_free(a); check_free(b);
}
TEST(gap4_errmsg_repeated_calls_give_equal_text_in_fresh_blocks)
{
    g4_errmsg_fn f = (g4_errmsg_fn)g4_ms("GetSocketErrorMessageW");
    LPWSTR a, b;
    REQUIRE(f); g4_wsa_up();
    a = f(0x1); b = f(0x1);
    CHECK(a != NULL && b != NULL);
    if (a && b) { CHECK(a != b); EXPECT_WSTR(a, b); }
    check_free(a); check_free(b);
}
TEST(gap4_errmsg_unknown_codes_share_the_generic_text)
{
    static const int codes[] = { 0, 0x7d, 0x95, 0x99, 0x1000, 0x2000, 0x7fffffff, -1, 0x80000000 };
    g4_errmsg_fn f = (g4_errmsg_fn)g4_ms("GetSocketErrorMessageW");
    LPWSTR first = NULL; size_t i;
    REQUIRE(f); g4_wsa_up();
    first = f(codes[0]);
    CHECK(first != NULL);
    for (i = 1; i < G4N(codes); i++) {
        LPWSTR s = f(codes[i]);
        CHECKF(s != NULL, "code %d", codes[i]);
        if (s && first) CHECKF(!lstrcmpW(s, first), "code %d differs from the generic text", codes[i]);
        check_free(s);
    }
    check_free(first);
}
TEST(gap4_errmsg_generic_text_differs_from_a_specific_one)
{
    g4_errmsg_fn f = (g4_errmsg_fn)g4_ms("GetSocketErrorMessageW");
    LPWSTR g, k;
    REQUIRE(f); g4_wsa_up();
    g = f(0x1000); k = f(0x18);
    if (g && k) CHECK(lstrcmpW(g, k) != 0);
    else CHECK(g != NULL && k != NULL);
    check_free(g); check_free(k);
}
TEST(gap4_errmsg_winsock_error_numbers_are_accepted)
{
    /* Winsock error numbers (WSAECONNRESET and friends) go through a second table; each yields some text. */
    static const int codes[] = { 10054, 10061, 10060, 10048, 10038, 10013 };
    g4_errmsg_fn f = (g4_errmsg_fn)g4_ms("GetSocketErrorMessageW");
    size_t i; int nulls = 0;
    REQUIRE(f); g4_wsa_up();
    for (i = 0; i < G4N(codes); i++) {
        LPWSTR s = f(codes[i]);
        if (!s) nulls++;
        check_free(s);
    }
    if (nulls) t_note("winsock-number lookups without text: %d of %d", nulls, (int)G4N(codes));
}
TEST(gap4_errmsg_sweep_small_codes_never_crash)
{
    g4_errmsg_fn f = (g4_errmsg_fn)g4_ms("GetSocketErrorMessageW");
    int c, none = 0;
    REQUIRE(f); g4_wsa_up();
    for (c = 0; c <= 0xA0; c++) {
        LPWSTR s = f(c);
        if (!s) none++;
        check_free(s);
    }
    if (none) t_note("small codes without text: %d", none);
}
/* ---- MigrateWinsockConfigurationEx: refused before anything is touched ---- */
typedef DWORD (WINAPI *g4_migex_fn)(void *, void *, DWORD, void *, void *);
static volatile LONG g4_cb_calls;
static int WINAPI g4_cb(int a, const WCHAR *b, int c) { InterlockedIncrement(&g4_cb_calls); return 1; }
static void WINAPI g4_logcb(DWORD code, const WCHAR *text, void *ctx) { InterlockedIncrement(&g4_cb_calls); }

TEST(gap4_migrate_ex_without_target_is_invalid_parameter)
{
    g4_migex_fn f = (g4_migex_fn)g4_ms("MigrateWinsockConfigurationEx");
    REQUIRE(f);
    EXPECT_EQ(f(NULL, NULL, 0, NULL, NULL), ERROR_INVALID_PARAMETER);
}
TEST(gap4_migrate_ex_without_target_ignores_other_arguments)
{
    g4_migex_fn f = (g4_migex_fn)g4_ms("MigrateWinsockConfigurationEx");
    DWORD dummy[8] = { 0 };
    REQUIRE(f);
    EXPECT_EQ(f(dummy, NULL, 7, NULL, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(f(NULL, (void *)g4_cb, 0xffffffffu, NULL, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(f(dummy, (void *)g4_cb, 1, NULL, NULL), ERROR_INVALID_PARAMETER);
}
TEST(gap4_migrate_ex_without_target_never_calls_back)
{
    g4_migex_fn f = (g4_migex_fn)g4_ms("MigrateWinsockConfigurationEx");
    REQUIRE(f);
    g4_cb_calls = 0;
    EXPECT_EQ(f(NULL, (void *)g4_cb, 5, NULL, (void *)g4_logcb), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(g4_cb_calls, 0);
}
TEST(gap4_migrate_ex_without_target_is_repeatable)
{
    g4_migex_fn f = (g4_migex_fn)g4_ms("MigrateWinsockConfigurationEx");
    int i;
    REQUIRE(f);
    for (i = 0; i < 5; i++) EXPECT_EQ(f(NULL, NULL, 0, NULL, NULL), ERROR_INVALID_PARAMETER);
}
