/* The non-SPI exports of mswsock.dll: the legacy name-service API (GetTypeByName*, GetNameByType*,
 * EnumProtocols*, NPLoadNameSpaces, ...), the BSD compatibility stubs (sethostname, getnetbyname, rcmd, ...),
 * the pure DNS name expansion helper dn_expand, and the transport helper entry points Tcpip4_WSH* /
 * Tcpip6_WSH* that the base provider itself uses for address classification and string conversion.
 *
 * Measures: every named export resolves; stubs fail with the odd (but fixed) version-not-supported error;
 * dn_expand on hand built wire-format names (labels, compression pointers, escapes, bounds); the helper
 * entry points' return values and output structures for good and bad arguments.
 * AcceptEx / TransmitFile / GetAcceptExSockaddrs semantics are covered by the extension-function areas.
 */
#include "spi.h"

static const char *const mswsock_names[] = {
    "AcceptEx", "EnumProtocolsA", "EnumProtocolsW", "GetAcceptExSockaddrs", "GetAddressByNameA", "GetAddressByNameW",
    "GetNameByTypeA", "GetNameByTypeW", "GetServiceA", "GetServiceW", "GetSocketErrorMessageW", "GetTypeByNameA",
    "GetTypeByNameW", "MigrateWinsockConfiguration", "MigrateWinsockConfigurationEx", "NPLoadNameSpaces", "NSPStartup",
    "SetServiceA", "SetServiceW", "StartWsdpService", "StopWsdpService",
    "Tcpip4_WSHAddressToString", "Tcpip4_WSHEnumProtocols", "Tcpip4_WSHGetBroadcastSockaddr", "Tcpip4_WSHGetProviderGuid",
    "Tcpip4_WSHGetSockaddrType", "Tcpip4_WSHGetSocketInformation", "Tcpip4_WSHGetWSAProtocolInfo",
    "Tcpip4_WSHGetWildcardSockaddr", "Tcpip4_WSHGetWinsockMapping", "Tcpip4_WSHIoctl", "Tcpip4_WSHJoinLeaf",
    "Tcpip4_WSHNotify", "Tcpip4_WSHOpenSocket", "Tcpip4_WSHOpenSocket2", "Tcpip4_WSHSetSocketInformation",
    "Tcpip4_WSHStringToAddress",
    "Tcpip6_WSHAddressToString", "Tcpip6_WSHEnumProtocols", "Tcpip6_WSHGetProviderGuid", "Tcpip6_WSHGetSockaddrType",
    "Tcpip6_WSHGetSocketInformation", "Tcpip6_WSHGetWSAProtocolInfo", "Tcpip6_WSHGetWildcardSockaddr",
    "Tcpip6_WSHGetWinsockMapping", "Tcpip6_WSHIoctl", "Tcpip6_WSHJoinLeaf", "Tcpip6_WSHNotify", "Tcpip6_WSHOpenSocket",
    "Tcpip6_WSHOpenSocket2", "Tcpip6_WSHSetSocketInformation", "Tcpip6_WSHStringToAddress",
    "TransmitFile", "WSARecvEx", "WSPStartup", "dn_expand", "getnetbyname", "inet_network", "rcmd", "rexec", "rresvport",
    "s_perror", "sethostname"
};

/* ---- the whole export surface ---- */
TEST(exports_all_named_entries_resolve)
{
    size_t i;
    for (i = 0; i < sizeof mswsock_names / sizeof mswsock_names[0]; i++)
        CHECKF(t_proc_in("mswsock.dll", mswsock_names[i]) != NULL, "%s missing", mswsock_names[i]);
}
TEST(exports_count_matches_the_reference_list)
{
    EXPECT_EQ(sizeof mswsock_names / sizeof mswsock_names[0], 63);
}
TEST(exports_names_are_case_sensitive)
{
    CHECK(t_proc_in("mswsock.dll", "wspstartup") == NULL);
    CHECK(t_proc_in("mswsock.dll", "ACCEPTEX") == NULL);
}
TEST(exports_wsp_entries_other_than_startup_are_not_exported)
{
    CHECK(t_proc_in("mswsock.dll", "WSPSocket") == NULL);
    CHECK(t_proc_in("mswsock.dll", "WSPCleanup") == NULL);
}
TEST(exports_every_function_is_executable_code)
{
    size_t i; MEMORY_BASIC_INFORMATION mbi;
    for (i = 0; i < sizeof mswsock_names / sizeof mswsock_names[0]; i++) {
        FARPROC p = t_proc_in("mswsock.dll", mswsock_names[i]);
        if (!p) continue;
        memset(&mbi, 0, sizeof mbi);
        CHECK(VirtualQuery((void *)p, &mbi, sizeof mbi) == sizeof mbi);
        CHECKF((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0, "%s not executable", mswsock_names[i]);
    }
}
TEST(exports_resolve_inside_mswsock_image)
{
    HMODULE ms = t_module("mswsock.dll"); size_t i;
    for (i = 0; i < sizeof mswsock_names / sizeof mswsock_names[0]; i++) {
        FARPROC p = t_proc_in("mswsock.dll", mswsock_names[i]); HMODULE h = NULL;
        if (!p) continue;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)p, &h);
        CHECKF(h == ms, "%s resolves outside mswsock", mswsock_names[i]);
    }
}
TEST(exports_ordinals_are_dense_and_resolvable)
{
    unsigned o, found = 0;
    for (o = 1; o <= 80; o++) if (t_proc_ord("mswsock.dll", o)) found++;
    CHECKF(found >= 60, "only %u ordinals resolve in 1..80", found);
}
TEST(exports_rcmd_rexec_rresvport_share_one_body)
{
    FARPROC a = t_proc_in("mswsock.dll", "rcmd"), b = t_proc_in("mswsock.dll", "rexec"), c = t_proc_in("mswsock.dll", "rresvport");
    REQUIRE(a && b && c);
    CHECK(a == b);
    CHECK(b == c);
}
TEST(exports_getnetbyname_and_sethostname_are_distinct_stubs)
{
    FARPROC a = t_proc_in("mswsock.dll", "getnetbyname"), b = t_proc_in("mswsock.dll", "sethostname");
    REQUIRE(a && b);
    CHECK(a != b);
}

/* Calls into the legacy exports are not made under the emulator: its versions of these entries are stubs that
 * abort the process.  Resolution-only checks above use t_proc_in directly. */
static FARPROC mp(const char *name) { return t_is_wine() ? NULL : t_proc_in("mswsock.dll", name); }

/* ---- BSD compatibility stubs ---- */
TEST(stub_sethostname_fails_with_version_not_supported)
{
    INT_PTR (WINAPI *f)(void) = (void *)mp("sethostname");
    REQUIRE(f);
    SetLastError(0);
    EXPECT_EQ((int)f(), -1);
    EXPECT_EQ(GetLastError(), SE_VERNOTSUP);
}
TEST(stub_getnetbyname_returns_null_with_version_not_supported)
{
    void *(WINAPI *f)(void) = (void *)mp("getnetbyname");
    REQUIRE(f);
    SetLastError(0);
    CHECK(f() == NULL);
    EXPECT_EQ(GetLastError(), SE_VERNOTSUP);
}
TEST(stub_rcmd_fails_with_version_not_supported)
{
    INT_PTR (WINAPI *f)(void) = (void *)mp("rcmd");
    REQUIRE(f);
    SetLastError(0);
    EXPECT_EQ(f(), (INT_PTR)-1);
    EXPECT_EQ(GetLastError(), SE_VERNOTSUP);
}
TEST(stub_rexec_fails_with_version_not_supported)
{
    INT_PTR (WINAPI *f)(void) = (void *)mp("rexec");
    REQUIRE(f);
    SetLastError(0);
    EXPECT_EQ(f(), (INT_PTR)-1);
    EXPECT_EQ(GetLastError(), SE_VERNOTSUP);
}
TEST(stub_rresvport_fails_with_version_not_supported)
{
    INT_PTR (WINAPI *f)(void) = (void *)mp("rresvport");
    REQUIRE(f);
    SetLastError(0);
    EXPECT_EQ(f(), (INT_PTR)-1);
    EXPECT_EQ(GetLastError(), SE_VERNOTSUP);
}
TEST(stub_failure_is_repeatable)
{
    INT_PTR (WINAPI *f)(void) = (void *)mp("sethostname");
    int i;
    REQUIRE(f);
    for (i = 0; i < 3; i++) { SetLastError(0); EXPECT_EQ((int)f(), -1); EXPECT_EQ(GetLastError(), SE_VERNOTSUP); }
}

/* ---- dn_expand: wire-format name expansion ---- */
typedef int (WINAPI *dn_expand_fn)(const unsigned char *msg, const unsigned char *eom, const unsigned char *src, char *dst, int dstsiz);
static dn_expand_fn dn(void) { return (dn_expand_fn)mp("dn_expand"); }

TEST(dn_expand_simple_name)
{
    static const unsigned char m[] = "\3www\7example\3com";   /* the literal's own NUL is the root label */
    char out[64];
    REQUIRE(dn());
    memset(out, 'x', sizeof out);
    EXPECT_EQ(dn()(m, m + sizeof m, m, out, sizeof out), 17);
    EXPECT_STR(out, "www.example.com");
}
TEST(dn_expand_root_is_empty_string)
{
    static const unsigned char m[] = { 0 };
    char out[8] = "zzzz";
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + 1, m, out, sizeof out), 1);
    EXPECT_STR(out, "");
}
TEST(dn_expand_single_label)
{
    static const unsigned char m[] = "\4host";
    char out[16];
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + sizeof m, m, out, sizeof out), 6);
    EXPECT_STR(out, "host");
}
TEST(dn_expand_compression_pointer)
{
    static const unsigned char m[] = { 3, 'f', 'o', 'o', 0,   3, 'b', 'a', 'r', 0xC0, 0x00 };
    char out[32];
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + sizeof m, m + 5, out, sizeof out), 6);   /* consumed: label + 2-byte pointer */
    EXPECT_STR(out, "bar.foo");
}
TEST(dn_expand_pointer_only)
{
    static const unsigned char m[] = { 3, 'f', 'o', 'o', 0,   0xC0, 0x00 };
    char out[32];
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + sizeof m, m + 5, out, sizeof out), 2);
    EXPECT_STR(out, "foo");
}
TEST(dn_expand_pointer_chain)
{
    static const unsigned char m[] = { 1, 'a', 0,   1, 'b', 0xC0, 0x00,   1, 'c', 0xC0, 0x03 };
    char out[32];
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + sizeof m, m + 7, out, sizeof out), 4);
    EXPECT_STR(out, "c.b.a");
}
TEST(dn_expand_dot_inside_label_is_escaped)
{
    static const unsigned char m[] = { 3, 'a', '.', 'b', 0 };
    char out[16];
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + sizeof m, m, out, sizeof out), 5);
    EXPECT_STR(out, "a\\.b");
}
TEST(dn_expand_destination_exactly_large_enough)
{
    static const unsigned char m[] = "\3www\7example\3com";
    char out[16];
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + sizeof m, m, out, 16), 17);   /* 15 characters + terminator */
    EXPECT_STR(out, "www.example.com");
}
TEST(dn_expand_destination_one_too_small)
{
    static const unsigned char m[] = "\3www\7example\3com";
    char out[16];
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + sizeof m, m, out, 15), -1);
}
TEST(dn_expand_destination_zero_length)
{
    static const unsigned char m[] = "\3abc";
    char out[4] = "q";
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + sizeof m, m, out, 0), -1);
}
TEST(dn_expand_reserved_label_type_01)
{
    static const unsigned char m[] = { 0x41, 'a', 0 };
    char out[16];
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + sizeof m, m, out, sizeof out), -1);
}
TEST(dn_expand_reserved_label_type_10)
{
    static const unsigned char m[] = { 0x81, 'a', 0 };
    char out[16];
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + sizeof m, m, out, sizeof out), -1);
}
TEST(dn_expand_pointer_beyond_message)
{
    static const unsigned char m[] = { 3, 'f', 'o', 'o', 0xC0, 0x30 };
    char out[16];
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + sizeof m, m, out, sizeof out), -1);
}
TEST(dn_expand_pointer_loop_to_itself)
{
    static const unsigned char m[] = { 0xC0, 0x00 };
    char out[16];
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + sizeof m, m, out, sizeof out), -1);
}
TEST(dn_expand_pointer_loop_between_labels)
{
    static const unsigned char m[] = { 1, 'a', 0xC0, 0x04,   1, 'b', 0xC0, 0x00 };
    char out[64];
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + sizeof m, m, out, sizeof out), -1);
}
TEST(dn_expand_missing_terminator_inside_message)
{
    static const unsigned char m[] = { 3, 'f', 'o', 'o', 0 };
    char out[16];
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + 4, m, out, sizeof out), -1);   /* the closing zero lies beyond eom */
}
TEST(dn_expand_label_runs_past_message_end)
{
    static const unsigned char m[] = { 9, 'a', 'b', 'c', 0 };
    char out[16];
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + sizeof m, m, out, sizeof out), -1);
}
TEST(dn_expand_pointer_missing_second_byte)
{
    static const unsigned char m[] = { 3, 'f', 'o', 'o', 0, 1, 'x', 0xC0 };
    char out[16];
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + sizeof m, m + 5, out, sizeof out), -1);
}
TEST(dn_expand_starting_offset_inside_message)
{
    static const unsigned char m[] = { 9, 9, 9, 2, 'h', 'i', 0 };
    char out[16];
    REQUIRE(dn());
    EXPECT_EQ(dn()(m, m + sizeof m, m + 3, out, sizeof out), 4);
    EXPECT_STR(out, "hi");
}
TEST(dn_expand_maximum_label_length)
{
    unsigned char m[70]; char out[128]; int i;
    REQUIRE(dn());
    m[0] = 63;
    for (i = 1; i <= 63; i++) m[i] = 'a';
    m[64] = 0;
    EXPECT_EQ(dn()(m, m + 65, m, out, sizeof out), 65);
    EXPECT_EQ(strlen(out), 63);
}

/* ---- NPLoadNameSpaces ---- */
typedef int (WINAPI *npload_fn)(DWORD *version, void *routines, DWORD *size);
TEST(npload_small_buffer_reports_required_size)
{
    npload_fn f = (npload_fn)mp("NPLoadNameSpaces");
    DWORD v = 0xAAAA, size = 8; DWORD buf[64];
    REQUIRE(f);
    SetLastError(0);
    EXPECT_EQ(f(&v, buf, &size), -1);
    EXPECT_EQ(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(size, 224);
    EXPECT_EQ(v, 0xAAAA);
}
TEST(npload_zero_size_buffer)
{
    npload_fn f = (npload_fn)mp("NPLoadNameSpaces");
    DWORD v = 0, size = 0; DWORD buf[4];
    REQUIRE(f);
    SetLastError(0);
    EXPECT_EQ(f(&v, buf, &size), -1);
    EXPECT_EQ(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(size, 224);
}
TEST(npload_one_byte_short)
{
    npload_fn f = (npload_fn)mp("NPLoadNameSpaces");
    DWORD v = 0, size = 223; DWORD buf[64];
    REQUIRE(f);
    SetLastError(0);
    EXPECT_EQ(f(&v, buf, &size), -1);
    EXPECT_EQ(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(size, 224);
}
TEST(npload_exact_buffer_returns_four_routines)
{
    npload_fn f = (npload_fn)mp("NPLoadNameSpaces");
    DWORD v = 0, size = 224; DWORD buf[56];
    REQUIRE(f);
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(f(&v, buf, &size), 4);
    EXPECT_EQ(v, 1);
    EXPECT_EQ(size, 224);
}
TEST(npload_routine_table_layout)
{
    npload_fn f = (npload_fn)mp("NPLoadNameSpaces");
    DWORD v = 0, size = 224; DWORD buf[56]; int i;
    REQUIRE(f);
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(f(&v, buf, &size), 4);
    /* four 24-byte routine records: function count, function-table pointer, namespace id, priority */
    for (i = 0; i < 4; i++) {
        EXPECT_EQ(buf[6 * i], 4);
        CHECK(*(void **)&buf[6 * i + 2] != NULL);
        EXPECT_EQ(buf[6 * i + 4], 10 + i);
    }
}
TEST(npload_function_tables_point_into_the_buffer)
{
    npload_fn f = (npload_fn)mp("NPLoadNameSpaces");
    DWORD v = 0, size = 224; DWORD buf[56]; int i;
    REQUIRE(f);
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(f(&v, buf, &size), 4);
    for (i = 0; i < 4; i++) {
        char *p = *(char **)&buf[6 * i + 2];
        CHECK(p >= (char *)buf && p < (char *)buf + sizeof buf);
    }
}
TEST(npload_first_routine_has_lookup_and_set_service_slots)
{
    npload_fn f = (npload_fn)mp("NPLoadNameSpaces");
    DWORD v = 0, size = 224; DWORD buf[56]; void **t;
    REQUIRE(f);
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(f(&v, buf, &size), 4);
    t = *(void ***)&buf[2];
    CHECK(t[0] != NULL);
    CHECK(t[1] == NULL);
    CHECK(t[2] != NULL);
    CHECK(t[3] == NULL);
}
TEST(npload_other_routines_only_have_lookup_slot)
{
    npload_fn f = (npload_fn)mp("NPLoadNameSpaces");
    DWORD v = 0, size = 224; DWORD buf[56]; int i;
    REQUIRE(f);
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(f(&v, buf, &size), 4);
    for (i = 1; i < 4; i++) {
        void **t = *(void ***)&buf[6 * i + 2];
        CHECK(t[0] != NULL);
        CHECK(t[1] == NULL && t[2] == NULL && t[3] == NULL);
    }
}
TEST(npload_is_repeatable)
{
    npload_fn f = (npload_fn)mp("NPLoadNameSpaces");
    DWORD v, size; DWORD a[56], b[56]; int i;
    REQUIRE(f);
    for (i = 0; i < 2; i++) {
        v = 0; size = 224;
        EXPECT_EQ(f(&v, i ? b : a, &size), 4);
    }
    EXPECT_EQ(a[4], b[4]);
    EXPECT_EQ(a[16], b[16]);
}

/* ---- GetTypeByName / GetNameByType ---- */
typedef int (WINAPI *gtbnw_fn)(const WCHAR *, GUID *);
typedef int (WINAPI *gtbna_fn)(const char *, GUID *);
typedef int (WINAPI *gnbtw_fn)(const GUID *, WCHAR *, DWORD);
typedef int (WINAPI *gnbta_fn)(const GUID *, char *, DWORD);

TEST(gettypebyname_unknown_name_w)
{
    gtbnw_fn f = (gtbnw_fn)mp("GetTypeByNameW");
    GUID g;
    REQUIRE(f);
    memset(&g, 0x33, sizeof g);
    SetLastError(0);
    EXPECT_EQ(f(L"ws2t no such service name", &g), -1);
    EXPECT_EQ(GetLastError(), ERROR_SERVICE_DOES_NOT_EXIST);
}
TEST(gettypebyname_unknown_name_a)
{
    gtbna_fn f = (gtbna_fn)mp("GetTypeByNameA");
    GUID g;
    REQUIRE(f);
    SetLastError(0);
    EXPECT_EQ(f("ws2t no such service name", &g), -1);
    EXPECT_EQ(GetLastError(), ERROR_SERVICE_DOES_NOT_EXIST);
}
TEST(gettypebyname_empty_name_is_unknown)
{
    gtbnw_fn f = (gtbnw_fn)mp("GetTypeByNameW");
    GUID g;
    REQUIRE(f);
    SetLastError(0);
    EXPECT_EQ(f(L"", &g), -1);
    EXPECT_EQ(GetLastError(), ERROR_SERVICE_DOES_NOT_EXIST);
}
static int ws2_started(void)
{
    static int up;
    if (!up) { WSADATA d; up = U(WSAStartup) && U(WSAStartup)(MAKEWORD(2, 2), &d) == 0 ? 1 : -1; }
    return up == 1;
}
TEST(gettypebyname_tcp_service_builds_a_well_known_guid)
{
    gtbnw_fn f = (gtbnw_fn)mp("GetTypeByNameW");
    GUID g; int i;
    REQUIRE(f);
    if (!ws2_started()) { t_skip("WSAStartup unavailable"); return; }
    memset(&g, 0, sizeof g);
    if (f(L"http", &g) != 0) { t_note("http is not resolvable through the services database here"); return; }
    EXPECT_EQ(g.Data1, 0x90050);
    EXPECT_EQ(g.Data2, 0);
    EXPECT_EQ(g.Data3, 0);
    EXPECT_EQ(g.Data4[0], 0xC0);
    for (i = 1; i < 7; i++) EXPECT_EQ(g.Data4[i], 0);
    EXPECT_EQ(g.Data4[7], 0x46);
}
TEST(getnamebytype_small_buffer_w)
{
    gnbtw_fn f = (gnbtw_fn)mp("GetNameByTypeW");
    static const GUID tcp80 = { 0x90050, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
    WCHAR b[8];
    REQUIRE(f);
    if (!ws2_started()) { t_skip("WSAStartup unavailable"); return; }
    SetLastError(0);
    if (f(&tcp80, b, 2) == 0) { t_note("name fit in one code unit"); return; }
    CHECK(GetLastError() == ERROR_INSUFFICIENT_BUFFER || GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST);
}
TEST(getnamebytype_tcp80_is_http_w)
{
    gnbtw_fn f = (gnbtw_fn)mp("GetNameByTypeW");
    static const GUID tcp80 = { 0x90050, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
    WCHAR b[64];
    REQUIRE(f);
    if (!ws2_started()) { t_skip("WSAStartup unavailable"); return; }
    memset(b, 0, sizeof b);
    if (f(&tcp80, b, sizeof b) != 0) { t_note("port 80 has no name in the services database here"); return; }
    EXPECT_WSTR(b, L"http");
}
TEST(getnamebytype_tcp80_is_http_a)
{
    gnbta_fn f = (gnbta_fn)mp("GetNameByTypeA");
    static const GUID tcp80 = { 0x90050, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
    char b[64];
    REQUIRE(f);
    if (!ws2_started()) { t_skip("WSAStartup unavailable"); return; }
    memset(b, 0, sizeof b);
    if (f(&tcp80, b, sizeof b) != 0) { t_note("port 80 has no name in the services database here"); return; }
    EXPECT_STR(b, "http");
}
TEST(getnamebytype_unknown_guid_w)
{
    gnbtw_fn f = (gnbtw_fn)mp("GetNameByTypeW");
    static const GUID odd = { 0x7e57ab1e, 0x1234, 0x4321, { 1, 2, 3, 4, 5, 6, 7, 8 } };
    WCHAR b[64];
    REQUIRE(f);
    SetLastError(0);
    EXPECT_EQ(f(&odd, b, sizeof b), -1);
    EXPECT_EQ(GetLastError(), ERROR_SERVICE_DOES_NOT_EXIST);
}
TEST(getnamebytype_unknown_guid_a)
{
    gnbta_fn f = (gnbta_fn)mp("GetNameByTypeA");
    static const GUID odd = { 0x7e57ab1e, 0x1234, 0x4321, { 1, 2, 3, 4, 5, 6, 7, 8 } };
    char b[64];
    REQUIRE(f);
    SetLastError(0);
    EXPECT_EQ(f(&odd, b, sizeof b), -1);
}

/* ---- EnumProtocols ---- */
typedef int (WINAPI *enumprot_fn)(int *, void *, DWORD *);
#define NOT_EMULATED() do { } while (0)
TEST(enumprotocols_w_zero_buffer_asks_for_more)
{
    enumprot_fn f = (enumprot_fn)mp("EnumProtocolsW");
    DWORD len = 0; char dummy[8];
    REQUIRE(f);
    NOT_EMULATED();
    if (!ws2_started()) { t_skip("WSAStartup unavailable"); return; }
    SetLastError(0);
    EXPECT_EQ(f(NULL, dummy, &len), -1);
    EXPECT_EQ(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
    CHECK(len > 0);
}
TEST(enumprotocols_a_zero_buffer_asks_for_more)
{
    enumprot_fn f = (enumprot_fn)mp("EnumProtocolsA");
    DWORD len = 0; char dummy[8];
    REQUIRE(f);
    NOT_EMULATED();
    if (!ws2_started()) { t_skip("WSAStartup unavailable"); return; }
    SetLastError(0);
    EXPECT_EQ(f(NULL, dummy, &len), -1);
    EXPECT_EQ(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
    CHECK(len > 0);
}
TEST(enumprotocols_w_lists_tcp_and_udp)
{
    enumprot_fn f = (enumprot_fn)mp("EnumProtocolsW");
    DWORD len = 0; char dummy[8]; char *buf; int n, i, tcp = 0, udp = 0;
    REQUIRE(f);
    NOT_EMULATED();
    if (!ws2_started()) { t_skip("WSAStartup unavailable"); return; }
    (void)f(NULL, dummy, &len);
    buf = (char *)LocalAlloc(LPTR, len + 64);
    CHECK(buf != NULL);
    if (!buf) return;
    {
        DWORD l2 = len + 64;
        n = f(NULL, buf, &l2);
    }
    CHECK(n > 0);
    /* PROTOCOL_INFOW: flags, family, maxaddr, minaddr, type, protocol, msgsize, pad, name pointer (40 bytes) */
    for (i = 0; i < n; i++) {
        DWORD *p = (DWORD *)(buf + i * 40);
        if (p[1] == AF_INET && p[4] == SOCK_STREAM && p[5] == IPPROTO_TCP) tcp++;
        if (p[1] == AF_INET && p[4] == SOCK_DGRAM && p[5] == IPPROTO_UDP) udp++;
    }
    CHECK(tcp >= 1);
    CHECK(udp >= 1);
    LocalFree(buf);
}
TEST(enumprotocols_w_protocol_filter_selects_tcp)
{
    enumprot_fn f = (enumprot_fn)mp("EnumProtocolsW");
    int want[2] = { IPPROTO_TCP, 0 }; DWORD len = 0; char dummy[8]; char *buf; int n, i;
    REQUIRE(f);
    NOT_EMULATED();
    if (!ws2_started()) { t_skip("WSAStartup unavailable"); return; }
    (void)f(want, dummy, &len);
    buf = (char *)LocalAlloc(LPTR, len + 64);
    if (!buf) return;
    {
        DWORD l2 = len + 64;
        n = f(want, buf, &l2);
    }
    CHECK(n > 0);
    {
        int tcp = 0;
        for (i = 0; i < n; i++) {
            DWORD *p = (DWORD *)(buf + i * 40);
            if (p[5] == IPPROTO_TCP) tcp++;
            t_note("filtered entry %d: family %lu type %lu protocol %lu", i, (unsigned long)p[1], (unsigned long)p[4], (unsigned long)p[5]);
        }
        CHECK(tcp >= 1);
    }
    LocalFree(buf);
}

/* ---- Tcpip4_WSH* / Tcpip6_WSH* helper entry points ---- */
typedef DWORD (WINAPI *wsh_sockaddr_type_fn)(const void *, DWORD, DWORD *);
typedef DWORD (WINAPI *wsh_wildcard_fn)(short family_or_context, void *, DWORD *);
typedef DWORD (WINAPI *wsh_guid_fn)(const WCHAR *, GUID *);
typedef DWORD (WINAPI *wsh_mapping_fn)(void *, DWORD);

static wsh_sockaddr_type_fn sat4(void) { return (wsh_sockaddr_type_fn)mp("Tcpip4_WSHGetSockaddrType"); }
static wsh_sockaddr_type_fn sat6(void) { return (wsh_sockaddr_type_fn)mp("Tcpip6_WSHGetSockaddrType"); }

/* address classes: 0 normal, 1 wildcard, 2 broadcast, 3 loopback; endpoint: 0 normal, 1 wildcard, 2 reserved */
static void sat4_case(unsigned addr_net, unsigned short port_host, DWORD want_addr, DWORD want_ep)
{
    struct sockaddr_in a; DWORD out[2] = { 0x77, 0x77 };
    sp_v4(&a, port_host);
    a.sin_addr.s_addr = addr_net;
    EXPECT_EQ(sat4()(&a, sizeof a, out), 0);
    EXPECT_EQ(out[0], want_addr);
    EXPECT_EQ(out[1], want_ep);
}
TEST(wsh4_sockaddr_type_wildcard_address) { REQUIRE(sat4()); sat4_case(0, 5000, 1, 0); }
TEST(wsh4_sockaddr_type_broadcast_address) { REQUIRE(sat4()); sat4_case(0xFFFFFFFFu, 5000, 2, 0); }
TEST(wsh4_sockaddr_type_loopback_address) { REQUIRE(sat4()); sat4_case(0x0100007Fu, 5000, 3, 0); }
TEST(wsh4_sockaddr_type_other_loopback_address) { REQUIRE(sat4()); sat4_case(0x0302017Fu, 5000, 3, 0); }
TEST(wsh4_sockaddr_type_normal_address) { REQUIRE(sat4()); sat4_case(0x04030201u, 5000, 0, 0); }
TEST(wsh4_sockaddr_type_port_zero_is_wildcard_endpoint) { REQUIRE(sat4()); sat4_case(0x04030201u, 0, 0, 1); }
TEST(wsh4_sockaddr_type_low_port_is_reserved) { REQUIRE(sat4()); sat4_case(0x04030201u, 1999, 0, 2); }
TEST(wsh4_sockaddr_type_port_2000_is_normal) { REQUIRE(sat4()); sat4_case(0x04030201u, 2000, 0, 0); }
TEST(wsh4_sockaddr_type_port_1_is_reserved) { REQUIRE(sat4()); sat4_case(0x04030201u, 1, 0, 2); }
TEST(wsh4_sockaddr_type_short_length)
{
    struct sockaddr_in a; DWORD out[2] = { 0x77, 0x77 };
    REQUIRE(sat4());
    sp_v4(&a, 80);
    EXPECT_EQ(sat4()(&a, 15, out), SE_FAULT);
    EXPECT_EQ(out[0], 0x77);
}
TEST(wsh4_sockaddr_type_wrong_family)
{
    struct sockaddr_in a; DWORD out[2] = { 0x77, 0x77 };
    REQUIRE(sat4());
    sp_v4(&a, 80);
    a.sin_family = AF_INET6;
    EXPECT_EQ(sat4()(&a, sizeof a, out), SE_AFNOSUPPORT);
    a.sin_family = AF_UNSPEC;
    EXPECT_EQ(sat4()(&a, sizeof a, out), SE_AFNOSUPPORT);
}
TEST(wsh6_sockaddr_type_wildcard)
{
    struct sockaddr_in6 a; DWORD out[2] = { 0x77, 0x77 };
    REQUIRE(sat6());
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_port = sp_swap16(4000);
    EXPECT_EQ(sat6()(&a, sizeof a, out), 0);
    EXPECT_EQ(out[0], 1);
    EXPECT_EQ(out[1], 0);
}
TEST(wsh6_sockaddr_type_loopback)
{
    struct sockaddr_in6 a; DWORD out[2] = { 0x77, 0x77 };
    REQUIRE(sat6());
    sp_v6(&a, 4000);
    EXPECT_EQ(sat6()(&a, sizeof a, out), 0);
    EXPECT_EQ(out[0], 3);
}
TEST(wsh6_sockaddr_type_normal)
{
    struct sockaddr_in6 a; DWORD out[2] = { 0x77, 0x77 };
    REQUIRE(sat6());
    sp_v6(&a, 4000);
    a.sin6_addr.s6_addr[0] = 0x20; a.sin6_addr.s6_addr[1] = 0x01; a.sin6_addr.s6_addr[15] = 5;
    EXPECT_EQ(sat6()(&a, sizeof a, out), 0);
    EXPECT_EQ(out[0], 0);
}
TEST(wsh6_sockaddr_type_port_classes)
{
    struct sockaddr_in6 a; DWORD out[2] = { 0, 0 };
    REQUIRE(sat6());
    sp_v6(&a, 0);
    EXPECT_EQ(sat6()(&a, sizeof a, out), 0);
    EXPECT_EQ(out[1], 1);
    sp_v6(&a, 100);
    EXPECT_EQ(sat6()(&a, sizeof a, out), 0);
    EXPECT_EQ(out[1], 2);
    sp_v6(&a, 3000);
    EXPECT_EQ(sat6()(&a, sizeof a, out), 0);
    EXPECT_EQ(out[1], 0);
}
TEST(wsh6_sockaddr_type_wrong_family_and_short_length)
{
    struct sockaddr_in6 a; DWORD out[2];
    REQUIRE(sat6());
    sp_v6(&a, 4000);
    EXPECT_EQ(sat6()(&a, 15, out), SE_FAULT);
    a.sin6_family = AF_INET;
    EXPECT_EQ(sat6()(&a, sizeof a, out), SE_AFNOSUPPORT);
}

static wsh_wildcard_fn wc4(void) { return (wsh_wildcard_fn)mp("Tcpip4_WSHGetWildcardSockaddr"); }
static wsh_wildcard_fn wc6(void) { return (wsh_wildcard_fn)mp("Tcpip6_WSHGetWildcardSockaddr"); }
TEST(wsh4_wildcard_inet)
{
    struct sockaddr_in a; DWORD l = sizeof a;
    REQUIRE(wc4());
    memset(&a, 0x77, sizeof a);
    EXPECT_EQ(wc4()(AF_INET, &a, &l), 0);
    EXPECT_EQ(l, 16);
    EXPECT_EQ(a.sin_family, AF_INET);
    EXPECT_EQ(a.sin_port, 0);
    EXPECT_EQ(a.sin_addr.s_addr, 0);
}
TEST(wsh4_wildcard_inet6)
{
    struct sockaddr_in6 a; DWORD l = sizeof a; int i;
    REQUIRE(wc4());
    memset(&a, 0x77, sizeof a);
    EXPECT_EQ(wc4()(AF_INET6, &a, &l), 0);
    EXPECT_EQ(l, 28);
    EXPECT_EQ(a.sin6_family, AF_INET6);
    EXPECT_EQ(a.sin6_port, 0);
    EXPECT_EQ(a.sin6_scope_id, 0);
    for (i = 0; i < 16; i++) EXPECT_EQ(a.sin6_addr.s6_addr[i], 0);
}
TEST(wsh4_wildcard_inet_buffer_too_small)
{
    struct sockaddr_in a; DWORD l = 15;
    REQUIRE(wc4());
    EXPECT_EQ(wc4()(AF_INET, &a, &l), SE_FAULT);
    EXPECT_EQ(l, 15);
}
TEST(wsh4_wildcard_inet6_buffer_too_small)
{
    struct sockaddr_in6 a; DWORD l = 27;
    REQUIRE(wc4());
    EXPECT_EQ(wc4()(AF_INET6, &a, &l), SE_FAULT);
    EXPECT_EQ(l, 27);
}
TEST(wsh4_wildcard_unknown_family_gives_inet)
{
    struct sockaddr_in a; DWORD l = sizeof a;
    REQUIRE(wc4());
    memset(&a, 0x77, sizeof a);
    EXPECT_EQ(wc4()(99, &a, &l), 0);
    EXPECT_EQ(l, 16);
    EXPECT_EQ(a.sin_family, AF_INET);
}
TEST(wsh6_wildcard_inet6)
{
    struct sockaddr_in6 a; DWORD l = sizeof a;
    REQUIRE(wc6());
    memset(&a, 0x77, sizeof a);
    EXPECT_EQ(wc6()(AF_INET6, &a, &l), 0);
    EXPECT_EQ(l, 28);
    EXPECT_EQ(a.sin6_family, AF_INET6);
    EXPECT_EQ(a.sin6_addr.s6_addr[15], 0);
}
TEST(wsh6_wildcard_buffer_too_small)
{
    struct sockaddr_in6 a; DWORD l = 20;
    REQUIRE(wc6());
    EXPECT_EQ(wc6()(AF_INET6, &a, &l), SE_FAULT);
}

TEST(wsh4_broadcast_address)
{
    DWORD (WINAPI *f)(short, void *, DWORD *) = (void *)mp("Tcpip4_WSHGetBroadcastSockaddr");
    struct sockaddr_in a; DWORD l = sizeof a;
    REQUIRE(f);
    memset(&a, 0x77, sizeof a);
    EXPECT_EQ(f(AF_INET, &a, &l), 0);
    EXPECT_EQ(l, 16);
    EXPECT_EQ(a.sin_family, AF_INET);
    EXPECT_EQ(a.sin_port, 0);
    EXPECT_EQ(a.sin_addr.s_addr, 0xFFFFFFFFu);
}
TEST(wsh4_broadcast_has_no_inet6_form)
{
    DWORD (WINAPI *f)(short, void *, DWORD *) = (void *)mp("Tcpip4_WSHGetBroadcastSockaddr");
    struct sockaddr_in6 a; DWORD l = sizeof a;
    REQUIRE(f);
    EXPECT_EQ(f(AF_INET6, &a, &l), WSAENOPROTOOPT);
}
TEST(wsh4_broadcast_buffer_too_small)
{
    DWORD (WINAPI *f)(short, void *, DWORD *) = (void *)mp("Tcpip4_WSHGetBroadcastSockaddr");
    struct sockaddr_in a; DWORD l = 15;
    REQUIRE(f);
    EXPECT_EQ(f(AF_INET, &a, &l), SE_FAULT);
}
TEST(wsh4_broadcast_null_buffer)
{
    DWORD (WINAPI *f)(short, void *, DWORD *) = (void *)mp("Tcpip4_WSHGetBroadcastSockaddr");
    DWORD l = 16;
    REQUIRE(f);
    EXPECT_EQ(f(AF_INET, NULL, &l), SE_FAULT);
}

static int guid_is(const GUID *g, const GUID *want) { return !memcmp(g, want, sizeof *g); }
TEST(wsh4_provider_guid_for_tcpip)
{
    wsh_guid_fn f = (wsh_guid_fn)mp("Tcpip4_WSHGetProviderGuid");
    GUID g;
    REQUIRE(f);
    memset(&g, 0, sizeof g);
    EXPECT_EQ(f(L"Tcpip", &g), 0);
    CHECK(guid_is(&g, &sp_guid_v4));
}
TEST(wsh4_provider_guid_name_is_case_insensitive)
{
    wsh_guid_fn f = (wsh_guid_fn)mp("Tcpip4_WSHGetProviderGuid");
    GUID g;
    REQUIRE(f);
    EXPECT_EQ(f(L"TCPIP", &g), 0);
    CHECK(guid_is(&g, &sp_guid_v4));
}
TEST(wsh4_provider_guid_other_name)
{
    wsh_guid_fn f = (wsh_guid_fn)mp("Tcpip4_WSHGetProviderGuid");
    GUID g;
    REQUIRE(f);
    EXPECT_EQ(f(L"Tcpip6", &g), SE_INVAL);
    EXPECT_EQ(f(L"", &g), SE_INVAL);
    EXPECT_EQ(f(L"Tcpip ", &g), SE_INVAL);
}
TEST(wsh4_provider_guid_null_arguments)
{
    wsh_guid_fn f = (wsh_guid_fn)mp("Tcpip4_WSHGetProviderGuid");
    GUID g;
    REQUIRE(f);
    EXPECT_EQ(f(NULL, &g), SE_FAULT);
    EXPECT_EQ(f(L"Tcpip", NULL), SE_FAULT);
}
TEST(wsh6_provider_guid_for_tcpip6)
{
    wsh_guid_fn f = (wsh_guid_fn)mp("Tcpip6_WSHGetProviderGuid");
    GUID g;
    REQUIRE(f);
    EXPECT_EQ(f(L"Tcpip6", &g), 0);
    CHECK(guid_is(&g, &sp_guid_v6));
    EXPECT_EQ(f(L"Tcpip", &g), SE_INVAL);
    EXPECT_EQ(f(NULL, &g), SE_FAULT);
}
TEST(wsh_provider_guids_match_the_catalog)
{
    const WSAPROTOCOL_INFOW *t = sp_pi(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    wsh_guid_fn f = (wsh_guid_fn)mp("Tcpip4_WSHGetProviderGuid");
    GUID g;
    REQUIRE(f);
    EXPECT_EQ(f(L"Tcpip", &g), 0);
    CHECK(guid_is(&g, &t->ProviderId));
}

TEST(wsh4_winsock_mapping_reports_required_size_only)
{
    wsh_mapping_fn f = (wsh_mapping_fn)mp("Tcpip4_WSHGetWinsockMapping");
    DWORD buf[32];
    REQUIRE(f);
    memset(buf, 0x66, sizeof buf);
    EXPECT_EQ(f(buf, 8), 104);
    EXPECT_EQ(buf[0], 0x66666666);
}
TEST(wsh4_winsock_mapping_one_byte_short)
{
    wsh_mapping_fn f = (wsh_mapping_fn)mp("Tcpip4_WSHGetWinsockMapping");
    DWORD buf[32];
    REQUIRE(f);
    memset(buf, 0x66, sizeof buf);
    EXPECT_EQ(f(buf, 103), 104);
    EXPECT_EQ(buf[0], 0x66666666);
}
TEST(wsh4_winsock_mapping_fills_rows)
{
    wsh_mapping_fn f = (wsh_mapping_fn)mp("Tcpip4_WSHGetWinsockMapping");
    DWORD buf[32]; int i;
    REQUIRE(f);
    memset(buf, 0x66, sizeof buf);
    EXPECT_EQ(f(buf, 104), 104);
    EXPECT_EQ(buf[0], 8);      /* rows */
    EXPECT_EQ(buf[1], 3);      /* columns: family, type, protocol */
    for (i = 0; i < 8; i++) EXPECT_EQ(buf[2 + 3 * i], AF_INET);
    EXPECT_EQ(buf[2 + 3 * 0 + 1], SOCK_STREAM);
    EXPECT_EQ(buf[2 + 3 * 3 + 1], SOCK_DGRAM);
    EXPECT_EQ(buf[2 + 3 * 6 + 1], SOCK_RAW);
}
TEST(wsh4_winsock_mapping_larger_buffer_returns_same_size)
{
    wsh_mapping_fn f = (wsh_mapping_fn)mp("Tcpip4_WSHGetWinsockMapping");
    DWORD buf[64];
    REQUIRE(f);
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(f(buf, sizeof buf), 104);
}
TEST(wsh6_winsock_mapping_rows)
{
    wsh_mapping_fn f = (wsh_mapping_fn)mp("Tcpip6_WSHGetWinsockMapping");
    DWORD buf[32]; int i;
    REQUIRE(f);
    memset(buf, 0x66, sizeof buf);
    EXPECT_EQ(f(buf, 104), 104);
    EXPECT_EQ(buf[0], 8);
    EXPECT_EQ(buf[1], 3);
    for (i = 0; i < 8; i++) EXPECT_EQ(buf[2 + 3 * i], AF_INET6);
}
TEST(wsh6_winsock_mapping_short_buffer)
{
    wsh_mapping_fn f = (wsh_mapping_fn)mp("Tcpip6_WSHGetWinsockMapping");
    DWORD buf[32];
    REQUIRE(f);
    memset(buf, 0x66, sizeof buf);
    EXPECT_EQ(f(buf, 50), 104);
    EXPECT_EQ(buf[0], 0x66666666);
}

typedef DWORD (WINAPI *wsh_a2s_fn)(const void *, DWORD, void *, WCHAR *, DWORD *);
typedef DWORD (WINAPI *wsh_s2a_fn)(const WCHAR *, int, void *, void *, DWORD *);
TEST(wsh4_address_to_string_ipv4)
{
    wsh_a2s_fn f = (wsh_a2s_fn)mp("Tcpip4_WSHAddressToString");
    struct sockaddr_in a; WCHAR b[64]; DWORD l = 64;
    REQUIRE(f);
    sp_v4(&a, 81);
    EXPECT_EQ(f(&a, sizeof a, NULL, b, &l), 0);
    EXPECT_WSTR(b, L"127.0.0.1:81");
    EXPECT_EQ(l, 13);
}
TEST(wsh4_address_to_string_argument_checks)
{
    wsh_a2s_fn f = (wsh_a2s_fn)mp("Tcpip4_WSHAddressToString");
    struct sockaddr_in a; WCHAR b[64]; DWORD l = 64;
    REQUIRE(f);
    sp_v4(&a, 81);
    EXPECT_EQ(f(NULL, sizeof a, NULL, b, &l), SE_FAULT);
    EXPECT_EQ(f(&a, 15, NULL, b, &l), SE_FAULT);
    EXPECT_EQ(f(&a, sizeof a, NULL, b, NULL), SE_FAULT);
    EXPECT_EQ(f(&a, sizeof a, NULL, NULL, &l), SE_FAULT);
}
TEST(wsh4_address_to_string_unknown_family)
{
    wsh_a2s_fn f = (wsh_a2s_fn)mp("Tcpip4_WSHAddressToString");
    struct sockaddr_in a; WCHAR b[64]; DWORD l = 64;
    REQUIRE(f);
    sp_v4(&a, 81);
    a.sin_family = 99;
    EXPECT_EQ(f(&a, sizeof a, NULL, b, &l), SE_INVAL);
}
TEST(wsh4_address_to_string_short_buffer_is_fault)
{
    wsh_a2s_fn f = (wsh_a2s_fn)mp("Tcpip4_WSHAddressToString");
    struct sockaddr_in a; WCHAR b[64]; DWORD l = 3;
    REQUIRE(f);
    sp_v4(&a, 81);
    EXPECT_EQ(f(&a, sizeof a, NULL, b, &l), SE_FAULT);
}
TEST(wsh4_address_to_string_ipv6_needs_28_bytes)
{
    wsh_a2s_fn f = (wsh_a2s_fn)mp("Tcpip4_WSHAddressToString");
    struct sockaddr_in6 a; WCHAR b[64]; DWORD l = 64;
    REQUIRE(f);
    sp_v6(&a, 0);
    EXPECT_EQ(f(&a, 27, NULL, b, &l), SE_FAULT);
    EXPECT_EQ(f(&a, 28, NULL, b, &l), 0);
    EXPECT_WSTR(b, L"::1");
}
TEST(wsh4_string_to_address_ipv4)
{
    wsh_s2a_fn f = (wsh_s2a_fn)mp("Tcpip4_WSHStringToAddress");
    struct sockaddr_in a; DWORD l = sizeof a;
    REQUIRE(f);
    memset(&a, 0x77, sizeof a);
    EXPECT_EQ(f(L"5.6.7.8:99", AF_INET, NULL, &a, &l), 0);
    EXPECT_EQ(l, 16);
    EXPECT_EQ(a.sin_family, AF_INET);
    EXPECT_EQ(a.sin_port, sp_swap16(99));
    EXPECT_EQ(a.sin_addr.s_addr, 0x08070605u);
}
TEST(wsh4_string_to_address_argument_checks)
{
    wsh_s2a_fn f = (wsh_s2a_fn)mp("Tcpip4_WSHStringToAddress");
    struct sockaddr_in a; DWORD l = sizeof a;
    REQUIRE(f);
    EXPECT_EQ(f(NULL, AF_INET, NULL, &a, &l), SE_FAULT);
    EXPECT_EQ(f(L"1.2.3.4", AF_INET, NULL, NULL, &l), SE_FAULT);
    EXPECT_EQ(f(L"1.2.3.4", AF_INET, NULL, &a, NULL), SE_FAULT);
    l = 15;
    EXPECT_EQ(f(L"1.2.3.4", AF_INET, NULL, &a, &l), SE_FAULT);
}
TEST(wsh4_string_to_address_bad_text_and_family)
{
    wsh_s2a_fn f = (wsh_s2a_fn)mp("Tcpip4_WSHStringToAddress");
    struct sockaddr_in a; DWORD l = sizeof a;
    REQUIRE(f);
    EXPECT_EQ(f(L"not an address", AF_INET, NULL, &a, &l), SE_INVAL);
    l = sizeof a;
    EXPECT_EQ(f(L"1.2.3.4", AF_INET6, NULL, &a, &l), SE_INVAL);
    EXPECT_EQ(f(L"1.2.3.4", 99, NULL, &a, &l), SE_INVAL);
}

typedef int (WINAPI *wsh_enum_fn)(int *, const WCHAR *, void *, DWORD *);
TEST(wsh4_enum_protocols_both)
{
    wsh_enum_fn f = (wsh_enum_fn)mp("Tcpip4_WSHEnumProtocols");
    DWORD len = 0; char buf[256];
    REQUIRE(f);
    len = 0;
    EXPECT_EQ(f(NULL, L"Tcpip", buf, &len), -1);
    EXPECT_EQ(len, 108);
}
TEST(wsh4_enum_protocols_fills_entries)
{
    wsh_enum_fn f = (wsh_enum_fn)mp("Tcpip4_WSHEnumProtocols");
    DWORD len = 256; char buf[256]; DWORD *p;
    REQUIRE(f);
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(f(NULL, L"Tcpip", buf, &len), 2);
    EXPECT_EQ(len, 108);
    p = (DWORD *)buf;
    EXPECT_EQ(p[1], AF_INET); EXPECT_EQ(p[2], 16); EXPECT_EQ(p[3], 16);
    EXPECT_EQ(p[4], SOCK_STREAM); EXPECT_EQ(p[5], IPPROTO_TCP);
    p = (DWORD *)(buf + 40);
    EXPECT_EQ(p[1], AF_INET); EXPECT_EQ(p[4], SOCK_DGRAM); EXPECT_EQ(p[5], IPPROTO_UDP);
    EXPECT_EQ(p[6], 0xFFF7);
}
TEST(wsh4_enum_protocols_tcp_only)
{
    wsh_enum_fn f = (wsh_enum_fn)mp("Tcpip4_WSHEnumProtocols");
    int want[2] = { IPPROTO_TCP, 0 }; DWORD len = 256; char buf[256];
    REQUIRE(f);
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(f(want, L"Tcpip", buf, &len), 1);
    EXPECT_EQ(len, 54);
    EXPECT_EQ(((DWORD *)buf)[5], IPPROTO_TCP);
}
TEST(wsh4_enum_protocols_udp_only)
{
    wsh_enum_fn f = (wsh_enum_fn)mp("Tcpip4_WSHEnumProtocols");
    int want[2] = { IPPROTO_UDP, 0 }; DWORD len = 256; char buf[256];
    REQUIRE(f);
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(f(want, L"Tcpip", buf, &len), 1);
    EXPECT_EQ(len, 54);
    EXPECT_EQ(((DWORD *)buf)[5], IPPROTO_UDP);
}
TEST(wsh4_enum_protocols_no_match)
{
    wsh_enum_fn f = (wsh_enum_fn)mp("Tcpip4_WSHEnumProtocols");
    int want[2] = { IPPROTO_ICMP, 0 }; DWORD len = 256; char buf[256];
    REQUIRE(f);
    EXPECT_EQ(f(want, L"Tcpip", buf, &len), 0);
    EXPECT_EQ(len, 0);
}
TEST(wsh4_enum_protocols_empty_list_matches_nothing)
{
    wsh_enum_fn f = (wsh_enum_fn)mp("Tcpip4_WSHEnumProtocols");
    int want[1] = { 0 }; DWORD len = 256; char buf[256];
    REQUIRE(f);
    EXPECT_EQ(f(want, L"Tcpip", buf, &len), 0);
    EXPECT_EQ(len, 0);
}
TEST(wsh4_enum_protocols_small_buffer)
{
    wsh_enum_fn f = (wsh_enum_fn)mp("Tcpip4_WSHEnumProtocols");
    DWORD len = 107; char buf[256];
    REQUIRE(f);
    EXPECT_EQ(f(NULL, L"Tcpip", buf, &len), -1);
    EXPECT_EQ(len, 108);
}
