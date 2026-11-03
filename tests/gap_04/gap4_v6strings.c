/* Text conversion and protocol listing of the IPv6 helper embedded in mswsock.dll
 * (Tcpip6_WSHAddressToString, Tcpip6_WSHStringToAddress, Tcpip6_WSHEnumProtocols,
 * Tcpip6_WSHGetWSAProtocolInfo) and the matching protocol-info lookup of the IPv4 helper.
 *
 * Measures: formatting of IPv6 and IPv4 socket addresses (port brackets, zone suffix, length protocol and the
 * exact error for bad arguments); parsing of IPv6 text with and without brackets, port and zone, the all-zero
 * output and the unchanged length on rejection; the enumeration of the two IPv6 transports (entry order, field
 * values, string placement at the end of the caller's buffer, the exact size protocol); and the catalog lookup by
 * transport key name (case-insensitive match, NULL arguments). */
#include "gap4.h"

static struct sockaddr_in6 mk6(const unsigned char *a16, unsigned short port_host, ULONG scope)
{
    struct sockaddr_in6 a;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6; a.sin6_port = g4_sw16(port_host); a.sin6_scope_id = scope;
    if (a16) memcpy(&a.sin6_addr, a16, 16);
    return a;
}
static const unsigned char A_LOOP[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
static const unsigned char A_ZERO[16] = { 0 };
static const unsigned char A_LL[16]   = { 0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
static const unsigned char A_DOC[16]  = { 0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x0a };
static const unsigned char A_SEQ[16]  = { 0,1,0,2,0,3,0,4,0,5,0,6,0,7,0,8 };
static const unsigned char A_MAP[16]  = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff,1,2,3,4 };

/* ---- AddressToString ---- */
typedef struct { const unsigned char *a; unsigned short port; ULONG scope; const WCHAR *want; } a2s6_row;
static const a2s6_row a2s6_rows[] = {
    { A_LOOP, 0, 0, L"::1" }, { A_ZERO, 0, 0, L"::" }, { A_LOOP, 80, 0, L"[::1]:80" }, { A_LL, 0, 5, L"fe80::1%5" },
    { A_LL, 443, 5, L"[fe80::1%5]:443" }, { A_DOC, 0, 0, L"2001:db8::a" }, { A_DOC, 65535, 0, L"[2001:db8::a]:65535" },
    { A_SEQ, 0, 0, L"1:2:3:4:5:6:7:8" }, { A_MAP, 0, 0, L"::ffff:1.2.3.4" }, { A_ZERO, 1, 0, L"[::]:1" },
};
static void a2s6(const g4_fam *fam)
{
    g4_a2s_fn f = (g4_a2s_fn)g4_fn(fam, "AddressToString"); size_t i;
    REQUIRE(f);
    for (i = 0; i < G4N(a2s6_rows); i++) {
        struct sockaddr_in6 a = mk6(a2s6_rows[i].a, a2s6_rows[i].port, a2s6_rows[i].scope);
        WCHAR b[96]; DWORD l = 96; INT r;
        memset(b, 0x7f, sizeof b);
        r = f((LPSOCKADDR)&a, sizeof a, NULL, b, &l);
        CHECKF(r == 0, "%s row %u: rc %d", fam->tag, (unsigned)i, r);
        if (r == 0) {
            CHECKF(!lstrcmpW(b, a2s6_rows[i].want), "%s row %u: text", fam->tag, (unsigned)i);
            CHECKF(l == (DWORD)lstrlenW(a2s6_rows[i].want) + 1, "%s row %u: length %lu", fam->tag, (unsigned)i, l);
        }
    }
}
TEST(gap4_v6_address_to_string_rows) { a2s6(&g4_v6); }
/* The IPv4 helper formats IPv6 addresses the same way. */
TEST(gap4_v4_address_to_string_ipv6_rows) { a2s6(&g4_v4); }

TEST(gap4_v6_address_to_string_ipv4_family)
{
    g4_a2s_fn f = (g4_a2s_fn)g4_fn(&g4_v6, "AddressToString");
    struct sockaddr_in a; WCHAR b[64]; DWORD l = 64;
    REQUIRE(f);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = 0x0100007Fu;
    EXPECT_EQ(f((LPSOCKADDR)&a, sizeof a, NULL, b, &l), 0);
    EXPECT_WSTR(b, L"127.0.0.1"); EXPECT_EQ(l, 10);
    a.sin_port = g4_sw16(80); l = 64;
    EXPECT_EQ(f((LPSOCKADDR)&a, sizeof a, NULL, b, &l), 0);
    EXPECT_WSTR(b, L"127.0.0.1:80"); EXPECT_EQ(l, 13);
}
TEST(gap4_v6_address_to_string_argument_checks)
{
    g4_a2s_fn f = (g4_a2s_fn)g4_fn(&g4_v6, "AddressToString");
    struct sockaddr_in6 a = mk6(A_LOOP, 0, 0); WCHAR b[64]; DWORD l = 64;
    REQUIRE(f);
    EXPECT_EQ(f(NULL, sizeof a, NULL, b, &l), G4_FAULT);
    l = 64; EXPECT_EQ(f((LPSOCKADDR)&a, 15, NULL, b, &l), G4_FAULT);
    l = 64; EXPECT_EQ(f((LPSOCKADDR)&a, 0, NULL, b, &l), G4_FAULT);
    EXPECT_EQ(f((LPSOCKADDR)&a, sizeof a, NULL, b, NULL), G4_FAULT);
    l = 64; EXPECT_EQ(f((LPSOCKADDR)&a, sizeof a, NULL, NULL, &l), G4_FAULT);
}
TEST(gap4_v6_address_to_string_ipv6_needs_28_bytes)
{
    g4_a2s_fn f = (g4_a2s_fn)g4_fn(&g4_v6, "AddressToString");
    struct sockaddr_in6 a = mk6(A_LOOP, 0, 0); WCHAR b[64]; DWORD l;
    REQUIRE(f);
    l = 64; EXPECT_EQ(f((LPSOCKADDR)&a, 16, NULL, b, &l), G4_FAULT);
    l = 64; EXPECT_EQ(f((LPSOCKADDR)&a, 27, NULL, b, &l), G4_FAULT);
    l = 64; EXPECT_EQ(f((LPSOCKADDR)&a, 28, NULL, b, &l), 0);
}
TEST(gap4_v6_address_to_string_ipv4_needs_only_16_bytes)
{
    g4_a2s_fn f = (g4_a2s_fn)g4_fn(&g4_v6, "AddressToString");
    struct sockaddr_in a; WCHAR b[64]; DWORD l = 64;
    REQUIRE(f);
    memset(&a, 0, sizeof a); a.sin_family = AF_INET;
    EXPECT_EQ(f((LPSOCKADDR)&a, 16, NULL, b, &l), 0);
    EXPECT_WSTR(b, L"0.0.0.0");
}
TEST(gap4_v6_address_to_string_unknown_family_is_invalid)
{
    g4_a2s_fn f = (g4_a2s_fn)g4_fn(&g4_v6, "AddressToString");
    struct sockaddr_in6 a = mk6(A_LOOP, 0, 0); WCHAR b[64]; DWORD l;
    int fams[] = { 0, 1, 6, 16, 22, 24, 99, 0xffff };
    size_t i;
    REQUIRE(f);
    for (i = 0; i < G4N(fams); i++) {
        a.sin6_family = (ADDRESS_FAMILY)fams[i]; l = 64;
        CHECKF(f((LPSOCKADDR)&a, sizeof a, NULL, b, &l) == G4_INVAL, "family %d", fams[i]);
    }
}
TEST(gap4_v6_address_to_string_short_buffer_is_fault)
{
    g4_a2s_fn f = (g4_a2s_fn)g4_fn(&g4_v6, "AddressToString");
    struct sockaddr_in6 a = mk6(A_LOOP, 0, 0); WCHAR b[64]; DWORD l;
    REQUIRE(f);
    l = 3; EXPECT_EQ(f((LPSOCKADDR)&a, sizeof a, NULL, b, &l), G4_FAULT);
    l = 1; EXPECT_EQ(f((LPSOCKADDR)&a, sizeof a, NULL, b, &l), G4_FAULT);
    l = 0; EXPECT_EQ(f((LPSOCKADDR)&a, sizeof a, NULL, b, &l), G4_FAULT);
    l = 0; EXPECT_EQ(f((LPSOCKADDR)&a, sizeof a, NULL, NULL, &l), G4_FAULT);
    l = 4; EXPECT_EQ(f((LPSOCKADDR)&a, sizeof a, NULL, b, &l), 0);
    EXPECT_WSTR(b, L"::1");
}
TEST(gap4_v6_address_to_string_exact_fit_for_ipv4)
{
    g4_a2s_fn f = (g4_a2s_fn)g4_fn(&g4_v6, "AddressToString");
    struct sockaddr_in a; WCHAR b[16]; DWORD l;
    REQUIRE(f);
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = 0x0100007Fu;
    l = 9; EXPECT_EQ(f((LPSOCKADDR)&a, sizeof a, NULL, b, &l), G4_FAULT);
    l = 10; EXPECT_EQ(f((LPSOCKADDR)&a, sizeof a, NULL, b, &l), 0);
    EXPECT_WSTR(b, L"127.0.0.1");
}
TEST(gap4_v6_address_to_string_ignores_protocol_info_argument)
{
    g4_a2s_fn f = (g4_a2s_fn)g4_fn(&g4_v6, "AddressToString");
    struct sockaddr_in6 a = mk6(A_LOOP, 0, 0); WCHAR b[64]; DWORD l = 64; WSAPROTOCOL_INFOW pi;
    REQUIRE(f);
    memset(&pi, 0, sizeof pi);
    EXPECT_EQ(f((LPSOCKADDR)&a, sizeof a, &pi, b, &l), 0);
    EXPECT_WSTR(b, L"::1");
}

/* ---- StringToAddress ---- */
typedef struct { const WCHAR *txt; const unsigned char *a; unsigned short port; ULONG scope; } s2a6_row;
static const s2a6_row s2a6_ok[] = {
    { L"::", A_ZERO, 0, 0 }, { L"::1", A_LOOP, 0, 0 }, { L"0:0:0:0:0:0:0:0", A_ZERO, 0, 0 }, { L"1:2:3:4:5:6:7:8", A_SEQ, 0, 0 },
    { L"fe80::1%7", A_LL, 0, 7 }, { L"[::1]:80", A_LOOP, 80, 0 }, { L"[fe80::1%7]:443", A_LL, 443, 7 },
    { L"::ffff:1.2.3.4", A_MAP, 0, 0 }, { L"2001:DB8::A", A_DOC, 0, 0 }, { L"2001:db8::a", A_DOC, 0, 0 },
    { L"[1:2:3:4:5:6:7:8]:65535", A_SEQ, 65535, 0 }, { L"[::]:1", A_ZERO, 1, 0 },
};
static const WCHAR *const s2a6_bad[] = {
    L"", L"g::1", L":::", L"1:2:3:4:5:6:7:8:9", L"1.2.3.4", L"[::1", L"12345::1", L"1::2::3", L"not an address",
    L"::1::", L"1:2:3:4:5:6:7", L"[::1]x", L":1:2:3:4:5:6:7:8",
};
TEST(gap4_v6_string_to_address_rows)
{
    g4_s2a_fn f = (g4_s2a_fn)g4_fn(&g4_v6, "StringToAddress"); size_t i;
    REQUIRE(f);
    for (i = 0; i < G4N(s2a6_ok); i++) {
        struct sockaddr_in6 a; DWORD l = sizeof a; INT r;
        memset(&a, 0x77, sizeof a);
        r = f((LPWSTR)s2a6_ok[i].txt, AF_INET6, NULL, (LPSOCKADDR)&a, &l);
        CHECKF(r == 0, "row %u: rc %d", (unsigned)i, r);
        if (r != 0) continue;
        CHECKF(l == 28, "row %u: length %lu", (unsigned)i, l);
        CHECKF(a.sin6_family == AF_INET6, "row %u: family", (unsigned)i);
        CHECKF(a.sin6_flowinfo == 0, "row %u: flowinfo", (unsigned)i);
        CHECKF(!memcmp(&a.sin6_addr, s2a6_ok[i].a, 16), "row %u: address", (unsigned)i);
        CHECKF(a.sin6_port == g4_sw16(s2a6_ok[i].port), "row %u: port", (unsigned)i);
        CHECKF(a.sin6_scope_id == s2a6_ok[i].scope, "row %u: scope", (unsigned)i);
    }
}
TEST(gap4_v6_string_to_address_bad_text_is_invalid)
{
    g4_s2a_fn f = (g4_s2a_fn)g4_fn(&g4_v6, "StringToAddress"); size_t i;
    REQUIRE(f);
    for (i = 0; i < G4N(s2a6_bad); i++) {
        unsigned char raw[40]; DWORD l = 28; INT r; size_t k; int zero = 1;
        memset(raw, 0x77, sizeof raw);
        r = f((LPWSTR)s2a6_bad[i], AF_INET6, NULL, (LPSOCKADDR)raw, &l);
        CHECKF(r == G4_INVAL, "text %u: rc %d", (unsigned)i, r);
        CHECKF(l == 28, "text %u: length changed to %lu", (unsigned)i, l);
        for (k = 0; k < 28; k++) if (raw[k] != 0) zero = 0;
        (void)zero; /* whether the output buffer is cleared varies per input on Windows 10; not asserted */
        CHECKF(raw[28] == 0x77, "text %u: wrote past 28 bytes", (unsigned)i);
    }
}
TEST(gap4_v6_string_to_address_argument_checks)
{
    g4_s2a_fn f = (g4_s2a_fn)g4_fn(&g4_v6, "StringToAddress");
    struct sockaddr_in6 a; DWORD l = sizeof a;
    REQUIRE(f);
    EXPECT_EQ(f(NULL, AF_INET6, NULL, (LPSOCKADDR)&a, &l), G4_FAULT);
    EXPECT_EQ(f((LPWSTR)L"::1", AF_INET6, NULL, NULL, &l), G4_FAULT);
    EXPECT_EQ(f((LPWSTR)L"::1", AF_INET6, NULL, (LPSOCKADDR)&a, NULL), G4_FAULT);
    l = 27; EXPECT_EQ(f((LPWSTR)L"::1", AF_INET6, NULL, (LPSOCKADDR)&a, &l), G4_FAULT);
    l = 0;  EXPECT_EQ(f((LPWSTR)L"::1", AF_INET6, NULL, (LPSOCKADDR)&a, &l), G4_FAULT);
    l = 28; EXPECT_EQ(f((LPWSTR)L"::1", AF_INET6, NULL, (LPSOCKADDR)&a, &l), 0);
    l = 100; EXPECT_EQ(f((LPWSTR)L"::1", AF_INET6, NULL, (LPSOCKADDR)&a, &l), 0);
    EXPECT_EQ(l, 28);
}
TEST(gap4_v6_string_to_address_other_families_are_invalid)
{
    g4_s2a_fn f = (g4_s2a_fn)g4_fn(&g4_v6, "StringToAddress");
    struct sockaddr_in6 a; DWORD l;
    int fams[] = { AF_INET, 0, 1, 16, 99, -1 };
    size_t i;
    REQUIRE(f);
    for (i = 0; i < G4N(fams); i++) {
        l = sizeof a;
        CHECKF(f((LPWSTR)L"::1", (DWORD)fams[i], NULL, (LPSOCKADDR)&a, &l) == G4_INVAL, "family %d", fams[i]);
        CHECKF(l == sizeof a, "family %d: length changed", fams[i]);
    }
}
TEST(gap4_v6_string_to_address_family_check_precedes_argument_checks)
{
    g4_s2a_fn f = (g4_s2a_fn)g4_fn(&g4_v6, "StringToAddress");
    REQUIRE(f);
    EXPECT_EQ(f(NULL, AF_INET, NULL, NULL, NULL), G4_INVAL);
    EXPECT_EQ(f((LPWSTR)L"1.2.3.4", AF_INET, NULL, NULL, NULL), G4_INVAL);
}
TEST(gap4_v6_string_to_address_ipv4_text_is_not_accepted)
{
    g4_s2a_fn f = (g4_s2a_fn)g4_fn(&g4_v6, "StringToAddress");
    struct sockaddr_in6 a; DWORD l = sizeof a;
    REQUIRE(f);
    EXPECT_EQ(f((LPWSTR)L"127.0.0.1", AF_INET6, NULL, (LPSOCKADDR)&a, &l), G4_INVAL);
    l = sizeof a;
    EXPECT_EQ(f((LPWSTR)L"127.0.0.1:80", AF_INET6, NULL, (LPSOCKADDR)&a, &l), G4_INVAL);
}
TEST(gap4_v6_string_roundtrip)
{
    g4_s2a_fn s = (g4_s2a_fn)g4_fn(&g4_v6, "StringToAddress");
    g4_a2s_fn t = (g4_a2s_fn)g4_fn(&g4_v6, "AddressToString"); size_t i;
    REQUIRE(s); REQUIRE(t);
    for (i = 0; i < G4N(a2s6_rows); i++) {
        struct sockaddr_in6 a; WCHAR b[96]; DWORD l = 96, sl = sizeof a;
        l = 96;
        {
            struct sockaddr_in6 src = mk6(a2s6_rows[i].a, a2s6_rows[i].port, a2s6_rows[i].scope);
            CHECK(t((LPSOCKADDR)&src, sizeof src, NULL, b, &l) == 0);
        }
        CHECKF(s(b, AF_INET6, NULL, (LPSOCKADDR)&a, &sl) == 0, "row %u: reparse", (unsigned)i);
        CHECKF(!memcmp(&a.sin6_addr, a2s6_rows[i].a, 16) && a.sin6_port == g4_sw16(a2s6_rows[i].port) && a.sin6_scope_id == a2s6_rows[i].scope, "row %u: roundtrip", (unsigned)i);
    }
}

/* ---- EnumProtocols (IPv6 helper) ---- */
typedef struct { DWORD flags, af, maxsa, minsa, type, proto, msgsize; LPWSTR name; } g4_pinfo;   /* PROTOCOL_INFOW */
#define NEED_ONE 0x3a
#define NEED_BOTH 0x74
static void expect_entry_tcp(const g4_pinfo *p, const char *w)
{
    CHECKF(p->flags == 0x1066 && p->af == 23 && p->maxsa == 28 && p->minsa == 28, "%s: tcp head", w);
    CHECKF(p->type == 1 && p->proto == 6 && p->msgsize == 0, "%s: tcp type/proto/msg", w);
}
static void expect_entry_udp(const g4_pinfo *p, const char *w)
{
    CHECKF(p->flags == 0x1609 && p->af == 23 && p->maxsa == 28 && p->minsa == 28, "%s: udp head", w);
    CHECKF(p->type == 2 && p->proto == 17 && p->msgsize == 0xfff7, "%s: udp type/proto/msg", w);
}
TEST(gap4_v6_enum_all_protocols)
{
    g4_enum_fn f = (g4_enum_fn)g4_fn(&g4_v6, "EnumProtocols");
    unsigned char buf[0x200]; DWORD len = sizeof buf; g4_pinfo *p = (g4_pinfo *)buf; INT r;
    REQUIRE(f);
    memset(buf, 0x5a, sizeof buf);
    r = f(NULL, (LPWSTR)L"Tcpip6", buf, &len);
    EXPECT_EQ(r, 2); EXPECT_EQ(len, NEED_BOTH);
    expect_entry_tcp(&p[0], "all"); expect_entry_udp(&p[1], "all");
    /* strings are packed at the end of the caller's buffer, TCP first from the end */
    CHECK((unsigned char *)p[0].name == buf + sizeof buf - 0x12);
    CHECK((unsigned char *)p[1].name == buf + sizeof buf - 0x24);
    CHECK(!lstrcmpW(p[0].name, L"TCP/IPv6")); CHECK(!lstrcmpW(p[1].name, L"UDP/IPv6"));
    CHECK(buf[2 * sizeof(g4_pinfo)] == 0x5a);
}
TEST(gap4_v6_enum_tcp_only)
{
    g4_enum_fn f = (g4_enum_fn)g4_fn(&g4_v6, "EnumProtocols");
    unsigned char buf[0x100]; DWORD len = sizeof buf; g4_pinfo *p = (g4_pinfo *)buf; int list[] = { 6, 0 };
    REQUIRE(f);
    memset(buf, 0x5a, sizeof buf);
    EXPECT_EQ(f(list, NULL, buf, &len), 1); EXPECT_EQ(len, NEED_ONE);
    expect_entry_tcp(&p[0], "tcp only");
    CHECK(!lstrcmpW(p[0].name, L"TCP/IPv6"));
    CHECK((unsigned char *)p[0].name == buf + sizeof buf - 0x12);
    CHECK(buf[sizeof(g4_pinfo)] == 0x5a);
}
TEST(gap4_v6_enum_udp_only)
{
    g4_enum_fn f = (g4_enum_fn)g4_fn(&g4_v6, "EnumProtocols");
    unsigned char buf[0x100]; DWORD len = sizeof buf; g4_pinfo *p = (g4_pinfo *)buf; int list[] = { 17, 0 };
    REQUIRE(f);
    memset(buf, 0x5a, sizeof buf);
    EXPECT_EQ(f(list, NULL, buf, &len), 1); EXPECT_EQ(len, NEED_ONE);
    expect_entry_udp(&p[0], "udp only");
    CHECK(!lstrcmpW(p[0].name, L"UDP/IPv6"));
    CHECK((unsigned char *)p[0].name == buf + sizeof buf - 0x12);
}
TEST(gap4_v6_enum_list_order_does_not_change_entry_order)
{
    g4_enum_fn f = (g4_enum_fn)g4_fn(&g4_v6, "EnumProtocols");
    unsigned char buf[0x100]; DWORD len = sizeof buf; g4_pinfo *p = (g4_pinfo *)buf; int list[] = { 17, 6, 0 };
    REQUIRE(f);
    EXPECT_EQ(f(list, NULL, buf, &len), 2); EXPECT_EQ(len, NEED_BOTH);
    CHECK(p[0].proto == 6 && p[1].proto == 17);
}
TEST(gap4_v6_enum_list_ignores_unknown_protocols)
{
    g4_enum_fn f = (g4_enum_fn)g4_fn(&g4_v6, "EnumProtocols");
    unsigned char buf[0x100]; DWORD len = sizeof buf; g4_pinfo *p = (g4_pinfo *)buf; int list[] = { 1, 58, 6, 255, 0 };
    REQUIRE(f);
    EXPECT_EQ(f(list, NULL, buf, &len), 1); EXPECT_EQ(len, NEED_ONE);
    CHECK(p[0].proto == 6);
}
TEST(gap4_v6_enum_no_matching_protocol_reports_zero)
{
    g4_enum_fn f = (g4_enum_fn)g4_fn(&g4_v6, "EnumProtocols");
    unsigned char buf[0x100]; DWORD len = sizeof buf; int l1[] = { 1, 0 }, l2[] = { 0 };
    REQUIRE(f);
    memset(buf, 0x5a, sizeof buf);
    EXPECT_EQ(f(l1, NULL, buf, &len), 0); EXPECT_EQ(len, 0);
    len = sizeof buf; EXPECT_EQ(f(l2, NULL, buf, &len), 0); EXPECT_EQ(len, 0);
    len = 0; EXPECT_EQ(f(l1, NULL, buf, &len), 0); EXPECT_EQ(len, 0);
    CHECK(buf[0] == 0x5a);
}
TEST(gap4_v6_enum_short_buffer_reports_required_size)
{
    g4_enum_fn f = (g4_enum_fn)g4_fn(&g4_v6, "EnumProtocols");
    unsigned char buf[0x100]; DWORD len; int tcp[] = { 6, 0 }, udp[] = { 17, 0 };
    REQUIRE(f);
    memset(buf, 0x5a, sizeof buf);
    len = 0;           EXPECT_EQ((INT)f(NULL, NULL, buf, &len), -1); EXPECT_EQ(len, NEED_BOTH);
    len = NEED_BOTH - 1; EXPECT_EQ((INT)f(NULL, NULL, buf, &len), -1); EXPECT_EQ(len, NEED_BOTH);
    len = 0;           EXPECT_EQ((INT)f(tcp, NULL, buf, &len), -1); EXPECT_EQ(len, NEED_ONE);
    len = NEED_ONE - 1; EXPECT_EQ((INT)f(udp, NULL, buf, &len), -1); EXPECT_EQ(len, NEED_ONE);
    len = NEED_ONE;    EXPECT_EQ((INT)f(NULL, NULL, buf, &len), -1); EXPECT_EQ(len, NEED_BOTH);
    CHECK(buf[0] == 0x5a);
}
TEST(gap4_v6_enum_exact_fit)
{
    g4_enum_fn f = (g4_enum_fn)g4_fn(&g4_v6, "EnumProtocols");
    unsigned char buf[NEED_BOTH]; DWORD len = NEED_BOTH; g4_pinfo *p = (g4_pinfo *)buf;
    REQUIRE(f);
    EXPECT_EQ(f(NULL, NULL, buf, &len), 2); EXPECT_EQ(len, NEED_BOTH);
    CHECK((unsigned char *)p[0].name == buf + NEED_BOTH - 0x12);
    CHECK((unsigned char *)p[1].name == buf + NEED_BOTH - 0x24);
    CHECK(!lstrcmpW(p[0].name, L"TCP/IPv6") && !lstrcmpW(p[1].name, L"UDP/IPv6"));
}
TEST(gap4_v6_enum_larger_buffer_reports_used_size)
{
    g4_enum_fn f = (g4_enum_fn)g4_fn(&g4_v6, "EnumProtocols");
    unsigned char buf[0x400]; DWORD len = sizeof buf;
    REQUIRE(f);
    EXPECT_EQ(f(NULL, NULL, buf, &len), 2); EXPECT_EQ(len, NEED_BOTH);
}

/* ---- GetWSAProtocolInfo ---- */
typedef struct { const WCHAR *name; int ok4, ok6; } pinfo_row;
static const pinfo_row pinfo_rows[] = {
    { L"Tcpip", 1, 0 }, { L"tcpip", 1, 0 }, { L"TCPIP", 1, 0 }, { L"TcPiP", 1, 0 },
    { L"Tcpip6", 0, 1 }, { L"tcpip6", 0, 1 }, { L"TCPIP6", 0, 1 },
    { L"", 0, 0 }, { L"Tcpip ", 0, 0 }, { L" Tcpip", 0, 0 }, { L"Tcpip4", 0, 0 }, { L"Tcpip66", 0, 0 }, { L"Tcp", 0, 0 },
    { L"Tcpip\\", 0, 0 }, { L"Bluetooth", 0, 0 }, { L"RSVP", 0, 0 },
};
static void pinfo_rows_run(const g4_fam *fam, int v6)
{
    g4_protoinfo_fn f = (g4_protoinfo_fn)g4_fn(fam, "GetWSAProtocolInfo"); size_t i;
    REQUIRE(f);
    for (i = 0; i < G4N(pinfo_rows); i++) {
        WSAPROTOCOL_INFOW *arr = (WSAPROTOCOL_INFOW *)(ULONG_PTR)0x1; DWORD n = 0x77; INT r;
        int ok = v6 ? pinfo_rows[i].ok6 : pinfo_rows[i].ok4;
        r = f((LPWSTR)pinfo_rows[i].name, &arr, &n);
        if (ok) {
            CHECKF(r == 0, "%s '%ls': rc %d", fam->tag, pinfo_rows[i].name, r);
            CHECKF(arr != NULL && arr != (void *)(ULONG_PTR)1 && n == 3, "%s '%ls': table %p count %lu", fam->tag, pinfo_rows[i].name, (void *)arr, n);
        } else {
            CHECKF(r == G4_INVAL, "%s '%ls': rc %d", fam->tag, pinfo_rows[i].name, r);
            CHECKF(arr == (void *)(ULONG_PTR)1 && n == 0x77, "%s '%ls': outputs written on failure", fam->tag, pinfo_rows[i].name);
        }
    }
}
TEST(gap4_v4_protocol_info_by_key_name) { pinfo_rows_run(&g4_v4, 0); }
TEST(gap4_v6_protocol_info_by_key_name) { pinfo_rows_run(&g4_v6, 1); }
static void pinfo_nulls(const g4_fam *fam, const WCHAR *good)
{
    g4_protoinfo_fn f = (g4_protoinfo_fn)g4_fn(fam, "GetWSAProtocolInfo");
    WSAPROTOCOL_INFOW *arr = NULL; DWORD n = 0;
    REQUIRE(f);
    EXPECT_EQ(f(NULL, &arr, &n), G4_FAULT);
    EXPECT_EQ(f((LPWSTR)good, NULL, &n), G4_FAULT);
    EXPECT_EQ(f((LPWSTR)good, &arr, NULL), G4_FAULT);
    EXPECT_EQ(f(NULL, NULL, NULL), G4_FAULT);
    CHECK(arr == NULL && n == 0);
}
TEST(gap4_v4_protocol_info_null_arguments) { pinfo_nulls(&g4_v4, L"Tcpip"); }
TEST(gap4_v6_protocol_info_null_arguments) { pinfo_nulls(&g4_v6, L"Tcpip6"); }
static void pinfo_stable(const g4_fam *fam, const WCHAR *good)
{
    g4_protoinfo_fn f = (g4_protoinfo_fn)g4_fn(fam, "GetWSAProtocolInfo");
    WSAPROTOCOL_INFOW *a1 = NULL, *a2 = NULL; DWORD n1 = 0, n2 = 0;
    REQUIRE(f);
    EXPECT_EQ(f((LPWSTR)good, &a1, &n1), 0); EXPECT_EQ(f((LPWSTR)good, &a2, &n2), 0);
    CHECK(a1 == a2 && n1 == n2);
}
TEST(gap4_v4_protocol_info_table_is_static) { pinfo_stable(&g4_v4, L"Tcpip"); }
TEST(gap4_v6_protocol_info_table_is_static) { pinfo_stable(&g4_v6, L"Tcpip6"); }
TEST(gap4_protocol_info_tables_differ_between_families)
{
    g4_protoinfo_fn f4 = (g4_protoinfo_fn)g4_fn(&g4_v4, "GetWSAProtocolInfo"), f6 = (g4_protoinfo_fn)g4_fn(&g4_v6, "GetWSAProtocolInfo");
    WSAPROTOCOL_INFOW *a4 = NULL, *a6 = NULL; DWORD n4 = 0, n6 = 0;
    REQUIRE(f4); REQUIRE(f6);
    EXPECT_EQ(f4(L"Tcpip", &a4, &n4), 0); EXPECT_EQ(f6(L"Tcpip6", &a6, &n6), 0);
    CHECK(a4 != a6);
}
TEST(gap4_protocol_info_table_entries_are_readable)
{
    g4_protoinfo_fn f4 = (g4_protoinfo_fn)g4_fn(&g4_v4, "GetWSAProtocolInfo"), f6 = (g4_protoinfo_fn)g4_fn(&g4_v6, "GetWSAProtocolInfo");
    WSAPROTOCOL_INFOW *a = NULL; DWORD n = 0; DWORD i;
    REQUIRE(f4); REQUIRE(f6);
    EXPECT_EQ(f4(L"Tcpip", &a, &n), 0);
    for (i = 0; a && i < n; i++) t_note("v4 entry %lu: af=%d type=%d proto=%d", i, a[i].iAddressFamily, a[i].iSocketType, a[i].iProtocol);
    a = NULL; n = 0;
    EXPECT_EQ(f6(L"Tcpip6", &a, &n), 0);
    for (i = 0; a && i < n; i++) t_note("v6 entry %lu: af=%d type=%d proto=%d", i, a[i].iAddressFamily, a[i].iSocketType, a[i].iProtocol);
}
