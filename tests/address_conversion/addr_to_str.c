/* WSAAddressToStringA / WSAAddressToStringW beyond the basic vectors.
 * Measures: argument validation order (NULL address, zero length or NULL length pointer ->
 * WSAEINVAL before anything else), sockaddr length checks (shorter than 16 / 28 -> WSAEFAULT with the
 * length variable untouched), unknown families (WSAEINVAL), the text for IPv4 and IPv6 sockaddrs built
 * byte by byte (port in network order, "%scope", "[addr]:port", flow info and sin_zero ignored),
 * the buffer protocol (NULL buffer with length 0 is a size query, NULL buffer with a non-zero length
 * is WSAEFAULT, exact fit succeeds and one short fails with the needed size, failure leaves the
 * buffer alone), A/W agreement, the protocol-info argument and the WSAStartup requirement. */
#include "ac.h"

#define OUTSZ 96

struct a2s_res { int ret, err; DWORD len; char a[OUTSZ]; WCHAR w[OUTSZ]; };

/* wide: use the W entry point. cap: value of *lpdwAddressStringLength on entry. nullbuf: pass a NULL string buffer. */
static void a2s_call(int wide, const unsigned char *sa, DWORD salen, DWORD cap, int nullbuf, struct a2s_res *r) {
    ac_a2s_a_fn fa = AC_A2S_A; ac_a2s_w_fn fw = AC_A2S_W; DWORD len = cap;
    memset(r->a, 0x7e, sizeof r->a);
    wmemset(r->w, 0x7e7e, OUTSZ);
    U(WSASetLastError)(0);
    if (wide) r->ret = fw((LPSOCKADDR)sa, salen, NULL, nullbuf ? NULL : r->w, &len);
    else      r->ret = fa((LPSOCKADDR)sa, salen, NULL, nullbuf ? NULL : r->a, &len);
    r->err = U(WSAGetLastError)();
    r->len = len;
}

static int a2s_ready(void) {
    if (!AC_A2S_A || !AC_A2S_W || !U(WSASetLastError) || !U(WSAGetLastError)) { t_skip("missing export"); return 0; }
    if (!ac_startup()) { t_skip("WSAStartup failed"); return 0; }
    return 1;
}

static int a2s_text_is(const struct a2s_res *r, int wide, const char *want) {
    if (wide) { WCHAR ww[OUTSZ]; ac_widen(want, ww, OUTSZ); return !wcscmp(r->w, ww); }
    return !strcmp(r->a, want);
}

/* One address, both entry points: exact text, exact length, then exact fit / one short. */
static void a2s_expect(const unsigned char *sa, DWORD salen, const char *want) {
    int wide; DWORD need = (DWORD)strlen(want) + 1;
    if (!a2s_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        struct a2s_res r; const char c = wide ? 'W' : 'A';
        a2s_call(wide, sa, salen, OUTSZ, 0, &r);
        CHECKF(r.ret == 0, "%c \"%s\": ret %d err %d", c, want, r.ret, r.err);
        CHECKF(a2s_text_is(&r, wide, want), "%c \"%s\": wrong text \"%s\"", c, want, wide ? "(wide)" : r.a);
        CHECKF(r.len == need, "%c \"%s\": length %lu want %lu", c, want, r.len, need);
        a2s_call(wide, sa, salen, need, 0, &r);                      /* exact fit */
        CHECKF(r.ret == 0 && r.len == need, "%c \"%s\": exact fit ret %d len %lu", c, want, r.ret, r.len);
        a2s_call(wide, sa, salen, need - 1, 0, &r);                  /* one short */
        CHECKF(r.ret == SOCKET_ERROR && r.err == AC_EFAULT, "%c \"%s\": one short ret %d err %d", c, want, r.ret, r.err);
        CHECKF(r.len == need, "%c \"%s\": one short reports %lu want %lu", c, want, r.len, need);
        CHECKF(wide ? r.w[0] == 0x7e7e : r.a[0] == 0x7e, "%c \"%s\": buffer written on failure", c, want);
        a2s_call(wide, sa, salen, 0, 1, &r);                         /* size query */
        CHECKF(r.ret == SOCKET_ERROR && r.err == AC_EFAULT && r.len == need, "%c \"%s\": size query ret %d err %d len %lu", c, want, r.ret, r.err, r.len);
    }
}

#define A4(name, port, a, b, c, d, text) \
    TEST(ac_a2s4_##name) { static const unsigned char ip[4] = { a, b, c, d }; unsigned char sa[28]; \
        ac_raw_v4(sa, port, ip); a2s_expect(sa, 16, text); }
#define A6(name, port, flow, scope, hex, text) \
    TEST(ac_a2s6_##name) { unsigned char sa[28], ip[16]; ac_unhex(hex, ip, 16); \
        ac_raw_v6(sa, port, flow, ip, scope); a2s_expect(sa, 28, text); }

A4(plain,        0, 1, 2, 3, 4, "1.2.3.4")
A4(port_one,     1, 1, 2, 3, 4, "1.2.3.4:1")
A4(port_256,     256, 10, 0, 0, 1, "10.0.0.1:256")
A4(port_0x1234,  0x1234, 10, 0, 0, 1, "10.0.0.1:4660")
A4(port_max,     65535, 127, 0, 0, 1, "127.0.0.1:65535")
A4(three_digit_octets, 0, 100, 200, 250, 199, "100.200.250.199")
A4(one_digit_octets,   9, 0, 0, 0, 0, "0.0.0.0:9")

#define L1 "00000000000000000000000000000001"
A6(loopback,          0, 0, 0, L1, "::1")
A6(port_only,         80, 0, 0, L1, "[::1]:80")
A6(port_byte_order,   0x1234, 0, 0, L1, "[::1]:4660")
A6(port_one,          1, 0, 0, "00000000000000000000000000000000", "[::]:1")
A6(scope_only,        0, 0, 4, "fe800000000000000000000000000001", "fe80::1%4")
A6(scope_and_port,    80, 0, 4, "fe800000000000000000000000000001", "[fe80::1%4]:80")
A6(scope_max,         0, 0, 0xffffffffUL, "fe800000000000000000000000000001", "fe80::1%4294967295")
A6(scope_one_unspecified, 0, 0, 1, "00000000000000000000000000000000", "::%1")
A6(mapped_with_port,  80, 0, 0, "00000000000000000000ffff01020304", "[::ffff:1.2.3.4]:80")
A6(mapped_with_scope, 0, 0, 9, "00000000000000000000ffff01020304", "::ffff:1.2.3.4%9")
A6(compat_dotted,     0, 0, 0, "00000000000000000000000001020304", "::1.2.3.4")
A6(flowinfo_ignored,  0, 0x12345678UL, 0, L1, "::1")
A6(flowinfo_ignored_with_port, 7, 0xffffffffUL, 0, L1, "[::1]:7")
A6(full_eight,        0, 0, 0, "20010db8000100020003000400050006", "2001:db8:1:2:3:4:5:6")
A6(compressed_middle, 0, 0, 0, "20010db8000000000000000000000001", "2001:db8::1")
A6(single_and_pair_runs,     0, 0, 0, "00010000000200000000000300040000", "1:0:2::3:4:0")

/* sin_zero garbage and a sockaddr buffer longer than the minimum are fine. */
TEST(ac_a2s4_sin_zero_and_extra_length_ignored) {
    unsigned char sa[28]; static const unsigned char ip[4] = { 5, 6, 7, 8 };
    ac_raw_v4(sa, 99, ip);
    memset(sa + 8, 0xff, 8);
    a2s_expect(sa, 16, "5.6.7.8:99");
    memset(sa + 16, 0xcd, 12);
    a2s_expect(sa, 28, "5.6.7.8:99");
}
TEST(ac_a2s6_extra_length_ignored) {
    unsigned char sa[64], ip[16];
    ac_unhex(L1, ip, 16);
    memset(sa, 0xcd, sizeof sa);
    ac_raw_v6(sa, 0, 0, ip, 0);
    a2s_expect(sa, 64, "::1");
}

/* Longer than the family needs, in the other direction: an IPv4 family value with a 28-byte length. */
TEST(ac_a2s_v4_family_in_v6_sized_buffer) {
    unsigned char sa[28]; static const unsigned char ip[4] = { 1, 1, 1, 1 };
    ac_raw_v4(sa, 0, ip); memset(sa + 16, 0, 12);
    a2s_expect(sa, 28, "1.1.1.1");
}

/* ---------------------------------------------------------------- argument validation */

TEST(ac_a2s_null_address_is_einval) {
    int wide; unsigned char buf[16];
    if (!a2s_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        struct a2s_res r;
        a2s_call(wide, NULL, 16, OUTSZ, 0, &r);
        CHECKF(r.ret == SOCKET_ERROR && r.err == AC_EINVAL, "%c: ret %d err %d", wide ? 'W' : 'A', r.ret, r.err);
        CHECK(r.len == OUTSZ);
    }
    (void)buf;
}

TEST(ac_a2s_zero_address_length_is_einval) {
    int wide; unsigned char sa[28]; static const unsigned char ip[4] = { 1, 2, 3, 4 };
    if (!a2s_ready()) return;
    ac_raw_v4(sa, 0, ip);
    for (wide = 0; wide < 2; wide++) {
        struct a2s_res r;
        a2s_call(wide, sa, 0, OUTSZ, 0, &r);
        CHECKF(r.ret == SOCKET_ERROR && r.err == AC_EINVAL, "%c: ret %d err %d", wide ? 'W' : 'A', r.ret, r.err);
        CHECK(r.len == OUTSZ);
    }
}

TEST(ac_a2s_null_length_pointer_is_einval) {
    unsigned char sa[28]; static const unsigned char ip[4] = { 1, 2, 3, 4 }; char a[32]; WCHAR w[32]; int r;
    if (!a2s_ready()) return;
    ac_raw_v4(sa, 0, ip);
    U(WSASetLastError)(0);
    r = AC_A2S_A((LPSOCKADDR)sa, 16, NULL, a, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
    U(WSASetLastError)(0);
    r = AC_A2S_W((LPSOCKADDR)sa, 16, NULL, w, NULL);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
}

/* Argument validation precedes the family lookup: a NULL address with a bogus protocol info is still WSAEINVAL. */
TEST(ac_a2s_argument_check_precedes_catalog) {
    WSAPROTOCOL_INFOW pi; DWORD len = OUTSZ; WCHAR w[OUTSZ]; int r;
    if (!a2s_ready()) return;
    memset(&pi, 0, sizeof pi); pi.dwCatalogEntryId = 0x7fffff01;
    U(WSASetLastError)(0);
    r = AC_A2S_W(NULL, 16, &pi, w, &len);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
}

static void short_sockaddr(unsigned char *sa, const DWORD *lens, unsigned n) {
    int wide; unsigned i;
    if (!a2s_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        for (i = 0; i < n; i++) {
            struct a2s_res r;
            a2s_call(wide, sa, lens[i], 77, 0, &r);
            CHECKF(r.ret == SOCKET_ERROR && r.err == AC_EFAULT, "%c addrlen %lu: ret %d err %d", wide ? 'W' : 'A', lens[i], r.ret, r.err);
            CHECKF(r.len == 77, "%c addrlen %lu: string length changed to %lu", wide ? 'W' : 'A', lens[i], r.len);
            CHECKF(wide ? r.w[0] == 0x7e7e : r.a[0] == 0x7e, "%c addrlen %lu: buffer written", wide ? 'W' : 'A', lens[i]);
        }
    }
}
TEST(ac_a2s4_short_sockaddr_is_efault) {
    static const DWORD lens[] = { 1, 2, 4, 8, 12, 15 }; unsigned char sa[28]; static const unsigned char ip[4] = { 1, 2, 3, 4 };
    ac_raw_v4(sa, 0, ip);
    short_sockaddr(sa, lens, AC_COUNT(lens));
}
TEST(ac_a2s6_short_sockaddr_is_efault) {
    static const DWORD lens[] = { 1, 2, 4, 16, 20, 24, 27 }; unsigned char sa[28], ip[16];
    ac_unhex(L1, ip, 16); ac_raw_v6(sa, 0, 0, ip, 0);
    short_sockaddr(sa, lens, AC_COUNT(lens));
}

TEST(ac_a2s_unknown_family_is_einval) {
    static const unsigned short fams[] = { 0x7ffe, 0x1234, 99, 0xffff };
    unsigned char sa[28]; unsigned i; int wide;
    if (!a2s_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        for (i = 0; i < AC_COUNT(fams); i++) {
            struct a2s_res r;
            memset(sa, 0, sizeof sa); sa[0] = (unsigned char)fams[i]; sa[1] = (unsigned char)(fams[i] >> 8);
            a2s_call(wide, sa, 28, 77, 0, &r);
            CHECKF(r.ret == SOCKET_ERROR && r.err == AC_EINVAL, "%c family 0x%x: ret %d err %d", wide ? 'W' : 'A', fams[i], r.ret, r.err);
            CHECKF(r.len == 77, "family 0x%x: length changed", fams[i]);
        }
    }
}

TEST(ac_a2s_unspec_family_outcome) {
    unsigned char sa[28] = {0}; int wide;
    if (!a2s_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        struct a2s_res r;
        a2s_call(wide, sa, 28, OUTSZ, 0, &r);
        t_note("%c AddressToString with family 0: ret=%d err=%d", wide ? 'W' : 'A', r.ret, r.err);
    }
}

/* A sockaddr_in6 length with an AF_INET family value is judged by the family: 16 bytes suffice. */
TEST(ac_a2s_family_not_length_selects_format) {
    unsigned char sa[28]; static const unsigned char ip[4] = { 1, 2, 3, 4 };
    ac_raw_v4(sa, 0, ip);
    a2s_expect(sa, 16, "1.2.3.4");
}

/* ---------------------------------------------------------------- buffer protocol */

TEST(ac_a2s_null_buffer_with_nonzero_length_is_efault_and_untouched) {
    unsigned char sa[28]; static const unsigned char ip[4] = { 1, 2, 3, 4 }; int wide;
    if (!a2s_ready()) return;
    ac_raw_v4(sa, 0, ip);
    for (wide = 0; wide < 2; wide++) {
        struct a2s_res r;
        a2s_call(wide, sa, 16, 40, 1, &r);
        CHECKF(r.ret == SOCKET_ERROR && r.err == AC_EFAULT, "%c: ret %d err %d", wide ? 'W' : 'A', r.ret, r.err);
        CHECKF(r.len == 40, "%c: length changed to %lu", wide ? 'W' : 'A', r.len);
    }
}

TEST(ac_a2s6_null_buffer_with_nonzero_length_is_efault_and_untouched) {
    unsigned char sa[28], ip[16]; int wide;
    if (!a2s_ready()) return;
    ac_unhex(L1, ip, 16); ac_raw_v6(sa, 0, 0, ip, 0);
    for (wide = 0; wide < 2; wide++) {
        struct a2s_res r;
        a2s_call(wide, sa, 28, 5, 1, &r);
        CHECKF(r.ret == SOCKET_ERROR && r.err == AC_EFAULT, "%c: ret %d err %d", wide ? 'W' : 'A', r.ret, r.err);
        CHECKF(r.len == 5, "%c: length changed to %lu", wide ? 'W' : 'A', r.len);
    }
}

TEST(ac_a2s_size_query_both_forms_both_families) {
    unsigned char s4[28], s6[28], ip6[16]; static const unsigned char ip4[4] = { 192, 168, 100, 200 }; int wide;
    if (!a2s_ready()) return;
    ac_raw_v4(s4, 8080, ip4);
    ac_unhex("fe800000000000000000000000000001", ip6, 16); ac_raw_v6(s6, 8080, 0, ip6, 3);
    for (wide = 0; wide < 2; wide++) {
        struct a2s_res r;
        a2s_call(wide, s4, 16, 0, 1, &r);
        CHECK(r.ret == SOCKET_ERROR); EXPECT_EQ(r.err, AC_EFAULT); EXPECT_EQ(r.len, strlen("192.168.100.200:8080") + 1);
        a2s_call(wide, s6, 28, 0, 1, &r);
        CHECK(r.ret == SOCKET_ERROR); EXPECT_EQ(r.err, AC_EFAULT); EXPECT_EQ(r.len, strlen("[fe80::1%3]:8080") + 1);
    }
}

/* A zero length with a real buffer behaves like a size query and writes nothing. */
TEST(ac_a2s_zero_length_with_buffer_reports_size) {
    unsigned char sa[28]; static const unsigned char ip[4] = { 1, 2, 3, 4 }; int wide;
    if (!a2s_ready()) return;
    ac_raw_v4(sa, 0, ip);
    for (wide = 0; wide < 2; wide++) {
        struct a2s_res r;
        a2s_call(wide, sa, 16, 0, 0, &r);
        CHECK(r.ret == SOCKET_ERROR); EXPECT_EQ(r.err, AC_EFAULT); EXPECT_EQ(r.len, 8);
        CHECK(wide ? r.w[0] == 0x7e7e : r.a[0] == 0x7e);
    }
}

/* Success writes the terminator and nothing past it. */
TEST(ac_a2s_success_writes_text_and_terminator_only) {
    unsigned char sa[28]; static const unsigned char ip[4] = { 1, 2, 3, 4 }; struct a2s_res r;
    if (!a2s_ready()) return;
    ac_raw_v4(sa, 0, ip);
    a2s_call(0, sa, 16, OUTSZ, 0, &r);
    CHECK(r.ret == 0); EXPECT_EQ(r.a[7], 0); EXPECT_EQ(r.a[8], 0x7e);
    a2s_call(1, sa, 16, OUTSZ, 0, &r);
    CHECK(r.ret == 0); EXPECT_EQ(r.w[7], 0); EXPECT_EQ(r.w[8], 0x7e7e);
}

/* ---------------------------------------------------------------- protocol info argument */

static int find_entry(int fam, WSAPROTOCOL_INFOW *out) {
    DWORD sz = 0; WSAPROTOCOL_INFOW *all; int n, i, found = 0;
    if (!U(WSAEnumProtocolsW)) return 0;
    U(WSAEnumProtocolsW)(NULL, NULL, &sz);
    if (!sz || sz > (1u << 20)) return 0;
    all = (WSAPROTOCOL_INFOW *)HeapAlloc(GetProcessHeap(), 0, sz);
    if (!all) return 0;
    n = U(WSAEnumProtocolsW)(NULL, all, &sz);
    for (i = 0; i < n && !found; i++)
        if (all[i].iAddressFamily == fam && all[i].ProtocolChain.ChainLen == 1) { *out = all[i]; found = 1; }
    HeapFree(GetProcessHeap(), 0, all);
    return found;
}

TEST(ac_a2s_protocol_info_matching_entry) {
    WSAPROTOCOL_INFOW pi; unsigned char sa[28]; static const unsigned char ip[4] = { 7, 7, 7, 7 }; DWORD len = OUTSZ; WCHAR w[OUTSZ]; char a[OUTSZ]; int r;
    if (!a2s_ready()) return;
    if (!find_entry(AF_INET, &pi)) { t_skip("no AF_INET catalog entry"); return; }
    ac_raw_v4(sa, 0, ip);
    r = AC_A2S_W((LPSOCKADDR)sa, 16, &pi, w, &len);
    EXPECT_EQ(r, 0); EXPECT_EQ(len, 8); CHECK(!wcscmp(w, L"7.7.7.7"));
    {   WSAPROTOCOL_INFOA pa; memset(&pa, 0, sizeof pa); pa.dwCatalogEntryId = pi.dwCatalogEntryId;
        len = OUTSZ;
        r = AC_A2S_A((LPSOCKADDR)sa, 16, &pa, a, &len);
        EXPECT_EQ(r, 0); EXPECT_EQ(len, 8); EXPECT_STR(a, "7.7.7.7");
    }
}

TEST(ac_a2s_protocol_info_unknown_catalog_id) {
    WSAPROTOCOL_INFOW pi; unsigned char sa[28]; static const unsigned char ip[4] = { 7, 7, 7, 7 }; DWORD len = 77; WCHAR w[OUTSZ]; int r;
    if (!a2s_ready()) return;
    ac_raw_v4(sa, 0, ip);
    memset(&pi, 0, sizeof pi);
    U(WSASetLastError)(0);
    r = AC_A2S_W((LPSOCKADDR)sa, 16, &pi, w, &len);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL); EXPECT_EQ(len, 77);
    pi.dwCatalogEntryId = 0x7fffff01;
    U(WSASetLastError)(0);
    r = AC_A2S_W((LPSOCKADDR)sa, 16, &pi, w, &len);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
}

/* ---------------------------------------------------------------- properties over many addresses */

static unsigned long lcg(unsigned long *s) { *s = *s * 1664525UL + 1013904223UL; return *s; }

/* Every IPv6 sockaddr prints as inet_ntop text, wrapped by the optional scope and port. */
TEST(ac_a2s6_random_addresses_match_ntop) {
    unsigned long seed = 12345; int i;
    ac_ntop_a_fn na = AC_NTOP_A;
    if (!a2s_ready()) return;
    REQUIRE(na);
    for (i = 0; i < 300; i++) {
        unsigned char ip[16], sa[28]; unsigned port, k; unsigned long scope; char base[64], want[96]; int wide;
        for (k = 0; k < 16; k++) {
            unsigned long v = lcg(&seed) >> 16;
            ip[k] = (unsigned char)((i % 3 == 0 && (v & 3) != 0) ? 0 : v);    /* many zero bytes: exercises compression */
        }
        port = (i % 4 == 0) ? 0 : (lcg(&seed) >> 8) & 0xffff;
        scope = (i % 5 < 2) ? 0 : (lcg(&seed) >> 4) % 100000;
        ac_raw_v6(sa, (unsigned short)port, 0, ip, scope);
        if (!na(AF_INET6, ip, base, sizeof base)) { CHECK(0); continue; }
        if (port && scope) snprintf(want, sizeof want, "[%s%%%lu]:%u", base, scope, port);
        else if (port)     snprintf(want, sizeof want, "[%s]:%u", base, port);
        else if (scope)    snprintf(want, sizeof want, "%s%%%lu", base, scope);
        else               snprintf(want, sizeof want, "%s", base);
        for (wide = 0; wide < 2; wide++) {
            struct a2s_res r;
            a2s_call(wide, sa, 28, OUTSZ, 0, &r);
            CHECKF(r.ret == 0 && a2s_text_is(&r, wide, want) && r.len == strlen(want) + 1,
                   "%c row %d: want \"%s\" got ret %d len %lu \"%s\"", wide ? 'W' : 'A', i, want, r.ret, r.len, wide ? "(wide)" : r.a);
        }
    }
}

TEST(ac_a2s4_random_addresses_match_ntoa) {
    unsigned long seed = 777; int i;
    if (!a2s_ready()) return;
    for (i = 0; i < 300; i++) {
        unsigned char ip[4], sa[28]; unsigned port; char want[40]; int wide;
        ip[0] = (unsigned char)(lcg(&seed) >> 12); ip[1] = (unsigned char)(lcg(&seed) >> 12);
        ip[2] = (unsigned char)(lcg(&seed) >> 12); ip[3] = (unsigned char)(lcg(&seed) >> 12);
        port = (i % 3 == 0) ? 0 : (lcg(&seed) >> 8) & 0xffff;
        ac_raw_v4(sa, (unsigned short)port, ip);
        if (port) snprintf(want, sizeof want, "%u.%u.%u.%u:%u", ip[0], ip[1], ip[2], ip[3], port);
        else      snprintf(want, sizeof want, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
        for (wide = 0; wide < 2; wide++) {
            struct a2s_res r;
            a2s_call(wide, sa, 16, OUTSZ, 0, &r);
            CHECKF(r.ret == 0 && a2s_text_is(&r, wide, want) && r.len == strlen(want) + 1,
                   "%c row %d: want \"%s\"", wide ? 'W' : 'A', i, want);
        }
    }
}

/* Converting to text and back reproduces the sockaddr fields. */
TEST(ac_a2s_s2a_roundtrip) {
    unsigned long seed = 4242; int i;
    if (!a2s_ready()) return;
    REQUIRE(AC_S2A_A);
    for (i = 0; i < 150; i++) {
        unsigned char ip[16], sa[28], back[28]; unsigned port, k; unsigned long scope; struct a2s_res r; int len = 28; int wide = i & 1;
        for (k = 0; k < 16; k++) { unsigned long v = lcg(&seed) >> 16; ip[k] = (unsigned char)((v & 1) ? 0 : v); }
        port = (lcg(&seed) >> 8) & 0xffff; if (port == 0) port = 1;
        scope = (lcg(&seed) >> 4) % 1000;
        ac_raw_v6(sa, (unsigned short)port, 0, ip, scope);
        a2s_call(wide, sa, 28, OUTSZ, 0, &r);
        CHECK(r.ret == 0);
        memset(back, 0xab, sizeof back);
        if (wide) CHECK(AC_S2A_W(r.w, AF_INET6, NULL, (LPSOCKADDR)back, &len) == 0);
        else      CHECK(AC_S2A_A(r.a, AF_INET6, NULL, (LPSOCKADDR)back, &len) == 0);
        EXPECT_EQ(len, 28);
        CHECKF(!memcmp(back, sa, 28), "row %d: %s did not survive the round trip", i, wide ? "(wide)" : r.a);
    }
}

/* ---------------------------------------------------------------- WSAStartup requirement */

CHILD(ac_nostart_wsa_calls) {
    unsigned char sa[28]; static const unsigned char ip[4] = { 1, 2, 3, 4 }; char a[32]; WCHAR w[32]; DWORD len; int bad = 0, r, e;
    SOCKET s = 0; WSAPROTOCOL_INFOW unused; int sl = 28; unsigned char out[28];
    ac_a2s_a_fn fa = AC_A2S_A; ac_a2s_w_fn fw = AC_A2S_W; ac_s2a_a_fn sa_a = AC_S2A_A; ac_s2a_w_fn sa_w = AC_S2A_W;
    int (WSAAPI *geterr)(void) = (int (WSAAPI *)(void))t_proc_in("ws2_32.dll", "WSAGetLastError");
    int (WSAAPI *hs)(SOCKET, u_short, u_short *) = (void *)t_proc_in("ws2_32.dll", "WSAHtons");
    int (WSAAPI *hl)(SOCKET, u_long, u_long *) = (void *)t_proc_in("ws2_32.dll", "WSAHtonl");
    u_short o2; u_long o4;
    (void)unused;
    if (!fa || !fw || !sa_a || !sa_w || !geterr || !hs || !hl) return 0;
    ac_raw_v4(sa, 0, ip);
    len = 32; r = fa((LPSOCKADDR)sa, 16, NULL, a, &len); e = geterr();
    if (r != -1 || e != AC_NOTINIT) { printf("AddressToStringA %d %d\n", r, e); bad++; }
    len = 32; r = fw((LPSOCKADDR)sa, 16, NULL, w, &len); e = geterr();
    if (r != -1 || e != AC_NOTINIT) { printf("AddressToStringW %d %d\n", r, e); bad++; }
    r = sa_a("1.2.3.4", AF_INET, NULL, (LPSOCKADDR)out, &sl); e = geterr();
    if (r != -1 || e != AC_NOTINIT) { printf("StringToAddressA %d %d\n", r, e); bad++; }
    sl = 28; r = sa_w(L"1.2.3.4", AF_INET, NULL, (LPSOCKADDR)out, &sl); e = geterr();
    if (r != -1 || e != AC_NOTINIT) { printf("StringToAddressW %d %d\n", r, e); bad++; }
    r = hs(s, 1, &o2); e = geterr();
    if (r != -1 || e != AC_NOTINIT) { printf("WSAHtons %d %d\n", r, e); bad++; }
    r = hl(s, 1, &o4); e = geterr();
    if (r != -1 || e != AC_NOTINIT) { printf("WSAHtonl %d %d\n", r, e); bad++; }
    return bad;
}
TEST(ac_wsa_text_conversions_need_wsastartup) {
    REQUIRE(AC_A2S_A);
    { DWORD code = t_run_child("ac_nostart_wsa_calls", "", 30000); EXPECT_EQ(code, 0); }
}
