/* inet_pton / InetPtonW / inet_ntop / InetNtopW beyond the basic vectors.
 * Measures: argument validation order (NULL pointer -> WSAEFAULT before the family is looked at,
 * unsupported family -> WSAEAFNOSUPPORT), strict grammar extras for both families (no scope id,
 * no brackets, no octal/hex IPv4 parts), exactly how many bytes a successful conversion writes,
 * the canonical IPv6 text form (longest-zero-run compression, first run wins ties, single zero
 * group kept, lower case, embedded dotted quad for the IPv4-compatible / mapped / translated /
 * ISATAP shapes), the exact-fit buffer protocol with WSAEINVAL, an untouched buffer on failure,
 * and that no WSAStartup is needed. Wide and narrow forms are held to the same expectations. */
#include "ac.h"

/* ------------------------------------------------------------------ argument validation */

TEST(ac_pton_null_destination_is_efault) {
    ac_pton_a_fn pa = AC_PTON_A; ac_pton_w_fn pw = AC_PTON_W; int r;
    REQUIRE(pa); REQUIRE(pw); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    AC_NEED_WSA();
    U(WSASetLastError)(0); r = pa(AF_INET, "1.2.3.4", NULL);
    EXPECT_EQ(r, -1); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
    U(WSASetLastError)(0); r = pa(AF_INET6, "::1", NULL);
    EXPECT_EQ(r, -1); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
    U(WSASetLastError)(0); r = pw(AF_INET, L"1.2.3.4", NULL);
    EXPECT_EQ(r, -1); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
    U(WSASetLastError)(0); r = pw(AF_INET6, L"::1", NULL);
    EXPECT_EQ(r, -1); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
}

TEST(ac_pton_both_pointers_null_is_efault) {
    ac_pton_a_fn pa = AC_PTON_A; ac_pton_w_fn pw = AC_PTON_W; int r;
    REQUIRE(pa); REQUIRE(pw); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    AC_NEED_WSA();
    U(WSASetLastError)(0); r = pa(AF_INET, NULL, NULL);
    EXPECT_EQ(r, -1); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
    U(WSASetLastError)(0); r = pw(AF_INET6, NULL, NULL);
    EXPECT_EQ(r, -1); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
}

/* The NULL test comes before the family test: a bogus family with a NULL pointer is still WSAEFAULT. */
TEST(ac_pton_null_beats_bad_family) {
    ac_pton_a_fn pa = AC_PTON_A; ac_pton_w_fn pw = AC_PTON_W; unsigned char buf[16]; int r;
    REQUIRE(pa); REQUIRE(pw); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    AC_NEED_WSA();
    U(WSASetLastError)(0); r = pa(99, NULL, buf);
    EXPECT_EQ(r, -1); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
    U(WSASetLastError)(0); r = pw(99, L"1.2.3.4", NULL);
    EXPECT_EQ(r, -1); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
}

static void pton_bad_family(int fam) {
    ac_pton_a_fn pa = AC_PTON_A; ac_pton_w_fn pw = AC_PTON_W; unsigned char buf[16]; int r;
    if (!pa || !pw || !U(WSASetLastError) || !U(WSAGetLastError)) { t_skip("missing export"); return; }
    if (!ac_startup()) { t_skip("WSAStartup failed"); return; }
    memset(buf, 0x5a, sizeof buf);
    U(WSASetLastError)(0); r = pa(fam, "1.2.3.4", buf);
    CHECKF(r == -1, "inet_pton family %d: ret %d", fam, r);
    CHECKF(U(WSAGetLastError)() == AC_EAFNOSUPPORT, "inet_pton family %d: error %d", fam, U(WSAGetLastError)());
    U(WSASetLastError)(0); r = pw(fam, L"::1", buf);
    CHECKF(r == -1, "InetPtonW family %d: ret %d", fam, r);
    CHECKF(U(WSAGetLastError)() == AC_EAFNOSUPPORT, "InetPtonW family %d: error %d", fam, U(WSAGetLastError)());
    CHECKF(buf[0] == 0x5a && buf[15] == 0x5a, "family %d: output modified", fam);
}
#define PBF(name, fam) TEST(ac_pton_family_##name) { pton_bad_family(fam); }
PBF(unix_1,        1)
PBF(ipx_6,         6)
PBF(netbios_17,    17)
PBF(irda_26,       26)
PBF(bth_32,        32)
PBF(negative,      -1)
PBF(high_bits_set, 0x10002)
PBF(big,           0x7fff)

TEST(ac_ntop_bad_family_is_afnosupport) {
    ac_ntop_a_fn na = AC_NTOP_A; ac_ntop_w_fn nw = AC_NTOP_W;
    unsigned char addr[16] = {0}; char ab[64]; WCHAR wb[64];
    static const int fams[] = { 0, 1, 6, 17, 22, 24, 26, 32, -1, 0x10002 };
    unsigned i;
    REQUIRE(na); REQUIRE(nw); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    AC_NEED_WSA();
    for (i = 0; i < AC_COUNT(fams); i++) {
        U(WSASetLastError)(0);
        CHECKF(na(fams[i], addr, ab, sizeof ab) == NULL, "inet_ntop family %d succeeded", fams[i]);
        CHECKF(U(WSAGetLastError)() == AC_EAFNOSUPPORT, "inet_ntop family %d: error %d", fams[i], U(WSAGetLastError)());
        U(WSASetLastError)(0);
        CHECKF(nw(fams[i], addr, wb, 64) == NULL, "InetNtopW family %d succeeded", fams[i]);
        CHECKF(U(WSAGetLastError)() == AC_EAFNOSUPPORT, "InetNtopW family %d: error %d", fams[i], U(WSAGetLastError)());
    }
}

/* The family is validated even when the destination is bad: family first, then the Rtl-level checks. */
TEST(ac_ntop_family_checked_before_destination) {
    ac_ntop_a_fn na = AC_NTOP_A; unsigned char addr[16] = {0};
    REQUIRE(na); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    AC_NEED_WSA();
    U(WSASetLastError)(0);
    CHECK(na(1, addr, NULL, 0) == NULL);
    EXPECT_EQ(U(WSAGetLastError)(), AC_EAFNOSUPPORT);
}

TEST(ac_ntop_null_source_is_einval) {
    ac_ntop_a_fn na = AC_NTOP_A; ac_ntop_w_fn nw = AC_NTOP_W; char ab[64]; WCHAR wb[64];
    REQUIRE(na); REQUIRE(nw); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    AC_NEED_WSA();
    U(WSASetLastError)(0); CHECK(na(AF_INET, NULL, ab, sizeof ab) == NULL); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
    U(WSASetLastError)(0); CHECK(na(AF_INET6, NULL, ab, sizeof ab) == NULL); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
    U(WSASetLastError)(0); CHECK(nw(AF_INET, NULL, wb, 64) == NULL); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
    U(WSASetLastError)(0); CHECK(nw(AF_INET6, NULL, wb, 64) == NULL); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
}

TEST(ac_ntopw_null_destination_and_zero_size) {
    ac_ntop_w_fn nw = AC_NTOP_W; unsigned long v4 = AC_RAW(1, 2, 3, 4); unsigned char v6[16] = {0}; WCHAR wb[64];
    REQUIRE(nw); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    AC_NEED_WSA();
    U(WSASetLastError)(0); CHECK(nw(AF_INET, &v4, NULL, 64) == NULL); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
    U(WSASetLastError)(0); CHECK(nw(AF_INET6, v6, NULL, 64) == NULL); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
    U(WSASetLastError)(0); CHECK(nw(AF_INET, &v4, wb, 0) == NULL); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
    U(WSASetLastError)(0); CHECK(nw(AF_INET6, v6, wb, 0) == NULL); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
}

/* A successful conversion leaves the thread's WinSock error alone; only failures set it. */
TEST(ac_ntop_success_keeps_last_error) {
    ac_ntop_a_fn na = AC_NTOP_A; ac_ntop_w_fn nw = AC_NTOP_W; unsigned long v4 = AC_RAW(1, 2, 3, 4);
    unsigned char v6[16] = {0}; char ab[64]; WCHAR wb[64];
    REQUIRE(na); REQUIRE(nw); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    AC_NEED_WSA();
    U(WSASetLastError)(0x2345); CHECK(na(AF_INET, &v4, ab, sizeof ab) == ab); EXPECT_EQ(U(WSAGetLastError)(), 0x2345);
    U(WSASetLastError)(0x2345); CHECK(na(AF_INET6, v6, ab, sizeof ab) == ab); EXPECT_EQ(U(WSAGetLastError)(), 0x2345);
    U(WSASetLastError)(0x2345); CHECK(nw(AF_INET, &v4, wb, 64) == wb); EXPECT_EQ(U(WSAGetLastError)(), 0x2345);
    U(WSASetLastError)(0x2345); CHECK(nw(AF_INET6, v6, wb, 64) == wb); EXPECT_EQ(U(WSAGetLastError)(), 0x2345);
}

/* ------------------------------------------------------------------ pton: bytes written */

TEST(ac_pton_v4_writes_exactly_four_bytes) {
    ac_pton_a_fn pa = AC_PTON_A; ac_pton_w_fn pw = AC_PTON_W; unsigned char buf[12]; int r;
    REQUIRE(pa); REQUIRE(pw); AC_NEED_WSA();
    memset(buf, 0xcc, sizeof buf);
    r = pa(AF_INET, "9.8.7.6", buf + 4);
    EXPECT_EQ(r, 1);
    CHECK(buf[3] == 0xcc && buf[4] == 9 && buf[5] == 8 && buf[6] == 7 && buf[7] == 6 && buf[8] == 0xcc);
    memset(buf, 0xcc, sizeof buf);
    r = pw(AF_INET, L"255.0.1.254", buf + 4);
    EXPECT_EQ(r, 1);
    CHECK(buf[3] == 0xcc && buf[4] == 255 && buf[5] == 0 && buf[6] == 1 && buf[7] == 254 && buf[8] == 0xcc);
}

TEST(ac_pton_v6_writes_exactly_sixteen_bytes) {
    ac_pton_a_fn pa = AC_PTON_A; ac_pton_w_fn pw = AC_PTON_W; unsigned char buf[24], want[16]; int r;
    REQUIRE(pa); REQUIRE(pw); AC_NEED_WSA();
    ac_unhex("20010db8000000000000000000000001", want, 16);
    memset(buf, 0xcc, sizeof buf);
    r = pa(AF_INET6, "2001:db8::1", buf + 4);
    EXPECT_EQ(r, 1);
    CHECK(buf[3] == 0xcc && !memcmp(buf + 4, want, 16) && buf[20] == 0xcc);
    memset(buf, 0xcc, sizeof buf);
    r = pw(AF_INET6, L"2001:db8::1", buf + 4);
    EXPECT_EQ(r, 1);
    CHECK(buf[3] == 0xcc && !memcmp(buf + 4, want, 16) && buf[20] == 0xcc);
}

TEST(ac_pton_v6_wildcard_all_zero_bytes) {
    ac_pton_a_fn pa = AC_PTON_A; unsigned char buf[16]; int i, z = 1;
    REQUIRE(pa); AC_NEED_WSA();
    memset(buf, 0xee, sizeof buf);
    EXPECT_EQ(pa(AF_INET6, "::", buf), 1);
    for (i = 0; i < 16; i++) if (buf[i]) z = 0;
    CHECK(z);
}

/* ------------------------------------------------------------------ pton: grammar tables */

/* hex = expected 16 bytes (or NULL when the conversion must fail). */
static void pton6_case(const char *text, const char *hex) {
    ac_pton_a_fn pa = AC_PTON_A; ac_pton_w_fn pw = AC_PTON_W;
    unsigned char out[16], want[16]; WCHAR w[128]; int ra, rw;
    if (!pa || !pw || !U(WSASetLastError) || !U(WSAGetLastError)) { t_skip("missing export"); return; }
    if (!ac_startup()) { t_skip("WSAStartup failed"); return; }
    if (hex) ac_unhex(hex, want, 16);
    ac_widen(text, w, 128);
    memset(out, 0xab, sizeof out);
    ra = pa(AF_INET6, text, out);
    CHECKF(ra == (hex ? 1 : 0), "inet_pton(AF_INET6, \"%s\") = %d", text, ra);
    if (hex && ra == 1) CHECKF(!memcmp(out, want, 16), "inet_pton(\"%s\"): wrong bytes", text);
    memset(out, 0xab, sizeof out);
    U(WSASetLastError)(0);
    rw = pw(AF_INET6, w, out);
    CHECKF(rw == (hex ? 1 : 0), "InetPtonW(AF_INET6, \"%s\") = %d", text, rw);
    if (hex && rw == 1) CHECKF(!memcmp(out, want, 16), "InetPtonW(\"%s\"): wrong bytes", text);
    if (!hex) CHECKF(U(WSAGetLastError)() == AC_EINVAL, "InetPtonW(\"%s\"): error %d", text, U(WSAGetLastError)());
}
#define P6(name, text, hex) TEST(ac_pton6_##name) { pton6_case(text, hex); }
P6(unspecified,        "::", "00000000000000000000000000000000")
P6(loopback,           "::1", "00000000000000000000000000000001")
P6(first_group_only,   "1::", "00010000000000000000000000000000")
P6(both_ends,          "1::1", "00010000000000000000000000000001")
P6(upper_case,         "FE80::ABCD", "fe80000000000000000000000000abcd")
P6(mixed_case,         "FeDc:BA98::7654:3210", "fedcba98000000000000000076543210")
P6(full_eight,         "1:2:3:4:5:6:7:8", "00010002000300040005000600070008")
P6(leading_zeros_ok,   "01:002:0003:0004:5:6:7:8", "00010002000300040005000600070008")
P6(four_digit_groups,  "0001:0002::", "00010002000000000000000000000000")
P6(mapped_dotted,      "::ffff:1.2.3.4", "00000000000000000000ffff01020304")
P6(compat_dotted,      "::1.2.3.4", "00000000000000000000000001020304")
P6(six_groups_dotted,  "1:2:3:4:5:6:9.8.7.6", "00010002000300040005000609080706")
P6(middle_compression, "1:2::7:8", "00010002000000000000000000070008")
P6(compress_after_five, "1:2:3:4:5::8", "00010002000300040005000000000008")
P6(scope_rejected,     "fe80::1%1", NULL)
P6(scope_name_rejected, "fe80::1%eth0", NULL)
P6(brackets_rejected,  "[::1]", NULL)
P6(brackets_port_rejected, "[::1]:80", NULL)
P6(prefix_length_rejected, "::1/64", NULL)
P6(three_colons,       ":::", NULL)
P6(three_colons_mid,   "1:::2", NULL)
P6(two_compressions,   "1::2::3", NULL)
P6(non_hex_digit,      "::g", NULL)
P6(five_hex_digits,    "12345::", NULL)
P6(nine_groups,        "1:2:3:4:5:6:7:8:9", NULL)
P6(seven_groups,       "1:2:3:4:5:6:7", NULL)
P6(leading_single_colon, ":1:2:3:4:5:6:7", NULL)
P6(trailing_single_colon, "1:2:3:4:5:6:7:", NULL)
P6(only_colon,         ":", NULL)
P6(empty,              "", NULL)
P6(space,              " ", NULL)
P6(trailing_space,     "::1 ", NULL)
P6(leading_space,      " ::1", NULL)
P6(trailing_newline,   "::1\n", NULL)
P6(bare_dotted_quad,   "1.2.3.4", NULL)
P6(short_dotted_tail,  "::1.2.3", NULL)
P6(long_dotted_tail,   "::1.2.3.4.5", NULL)
P6(dotted_part_256,    "::1.2.3.256", NULL)
P6(dotted_then_group,  "::1.2.3.4:5", NULL)
P6(dotted_not_last,    "1.2.3.4::", NULL)
P6(dotted_with_eight_groups, "1:2:3:4:5:6:7:1.2.3.4", NULL)
P6(plus_sign,          "+::1", NULL)
P6(ipv4_text_dot_only, ".", NULL)

static void pton4_case(const char *text, const char *hex /* 4 bytes or NULL */) {
    ac_pton_a_fn pa = AC_PTON_A; ac_pton_w_fn pw = AC_PTON_W;
    unsigned char out[4], want[4]; WCHAR w[128]; int ra, rw;
    if (!pa || !pw) { t_skip("missing export"); return; }
    if (!ac_startup()) { t_skip("WSAStartup failed"); return; }
    if (hex) ac_unhex(hex, want, 4);
    ac_widen(text, w, 128);
    memset(out, 0xab, sizeof out);
    ra = pa(AF_INET, text, out);
    CHECKF(ra == (hex ? 1 : 0), "inet_pton(AF_INET, \"%s\") = %d", text, ra);
    if (hex && ra == 1) CHECKF(!memcmp(out, want, 4), "inet_pton(\"%s\"): wrong bytes", text);
    memset(out, 0xab, sizeof out);
    rw = pw(AF_INET, w, out);
    CHECKF(rw == (hex ? 1 : 0), "InetPtonW(AF_INET, \"%s\") = %d", text, rw);
    if (hex && rw == 1) CHECKF(!memcmp(out, want, 4), "InetPtonW(\"%s\"): wrong bytes", text);
}
#define P4(name, text, hex) TEST(ac_pton4_##name) { pton4_case(text, hex); }
P4(plain,              "1.2.3.4", "01020304")
P4(all_ones,           "255.255.255.255", "ffffffff")
P4(all_zero,           "0.0.0.0", "00000000")
P4(zero_parts_ok,      "10.0.0.1", "0a000001")
P4(leading_zero_octal_rejected, "01.2.3.4", NULL)
P4(double_zero_rejected, "00.1.1.1", NULL)
P4(zero_zero_last_rejected, "1.1.1.00", NULL)
P4(hex_part_rejected,  "0x1.2.3.4", NULL)
P4(hex_part_upper_rejected, "1.2.3.0X4", NULL)
P4(first_over,         "256.1.1.1", NULL)
P4(last_over,          "1.2.3.256", NULL)
P4(four_digit_part,    "1000.1.1.1", NULL)
P4(five_parts,         "1.2.3.4.5", NULL)
P4(trailing_dot,       "1.2.3.4.", NULL)
P4(leading_dot,        ".1.2.3.4", NULL)
P4(double_dot,         "1..2.3", NULL)
P4(space_in_middle,    "1. 2.3.4", NULL)
P4(trailing_newline,   "1.2.3.4\n", NULL)
P4(trailing_tab,       "1.2.3.4\t", NULL)
P4(one_part_rejected,  "16909060", NULL)
P4(two_part_rejected,  "1.66051", NULL)
P4(three_part_rejected, "1.2.772", NULL)
P4(comma,              "1,2,3,4", NULL)
P4(prefix_len,         "1.2.3.4/32", NULL)
P4(ipv6_text,          "::1", NULL)
P4(empty,              "", NULL)

/* ------------------------------------------------------------------ ntop: canonical text */

static void ntop6_case(const unsigned short g[8], const char *want) {
    ac_ntop_a_fn na = AC_NTOP_A; ac_ntop_w_fn nw = AC_NTOP_W;
    unsigned char addr[16]; char ab[64]; WCHAR wb[64], ww[64]; const char *ra; const WCHAR *rw;
    if (!na || !nw) { t_skip("missing export"); return; }
    if (!ac_startup()) { t_skip("WSAStartup failed"); return; }
    ac_groups(g, addr);
    ra = na(AF_INET6, addr, ab, sizeof ab);
    CHECK(ra == ab);
    if (ra) CHECKF(!strcmp(ab, want), "inet_ntop: got \"%s\" want \"%s\"", ab, want);
    ac_widen(want, ww, 64);
    rw = nw(AF_INET6, addr, wb, 64);
    CHECK(rw == wb);
    if (rw) CHECKF(!wcscmp(wb, ww), "InetNtopW: differs from \"%s\"", want);
}
#define N6(name, text, g0, g1, g2, g3, g4, g5, g6, g7) \
    TEST(ac_ntop6_##name) { static const unsigned short g[8] = { g0, g1, g2, g3, g4, g5, g6, g7 }; ntop6_case(g, text); }

N6(unspecified,        "::",                0, 0, 0, 0, 0, 0, 0, 0)
N6(loopback,           "::1",               0, 0, 0, 0, 0, 0, 0, 1)
N6(first_group_only,   "1::",               1, 0, 0, 0, 0, 0, 0, 0)
N6(both_ends,          "1::1",              1, 0, 0, 0, 0, 0, 0, 1)
N6(single_zero_kept,   "1:0:2:3:4:5:6:7",   1, 0, 2, 3, 4, 5, 6, 7)
N6(leading_zero_group_kept, "0:1:2:3:4:5:6:7", 0, 1, 2, 3, 4, 5, 6, 7)
N6(trailing_zero_group_kept, "1:2:3:4:5:6:7:0", 1, 2, 3, 4, 5, 6, 7, 0)
N6(trailing_pair,      "1:2:3:4:5:6::",     1, 2, 3, 4, 5, 6, 0, 0)
N6(leading_pair,       "::3:4:5:6:7:8",     0, 0, 3, 4, 5, 6, 7, 8)
N6(longest_run_second, "1:0:0:2::3",        1, 0, 0, 2, 0, 0, 0, 3)
N6(longest_run_first,  "1::2:0:0:3",        1, 0, 0, 0, 2, 0, 0, 3)
N6(tie_first_wins,     "1::2:0:0:3:4",      1, 0, 0, 2, 0, 0, 3, 4)
N6(all_ones,           "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff)
N6(documentation,      "2001:db8::1",       0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
N6(middle_pair,        "2001:db8:85a3::8a2e:370:7334", 0x2001, 0xdb8, 0x85a3, 0, 0, 0x8a2e, 0x370, 0x7334)
N6(prefix_only,        "2001:db8::",        0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)
N6(link_local_eui64,   "fe80::202:b3ff:fe1e:8329", 0xfe80, 0, 0, 0, 0x202, 0xb3ff, 0xfe1e, 0x8329)
N6(global_unicast,     "2a00:1450:4001:80b::200e", 0x2a00, 0x1450, 0x4001, 0x80b, 0, 0, 0, 0x200e)
N6(lower_case_hex,     "abcd:ef01:2345:6789:abcd:ef01:2345:6789", 0xabcd, 0xef01, 0x2345, 0x6789, 0xabcd, 0xef01, 0x2345, 0x6789)
N6(leading_zeros_dropped, "1:20:300:4000:5:6:7:8", 1, 0x20, 0x300, 0x4000, 5, 6, 7, 8)
/* IPv4-compatible (::a.b.c.d) is printed in dotted form only while the third-from-last group is non-zero. */
N6(compat_dotted,      "::1.2.3.4",         0, 0, 0, 0, 0, 0, 0x102, 0x304)
N6(compat_small_group, "::0.1.0.2",         0, 0, 0, 0, 0, 0, 1, 2)
N6(compat_group6_zero_is_hex, "::102",      0, 0, 0, 0, 0, 0, 0, 0x102)
N6(mapped_dotted,      "::ffff:1.2.3.4",    0, 0, 0, 0, 0, 0xffff, 0x102, 0x304)
N6(mapped_loopback,    "::ffff:127.0.0.1",  0, 0, 0, 0, 0, 0xffff, 0x7f00, 1)
N6(mapped_group6_zero_is_hex, "::ffff:0:102", 0, 0, 0, 0, 0, 0xffff, 0, 0x102)
N6(mapped_group6_zero_tiny,   "::ffff:0:1",   0, 0, 0, 0, 0, 0xffff, 0, 1)
N6(translated_dotted,  "::ffff:0:1.2.3.4",  0, 0, 0, 0, 0xffff, 0, 0x102, 0x304)
N6(isatap_dotted,      "::5efe:1.2.3.4",    0, 0, 0, 0, 0, 0x5efe, 0x102, 0x304)
N6(isatap_local_bit_dotted, "::200:5efe:192.168.1.1", 0, 0, 0, 0, 0x200, 0x5efe, 0xc0a8, 0x101)
N6(isatap_with_prefix, "fe80::5efe:192.168.1.1", 0xfe80, 0, 0, 0, 0, 0x5efe, 0xc0a8, 0x101)
N6(isatap_zero_address, "fe80::5efe:0.0.0.0", 0xfe80, 0, 0, 0, 0, 0x5efe, 0, 0)
N6(isatap_zero_prefix_zero_address, "::5efe:0.0.0.0", 0, 0, 0, 0, 0, 0x5efe, 0, 0)
N6(near_isatap_other_group4, "1:2:3:4:1:5efe:102:304", 1, 2, 3, 4, 1, 0x5efe, 0x102, 0x304)
N6(near_mapped_group5_one, "::1:102:304", 0, 0, 0, 0, 0, 1, 0x102, 0x304)
N6(near_translated_group4_one, "::1:2:102:304", 0, 0, 0, 0, 1, 2, 0x102, 0x304)

static void ntop4_case(unsigned long raw, const char *want) {
    ac_ntop_a_fn na = AC_NTOP_A; ac_ntop_w_fn nw = AC_NTOP_W;
    char ab[32]; WCHAR wb[32], ww[32]; const char *ra; const WCHAR *rw;
    if (!na || !nw) { t_skip("missing export"); return; }
    if (!ac_startup()) { t_skip("WSAStartup failed"); return; }
    ra = na(AF_INET, &raw, ab, sizeof ab);
    CHECK(ra == ab);
    if (ra) CHECKF(!strcmp(ab, want), "inet_ntop: got \"%s\" want \"%s\"", ab, want);
    ac_widen(want, ww, 32);
    rw = nw(AF_INET, &raw, wb, 32);
    CHECK(rw == wb);
    if (rw) CHECKF(!wcscmp(wb, ww), "InetNtopW: differs from \"%s\"", want);
}
#define N4(name, a, b, c, d, text) TEST(ac_ntop4_##name) { ntop4_case(AC_RAW(a, b, c, d), text); }
N4(zero,        0, 0, 0, 0, "0.0.0.0")
N4(ones,        255, 255, 255, 255, "255.255.255.255")
N4(plain,       1, 2, 3, 4, "1.2.3.4")
N4(two_digit,   10, 20, 30, 40, "10.20.30.40")
N4(three_digit, 100, 200, 150, 199, "100.200.150.199")
N4(mixed,       1, 20, 100, 9, "1.20.100.9")
N4(loopback,    127, 0, 0, 1, "127.0.0.1")
N4(no_padding,  0, 0, 0, 7, "0.0.0.7")

/* ------------------------------------------------------------------ ntop: buffer protocol */

TEST(ac_ntop_v4_exact_fit_and_one_short) {
    ac_ntop_a_fn na = AC_NTOP_A; ac_ntop_w_fn nw = AC_NTOP_W; unsigned long raw = AC_RAW(1, 2, 3, 4);
    char ab[32]; WCHAR wb[32];
    REQUIRE(na); REQUIRE(nw); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    AC_NEED_WSA();
    /* "1.2.3.4" is 7 characters: 8 with the terminator is exactly enough, 7 is not. */
    memset(ab, 0x7e, sizeof ab);
    CHECK(na(AF_INET, &raw, ab, 8) == ab);
    EXPECT_STR(ab, "1.2.3.4"); EXPECT_EQ(ab[8], 0x7e);
    memset(ab, 0x7e, sizeof ab);
    U(WSASetLastError)(0);
    CHECK(na(AF_INET, &raw, ab, 7) == NULL); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
    CHECK(ab[0] == 0x7e && ab[6] == 0x7e); /* failure writes nothing */
    wmemset(wb, 0x7e7e, 32);
    CHECK(nw(AF_INET, &raw, wb, 8) == wb);
    CHECK(!wcscmp(wb, L"1.2.3.4") && wb[8] == 0x7e7e);
    wmemset(wb, 0x7e7e, 32);
    U(WSASetLastError)(0);
    CHECK(nw(AF_INET, &raw, wb, 7) == NULL); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
    CHECK(wb[0] == 0x7e7e && wb[6] == 0x7e7e);
}

TEST(ac_ntop_v6_exact_fit_and_one_short) {
    ac_ntop_a_fn na = AC_NTOP_A; ac_ntop_w_fn nw = AC_NTOP_W; unsigned char addr[16] = {0}; char ab[64]; WCHAR wb[64];
    REQUIRE(na); REQUIRE(nw); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError));
    AC_NEED_WSA();
    addr[15] = 1; /* "::1": 3 characters, 4 with the terminator */
    memset(ab, 0x7e, sizeof ab);
    CHECK(na(AF_INET6, addr, ab, 4) == ab);
    EXPECT_STR(ab, "::1"); EXPECT_EQ(ab[4], 0x7e);
    memset(ab, 0x7e, sizeof ab);
    U(WSASetLastError)(0);
    CHECK(na(AF_INET6, addr, ab, 3) == NULL); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
    CHECK(ab[0] == 0x7e && ab[2] == 0x7e);
    wmemset(wb, 0x7e7e, 64);
    CHECK(nw(AF_INET6, addr, wb, 4) == wb);
    CHECK(!wcscmp(wb, L"::1") && wb[4] == 0x7e7e);
    wmemset(wb, 0x7e7e, 64);
    U(WSASetLastError)(0);
    CHECK(nw(AF_INET6, addr, wb, 3) == NULL); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
    CHECK(wb[0] == 0x7e7e);
}

TEST(ac_ntop_v6_eight_full_groups_need_40) {
    /* Eight non-zero four-digit groups give the 39-character text; it fits 40 but not 39. */
    ac_ntop_a_fn na = AC_NTOP_A; unsigned char addr[16]; char ab[64]; int i;
    REQUIRE(na); AC_NEED_WSA();
    for (i = 0; i < 16; i++) addr[i] = (unsigned char)(0x10 + 0x11 * (i & 7)); /* no zero group */
    CHECK(na(AF_INET6, addr, ab, 46) == ab);
    CHECK(strlen(ab) == 39);
    memset(addr, 0xff, 16);
    CHECK(na(AF_INET6, addr, ab, 40) == ab);
    EXPECT_EQ(strlen(ab), 39);
    CHECK(na(AF_INET6, addr, ab, 39) == NULL);
}

TEST(ac_ntop_ignores_size_beyond_text) {
    ac_ntop_a_fn na = AC_NTOP_A; ac_ntop_w_fn nw = AC_NTOP_W; unsigned long raw = AC_RAW(8, 8, 8, 8);
    char ab[300]; WCHAR wb[300];
    REQUIRE(na); REQUIRE(nw); AC_NEED_WSA();
    memset(ab, 0x7e, sizeof ab);
    CHECK(na(AF_INET, &raw, ab, sizeof ab) == ab);
    EXPECT_STR(ab, "8.8.8.8"); EXPECT_EQ(ab[8], 0x7e);
    wmemset(wb, 0x7e7e, 300);
    CHECK(nw(AF_INET, &raw, wb, 300) == wb);
    CHECK(!wcscmp(wb, L"8.8.8.8")); CHECK(wb[8] == 0x7e7e);
}

/* inet_pton -> inet_ntop reproduces the canonical text for canonical input. */
TEST(ac_pton_ntop_roundtrip_canonical_v6) {
    static const char *const t[] = { "::", "::1", "1::", "2001:db8::1", "fe80::1", "ff02::fb", "::ffff:10.1.2.3",
        "1:2:3:4:5:6:7:8", "2001:db8:0:1:1:1:1:1", "1::8", "::1.2.3.4", "fe80::5efe:10.0.0.1" };
    ac_pton_a_fn pa = AC_PTON_A; ac_ntop_a_fn na = AC_NTOP_A; unsigned i;
    REQUIRE(pa); REQUIRE(na); AC_NEED_WSA();
    for (i = 0; i < AC_COUNT(t); i++) {
        unsigned char b[16]; char s[64];
        CHECKF(pa(AF_INET6, t[i], b) == 1, "parse of \"%s\" failed", t[i]);
        CHECKF(na(AF_INET6, b, s, sizeof s) && !strcmp(s, t[i]), "\"%s\" came back as \"%s\"", t[i], s);
    }
}

/* Non-canonical spellings come back in canonical form. */
TEST(ac_pton_ntop_canonicalises_v6) {
    static const struct { const char *in, *out; } t[] = {
        { "0:0:0:0:0:0:0:0", "::" }, { "0000:0000:0000:0000:0000:0000:0000:0001", "::1" },
        { "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1" }, { "2001:DB8::A", "2001:db8::a" },
        { "1:0:0:0:0:0:0:0", "1::" }, { "1:0:0:2:0:0:0:3", "1:0:0:2::3" }, { "0:0:0:0:0:ffff:0102:0304", "::ffff:1.2.3.4" },
        { "0:0:0:0:0:0:0102:0304", "::1.2.3.4" }, { "1:0:0:0:2:0:0:3", "1::2:0:0:3" },
    };
    ac_pton_a_fn pa = AC_PTON_A; ac_ntop_a_fn na = AC_NTOP_A; unsigned i;
    REQUIRE(pa); REQUIRE(na); AC_NEED_WSA();
    for (i = 0; i < AC_COUNT(t); i++) {
        unsigned char b[16]; char s[64];
        CHECKF(pa(AF_INET6, t[i].in, b) == 1, "parse of \"%s\" failed", t[i].in);
        CHECKF(na(AF_INET6, b, s, sizeof s) && !strcmp(s, t[i].out), "\"%s\" -> \"%s\", want \"%s\"", t[i].in, s, t[i].out);
    }
}

/* inet_ntop and inet_ntoa agree on every dotted quad sampled. */
TEST(ac_ntop_agrees_with_ntoa) {
    ac_ntop_a_fn na = AC_NTOP_A; unsigned v;
    REQUIRE(na); REQUIRE(U(inet_ntoa)); AC_NEED_WSA();
    for (v = 0; v < 0x1000000u; v += 0x4d2b1) {
        unsigned long raw = (v * 2654435761u) ^ v; char s[32]; struct in_addr in; char *p;
        in.s_addr = raw;
        p = U(inet_ntoa)(in);
        CHECK(na(AF_INET, &raw, s, sizeof s) == s);
        if (p) CHECKF(!strcmp(p, s), "ntoa \"%s\" vs ntop \"%s\"", p, s);
    }
}

/* ------------------------------------------------------------------ no WSAStartup */

CHILD(ac_conv_no_startup) {
    ac_pton_a_fn pa = AC_PTON_A; ac_pton_w_fn pw = AC_PTON_W; ac_ntop_a_fn na = AC_NTOP_A; ac_ntop_w_fn nw = AC_NTOP_W;
    unsigned char b[16]; char s[64]; WCHAR w[64]; int bad = 0;
    if (!pa || !pw || !na || !nw) return 0;
    if (pa(AF_INET, "1.2.3.4", b) != 1 || b[0] != 1 || b[3] != 4) { printf("inet_pton v4\n"); bad++; }
    if (pw(AF_INET6, L"::1", b) != 1 || b[15] != 1) { printf("InetPtonW v6\n"); bad++; }
    if (na(AF_INET6, b, s, sizeof s) == NULL || strcmp(s, "::1")) { printf("inet_ntop v6\n"); bad++; }
    if (nw(AF_INET6, b, w, 64) == NULL || wcscmp(w, L"::1")) { printf("InetNtopW v6\n"); bad++; }
    return bad;
}
TEST(ac_conv_works_without_wsastartup) {
    REQUIRE(AC_PTON_A);
    { DWORD code = t_run_child("ac_conv_no_startup", "", 30000); EXPECT_EQ(code, 0); }
}
