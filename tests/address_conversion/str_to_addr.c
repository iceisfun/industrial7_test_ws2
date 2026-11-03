/* WSAStringToAddressA / WSAStringToAddressW beyond the basic tables.
 * Measures: the byte-exact sockaddr produced (family, port, flow info, address, scope id at their
 * documented offsets, trailing bytes of a larger buffer untouched), the length protocol (too small
 * -> SOCKET_ERROR / WSAEFAULT with the required size, exact and larger lengths report 16 or 28),
 * IPv6 syntax (brackets, "%scope" decimal scope id, ":port" with decimal / 0-octal / 0x-hex digits),
 * IPv4 port spellings, unsupported or unknown families (WSAEINVAL), the protocol-info argument
 * (catalog entry id decides the provider; an unknown id is WSAEINVAL), and that the call needs
 * WSAStartup. A and W forms are held to identical expectations. */
#include "ac.h"

#define BUFSZ 64

struct s2a_res { int ret, err, len; unsigned char buf[BUFSZ]; };

/* wide != 0 selects the W entry point. Buffer starts as 0xAB, *len starts as len_in. */
static void s2a_call(int wide, const char *text, int fam, int len_in, struct s2a_res *r) {
    WCHAR w[256]; char a[256]; int len = len_in;
    ac_s2a_a_fn fa = AC_S2A_A; ac_s2a_w_fn fw = AC_S2A_W;
    memset(r, 0, sizeof *r);
    memset(r->buf, 0xab, sizeof r->buf);
    ac_widen(text, w, 256);
    snprintf(a, sizeof a, "%s", text);
    U(WSASetLastError)(0);
    r->ret = wide ? fw(w, fam, NULL, (LPSOCKADDR)r->buf, &len) : fa(a, fam, NULL, (LPSOCKADDR)r->buf, &len);
    r->err = U(WSAGetLastError)();
    r->len = len;
}

static int s2a_ready(void) {
    if (!AC_S2A_A || !AC_S2A_W || !U(WSASetLastError) || !U(WSAGetLastError)) { t_skip("missing export"); return 0; }
    if (!ac_startup()) { t_skip("WSAStartup failed"); return 0; }
    return 1;
}

/* A successful IPv4 conversion: 16 bytes written, the rest of the buffer untouched. */
static void s2a4_ok(const char *text, const unsigned char ip[4], unsigned short port) {
    int wide;
    if (!s2a_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        struct s2a_res r; unsigned char want[BUFSZ];
        s2a_call(wide, text, AF_INET, BUFSZ, &r);
        memset(want, 0xab, sizeof want);
        ac_raw_v4(want, port, ip);
        CHECKF(r.ret == 0, "%c \"%s\": ret %d err %d", wide ? 'W' : 'A', text, r.ret, r.err);
        CHECKF(r.len == 16, "%c \"%s\": length %d", wide ? 'W' : 'A', text, r.len);
        CHECKF(!memcmp(r.buf, want, BUFSZ), "%c \"%s\": sockaddr bytes differ", wide ? 'W' : 'A', text);
    }
}

static void s2a_bad(const char *text, int fam) {
    int wide;
    if (!s2a_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        struct s2a_res r;
        s2a_call(wide, text, fam, BUFSZ, &r);
        CHECKF(r.ret == SOCKET_ERROR, "%c \"%s\": ret %d", wide ? 'W' : 'A', text, r.ret);
        CHECKF(r.err == AC_EINVAL, "%c \"%s\": error %d", wide ? 'W' : 'A', text, r.err);
        CHECKF(r.len == BUFSZ, "%c \"%s\": length changed to %d", wide ? 'W' : 'A', text, r.len);
    }
}

/* ---------------------------------------------------------------- IPv4 */
#define S4(name, text, a, b, c, d, port) \
    TEST(ac_s2a4_##name) { static const unsigned char ip[4] = { a, b, c, d }; s2a4_ok(text, ip, port); }
#define S4BAD(name, text) TEST(ac_s2a4_##name) { s2a_bad(text, AF_INET); }

S4(plain,              "1.2.3.4", 1, 2, 3, 4, 0)
S4(with_port,          "1.2.3.4:80", 1, 2, 3, 4, 80)
S4(port_swapped_bytes, "1.2.3.4:258", 1, 2, 3, 4, 258)
S4(port_hex,           "1.2.3.4:0x1F", 1, 2, 3, 4, 31)
S4(port_hex_max,       "1.2.3.4:0xFFFF", 1, 2, 3, 4, 65535)
S4(port_octal_max,     "1.2.3.4:0177777", 1, 2, 3, 4, 65535)
S4(port_decimal_max,   "1.2.3.4:65535", 1, 2, 3, 4, 65535)
S4(port_one,           "1.2.3.4:1", 1, 2, 3, 4, 1)
S4(broadcast_with_port, "255.255.255.255:1", 255, 255, 255, 255, 1)
S4(two_part_form,      "127.1", 127, 0, 0, 1, 0)
S4(three_part_form_port, "10.1.258:9", 10, 1, 1, 2, 9)
S4(hex_part_form,      "0x7f.0.0.1", 127, 0, 0, 1, 0)
S4(octal_part_form,    "0177.0.0.01", 127, 0, 0, 1, 0)
S4(one_part_form,      "2130706433", 127, 0, 0, 1, 0)
S4BAD(port_octal_over, "1.2.3.4:0200000")
S4BAD(port_decimal_over, "1.2.3.4:99999")
S4BAD(port_letters,    "1.2.3.4:abc")
S4BAD(port_negative,   "1.2.3.4:-1")
S4BAD(port_plus,       "1.2.3.4:+1")
S4BAD(port_trailing_space, "1.2.3.4:80 ")
S4BAD(port_twice,      "1.2.3.4:1:2")
S4BAD(port_hex_bad_digit, "1.2.3.4:0x1G")
S4BAD(brackets,        "[1.2.3.4]")
S4BAD(brackets_port,   "[1.2.3.4]:80")
S4BAD(trailing_dot,    "1.2.3.4.")
S4BAD(five_parts,      "1.2.3.4.5")
S4BAD(slash_prefix,    "1.2.3.4/24")
S4BAD(letters,         "one.two.three.four")
S4BAD(high_byte_char,  "1.2.3.4\xe9")
S4BAD(tab_inside,      "1.2.\t3.4")
S4BAD(ipv6_text,       "::1")
S4BAD(ipv6_mapped_text, "::ffff:1.2.3.4")
S4BAD(newline_tail,    "1.2.3.4\n")

/* ---------------------------------------------------------------- IPv6 */

static void s2a6_ok(const char *text, const char *hex, unsigned short port, unsigned long scope) {
    int wide;
    if (!s2a_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        struct s2a_res r; unsigned char want[BUFSZ], ip[16];
        s2a_call(wide, text, AF_INET6, BUFSZ, &r);
        ac_unhex(hex, ip, 16);
        memset(want, 0xab, sizeof want);
        ac_raw_v6(want, port, 0, ip, scope);
        CHECKF(r.ret == 0, "%c \"%s\": ret %d err %d", wide ? 'W' : 'A', text, r.ret, r.err);
        CHECKF(r.len == 28, "%c \"%s\": length %d", wide ? 'W' : 'A', text, r.len);
        CHECKF(!memcmp(r.buf, want, BUFSZ), "%c \"%s\": sockaddr bytes differ", wide ? 'W' : 'A', text);
    }
}
#define S6(name, text, hex, port, scope) TEST(ac_s2a6_##name) { s2a6_ok(text, hex, port, scope); }
#define S6BAD(name, text) TEST(ac_s2a6_##name) { s2a_bad(text, AF_INET6); }

#define Z16 "00000000000000000000000000000000"
S6(unspecified,       "::", Z16, 0, 0)
S6(first_group,       "1::", "00010000000000000000000000000000", 0, 0)
S6(upper_case,        "FE80::ABCD", "fe80000000000000000000000000abcd", 0, 0)
S6(full_eight,        "1:2:3:4:5:6:7:8", "00010002000300040005000600070008", 0, 0)
S6(zero_padded_groups, "0001:0002:0003:0004:0005:0006:0007:0008", "00010002000300040005000600070008", 0, 0)
S6(mapped_dotted,     "::ffff:1.2.3.4", "00000000000000000000ffff01020304", 0, 0)
S6(six_groups_dotted, "1:2:3:4:5:6:1.2.3.4", "00010002000300040005000601020304", 0, 0)
S6(bracketed,         "[::1]", "00000000000000000000000000000001", 0, 0)
S6(bracketed_port,    "[::1]:80", "00000000000000000000000000000001", 80, 0)
S6(port_swapped_bytes, "[::1]:258", "00000000000000000000000000000001", 258, 0)
S6(port_hex,          "[::1]:0x50", "00000000000000000000000000000001", 80, 0)
S6(port_hex_upper_x,  "[::1]:0X50", "00000000000000000000000000000001", 80, 0)
S6(port_octal,        "[::1]:0120", "00000000000000000000000000000001", 80, 0)
S6(port_hex_max,      "[::1]:0xFFFF", "00000000000000000000000000000001", 65535, 0)
S6(port_octal_max,    "[::1]:0177777", "00000000000000000000000000000001", 65535, 0)
S6(scope_plain,       "fe80::1%5", "fe800000000000000000000000000001", 0, 5)
S6(scope_zero,        "fe80::1%0", "fe800000000000000000000000000001", 0, 0)
S6(scope_multi_digit, "fe80::1%12", "fe800000000000000000000000000001", 0, 12)
S6(scope_max,         "fe80::1%4294967295", "fe800000000000000000000000000001", 0, 0xffffffffUL)
S6(scope_bracketed,   "[fe80::1%2]", "fe800000000000000000000000000001", 0, 2)
S6(scope_bracketed_port, "[fe80::1%3]:443", "fe800000000000000000000000000001", 443, 3)
S6(scope_on_mapped,   "::ffff:1.2.3.4%7", "00000000000000000000ffff01020304", 0, 7)
S6BAD(three_colons,   ":::")
S6BAD(two_compressions, "1::2::3")
S6BAD(bad_digit,      "::g")
S6BAD(five_hex_digits, "12345::")
S6BAD(nine_groups,    "1:2:3:4:5:6:7:8:9")
S6BAD(leading_colon,  ":1:2:3:4:5:6:7")
S6BAD(dotted_first,   "1.2.3.4::")
S6BAD(dotted_short,   "::1.2.3")
S6BAD(dotted_long,    "::1.2.3.4.5")
S6BAD(dotted_256,     "::1.2.3.256")
S6BAD(missing_close,  "[::1")
S6BAD(missing_open,   "::1]")
S6BAD(empty_brackets, "[]")
S6BAD(double_brackets, "[[::1]]")
S6BAD(text_after_bracket, "[::1]x")
S6BAD(space_after_bracket, "[::1] ")
S6BAD(port_over,      "[::1]:65536")
S6BAD(port_negative,  "[::1]:-1")
S6BAD(port_octal_digit_8, "[::1]:080")
S6BAD(port_letters,   "[::1]:abc")
S6BAD(port_trailing,  "[::1]:80x")
S6BAD(port_twice,     "[::1]:1:2")
S6BAD(port_hex_bad_digit, "[::1]:0xg")
S6BAD(port_octal_over, "[::1]:0200000")
S6BAD(port_hex_over,  "[::1]:0x10000")
S6BAD(scope_empty,    "::1%")
S6BAD(scope_letters,  "fe80::1%abc")
S6BAD(scope_trailing_letter, "fe80::1%1x")
S6BAD(scope_over_32_bits, "fe80::1%4294967296")
S6BAD(scope_without_open_bracket, "fe80::1%2]")
S6BAD(scope_then_port_unbracketed, "fe80::1%1:80")
S6BAD(scope_before_address, "%1fe80::1")
S6BAD(trailing_space, "::1 ")
S6BAD(leading_space,  " ::1")
S6BAD(trailing_newline, "::1\n")
S6BAD(ipv4_text,      "1.2.3.4")
S6BAD(ipv4_with_port, "1.2.3.4:80")

/* Asymmetry: an empty port after the bracket is accepted for IPv6 (port 0) while the
 * IPv4 spelling "a.b.c.d:" is rejected. Observed, recorded rather than required. */
TEST(ac_s2a6_quirk_empty_port_after_bracket) {
    struct s2a_res r;
    if (!s2a_ready()) return;
    s2a_call(1, "[::1]:", AF_INET6, BUFSZ, &r);
    t_note("StringToAddress(\"[::1]:\") ret=%d err=%d", r.ret, r.err);
    s2a_call(1, "[::1]:0x", AF_INET6, BUFSZ, &r);
    t_note("StringToAddress(\"[::1]:0x\") ret=%d err=%d", r.ret, r.err);
    s2a_call(1, "[::1]:0", AF_INET6, BUFSZ, &r);
    t_note("StringToAddress(\"[::1]:0\") ret=%d err=%d", r.ret, r.err);
    s2a_call(1, "[::1]:00", AF_INET6, BUFSZ, &r);
    t_note("StringToAddress(\"[::1]:00\") ret=%d err=%d", r.ret, r.err);
}

/* The flow info field and everything after the scope id stay zero / untouched. */
TEST(ac_s2a6_flowinfo_zeroed_and_tail_untouched) {
    int wide;
    if (!s2a_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        struct s2a_res r; int i, z = 1;
        s2a_call(wide, "fe80::9", AF_INET6, BUFSZ, &r);
        CHECK(r.ret == 0);
        for (i = 4; i < 8; i++) if (r.buf[i]) z = 0;  /* sin6_flowinfo */
        CHECK(z);
        for (i = 28; i < BUFSZ; i++) if (r.buf[i] != 0xab) z = 0;
        CHECK(z);
    }
}

TEST(ac_s2a4_sin_zero_cleared) {
    int wide;
    if (!s2a_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        struct s2a_res r; int i, z = 1;
        s2a_call(wide, "9.9.9.9", AF_INET, BUFSZ, &r);
        CHECK(r.ret == 0);
        for (i = 8; i < 16; i++) if (r.buf[i]) z = 0;
        CHECK(z);
        for (i = 16; i < BUFSZ; i++) if (r.buf[i] != 0xab) z = 0;
        CHECK(z);
    }
}

/* ---------------------------------------------------------------- length protocol */

static void len_too_small(int fam, const char *text, int req, const int *lens, unsigned n) {
    int wide; unsigned i;
    if (!s2a_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        for (i = 0; i < n; i++) {
            struct s2a_res r;
            s2a_call(wide, text, fam, lens[i], &r);
            CHECKF(r.ret == SOCKET_ERROR, "%c len %d: ret %d", wide ? 'W' : 'A', lens[i], r.ret);
            CHECKF(r.err == AC_EFAULT, "%c len %d: error %d", wide ? 'W' : 'A', lens[i], r.err);
            CHECKF(r.len >= req, "%c len %d: reported %d, need at least %d", wide ? 'W' : 'A', lens[i], r.len, req);
            CHECKF(r.buf[0] == 0xab && r.buf[15] == 0xab, "%c len %d: buffer written", wide ? 'W' : 'A', lens[i]);
            if (i == 0) t_note("%c required length for family %d reported as %d", wide ? 'W' : 'A', fam, r.len);
        }
    }
}
TEST(ac_s2a4_length_too_small) {
    static const int lens[] = { 0, 1, 2, 8, 15 };
    len_too_small(AF_INET, "1.2.3.4", 16, lens, AC_COUNT(lens));
}
TEST(ac_s2a6_length_too_small) {
    static const int lens[] = { 0, 1, 16, 24, 27 };
    len_too_small(AF_INET6, "::1", 28, lens, AC_COUNT(lens));
}

/* Length errors take precedence over the text: even an unparsable string reports WSAEFAULT. */
TEST(ac_s2a_length_checked_before_parsing) {
    int wide;
    if (!s2a_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        struct s2a_res r;
        s2a_call(wide, "not an address", AF_INET, 4, &r);
        CHECK(r.ret == SOCKET_ERROR); EXPECT_EQ(r.err, AC_EFAULT);
        s2a_call(wide, "not an address", AF_INET6, 20, &r);
        CHECK(r.ret == SOCKET_ERROR); EXPECT_EQ(r.err, AC_EFAULT);
    }
}

TEST(ac_s2a4_exact_length_reports_16) {
    int wide;
    if (!s2a_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        struct s2a_res r;
        s2a_call(wide, "1.2.3.4", AF_INET, 16, &r);
        CHECK(r.ret == 0); EXPECT_EQ(r.len, 16);
        CHECK(r.buf[16] == 0xab);
    }
}
TEST(ac_s2a6_exact_length_reports_28) {
    int wide;
    if (!s2a_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        struct s2a_res r;
        s2a_call(wide, "::1", AF_INET6, 28, &r);
        CHECK(r.ret == 0); EXPECT_EQ(r.len, 28);
        CHECK(r.buf[28] == 0xab);
    }
}
TEST(ac_s2a_larger_length_is_lowered_to_size_written) {
    int wide;
    if (!s2a_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        struct s2a_res r;
        s2a_call(wide, "1.2.3.4", AF_INET, 60, &r);
        CHECK(r.ret == 0); EXPECT_EQ(r.len, 16);
        s2a_call(wide, "::1", AF_INET6, 60, &r);
        CHECK(r.ret == 0); EXPECT_EQ(r.len, 28);
    }
}
/* An IPv4 text with a 28-byte buffer is fine; an IPv6 text with a 16-byte buffer is a length error. */
TEST(ac_s2a_v6_text_in_v4_sized_buffer) {
    int wide;
    if (!s2a_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        struct s2a_res r;
        s2a_call(wide, "::1", AF_INET6, 16, &r);
        CHECK(r.ret == SOCKET_ERROR); EXPECT_EQ(r.err, AC_EFAULT);
        s2a_call(wide, "1.2.3.4", AF_INET, 28, &r);
        CHECK(r.ret == 0); EXPECT_EQ(r.len, 16);
    }
}

/* ---------------------------------------------------------------- families */

TEST(ac_s2a_unknown_family_is_einval) {
    static const int fams[] = { 0x7ffe, 0x1234, 99, -1, 0x10002, 0x10017 };
    unsigned i; int wide;
    if (!s2a_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        for (i = 0; i < AC_COUNT(fams); i++) {
            struct s2a_res r;
            s2a_call(wide, "1.2.3.4", fams[i], BUFSZ, &r);
            CHECKF(r.ret == SOCKET_ERROR && r.err == AC_EINVAL, "%c family %d: ret %d err %d", wide ? 'W' : 'A', fams[i], r.ret, r.err);
            CHECKF(r.buf[0] == 0xab, "family %d: buffer written", fams[i]);
        }
    }
}

/* The catalog lookup happens before the length is looked at: an unknown family with a hopeless length still gives WSAEINVAL. */
TEST(ac_s2a_unknown_family_checked_before_length) {
    int wide;
    if (!s2a_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        struct s2a_res r;
        s2a_call(wide, "1.2.3.4", 0x7ffe, 0, &r);
        CHECK(r.ret == SOCKET_ERROR); EXPECT_EQ(r.err, AC_EINVAL);
    }
}

TEST(ac_s2a_unspec_family_outcome) {
    int wide;
    if (!s2a_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        struct s2a_res r;
        s2a_call(wide, "1.2.3.4", AF_UNSPEC, BUFSZ, &r);
        t_note("%c StringToAddress with AF_UNSPEC: ret=%d err=%d", wide ? 'W' : 'A', r.ret, r.err);
        CHECK(r.ret == SOCKET_ERROR || r.ret == 0);
    }
}

TEST(ac_s2a_wrong_family_for_text) {
    int wide;
    if (!s2a_ready()) return;
    for (wide = 0; wide < 2; wide++) {
        struct s2a_res r;
        s2a_call(wide, "::1", AF_INET, BUFSZ, &r);
        CHECK(r.ret == SOCKET_ERROR); EXPECT_EQ(r.err, AC_EINVAL); EXPECT_EQ(r.len, BUFSZ);
        s2a_call(wide, "1.2.3.4", AF_INET6, BUFSZ, &r);
        CHECK(r.ret == SOCKET_ERROR); EXPECT_EQ(r.err, AC_EINVAL); EXPECT_EQ(r.len, BUFSZ);
    }
}

/* ---------------------------------------------------------------- NULL arguments (wide form; the ANSI form measures the string first) */

TEST(ac_s2aw_null_string_is_efault) {
    ac_s2a_w_fn fw = AC_S2A_W; unsigned char buf[BUFSZ]; int len = BUFSZ, r;
    if (!s2a_ready()) return;
    memset(buf, 0xab, sizeof buf);
    U(WSASetLastError)(0);
    r = fw(NULL, AF_INET, NULL, (LPSOCKADDR)buf, &len);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
    len = BUFSZ;
    U(WSASetLastError)(0);
    r = fw(NULL, AF_INET6, NULL, (LPSOCKADDR)buf, &len);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
}

TEST(ac_s2a_null_address_with_room_is_efault) {
    ac_s2a_a_fn fa = AC_S2A_A; ac_s2a_w_fn fw = AC_S2A_W; int len = BUFSZ, r;
    if (!s2a_ready()) return;
    U(WSASetLastError)(0);
    r = fa("1.2.3.4", AF_INET, NULL, NULL, &len);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
    len = BUFSZ;
    U(WSASetLastError)(0);
    r = fw(L"::1", AF_INET6, NULL, NULL, &len);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
}

/* A size query: NULL address and zero length reports the needed size (the lifted tests cover IPv4). */
TEST(ac_s2a6_zero_length_size_query) {
    ac_s2a_a_fn fa = AC_S2A_A; ac_s2a_w_fn fw = AC_S2A_W; int len = 0, r;
    if (!s2a_ready()) return;
    U(WSASetLastError)(0);
    r = fa("::1", AF_INET6, NULL, NULL, &len);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
    CHECK(len >= 28);
    len = 0;
    U(WSASetLastError)(0);
    r = fw(L"::1", AF_INET6, NULL, NULL, &len);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EFAULT);
    CHECK(len >= 28);
}

/* ---------------------------------------------------------------- protocol-info argument */

/* First base-chain catalog entry of the given family and type. */
static int find_entry(int fam, int type, WSAPROTOCOL_INFOW *out) {
    DWORD sz = 0; WSAPROTOCOL_INFOW *all; int n, i, found = 0;
    if (!U(WSAEnumProtocolsW)) return 0;
    U(WSAEnumProtocolsW)(NULL, NULL, &sz);
    if (!sz || sz > (1u << 20)) return 0;
    all = (WSAPROTOCOL_INFOW *)HeapAlloc(GetProcessHeap(), 0, sz);
    if (!all) return 0;
    n = U(WSAEnumProtocolsW)(NULL, all, &sz);
    for (i = 0; i < n && !found; i++)
        if (all[i].iAddressFamily == fam && all[i].iSocketType == type && all[i].ProtocolChain.ChainLen == 1) { *out = all[i]; found = 1; }
    HeapFree(GetProcessHeap(), 0, all);
    return found;
}

TEST(ac_s2a_protocol_info_of_matching_family) {
    WSAPROTOCOL_INFOW pi; ac_s2a_w_fn fw = AC_S2A_W; ac_s2a_a_fn fa = AC_S2A_A;
    unsigned char buf[BUFSZ], ip[4] = { 1, 2, 3, 4 }, want[16]; int len = BUFSZ, r;
    if (!s2a_ready()) return;
    if (!find_entry(AF_INET, SOCK_STREAM, &pi)) { t_skip("no AF_INET stream catalog entry"); return; }
    memset(buf, 0xab, sizeof buf);
    r = fw(L"1.2.3.4:5", AF_INET, &pi, (LPSOCKADDR)buf, &len);
    EXPECT_EQ(r, 0); EXPECT_EQ(len, 16);
    ac_raw_v4(want, 5, ip);
    CHECK(!memcmp(buf, want, 16));
    {   /* the ANSI form takes a WSAPROTOCOL_INFOA with the same leading layout; the catalog entry id is what matters */
        WSAPROTOCOL_INFOA pa; memset(&pa, 0, sizeof pa);
        pa.dwCatalogEntryId = pi.dwCatalogEntryId; pa.iAddressFamily = pi.iAddressFamily;
        len = BUFSZ; memset(buf, 0xab, sizeof buf);
        r = fa("1.2.3.4:5", AF_INET, &pa, (LPSOCKADDR)buf, &len);
        EXPECT_EQ(r, 0); EXPECT_EQ(len, 16);
        CHECK(!memcmp(buf, want, 16));
    }
}

TEST(ac_s2a_protocol_info_unknown_catalog_id) {
    WSAPROTOCOL_INFOW pi; unsigned char buf[BUFSZ]; int len = BUFSZ, r;
    if (!s2a_ready()) return;
    memset(&pi, 0, sizeof pi);                       /* catalog entry id 0 names nothing */
    memset(buf, 0xab, sizeof buf);
    U(WSASetLastError)(0);
    r = AC_S2A_W(L"1.2.3.4", AF_INET, &pi, (LPSOCKADDR)buf, &len);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
    CHECK(buf[0] == 0xab); EXPECT_EQ(len, BUFSZ);
    pi.dwCatalogEntryId = 0x7fffff01;
    len = BUFSZ;
    U(WSASetLastError)(0);
    r = AC_S2A_W(L"1.2.3.4", AF_INET, &pi, (LPSOCKADDR)buf, &len);
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(U(WSAGetLastError)(), AC_EINVAL);
}

TEST(ac_s2a_protocol_info_family_field_is_ignored) {
    /* Only the catalog entry id is read: a zero-filled structure with a good id works. */
    WSAPROTOCOL_INFOW good, pi; unsigned char buf[BUFSZ]; int len = BUFSZ, r;
    if (!s2a_ready()) return;
    if (!find_entry(AF_INET, SOCK_DGRAM, &good)) { t_skip("no AF_INET datagram catalog entry"); return; }
    memset(&pi, 0, sizeof pi);
    pi.dwCatalogEntryId = good.dwCatalogEntryId;
    r = AC_S2A_W(L"4.3.2.1", AF_INET, &pi, (LPSOCKADDR)buf, &len);
    EXPECT_EQ(r, 0); EXPECT_EQ(len, 16);
}

/* A catalog entry of the other address family is only noted: which provider parses is its business. */
TEST(ac_s2a_protocol_info_family_mismatch_note) {
    WSAPROTOCOL_INFOW pi; unsigned char buf[BUFSZ]; int len = BUFSZ, r;
    if (!s2a_ready()) return;
    if (!find_entry(AF_INET, SOCK_STREAM, &pi)) { t_skip("no AF_INET stream catalog entry"); return; }
    U(WSASetLastError)(0);
    r = AC_S2A_W(L"::1", AF_INET6, &pi, (LPSOCKADDR)buf, &len);
    t_note("StringToAddress(AF_INET6, AF_INET catalog entry): ret=%d err=%d", r, U(WSAGetLastError)());
}
