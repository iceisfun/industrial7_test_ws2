/* inet_addr / inet_ntoa beyond the basic vectors.
 * Measures: the classic BSD number grammar of inet_addr as Windows 10 implements it (one to four
 * dot separated parts, decimal / 0-prefixed octal / 0x-prefixed hex per part, the width limit of
 * the last part, how a trailing byte is judged), INADDR_NONE aliasing with 255.255.255.255, a
 * per-octet sweep in all three radixes, and inet_ntoa's formatting and its per-thread result buffer.
 * Parts are checked in terms of the resulting octets, written AC_RAW(a,b,c,d) = memory order. */
#include "ac.h"

static void ia_case(const char *text, unsigned long want) {
    unsigned long r;
    if (!U(inet_addr)) { t_skip("missing export: inet_addr"); return; }
    r = U(inet_addr)(text);
    CHECKF(r == want, "inet_addr(\"%s\"): got %08lx want %08lx", text, r, want);
}

#define IA(name, text, a, b, c, d) TEST(ac_ia_##name) { ia_case(text, AC_RAW(a, b, c, d)); }
#define IA_NONE(name, text)        TEST(ac_ia_##name) { ia_case(text, AC_NONE); }

/* ---- zero spellings: a lone "0" is a complete number, "00" is octal zero, "0x" alone is empty ---- */
IA(zero_single,          "0", 0, 0, 0, 0)
IA(zero_double,          "00", 0, 0, 0, 0)
IA(zero_octal_one,       "0000000001", 0, 0, 0, 1)
IA(zero_hex,             "0x0", 0, 0, 0, 0)
IA(zero_hex_upper_x,     "0X0", 0, 0, 0, 0)
IA(zero_hex_two_digits,  "0x00", 0, 0, 0, 0)
IA(zero_two_parts,       "0.0", 0, 0, 0, 0)
IA(zero_three_parts,     "0.0.0", 0, 0, 0, 0)
IA(zero_four_octal,      "00.00.00.00", 0, 0, 0, 0)
IA_NONE(hex_prefix_only, "0x")
IA_NONE(hex_prefix_dot,  "0x.1")
IA_NONE(hex_prefix_last, "1.2.3.0X")

/* ---- one-part forms fill all 32 bits ---- */
IA(one_part_2_24,        "16777216", 1, 0, 0, 0)
IA(one_part_loopback,    "2130706433", 127, 0, 0, 1)
IA(one_part_max_minus_1, "4294967294", 255, 255, 255, 254)
IA(one_part_max_is_none, "4294967295", 255, 255, 255, 255)
IA_NONE(one_part_2_32,   "4294967296")
IA_NONE(one_part_2_32_p4, "4294967300")
IA(one_part_hex_max_minus_1, "0xfffffffe", 255, 255, 255, 254)
IA_NONE(one_part_hex_2_32, "0x100000000")
IA(one_part_octal_max_minus_1, "037777777776", 255, 255, 255, 254)
IA_NONE(one_part_octal_2_32, "040000000000")
IA(one_part_octal_eight, "010", 0, 0, 0, 8)

/* ---- two parts: first is the top octet, second the low 24 bits ---- */
IA(two_part_loopback,    "127.1", 127, 0, 0, 1)
IA(two_part_24bit,       "10.65793", 10, 1, 1, 1)
IA(two_part_24bit_max,   "1.16777215", 1, 255, 255, 255)
IA_NONE(two_part_24bit_over, "1.16777216")
IA_NONE(two_part_first_over, "256.1")
IA(two_part_hex,         "0x7f.0x1", 127, 0, 0, 1)
IA(two_part_octal_first, "0177.1", 127, 0, 0, 1)
IA(two_part_almost_none, "255.16777214", 255, 255, 255, 254)

/* ---- three parts: two top octets, then the low 16 bits ---- */
IA(three_part_16bit,     "10.1.258", 10, 1, 1, 2)
IA(three_part_16bit_max, "10.1.65535", 10, 1, 255, 255)
IA_NONE(three_part_16bit_over, "10.1.65536")
IA_NONE(three_part_first_over, "256.1.1")
IA_NONE(three_part_second_over, "1.256.1")
IA(three_part_private,   "192.168.257", 192, 168, 1, 1)
IA(three_part_loopback,  "127.0.1", 127, 0, 0, 1)

/* ---- four parts: each limited to 255 ---- */
IA_NONE(four_part_first_over,  "256.0.0.0")
IA_NONE(four_part_second_over, "0.256.0.0")
IA_NONE(four_part_third_over,  "0.0.256.0")
IA_NONE(four_part_fourth_over, "0.0.0.256")
IA(four_part_octal,      "01.02.03.04", 1, 2, 3, 4)
IA(four_part_octal_max,  "0377.0377.0377.0376", 255, 255, 255, 254)
IA_NONE(four_part_octal_over, "0400.0.0.0")
IA(four_part_hex,        "0x01.0x02.0x03.0x04", 1, 2, 3, 4)
IA(four_part_hex_mixed_case, "0X7F.0xa.0XB.0xc", 127, 10, 11, 12)
IA_NONE(four_part_hex_over, "0x100.0.0.0")
IA(four_part_mixed_radix, "0x7f.0.0.01", 127, 0, 0, 1)
IA(four_part_leading_zero_last, "1.2.3.04", 1, 2, 3, 4)
IA(four_part_max_minus_1, "255.255.255.254", 255, 255, 255, 254)

/* ---- digits that do not belong to the radix, letters, signs, stray punctuation ---- */
IA_NONE(octal_digit_8,   "08.1.1.1")
IA_NONE(octal_digit_9,   "1.2.3.09")
IA_NONE(hex_digit_g,     "0xG")
IA_NONE(hex_trailing_g,  "0x1G")
IA_NONE(letters_only,    "a.b.c.d")
IA_NONE(trailing_letter, "1.2.3.4a")
IA_NONE(trailing_x,      "1.2.3.4x")
IA_NONE(last_part_letter, "1.2.3.x")
IA_NONE(exponent,        "1.2.3.4e0")
IA_NONE(plus_sign,       "+1")
IA_NONE(minus_sign,      "-1")
IA_NONE(commas,          "1,2,3,4")
IA_NONE(prefix_len,      "1.2.3.4/24")
IA_NONE(scope_suffix,    "1.2.3.4%1")
IA_NONE(underscore,      "1_2")

/* ---- dot placement ---- */
IA_NONE(trailing_dot,    "1.2.3.4.")
IA_NONE(trailing_dot_3,  "1.2.3.")
IA_NONE(double_dot,      "1..3")
IA_NONE(leading_dots,    "..1")
IA_NONE(five_parts,      "1.2.3.4.5")
IA_NONE(dot_then_space_part, "1. 2")

/* ---- trailing bytes: white space (isspace in the C locale) ends the address, anything else fails ---- */
IA(tail_space,           "1.2.3.4 ", 1, 2, 3, 4)
IA(tail_tab,             "1.2.3.4\t", 1, 2, 3, 4)
IA(tail_crlf,            "1.2.3.4\r\n", 1, 2, 3, 4)
IA(tail_space_junk,      "1.2.3.4 junk", 1, 2, 3, 4)
IA(tail_vtab_junk,       "1.2.3.4\vx", 1, 2, 3, 4)
IA(tail_formfeed,        "1.2.3.4\f", 1, 2, 3, 4)
IA(tail_space_then_dot,  "1.2.3.4 .5", 1, 2, 3, 4)
IA(tail_one_part,        "7 ", 0, 0, 0, 7)
IA(tail_hex_part,        "0x7f.1 trailing", 127, 0, 0, 1)
IA_NONE(tail_backspace,  "1.2.3.4\x08")
TEST(ac_ia_tail_high_bytes_noted) { /* classification of bytes >= 0x80 may follow the C library locale: observe only */
    if (!U(inet_addr)) { t_skip("missing export: inet_addr"); return; }
    t_note("inet_addr tail 0xa0 -> %s, tail 0x85 -> %s", U(inet_addr)("1.2.3.4\xa0") == AC_NONE ? "none" : "accepted",
           U(inet_addr)("1.2.3.4\x85") == AC_NONE ? "none" : "accepted");
}
IA_NONE(tail_del,        "1.2.3.4\x7f")

/* The tail rule for a four-part address: every byte value after "1.2.3.4". */
TEST(ac_ia_tail_byte_sweep_four_parts) {
    unsigned c;
    REQUIRE(U(inet_addr));
    for (c = 1; c < 256; c++) {
        char s[16] = "1.2.3.4";
        unsigned long r, want;
        int space = (c >= 9 && c <= 13) || c == 32;
        if (c >= 128) continue; /* locale-dependent classification */
        if (c == '.' || (c >= '0' && c <= '9')) continue; /* these extend the number or add a part */
        s[7] = (char)c; s[8] = 0;
        want = space ? AC_RAW(1, 2, 3, 4) : AC_NONE;
        r = U(inet_addr)(s);
        CHECKF(r == want, "tail byte 0x%02x: got %08lx want %08lx", c, r, want);
    }
}

/* Same sweep after a single hexadecimal number: the tail must not be taken for a digit unless it is one. */
TEST(ac_ia_tail_byte_sweep_hex_part) {
    unsigned c;
    REQUIRE(U(inet_addr));
    for (c = 1; c < 256; c++) {
        char s[16] = "0x10";
        unsigned long r, want;
        int space = (c >= 9 && c <= 13) || c == 32;
        int hexd = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (c >= 128) continue; /* locale-dependent classification */
        if (c == '.' || hexd) continue;
        s[4] = (char)c; s[5] = 0;
        want = space ? AC_RAW(0, 0, 0, 0x10) : AC_NONE;
        r = U(inet_addr)(s);
        CHECKF(r == want, "tail byte 0x%02x: got %08lx want %08lx", c, r, want);
    }
}

/* The 32-bit accumulator wraps without every overflow being noticed: this value is accepted. */
TEST(ac_ia_quirk_undetected_overflow) {
    unsigned long r;
    REQUIRE(U(inet_addr));
    r = U(inet_addr)("5000000000");
    t_note("inet_addr(\"5000000000\") = %08lx (INADDR_NONE would be ffffffff)", r);
}

/* ---- sweeps: every value 0..255 in every octet position, written in each radix ---- */
static void sweep(const char *fmt) {
    int pos, v;
    if (!U(inet_addr)) { t_skip("missing export: inet_addr"); return; }
    for (pos = 0; pos < 4; pos++) {
        for (v = 0; v < 256; v++) {
            int o[4] = { 11, 22, 33, 44 };
            char s[96], f4[96];
            unsigned long r, want;
            o[pos] = v;
            snprintf(f4, sizeof f4, "%s.%s.%s.%s", fmt, fmt, fmt, fmt);
            snprintf(s, sizeof s, f4, o[0], o[1], o[2], o[3]);
            want = AC_RAW(o[0], o[1], o[2], o[3]);
            r = U(inet_addr)(s);
            CHECKF(r == want, "inet_addr(\"%s\"): got %08lx want %08lx", s, r, want);
        }
    }
}
TEST(ac_ia_sweep_decimal) { sweep("%d"); }
TEST(ac_ia_sweep_octal)   { sweep("0%o"); }
TEST(ac_ia_sweep_hex_lower) { sweep("0x%x"); }
TEST(ac_ia_sweep_hex_upper) { sweep("0X%X"); }

/* The three-part and two-part forms: sweep the wide last part in steps. */
TEST(ac_ia_sweep_wide_last_part) {
    unsigned v;
    REQUIRE(U(inet_addr));
    for (v = 0; v < 65536; v += 257) {
        char s[64]; unsigned long r, want;
        snprintf(s, sizeof s, "9.8.%u", v);
        want = AC_RAW(9, 8, (v >> 8) & 255, v & 255);
        r = U(inet_addr)(s);
        CHECKF(r == want, "\"%s\": got %08lx want %08lx", s, r, want);
    }
    for (v = 0; v < 0x1000000u; v += 0x10101) {
        char s[64]; unsigned long r, want;
        snprintf(s, sizeof s, "9.%u", v);
        want = AC_RAW(9, (v >> 16) & 255, (v >> 8) & 255, v & 255);
        r = U(inet_addr)(s);
        CHECKF(r == want, "\"%s\": got %08lx want %08lx", s, r, want);
    }
}

/* ---- inet_ntoa ---- */

static void ntoa_case(unsigned long raw, const char *want) {
    struct in_addr in; char *p;
    if (!U(inet_ntoa)) { t_skip("missing export: inet_ntoa"); return; }
    in.s_addr = raw;
    p = U(inet_ntoa)(in);
    CHECKF(p != NULL, "inet_ntoa returned NULL for %08lx", raw);
    if (p) CHECKF(!strcmp(p, want), "inet_ntoa(%08lx): got \"%s\" want \"%s\"", raw, p, want);
}
#define NT(name, a, b, c, d, text) TEST(ac_ntoa_##name) { ntoa_case(AC_RAW(a, b, c, d), text); }
NT(all_zero,      0, 0, 0, 0, "0.0.0.0")
NT(all_ones,      255, 255, 255, 255, "255.255.255.255")
NT(one_digit,     1, 2, 3, 4, "1.2.3.4")
NT(two_digit,     10, 20, 30, 40, "10.20.30.40")
NT(three_digit,   100, 200, 150, 199, "100.200.150.199")
NT(mixed_widths,  1, 20, 100, 9, "1.20.100.9")
NT(loopback,      127, 0, 0, 1, "127.0.0.1")
NT(no_leading_zeros, 0, 0, 0, 7, "0.0.0.7")
NT(zero_in_middle, 10, 0, 0, 10, "10.0.0.10")
NT(byte_order_is_memory, 1, 0, 0, 0, "1.0.0.0")
NT(high_bit_octets, 128, 129, 254, 192, "128.129.254.192")

TEST(ac_ntoa_every_octet_value) {
    int pos, v;
    REQUIRE(U(inet_ntoa));
    for (pos = 0; pos < 4; pos++) {
        for (v = 0; v < 256; v++) {
            int o[4] = { 7, 77, 177, 17 };
            char want[32]; struct in_addr in; char *p;
            o[pos] = v;
            snprintf(want, sizeof want, "%d.%d.%d.%d", o[0], o[1], o[2], o[3]);
            in.s_addr = AC_RAW(o[0], o[1], o[2], o[3]);
            p = U(inet_ntoa)(in);
            CHECKF(p && !strcmp(p, want), "pos %d value %d: got \"%s\" want \"%s\"", pos, v, p ? p : "(null)", want);
        }
    }
}

TEST(ac_ntoa_result_is_the_same_buffer_each_call) {
    struct in_addr a, b; char *p1, *p2;
    REQUIRE(U(inet_ntoa));
    a.s_addr = AC_RAW(1, 1, 1, 1); b.s_addr = AC_RAW(222, 222, 222, 222);
    p1 = U(inet_ntoa)(a);
    p2 = U(inet_ntoa)(b);
    CHECK(p1 != NULL); CHECK(p1 == p2);
    if (p1) EXPECT_STR(p1, "222.222.222.222");
}

TEST(ac_ntoa_shorter_result_terminates_longer_one) {
    struct in_addr a, b; char *p;
    REQUIRE(U(inet_ntoa));
    a.s_addr = AC_NONE; b.s_addr = AC_RAW(1, 1, 1, 1);
    U(inet_ntoa)(a);
    p = U(inet_ntoa)(b);
    CHECK(p != NULL);
    if (p) { EXPECT_STR(p, "1.1.1.1"); EXPECT_EQ(strlen(p), 7); }
}

TEST(ac_ntoa_inet_addr_roundtrip_table) {
    static const char *const t[] = { "0.0.0.0", "1.2.3.4", "10.0.0.1", "127.0.0.1", "192.168.100.200",
        "255.255.255.255", "8.8.4.4", "100.64.0.1", "169.254.1.1", "224.0.0.251" };
    unsigned i;
    REQUIRE(U(inet_ntoa)); REQUIRE(U(inet_addr));
    for (i = 0; i < AC_COUNT(t); i++) {
        struct in_addr in; char *p;
        in.s_addr = U(inet_addr)(t[i]);
        p = U(inet_ntoa)(in);
        CHECKF(p && !strcmp(p, t[i]), "roundtrip of \"%s\" gave \"%s\"", t[i], p ? p : "(null)");
    }
}

static DWORD WINAPI ntoa_thread(void *arg) {
    struct in_addr in; char *p;
    in.s_addr = AC_RAW(4, 3, 2, 1);
    p = U(inet_ntoa)(in);
    *(ULONG_PTR *)arg = (ULONG_PTR)p;
    return (p && !strcmp(p, "4.3.2.1")) ? 0 : 1;
}

TEST(ac_ntoa_buffer_pointer_differs_between_threads) {
    struct in_addr in; char *mine; ULONG_PTR theirs = 0; HANDLE h; DWORD code = 99;
    REQUIRE(U(inet_ntoa));
    AC_NEED_WSA();
    in.s_addr = AC_RAW(1, 2, 3, 4);
    mine = U(inet_ntoa)(in);
    h = CreateThread(NULL, 0, ntoa_thread, &theirs, 0, NULL);
    CHECK(h != NULL);
    if (!h) return;
    CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0);
    GetExitCodeThread(h, &code);
    CloseHandle(h);
    EXPECT_EQ(code, 0);
    CHECK(theirs != 0 && theirs != (ULONG_PTR)mine);
    if (mine) EXPECT_STR(mine, "1.2.3.4"); /* the other thread did not disturb this thread's buffer */
}

/* inet_ntoa, inet_addr and the byte-order helpers have no WinSock state requirement. */
CHILD(ac_addr_no_startup) {
    struct in_addr in; char *p; int bad = 0;
    FARPROC ntoa = t_proc_in("ws2_32.dll", "inet_ntoa"), addr = t_proc_in("ws2_32.dll", "inet_addr");
    in.s_addr = AC_RAW(9, 8, 7, 6);
    if (!ntoa || !addr) return 0;
    if (((unsigned long (WSAAPI *)(const char *))addr)("9.8.7.6") != AC_RAW(9, 8, 7, 6)) { printf("inet_addr wrong\n"); bad++; }
    p = ((char *(WSAAPI *)(struct in_addr))ntoa)(in);
    if (!p || strcmp(p, "9.8.7.6")) { printf("inet_ntoa without startup gave %s\n", p ? p : "(null)"); bad++; }
    return bad;
}
TEST(ac_ntoa_works_without_wsastartup) {
    REQUIRE(U(inet_ntoa));
    { DWORD code = t_run_child("ac_addr_no_startup", "", 30000); EXPECT_EQ(code, 0); }
}
