/* InetPtonW depth: argument-check order, the exact error for each failure class, the text grammar accepted for
 * AF_INET (strict dotted quad) and AF_INET6 (compression, embedded IPv4, no scope/brackets/prefix), how many
 * bytes a success writes, parity with the narrow form, and independence from WSAStartup.
 * Return protocol: 1 parsed, 0 text rejected (WSAEINVAL), -1 argument error (WSAEFAULT / WSAEAFNOSUPPORT). */
#include "g3.h"

typedef INT (WSAAPI *pw_fn)(INT, PCWSTR, PVOID);
typedef INT (WSAAPI *pa_fn)(INT, PCSTR, PVOID);
typedef PCWSTR (WSAAPI *nw_fn)(INT, const VOID *, PWSTR, size_t);
#define PW() ((pw_fn)t_proc_in("ws2_32.dll", "InetPtonW"))
#define PA() ((pa_fn)t_proc_in("ws2_32.dll", "inet_pton"))
#define NW() ((nw_fn)t_proc_in("ws2_32.dll", "InetNtopW"))

struct vec { const WCHAR *text; int af; int ok; unsigned char bytes[16]; };

/* ok vectors carry the expected bytes. Only grammar the parser must reproduce on every Windows 10 is listed. */
static const struct vec v4ok[] = {
    { L"0.0.0.0", AF_INET, 1, { 0, 0, 0, 0 } },
    { L"1.2.3.4", AF_INET, 1, { 1, 2, 3, 4 } },
    { L"127.0.0.1", AF_INET, 1, { 127, 0, 0, 1 } },
    { L"255.255.255.255", AF_INET, 1, { 255, 255, 255, 255 } },
    { L"10.20.30.40", AF_INET, 1, { 10, 20, 30, 40 } },
    { L"192.168.0.255", AF_INET, 1, { 192, 168, 0, 255 } },
    { L"0.0.0.1", AF_INET, 1, { 0, 0, 0, 1 } },
    { L"200.100.50.25", AF_INET, 1, { 200, 100, 50, 25 } },
};
static const WCHAR *const v4bad[] = {
    L"", L" ", L"1", L"1.2", L"1.2.3", L"1.2.3.", L".1.2.3", L"1..2.3", L"1.2.3.4.5", L"1.2.3.4.",
    L"256.1.1.1", L"1.256.1.1", L"1.1.256.1", L"1.1.1.256", L"999.999.999.999", L"-1.2.3.4", L"+1.2.3.4",
    L"1.2.3.4 ", L" 1.2.3.4", L"1.2.3.4\t", L"1.2.3.4:80", L"1.2.3.4/24", L"1.2.3.4abc", L"a.b.c.d",
    L"1.2.3.x", L"1,2,3,4", L"1.2.3 .4", L"::1", L"::ffff:1.2.3.4", L"[1.2.3.4]", L"localhost", L"1.2.3.4%1",
    L"4294967295", L"0x7f.0.0.1", L"1.2.3.0x4",
};
static const struct vec v6ok[] = {
    { L"::", AF_INET6, 1, { 0 } },
    { L"::1", AF_INET6, 1, { [15] = 1 } },
    { L"1::", AF_INET6, 1, { 0, 1 } },
    { L"1:2:3:4:5:6:7:8", AF_INET6, 1, { 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8 } },
    { L"ABCD:ef01:2345:6789:abcd:EF01:2345:6789", AF_INET6, 1, { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89 } },
    { L"1::8", AF_INET6, 1, { 0, 1, [15] = 8 } },
    { L"1:2::7:8", AF_INET6, 1, { 0, 1, 0, 2, [12] = 0, 7, 0, 8 } },
    { L"::ffff:1.2.3.4", AF_INET6, 1, { [10] = 0xff, 0xff, 1, 2, 3, 4 } },
    { L"::1.2.3.4", AF_INET6, 1, { [12] = 1, 2, 3, 4 } },
    { L"1:2:3:4:5:6:1.2.3.4", AF_INET6, 1, { 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 1, 2, 3, 4 } },
    { L"fe80::1", AF_INET6, 1, { 0xfe, 0x80, [15] = 1 } },
    { L"0:0:0:0:0:0:0:0", AF_INET6, 1, { 0 } },
    { L"0001:0002:0003:0004:0005:0006:0007:0008", AF_INET6, 1, { 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8 } },
    { L"2001:db8::ff00:42:8329", AF_INET6, 1, { 0x20, 0x01, 0x0d, 0xb8, [10] = 0xff, 0x00, 0x00, 0x42, 0x83, 0x29 } },
};
static const WCHAR *const v6bad[] = {
    L"", L":", L":::", L"1:::2", L"1::2::3", L"1:2:3:4:5:6:7:8:9", L"1:2:3:4:5:6:7", L"12345::", L"g::", L"::g",
    L":1:2:3:4:5:6:7", L"1:2:3:4:5:6:7:", L"[::1]", L"::1/64",
    L"::1%1", L"::1 ", L" ::1", L"1.2.3.4", L"::1.2.3.4.5", L"::1.2.3.256", L"1.2.3.4::", L"::1.2.3.4:5",
    L"1:2:3:4:5:6:7:1.2.3.4", L"::-1", L"::1:", L"0x1::", L"::ffff:1.2.3.4abc", L"1 ::", L"::1\t",
};

static int ptonw(INT af, const WCHAR *s, void *out) { return PW()(af, s, out); }

TEST(gap3_inetptonw_exported_and_distinct_from_inet_pton)
{
    CHECK(PW() != NULL); CHECK(PA() != NULL); CHECK((void *)PW() != (void *)PA());
}

TEST(gap3_inetptonw_works_in_a_process_that_never_called_wsastartup)
{
    /* The conversion is pure parsing; it must not need the Winsock reference count. Child process: nothing in
     * it calls WSAStartup. */
    G3_EQ(t_run_child("pton_nostart", "", 20000), 0);
}
CHILD(pton_nostart)
{
    unsigned char b[16] = {0};
    int r = ptonw(AF_INET, L"9.8.7.6", b);
    if (r != 1 || b[0] != 9 || b[3] != 6) return 2;
    SetLastError(0);
    r = ptonw(AF_INET6, L"::1", b);
    if (r != 1 || b[15] != 1) return 3;
    SetLastError(0);
    r = ptonw(AF_INET, L"nonsense", b);
    if (r != 0 || GetLastError() != WSAEINVAL) return 4;
    return 0;
}

TEST(gap3_inetptonw_null_text_is_efault_for_every_family)
{
    static const int fams[] = { AF_UNSPEC, AF_INET, AF_INET6, AF_UNIX, 99, -1 };
    unsigned char b[16];
    unsigned i;
    REQUIRE(PW());
    for (i = 0; i < sizeof fams / sizeof *fams; i++) {
        SET_ERR(0x1234);
        G3_EQ(PW()(fams[i], NULL, b), -1);
        CHECKF(GetLastError() == WSAEFAULT, "family %d: error %lu", fams[i], GetLastError());
    }
}

TEST(gap3_inetptonw_null_destination_is_efault_for_every_family)
{
    static const int fams[] = { AF_UNSPEC, AF_INET, AF_INET6, 99 };
    unsigned i;
    REQUIRE(PW());
    for (i = 0; i < sizeof fams / sizeof *fams; i++) {
        SET_ERR(0x1234);
        G3_EQ(PW()(fams[i], L"1.2.3.4", NULL), -1);
        CHECKF(GetLastError() == WSAEFAULT, "family %d: error %lu", fams[i], GetLastError());
    }
}

TEST(gap3_inetptonw_both_null_is_efault)
{
    REQUIRE(PW());
    SET_ERR(0x1234);
    G3_EQ(PW()(AF_INET, NULL, NULL), -1); EXPECT_ERR(WSAEFAULT);
    SET_ERR(0x1234);
    G3_EQ(PW()(AF_UNSPEC, NULL, NULL), -1); EXPECT_ERR(WSAEFAULT);
}

TEST(gap3_inetptonw_unsupported_family_is_afnosupport_even_for_good_text)
{
    static const int fams[] = { AF_UNSPEC, AF_UNIX, AF_IPX, AF_NETBIOS, AF_APPLETALK, 3, 22, 24, 99, -1, 0x10002 };
    unsigned char b[16];
    unsigned i;
    REQUIRE(PW());
    for (i = 0; i < sizeof fams / sizeof *fams; i++) {
        SET_ERR(0x1234);
        G3_EQ(PW()(fams[i], L"1.2.3.4", b), -1);
        CHECKF(GetLastError() == WSAEAFNOSUPPORT, "v4 text family %d: error %lu", fams[i], GetLastError());
        SET_ERR(0x1234);
        G3_EQ(PW()(fams[i], L"::1", b), -1);
        CHECKF(GetLastError() == WSAEAFNOSUPPORT, "v6 text family %d: error %lu", fams[i], GetLastError());
    }
}

TEST(gap3_inetptonw_family_is_checked_before_the_text)
{
    unsigned char b[16];
    REQUIRE(PW());
    SET_ERR(0);
    G3_EQ(PW()(AF_UNSPEC, L"", b), -1); EXPECT_ERR(WSAEAFNOSUPPORT);
    SET_ERR(0);
    G3_EQ(PW()(99, L"not an address", b), -1); EXPECT_ERR(WSAEAFNOSUPPORT);
}

TEST(gap3_inetptonw_wrong_family_for_the_text_is_einval_not_afnosupport)
{
    unsigned char b[16];
    REQUIRE(PW());
    SET_ERR(0);
    G3_EQ(PW()(AF_INET, L"::1", b), 0); EXPECT_ERR(WSAEINVAL);
    SET_ERR(0);
    G3_EQ(PW()(AF_INET6, L"1.2.3.4", b), 0); EXPECT_ERR(WSAEINVAL);
}

TEST(gap3_inetptonw_v4_good_table)
{
    unsigned i;
    REQUIRE(PW());
    for (i = 0; i < sizeof v4ok / sizeof *v4ok; i++) {
        unsigned char b[8]; memset(b, 0xCC, sizeof b);
        SET_ERR(0x1234);
        G3_EQ(ptonw(AF_INET, v4ok[i].text, b), 1);
        CHECKF(!memcmp(b, v4ok[i].bytes, 4), "vector %u bytes", i);
        CHECKF(b[4] == 0xCC && b[7] == 0xCC, "vector %u wrote past four bytes", i);
    }
}

TEST(gap3_inetptonw_v4_bad_table_is_zero_with_einval)
{
    unsigned i;
    unsigned char b[16];
    REQUIRE(PW());
    for (i = 0; i < sizeof v4bad / sizeof *v4bad; i++) {
        int r;
        SET_ERR(0x1234);
        r = ptonw(AF_INET, v4bad[i], b);
        CHECKF(r == 0 && GetLastError() == WSAEINVAL, "v4 reject #%u: ret %d err %lu", i, r, GetLastError());
    }
}

TEST(gap3_inetptonw_v6_good_table)
{
    unsigned i;
    REQUIRE(PW());
    for (i = 0; i < sizeof v6ok / sizeof *v6ok; i++) {
        unsigned char b[20]; memset(b, 0xCC, sizeof b);
        SET_ERR(0x1234);
        G3_EQ(ptonw(AF_INET6, v6ok[i].text, b), 1);
        CHECKF(!memcmp(b, v6ok[i].bytes, 16), "v6 vector %u bytes", i);
        CHECKF(b[16] == 0xCC && b[19] == 0xCC, "v6 vector %u wrote past sixteen bytes", i);
    }
}

TEST(gap3_inetptonw_v6_bad_table_is_zero_with_einval)
{
    unsigned i;
    unsigned char b[16];
    REQUIRE(PW());
    for (i = 0; i < sizeof v6bad / sizeof *v6bad; i++) {
        int r;
        SET_ERR(0x1234);
        r = ptonw(AF_INET6, v6bad[i], b);
        CHECKF(r == 0 && GetLastError() == WSAEINVAL, "v6 reject #%u: ret %d err %lu", i, r, GetLastError());
    }
}

TEST(gap3_inetptonw_success_leaves_last_error_alone_or_not_recorded)
{
    /* The success path performs no SetLastError in the wide form: a sentinel survives. Recorded as a note when
     * it does not, since callers must not rely on it either way. */
    unsigned char b[4];
    REQUIRE(PW());
    SET_ERR(0x4321);
    G3_EQ(PW()(AF_INET, L"1.2.3.4", b), 1);
    if (GetLastError() != 0x4321) t_note("InetPtonW success changed last error to %lu", GetLastError());
}

TEST(gap3_inetptonw_v6_case_insensitive_hex)
{
    unsigned char a[16], b[16];
    REQUIRE(PW());
    G3_EQ(ptonw(AF_INET6, L"ABCD:EF01::A", a), 1);
    G3_EQ(ptonw(AF_INET6, L"abcd:ef01::a", b), 1);
    CHECK(!memcmp(a, b, 16));
}

TEST(gap3_inetptonw_v6_zero_runs_compress_to_the_same_bytes)
{
    unsigned char a[16], b[16], c[16];
    REQUIRE(PW());
    G3_EQ(ptonw(AF_INET6, L"1:0:0:0:0:0:0:2", a), 1);
    G3_EQ(ptonw(AF_INET6, L"1::2", b), 1);
    G3_EQ(ptonw(AF_INET6, L"1:0:0::2", c), 1);
    CHECK(!memcmp(a, b, 16)); CHECK(!memcmp(a, c, 16));
}

TEST(gap3_inetptonw_embedded_v4_equals_hex_groups)
{
    unsigned char a[16], b[16];
    REQUIRE(PW());
    G3_EQ(ptonw(AF_INET6, L"::ffff:10.20.30.40", a), 1);
    G3_EQ(ptonw(AF_INET6, L"::ffff:a14:1e28", b), 1);
    CHECK(!memcmp(a, b, 16));
}

TEST(gap3_inetptonw_agrees_with_narrow_form_on_results_and_bytes)
{
    unsigned i;
    REQUIRE(PW()); REQUIRE(PA());
    for (i = 0; i < sizeof v4bad / sizeof *v4bad; i++) {
        char n[64]; unsigned char bw[16] = {0}, ba[16] = {0}; int rw, ra, k;
        for (k = 0; v4bad[i][k] && k < 60; k++) n[k] = (char)v4bad[i][k];
        n[k] = 0;
        rw = PW()(AF_INET, v4bad[i], bw); ra = PA()(AF_INET, n, ba);
        CHECKF(rw == ra, "v4 reject #%u: W %d A %d", i, rw, ra);
    }
    for (i = 0; i < sizeof v6bad / sizeof *v6bad; i++) {
        char n[64]; unsigned char bw[16] = {0}, ba[16] = {0}; int rw, ra, k;
        for (k = 0; v6bad[i][k] && k < 60; k++) n[k] = (char)v6bad[i][k];
        n[k] = 0;
        rw = PW()(AF_INET6, v6bad[i], bw); ra = PA()(AF_INET6, n, ba);
        CHECKF(rw == ra, "v6 reject #%u: W %d A %d", i, rw, ra);
    }
    for (i = 0; i < sizeof v6ok / sizeof *v6ok; i++) {
        char n[64]; unsigned char bw[16] = {0}, ba[16] = {0}; int k;
        for (k = 0; v6ok[i].text[k] && k < 60; k++) n[k] = (char)v6ok[i].text[k];
        n[k] = 0;
        G3_EQ(PW()(AF_INET6, v6ok[i].text, bw), 1); G3_EQ(PA()(AF_INET6, n, ba), 1);
        CHECK(!memcmp(bw, ba, 16));
    }
}

TEST(gap3_inetptonw_roundtrips_through_inetntopw)
{
    static const WCHAR *const t6[] = { L"::", L"::1", L"1::", L"2001:db8::1", L"fe80::1:2:3:4", L"1:2:3:4:5:6:7:8" };
    unsigned i;
    REQUIRE(PW()); REQUIRE(NW());
    for (i = 0; i < sizeof t6 / sizeof *t6; i++) {
        unsigned char b[16]; WCHAR out[64]; PCWSTR r;
        G3_EQ(ptonw(AF_INET6, t6[i], b), 1);
        r = NW()(AF_INET6, b, out, 64);
        CHECKF(r != NULL && !lstrcmpW(out, t6[i]), "round trip #%u", i);
    }
    {
        unsigned char b[4]; WCHAR out[32];
        G3_EQ(ptonw(AF_INET, L"172.16.254.1", b), 1);
        CHECK(NW()(AF_INET, b, out, 32) != NULL); CHECK(!lstrcmpW(out, L"172.16.254.1"));
    }
}

TEST(gap3_inetptonw_leading_zero_v4_octets_are_recorded)
{
    /* Strict dotted-decimal handling of redundant zeros varies by parser; only record. */
    unsigned char b[4] = {0};
    int r;
    REQUIRE(PW());
    SET_ERR(0);
    r = ptonw(AF_INET, L"01.2.3.4", b);
    t_note("InetPtonW(\"01.2.3.4\") -> %d (bytes %d.%d.%d.%d)", r, b[0], b[1], b[2], b[3]);
    r = ptonw(AF_INET, L"001.002.003.004", b);
    t_note("InetPtonW(\"001.002.003.004\") -> %d", r);
}

TEST(gap3_inetptonw_embedded_nul_ends_the_text)
{
    /* Text is NUL terminated: characters after the first NUL are never read. */
    static const WCHAR t[] = { '1', '.', '2', '.', '3', '.', '4', 0, 'z', 'z', 0 };
    unsigned char b[4];
    REQUIRE(PW());
    G3_EQ(ptonw(AF_INET, t, b), 1);
    CHECK(b[0] == 1 && b[3] == 4);
}
