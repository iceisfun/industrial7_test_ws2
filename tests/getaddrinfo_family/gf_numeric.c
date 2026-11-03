/* getaddrinfo family: numeric host literals and service strings.
 *
 * Measures: which spellings of IPv4 (strict dotted quad without AI_NUMERICHOST, inet_addr-style abbreviations
 * with it) and IPv6 (compressed, embedded IPv4, scope id, brackets, port after the bracket, the
 * ipv6-literal name form) are accepted without any name resolution, the exact error for everything else under
 * AI_NUMERICHOST, the flags/canonical-name fields of literal answers (AI_NUMERICHOST bit set in the answer,
 * AI_CANONNAME = normalised text, AI_FQDN = input text, extended v2 structure for both), and the service
 * string rules (decimal strtoul with 16-bit truncation, trailing junk becomes a name lookup,
 * AI_NUMERICSERV, services-database lookup per socket type, 255-character limit). Nothing here contacts a
 * resolver. */
#include "gf.h"

/* ---- IPv4 literals --------------------------------------------------------------------------- */
#define NH(fl) (AI_NUMERICHOST | (fl))
/* strict dotted quad: accepted with or without AI_NUMERICHOST */
OK_ROW(gfn_v4_plain,          GF_ALL, "1.2.3.4",         NULL, NULL, "1.2.3.4", 0, 1)
OK_ROW(gfn_v4_zero,           GF_ALL, "0.0.0.0",         NULL, NULL, "0.0.0.0", 0, 1)
OK_ROW(gfn_v4_broadcast,      GF_ALL, "255.255.255.255", NULL, NULL, "255.255.255.255", 0, 1)
OK_ROW(gfn_v4_loopback,       GF_ALL, "127.0.0.1",       NULL, NULL, "127.0.0.1", 0, 1)
OK_ROW(gfn_v4_private,        GF_ALL, "10.255.0.77",     NULL, NULL, "10.255.0.77", 0, 1)
OK_ROW(gfn_v4_numerichost,    GF_ALL, "192.0.2.77",      NULL, H(AI_NUMERICHOST, 0, 0, 0), "192.0.2.77", 0, 1)
OK_ROW(gfn_v4_inet_hint,      GF_ALL, "192.0.2.77",      NULL, H(0, AF_INET, 0, 0), "192.0.2.77", 0, 1)
OK_ROW(gfn_v4_inet_hint_nh,   GF_ALL, "192.0.2.77",      NULL, H(AI_NUMERICHOST, AF_INET, 0, 0), "192.0.2.77", 0, 1)
OK_ROW(gfn_v4_unspec_hint,    GF_ALL, "192.0.2.77",      NULL, H(0, AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP), "192.0.2.77", 0, 1)
OK_ROW(gfn_v4_with_port_serv, GF_ALL, "192.0.2.77",      "8080", NULL, "192.0.2.77", 8080, 1)
/* inet_addr-style forms are accepted only when name resolution is forbidden */
OK_ROW(gfn_v4_abbrev_127_1,   GF_ALL, "127.1",       NULL, H(AI_NUMERICHOST, 0, 0, 0), "127.0.0.1", 0, 1)
OK_ROW(gfn_v4_abbrev_1_2,     GF_ALL, "1.2",         NULL, H(AI_NUMERICHOST, 0, 0, 0), "1.0.0.2", 0, 1)
OK_ROW(gfn_v4_abbrev_127_0_1, GF_ALL, "127.0.1",     NULL, H(AI_NUMERICHOST, 0, 0, 0), "127.0.0.1", 0, 1)
OK_ROW(gfn_v4_abbrev_10_1_2,  GF_ALL, "10.1.2",      NULL, H(AI_NUMERICHOST, 0, 0, 0), "10.1.0.2", 0, 1)
OK_ROW(gfn_v4_single_number,  GF_ALL, "2130706433",  NULL, H(AI_NUMERICHOST, 0, 0, 0), "127.0.0.1", 0, 1)
OK_ROW(gfn_v4_single_number2, GF_ALL, "203569230",   NULL, H(AI_NUMERICHOST, 0, 0, 0), "12.34.56.78", 0, 1)
OK_ROW(gfn_v4_single_zero,    GF_ALL, "0",           NULL, H(AI_NUMERICHOST, 0, 0, 0), "0.0.0.0", 0, 1)
OK_ROW(gfn_v4_single_max,     GF_ALL, "4294967295",  NULL, H(AI_NUMERICHOST, 0, 0, 0), "255.255.255.255", 0, 1)
OK_ROW(gfn_v4_hex_single,     GF_ALL, "0x7f000001",  NULL, H(AI_NUMERICHOST, 0, 0, 0), "127.0.0.1", 0, 1)
OK_ROW(gfn_v4_hex_parts,      GF_ALL, "0x7f.0.0.1",  NULL, H(AI_NUMERICHOST, 0, 0, 0), "127.0.0.1", 0, 1)
OK_ROW(gfn_v4_hex_abbrev,     GF_ALL, "0x7f.1",      NULL, H(AI_NUMERICHOST, 0, 0, 0), "127.0.0.1", 0, 1)
OK_ROW(gfn_v4_octal_parts,    GF_ALL, "0177.0.0.1",  NULL, H(AI_NUMERICHOST, 0, 0, 0), "127.0.0.1", 0, 1)
OK_ROW(gfn_v4_abbrev_inet,    GF_ALL, "127.1",       NULL, H(AI_NUMERICHOST, AF_INET, 0, 0), "127.0.0.1", 0, 1)
/* invalid IPv4 spellings under AI_NUMERICHOST: not found */
#define BADNH(nm, text) ERR_ROW(nm, GF_ALL, text, NULL, H(AI_NUMERICHOST, 0, 0, 0), WSAHOST_NOT_FOUND)
BADNH(gfn_bad_five_parts,       "1.2.3.4.5")
BADNH(gfn_bad_part_256,         "127.127.127.256")
BADNH(gfn_bad_all_256,          "256.256.256.256")
BADNH(gfn_bad_port_suffix,      "1.2.3.4:80")
BADNH(gfn_bad_prefix_suffix,    "1.2.3.4/24")
BADNH(gfn_bad_leading_dot,      ".1.2.3")
BADNH(gfn_bad_letters,          "abc")
BADNH(gfn_bad_mixed_letters,    "1.2.3.a")
BADNH(gfn_bad_comma,            "1,2,3,4")
BADNH(gfn_bad_brackets_v4,      "[1.2.3.4]")
BADNH(gfn_bad_hostname,         "localhost")
BADNH(gfn_bad_domain,           "host.example")
BADNH(gfn_bad_underscore,       "a_b")
BADNH(gfn_bad_hex_junk,         "0xzz")
BADNH(gfn_bad_email_name,       "user@host")
/* the same text with a family that cannot match */
ERR_ROW(gfn_bad_v4_text_inet6_hint, GF_ALL, "127.0.0.1", NULL, H(AI_NUMERICHOST, AF_INET6, 0, 0), WSAHOST_NOT_FOUND)
ERR_ROW(gfn_bad_v6_text_inet_hint,  GF_ALL, "::1",       NULL, H(AI_NUMERICHOST, AF_INET, 0, 0), WSAHOST_NOT_FOUND)
/* The extended calls reject an IPv4 literal for AF_INET6 even without AI_NUMERICHOST (no mapping requested). */
ERR_ROW(gfn_x_v4_text_inet6_no_flag, GF_XW | GF_XA, "127.0.0.1", NULL, H(0, AF_INET6, 0, 0), WSAHOST_NOT_FOUND)
/* A node containing '@' is not given a service lookup: the service error is not reported. */
ERR_ROW(gfn_email_node_skips_service, GF_ALL, "user@host", "no_such_service_zz", H(AI_NUMERICHOST, 0, 0, 0), WSAHOST_NOT_FOUND)

/* ---- IPv6 literals --------------------------------------------------------------------------- */
OK_ROW(gfn_v6_loopback,      GF_ALL, "::1",        NULL, NULL, "0:0:0:0:0:0:0:1", 0, 1)
OK_ROW(gfn_v6_unspecified,   GF_ALL, "::",         NULL, NULL, "0:0:0:0:0:0:0:0", 0, 1)
OK_ROW(gfn_v6_linklocal,     GF_ALL, "fe80::1",    NULL, NULL, "fe80:0:0:0:0:0:0:1", 0, 1)
OK_ROW(gfn_v6_upper,         GF_ALL, "FE80::ABCD", NULL, NULL, "fe80:0:0:0:0:0:0:abcd", 0, 1)
OK_ROW(gfn_v6_doc,           GF_ALL, "2001:db8::5", NULL, NULL, "2001:db8:0:0:0:0:0:5", 0, 1)
OK_ROW(gfn_v6_full,          GF_ALL, "1:2:3:4:5:6:7:8", NULL, NULL, "1:2:3:4:5:6:7:8", 0, 1)
OK_ROW(gfn_v6_leading_zeros, GF_ALL, "0001:0002:0003:0004:0005:0006:0007:0008", NULL, NULL, "1:2:3:4:5:6:7:8", 0, 1)
OK_ROW(gfn_v6_mid_compress,  GF_ALL, "1::8",       NULL, NULL, "1:0:0:0:0:0:0:8", 0, 1)
OK_ROW(gfn_v6_trail_compress,GF_ALL, "1:2:3::",    NULL, NULL, "1:2:3:0:0:0:0:0", 0, 1)
OK_ROW(gfn_v6_v4_embedded,   GF_ALL, "::ffff:1.2.3.4", NULL, NULL, "0:0:0:0:0:ffff:102:304", 0, 1)
OK_ROW(gfn_v6_v4_compat,     GF_ALL, "::1.2.3.4",  NULL, NULL, "0:0:0:0:0:0:102:304", 0, 1)
OK_ROW(gfn_v6_bracketed,     GF_ALL, "[2001:db8::5]", NULL, NULL, "2001:db8:0:0:0:0:0:5", 0, 1)
OK_ROW(gfn_v6_inet6_hint,    GF_ALL, "2001:db8::5", NULL, H(0, AF_INET6, 0, 0), "2001:db8:0:0:0:0:0:5", 0, 1)
OK_ROW(gfn_v6_numerichost,   GF_ALL, "2001:db8::5", NULL, H(AI_NUMERICHOST, 0, 0, 0), "2001:db8:0:0:0:0:0:5", 0, 1)
OK_ROW(gfn_v6_serv_port,     GF_ALL, "2001:db8::5", "8080", NULL, "2001:db8:0:0:0:0:0:5", 8080, 1)
/* scope id */
OK_ROW(gfn_v6_scope_1,       GF_ALL, "fe80::1%1",  NULL, NULL, "fe80:0:0:0:0:0:0:1%1", 0, 1)
OK_ROW(gfn_v6_scope_12,      GF_ALL, "fe80::1%12", NULL, NULL, "fe80:0:0:0:0:0:0:1%12", 0, 1)
OK_ROW(gfn_v6_scope_in_brackets, GF_ALL, "[fe80::1%3]", NULL, NULL, "fe80:0:0:0:0:0:0:1%3", 0, 1)
OK_ROW(gfn_v6_scope_loopback,GF_ALL, "::1%1",      NULL, NULL, "0:0:0:0:0:0:0:1%1", 0, 1)
OK_ROW(gfn_v6_scope_numerichost, GF_ALL, "fe80::7%9", NULL, H(AI_NUMERICHOST, AF_INET6, 0, 0), "fe80:0:0:0:0:0:0:7%9", 0, 1)
/* a port after the bracket is parsed but replaced by the service port */
OK_ROW(gfn_v6_bracket_port_dropped,  GF_ALL, "[2001:db8::5]:99", NULL, NULL, "2001:db8:0:0:0:0:0:5", 0, 1)
OK_ROW(gfn_v6_bracket_port_replaced, GF_ALL, "[2001:db8::5]:99", "80", NULL, "2001:db8:0:0:0:0:0:5", 80, 1)
OK_ROW(gfn_v6_bracket_port_zero_serv,GF_ALL, "[2001:db8::5]:99", "0",  NULL, "2001:db8:0:0:0:0:0:5", 0, 1)
/* the ipv6-literal name form (colons become dashes) is recognised without a lookup */
OK_ROW(gfn_v6_literal_name,        GF_ALL, "2001-db8--5.ipv6-literal.net", NULL, H(AI_NUMERICHOST, 0, 0, 0), "2001:db8:0:0:0:0:0:5", 0, 1)
OK_ROW(gfn_v6_literal_name_loop,   GF_ALL, "--1.ipv6-literal.net",         NULL, H(AI_NUMERICHOST, 0, 0, 0), "0:0:0:0:0:0:0:1", 0, 1)
OK_ROW(gfn_v6_literal_name_scope,  GF_ALL, "fe80--1s5.ipv6-literal.net",   NULL, H(AI_NUMERICHOST, 0, 0, 0), "fe80:0:0:0:0:0:0:1%5", 0, 1)
OK_ROW(gfn_v6_literal_name_nohint, GF_ALL, "2001-db8--5.ipv6-literal.net", NULL, NULL, "2001:db8:0:0:0:0:0:5", 0, 1)
/* invalid IPv6 spellings under AI_NUMERICHOST */
BADNH(gfn_bad6_two_compress,    "1::2::3")
BADNH(gfn_bad6_five_digit_group,"12345::1")
BADNH(gfn_bad6_nine_groups,     "1:2:3:4:5:6:7:8:9")
BADNH(gfn_bad6_seven_groups,    "1:2:3:4:5:6:7")
BADNH(gfn_bad6_non_hex,         "g::1")
BADNH(gfn_bad6_prefix,          "::1/64")
BADNH(gfn_bad6_triple_colon,    ":::1")
BADNH(gfn_bad6_single_colon,    ":1")
BADNH(gfn_bad6_trailing_colon,  "1:")
BADNH(gfn_bad6_unclosed,        "[::1")
BADNH(gfn_bad6_unopened,        "::1]")
BADNH(gfn_bad6_empty_brackets,  "[]")
BADNH(gfn_bad6_bad_v4_tail,     "::1.2.3")
BADNH(gfn_bad6_v4_in_front,     "1.2.3.4::")
BADNH(gfn_bad6_literal_name_v4, "1.2.3.4.ipv6-literal.net")
/* IPv6 text with an AF_INET hint cannot match */
ERR_ROW(gfn_v6_literal_name_inet_hint, GF_ALL, "2001-db8--5.ipv6-literal.net", NULL, H(AI_NUMERICHOST, AF_INET, 0, 0), WSAHOST_NOT_FOUND)
ERR_ROW(gfn_v6_bracket_inet_hint,      GF_ALL, "[::1]", NULL, H(AI_NUMERICHOST, AF_INET, 0, 0), WSAHOST_NOT_FOUND)

/* ---- literal answers: flags, canonical name, FQDN ----------------------------------------------- */
/* Every literal answer carries AI_NUMERICHOST in ai_flags, whatever was asked, and nothing else. */
static void literal_flags(const char *node, int hint_flags, int want_extra)
{
    int api;
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, node, NULL, H(hint_flags, 0, 0, 0), &r);
        CHECKF(r.ret == 0 && GF_N1(r.n), "%s ret %d n %d", gf_api_name(api), r.ret, r.n);
        if (r.ret || !GF_N1(r.n)) continue;
        CHECKF(r.e[0].flags == (AI_NUMERICHOST | want_extra), "%s flags 0x%x", gf_api_name(api), r.e[0].flags);
    }
}
TEST(gfn_flags_v4_no_hint)        { GFB_BEGIN(GF_ALL); literal_flags("1.2.3.4", 0, 0); GFB_END(); }
TEST(gfn_flags_v4_passive)        { GFB_BEGIN(GF_ALL); literal_flags("1.2.3.4", AI_PASSIVE, 0); GFB_END(); }
TEST(gfn_flags_v4_numerichost)    { GFB_BEGIN(GF_ALL); literal_flags("1.2.3.4", AI_NUMERICHOST, 0); GFB_END(); }
TEST(gfn_flags_v4_all_flags_set)  { GFB_BEGIN(GF_ALL); literal_flags("1.2.3.4", AI_NUMERICHOST | AI_NUMERICSERV | AI_ADDRCONFIG, 0); GFB_END(); }
TEST(gfn_flags_v6_no_hint)        { GFB_BEGIN(GF_ALL); literal_flags("::1", 0, 0); GFB_END(); }
TEST(gfn_flags_v6_passive)        { GFB_BEGIN(GF_ALL); literal_flags("::1", AI_PASSIVE, 0); GFB_END(); }
TEST(gfn_flags_v6_numerichost)    { GFB_BEGIN(GF_ALL); literal_flags("::1", AI_NUMERICHOST, 0); GFB_END(); }
TEST(gfn_flags_v6_bracketed)      { GFB_BEGIN(GF_ALL); literal_flags("[::1]", 0, 0); GFB_END(); }
TEST(gfn_flags_v6_scoped)         { GFB_BEGIN(GF_ALL); literal_flags("fe80::1%2", 0, 0); GFB_END(); }
TEST(gfn_flags_v6_literal_name)   { GFB_BEGIN(GF_ALL); literal_flags("--1.ipv6-literal.net", AI_NUMERICHOST, 0); GFB_END(); }

/* AI_CANONNAME on a literal returns the normalised text of the address. */
static void canon_expect(const char *node, int flags, int family, const char *want)
{
    int api;
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, node, NULL, H(flags, family, 0, 0), &r);
        CHECKF(r.ret == 0 && GF_N1(r.n), "%s ret %d n %d", gf_api_name(api), r.ret, r.n);
        if (r.ret || !GF_N1(r.n)) continue;
        CHECKF(r.e[0].has_canon, "%s no canonical name", gf_api_name(api));
        if (r.e[0].has_canon) CHECKF(!strcmp(r.e[0].canon, want), "%s canon \"%s\" want \"%s\"", gf_api_name(api), r.e[0].canon, want);
    }
}
#define CANON_TEST(nm, node, fl, fam, want) TEST(nm) { GFB_BEGIN(GF_ALL); canon_expect(node, fl, fam, want); GFB_END(); }
CANON_TEST(gfn_canon_v4_plain,       "10.1.2.3",   AI_CANONNAME, 0, "10.1.2.3")
CANON_TEST(gfn_canon_v4_inet,        "10.1.2.3",   AI_CANONNAME, AF_INET, "10.1.2.3")
CANON_TEST(gfn_canon_v4_zero,        "0.0.0.0",    AI_CANONNAME, 0, "0.0.0.0")
CANON_TEST(gfn_canon_v4_normalised,  "127.1",      AI_CANONNAME | AI_NUMERICHOST, 0, "127.0.0.1")
CANON_TEST(gfn_canon_v4_hex_normalised, "0x7f000001", AI_CANONNAME | AI_NUMERICHOST, 0, "127.0.0.1")
CANON_TEST(gfn_canon_v4_single_number, "2130706433", AI_CANONNAME | AI_NUMERICHOST, 0, "127.0.0.1")
CANON_TEST(gfn_canon_v6_loopback,    "0:0:0:0:0:0:0:1", AI_CANONNAME, 0, "::1")
CANON_TEST(gfn_canon_v6_compressed,  "2001:0db8:0:0:0:0:0:5", AI_CANONNAME, 0, "2001:db8::5")
CANON_TEST(gfn_canon_v6_bracketed_in, "[::1]",     AI_CANONNAME, 0, "::1")
CANON_TEST(gfn_canon_v6_scope,       "fe80::1%3",  AI_CANONNAME, 0, "fe80::1%3")
CANON_TEST(gfn_canon_v6_inet6_hint,  "::1",        AI_CANONNAME, AF_INET6, "::1")
CANON_TEST(gfn_canon_v6_upper_in,    "2001:DB8::A", AI_CANONNAME, 0, "2001:db8::a")
CANON_TEST(gfn_canon_v6_v4_embedded, "::ffff:1.2.3.4", AI_CANONNAME, 0, "::ffff:1.2.3.4")
/* AI_FQDN on a literal returns the input text unchanged. */
CANON_TEST(gfn_fqdn_v4_plain,        "10.1.2.3",   AI_FQDN, 0, "10.1.2.3")
CANON_TEST(gfn_fqdn_v4_abbrev_kept,  "127.1",      AI_FQDN | AI_NUMERICHOST, 0, "127.1")
CANON_TEST(gfn_fqdn_v4_hex_kept,     "0x7f000001", AI_FQDN | AI_NUMERICHOST, 0, "0x7f000001")
CANON_TEST(gfn_fqdn_v6_bracket_kept, "[::1]",      AI_FQDN, 0, "[::1]")
CANON_TEST(gfn_fqdn_v6_upper_kept,   "FE80::A",    AI_FQDN, 0, "FE80::A")
CANON_TEST(gfn_fqdn_v6_scope_kept,   "fe80::1%3",  AI_FQDN, 0, "fe80::1%3")
CANON_TEST(gfn_fqdn_v6_name_kept,    "--1.ipv6-literal.net", AI_FQDN | AI_NUMERICHOST, 0, "--1.ipv6-literal.net")
/* No canonical-name flag: no canonical name. */
static void no_canon(const char *node, int flags)
{
    int api;
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, node, NULL, H(flags, 0, 0, 0), &r);
        CHECKF(r.ret == 0 && GF_N1(r.n), "%s ret %d n %d", gf_api_name(api), r.ret, r.n);
        if (r.ret || !GF_N1(r.n)) continue;
        CHECKF(!r.e[0].has_canon, "%s unexpected canonical name \"%s\"", gf_api_name(api), r.e[0].canon);
    }
}
TEST(gfn_no_canon_v4)       { GFB_BEGIN(GF_ALL); no_canon("10.1.2.3", 0); GFB_END(); }
TEST(gfn_no_canon_v6)       { GFB_BEGIN(GF_ALL); no_canon("::1", 0); GFB_END(); }
TEST(gfn_no_canon_v4_nh)    { GFB_BEGIN(GF_ALL); no_canon("10.1.2.3", AI_NUMERICHOST); GFB_END(); }
TEST(gfn_no_canon_v6_pass)  { GFB_BEGIN(GF_ALL); no_canon("::1", AI_PASSIVE); GFB_END(); }
TEST(gfn_no_canon_nonode)
{
    int api;
    GFB_BEGIN(GF_ALL);
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, NULL, "80", H(AI_PASSIVE, 0, 0, 0), &r);
        CHECKF(r.ret == 0 && r.n >= 1 && !r.canon_after_first && !r.e[0].has_canon, "%s ret %d", gf_api_name(api), r.ret);
    }
    GFB_END();
}

/* Extended calls: CANONNAME together with FQDN on a literal returns the version-2 structure. */
static void v2_check(int api, const char *node, const char *canon_want)
{
    struct gf_res r;
    gf_run(api, node, NULL, H(AI_CANONNAME | AI_FQDN | AI_NUMERICHOST, 0, 0, 0), &r);
    CHECKF(r.ret == 0 && GF_N1(r.n), "%s ret %d n %d", gf_api_name(api), r.ret, r.n);
    if (r.ret || !GF_N1(r.n)) return;
    CHECKF(r.e[0].flags == (int)(0x80000000u | AI_NUMERICHOST), "%s flags 0x%x", gf_api_name(api), r.e[0].flags);
    CHECKF(r.e[0].xver == 2, "%s version %d", gf_api_name(api), r.e[0].xver);
    CHECKF(r.e[0].x_fqdn, "%s no fqdn", gf_api_name(api));
    CHECKF(r.e[0].has_canon && !strcmp(r.e[0].canon, canon_want), "%s canon \"%s\"", gf_api_name(api), r.e[0].canon);
    if (api == GF_XW) CHECKF(!strcmp(r.e[0].x_fqdn_text, node), "%s fqdn \"%s\"", gf_api_name(api), r.e[0].x_fqdn_text);
}
TEST(gfn_x_v2_struct_v4_xw) { GFB_BEGIN(GF_XW); v2_check(GF_XW, "127.1", "127.0.0.1"); GFB_END(); }
TEST(gfn_x_v2_struct_v4_xa) { GFB_BEGIN(GF_XA); v2_check(GF_XA, "127.1", "127.0.0.1"); GFB_END(); }
TEST(gfn_x_v2_struct_v6_xw) { GFB_BEGIN(GF_XW); v2_check(GF_XW, "0:0:0:0:0:0:0:1", "::1"); GFB_END(); }
TEST(gfn_x_v2_struct_v6_xa) { GFB_BEGIN(GF_XA); v2_check(GF_XA, "0:0:0:0:0:0:0:1", "::1"); GFB_END(); }
/* With only one of the two flags the plain (version 1) structure comes back. */
static void v1_check(int api, int flags)
{
    struct gf_res r;
    gf_run(api, "10.1.2.3", NULL, H(flags, 0, 0, 0), &r);
    CHECKF(r.ret == 0 && GF_N1(r.n), "%s ret %d n %d", gf_api_name(api), r.ret, r.n);
    if (r.ret || !GF_N1(r.n)) return;
    CHECKF(r.e[0].flags == AI_NUMERICHOST, "%s flags 0x%x", gf_api_name(api), r.e[0].flags);
    CHECKF(r.e[0].xver == 0, "%s version %d", gf_api_name(api), r.e[0].xver);
}
TEST(gfn_x_v1_struct_canon_only_xw) { GFB_BEGIN(GF_XW); v1_check(GF_XW, AI_CANONNAME); GFB_END(); }
TEST(gfn_x_v1_struct_canon_only_xa) { GFB_BEGIN(GF_XA); v1_check(GF_XA, AI_CANONNAME); GFB_END(); }
TEST(gfn_x_v1_struct_fqdn_only_xw)  { GFB_BEGIN(GF_XW); v1_check(GF_XW, AI_FQDN); GFB_END(); }
TEST(gfn_x_v1_struct_fqdn_only_xa)  { GFB_BEGIN(GF_XA); v1_check(GF_XA, AI_FQDN); GFB_END(); }
TEST(gfn_x_v1_struct_plain_xw)      { GFB_BEGIN(GF_XW); v1_check(GF_XW, 0); GFB_END(); }

/* Literal answers have no blob and no provider. */
TEST(gfn_x_literal_no_blob_no_provider)
{
    int api;
    GFB_BEGIN(GF_XW);
    GF_EACH(api, GF_XW | GF_XA) {
        struct gf_res r;
        gf_run(api, "10.1.2.3", NULL, NULL, &r);
        CHECKF(r.ret == 0 && GF_N1(r.n), "%s ret %d", gf_api_name(api), r.ret);
        if (r.ret || !GF_N1(r.n)) continue;
        CHECK(!r.e[0].x_blob);
        EXPECT_EQ(r.e[0].x_bloblen, 0);
        CHECK(!r.e[0].x_provider);
    }
    GFB_END();
}

/* Socket type / protocol of a literal answer follow the hint. */
OK_ROW(gfn_lit_hint_stream_tcp, GF_ALL, "10.1.2.3", NULL, H(0, 0, SOCK_STREAM, IPPROTO_TCP), "10.1.2.3", 0, 1)
OK_ROW(gfn_lit_hint_dgram_udp,  GF_ALL, "10.1.2.3", NULL, H(0, 0, SOCK_DGRAM, IPPROTO_UDP),  "10.1.2.3", 0, 1)
TEST(gfn_lit_entry_fields_follow_hint)
{
    int api;
    GFB_BEGIN(GF_ALL);
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, "10.1.2.3", NULL, H(0, AF_INET, SOCK_DGRAM, IPPROTO_UDP), &r);
        CHECKF(r.ret == 0 && GF_N1(r.n), "%s ret %d", gf_api_name(api), r.ret);
        if (r.ret || !GF_N1(r.n)) continue;
        EXPECT_EQ(r.e[0].family, AF_INET);
        EXPECT_EQ(r.e[0].socktype, SOCK_DGRAM);
        EXPECT_EQ(r.e[0].protocol, IPPROTO_UDP);
        EXPECT_EQ(r.e[0].addrlen, sizeof(SOCKADDR_IN));
        EXPECT_EQ(r.e[0].addr[0] | r.e[0].addr[1] << 8, AF_INET);
    }
    GFB_END();
}
TEST(gfn_lit_v6_entry_fields)
{
    int api;
    GFB_BEGIN(GF_ALL);
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, "fe80::9%4", "53", H(0, AF_INET6, SOCK_STREAM, IPPROTO_TCP), &r);
        CHECKF(r.ret == 0 && GF_N1(r.n), "%s ret %d", gf_api_name(api), r.ret);
        if (r.ret || !GF_N1(r.n)) continue;
        EXPECT_EQ(r.e[0].family, AF_INET6);
        EXPECT_EQ(r.e[0].addrlen, sizeof(SOCKADDR_IN6));
        EXPECT_EQ(gf_port(&r.e[0]), 53);
        EXPECT_EQ(gf_v6_scope(&r.e[0]), 4);
        EXPECT_EQ(gf_v6_flow(&r.e[0]), 0);
    }
    GFB_END();
}
/* A literal is never multiplied into several entries (no per-socket-type expansion). */
TEST(gfn_lit_single_entry_without_socktype)
{
    int api;
    GFB_BEGIN(GF_ALL);
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, "10.1.2.3", "80", NULL, &r);
        CHECKF(r.ret == 0 && GF_N1(r.n), "%s ret %d n %d", gf_api_name(api), r.ret, r.n);
        if (r.ret || !GF_N1(r.n)) continue;
    }
    GFB_END();
}

/* ---- numeric services -------------------------------------------------------------------------- */
/* strtoul(base 10) then the low 16 bits become the port. */
#define SV(nm, text, port) OK_ROW(nm, GF_ALL, NULL, text, H(0, AF_INET, 0, 0), "127.0.0.1", port, 1)
SV(gfn_serv_80,        "80", 80)
SV(gfn_serv_0,         "0", 0)
SV(gfn_serv_1,         "1", 1)
SV(gfn_serv_255,       "255", 255)
SV(gfn_serv_256,       "256", 256)
SV(gfn_serv_443,       "443", 443)
SV(gfn_serv_8080,      "8080", 8080)
SV(gfn_serv_32768,     "32768", 32768)
SV(gfn_serv_65534,     "65534", 65534)
SV(gfn_serv_65535,     "65535", 65535)
SV(gfn_serv_65536,     "65536", 0)
SV(gfn_serv_65537,     "65537", 1)
SV(gfn_serv_70000,     "70000", 4464)
SV(gfn_serv_131072,    "131072", 0)
SV(gfn_serv_u32max,    "4294967295", 65535)
SV(gfn_serv_u32max_p1, "4294967296", 65535)
SV(gfn_serv_huge,      "99999999999999999999", 65535)
SV(gfn_serv_minus1,    "-1", 65535)
SV(gfn_serv_minus2,    "-2", 65534)
SV(gfn_serv_plus,      "+80", 80)
SV(gfn_serv_leading_space, " 80", 80)
SV(gfn_serv_leading_tab,   "\t80", 80)
SV(gfn_serv_zero_pad,  "0080", 80)
SV(gfn_serv_double_zero, "00", 0)
SV(gfn_serv_empty,     "", 0)
/* anything after the digits turns it into a service name, which is then not found */
#define SVBAD(nm, text) ERR_ROW(nm, GF_ALL, NULL, text, H(0, AF_INET, 0, 0), WSATYPE_NOT_FOUND)
SVBAD(gfn_servbad_trailing_letter, "80x")
SVBAD(gfn_servbad_hex,             "0x50")
SVBAD(gfn_servbad_trailing_space,  "80 ")
SVBAD(gfn_servbad_inner_space,     "8 0")
SVBAD(gfn_servbad_exponent,        "1e3")
SVBAD(gfn_servbad_decimal_point,   "80.0")
SVBAD(gfn_servbad_plain_name,      "nosuchservice")
SVBAD(gfn_servbad_underscore_name, "no_such_service_zz")
SVBAD(gfn_servbad_dash,            "80-90")
SVBAD(gfn_servbad_slash,           "80/tcp")
SVBAD(gfn_servbad_colon,           ":80")
SVBAD(gfn_servbad_only_plus,       "+")
SVBAD(gfn_servbad_only_space,      " ")
/* AI_NUMERICSERV: only digits are acceptable, a name is "host not found", not "type not found" */
#define SVNS(nm, text, err) ERR_ROW(nm, GF_ALL, NULL, text, H(AI_NUMERICSERV, AF_INET, 0, 0), err)
SVNS(gfn_numserv_name_http,    "http", WSAHOST_NOT_FOUND)
SVNS(gfn_numserv_trailing,     "80x", WSAHOST_NOT_FOUND)
SVNS(gfn_numserv_unknown_name, "nosuchservice", WSAHOST_NOT_FOUND)
SVNS(gfn_numserv_hex,          "0x50", WSAHOST_NOT_FOUND)
OK_ROW(gfn_numserv_digits_ok,  GF_ALL, NULL, "80", H(AI_NUMERICSERV, AF_INET, 0, 0), "127.0.0.1", 80, 1)
OK_ROW(gfn_numserv_empty_ok,   GF_ALL, NULL, "",   H(AI_NUMERICSERV, AF_INET, 0, 0), "127.0.0.1", 0, 1)
OK_ROW(gfn_numserv_wraps,      GF_ALL, NULL, "65537", H(AI_NUMERICSERV, AF_INET, 0, 0), "127.0.0.1", 1, 1)
/* the service is evaluated before the node: a bad service beats an unresolvable numeric host */
ERR_ROW(gfn_service_error_beats_bad_literal, GF_ALL, "not.a.number", "no_such_service_zz", H(AI_NUMERICHOST, 0, 0, 0), WSATYPE_NOT_FOUND)
ERR_ROW(gfn_service_error_beats_good_literal,GF_ALL, "10.1.2.3",     "no_such_service_zz", NULL, WSATYPE_NOT_FOUND)
ERR_ROW(gfn_numserv_error_beats_bad_literal, GF_ALL, "not.a.number", "http", H(AI_NUMERICHOST | AI_NUMERICSERV, 0, 0, 0), WSAHOST_NOT_FOUND)
ERR_ROW(gfn_service_error_with_v6_literal,   GF_ALL, "::1", "no_such_service_zz", NULL, WSATYPE_NOT_FOUND)
ERR_ROW(gfn_service_error_with_bracket,      GF_ALL, "[::1]", "no_such_service_zz", NULL, WSATYPE_NOT_FOUND)

/* The service text is limited by a 256-byte conversion buffer (255 characters plus NUL). */
static void long_service(size_t digits_total, int want_ok)
{
    char text[400];
    int api;
    size_t i;
    for (i = 0; i + 2 < digits_total; i++) text[i] = '0';
    text[digits_total - 2] = '8'; text[digits_total - 1] = '0'; text[digits_total] = 0;
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, NULL, text, H(0, AF_INET, 0, 0), &r);
        if (want_ok) {
            CHECKF(r.ret == 0 && GF_N1(r.n), "%s ret %d", gf_api_name(api), r.ret);
            if (!r.ret && GF_N1(r.n)) EXPECT_EQ(gf_port(&r.e[0]), 80);
        } else {
            CHECKF(r.ret == WSATYPE_NOT_FOUND, "%s ret %d want %d", gf_api_name(api), r.ret, WSATYPE_NOT_FOUND);
            CHECK(r.out_null);
        }
    }
}
TEST(gfn_serv_255_chars_ok)      { GFB_BEGIN(GF_ALL); long_service(255, 1); GFB_END(); }
TEST(gfn_serv_256_chars_too_long){ GFB_BEGIN(GF_ALL); long_service(256, 0); GFB_END(); }
TEST(gfn_serv_300_chars_too_long){ GFB_BEGIN(GF_ALL); long_service(300, 0); GFB_END(); }
TEST(gfn_serv_100_chars_ok)      { GFB_BEGIN(GF_ALL); long_service(100, 1); GFB_END(); }

/* ---- named services ------------------------------------------------------------------------------ */
/* For each name and requested socket type, the answer must match the rules applied to the services
 * database as the same library reports it through getservbyname (never a hard-coded port). */
static void service_model_check(const char *name)
{
    int st;
    for (st = 0; st <= 3; st++) {
        int api;
        struct gf_svc m = gf_model_service(name, st);
        GF_EACH(api, GF_ALL) {
            struct gf_res r;
            gf_run(api, NULL, name, H(0, AF_INET, st, 0), &r);
            if (m.err) {
                CHECKF(r.ret == m.err, "%s \"%s\" st=%d ret %d want %d", gf_api_name(api), name, st, r.ret, m.err);
                continue;
            }
            CHECKF(r.ret == 0 && GF_N1(r.n), "%s \"%s\" st=%d ret %d n %d", gf_api_name(api), name, st, r.ret, r.n);
            if (r.ret || !GF_N1(r.n)) continue;
            CHECKF(gf_port(&r.e[0]) == gf_ntohs16(m.port_be), "%s \"%s\" st=%d port %u want %u", gf_api_name(api), name, st, gf_port(&r.e[0]), gf_ntohs16(m.port_be));
            CHECKF(r.e[0].socktype == m.socktype, "%s \"%s\" st=%d socktype %d want %d", gf_api_name(api), name, st, r.e[0].socktype, m.socktype);
        }
    }
}
#define SVC_MODEL(nm, name) TEST(nm) { GFB_BEGIN(GF_ALL); if (!U(getservbyname)) { t_skip("no getservbyname"); GFB_END(); return; } service_model_check(name); GFB_END(); }
SVC_MODEL(gfn_svcmodel_http,      "http")
SVC_MODEL(gfn_svcmodel_https,     "https")
SVC_MODEL(gfn_svcmodel_ftp,       "ftp")
SVC_MODEL(gfn_svcmodel_ssh,       "ssh")
SVC_MODEL(gfn_svcmodel_telnet,    "telnet")
SVC_MODEL(gfn_svcmodel_smtp,      "smtp")
SVC_MODEL(gfn_svcmodel_domain,    "domain")
SVC_MODEL(gfn_svcmodel_ntp,       "ntp")
SVC_MODEL(gfn_svcmodel_echo,      "echo")
SVC_MODEL(gfn_svcmodel_daytime,   "daytime")
SVC_MODEL(gfn_svcmodel_bootps,    "bootps")
SVC_MODEL(gfn_svcmodel_snmp,      "snmp")
SVC_MODEL(gfn_svcmodel_pop3,      "pop3")
SVC_MODEL(gfn_svcmodel_imap,      "imap")
SVC_MODEL(gfn_svcmodel_ldap,      "ldap")
SVC_MODEL(gfn_svcmodel_unknown,   "no_such_service_zz")
SVC_MODEL(gfn_svcmodel_case_upper,"HTTP")
SVC_MODEL(gfn_svcmodel_case_mixed,"Domain")

/* A named service gives the same answer with a literal node and with no node. */
TEST(gfn_svc_name_same_with_literal_node)
{
    int api;
    GFB_BEGIN(GF_ALL);
    if (!U(getservbyname)) { t_skip("no getservbyname"); GFB_END(); return; }
    GF_EACH(api, GF_ALL) {
        struct gf_res a, b;
        gf_run(api, NULL, "domain", H(0, AF_INET, 0, 0), &a);
        gf_run(api, "10.1.2.3", "domain", H(0, AF_INET, 0, 0), &b);
        CHECKF(a.ret == b.ret, "%s ret %d vs %d", gf_api_name(api), a.ret, b.ret);
        if (!a.ret && !b.ret && GF_N1(a.n) && GF_N1(b.n)) {
            EXPECT_EQ(gf_port(&a.e[0]), gf_port(&b.e[0]));
            EXPECT_EQ(a.e[0].socktype, b.e[0].socktype);
        }
    }
    GFB_END();
}
/* "domain" is registered for both tcp and udp with the same port: an unconstrained query keeps socktype 0. */
TEST(gfn_svc_domain_both_protocols_keeps_zero_socktype)
{
    const struct servent *t, *u;
    struct gf_res r;
    GFB_BEGIN(GF_A);
    if (!U(getservbyname)) { t_skip("no getservbyname"); GFB_END(); return; }
    t = U(getservbyname)("domain", "tcp");
    u = U(getservbyname)("domain", "udp");
    if (!t || !u || t->s_port != u->s_port) { t_skip("services database lacks a shared domain entry"); GFB_END(); return; }
    gf_run(GF_A, NULL, "domain", H(0, AF_INET, 0, 0), &r);
    EXPECT_EQ(r.ret, 0);
    if (!r.ret && GF_N1(r.n)) { EXPECT_EQ(r.e[0].socktype, 0); EXPECT_EQ(gf_port(&r.e[0]), gf_ntohs16((unsigned short)t->s_port)); }
    GFB_END();
}
