/* getaddrinfo / GetAddrInfoW / GetAddrInfoExW / GetAddrInfoExA: validation of the hints structure and the
 * node == NULL results.
 *
 * Measures: the order in which arguments are rejected (both names NULL first, then the four hint fields that
 * must be zero, then flag combinations, then family, then socket type), the exact error code for each, the
 * result pointer being cleared on failure, the difference between the ANSI/wide pair (which validate the socket
 * type and the CANONNAME+FQDN pair) and the extended pair (which do not), and the shape of the synthetic
 * answer produced for a NULL node (loopback or wildcard, per family, entry layout, flags). */
#include "gf.h"

/* ---- argument order ----------------------------------------------------------------------- */
/* Both names NULL is rejected before anything else, hints included. */
ERR_ROW(gfh_both_null_nohint,        GF_ALL, NULL, NULL, NULL, WSAHOST_NOT_FOUND)
ERR_ROW(gfh_both_null_dirty_addrlen, GF_ALL, NULL, NULL, HD(0, 0, 0, 0, 1), WSAHOST_NOT_FOUND)
ERR_ROW(gfh_both_null_dirty_next,    GF_ALL, NULL, NULL, HD(0, 0, 0, 0, 4), WSAHOST_NOT_FOUND)
ERR_ROW(gfh_both_null_bad_family,    GF_ALL, NULL, NULL, H(0, 1, 0, 0), WSAHOST_NOT_FOUND)
ERR_ROW(gfh_both_null_canonname,     GF_ALL, NULL, NULL, H(AI_CANONNAME, 0, 0, 0), WSAHOST_NOT_FOUND)
ERR_ROW(gfh_both_null_passive,       GF_ALL, NULL, NULL, H(AI_PASSIVE, 0, 0, 0), WSAHOST_NOT_FOUND)
ERR_ROW(gfh_both_null_numerichost,   GF_ALL, NULL, NULL, H(AI_NUMERICHOST, 0, 0, 0), WSAHOST_NOT_FOUND)

/* ---- the four hint fields that must be zero ------------------------------------------------- */
/* Any of ai_addrlen / ai_canonname / ai_addr / ai_next set in the hint is WSANO_RECOVERY (EAI_FAIL). */
ERR_ROW(gfh_dirty_addrlen,   GF_ALL, "127.0.0.1", NULL, HD(0, 0, 0, 0, 1), WSANO_RECOVERY)
ERR_ROW(gfh_dirty_canonname, GF_ALL, "127.0.0.1", NULL, HD(0, 0, 0, 0, 2), WSANO_RECOVERY)
ERR_ROW(gfh_dirty_addr,      GF_ALL, "127.0.0.1", NULL, HD(0, 0, 0, 0, 3), WSANO_RECOVERY)
ERR_ROW(gfh_dirty_next,      GF_ALL, "127.0.0.1", NULL, HD(0, 0, 0, 0, 4), WSANO_RECOVERY)
/* They are checked before the flags, family and socket type, so a second defect does not change the code. */
ERR_ROW(gfh_dirty_beats_family,   GF_ALL, "127.0.0.1", NULL, HD(0, 1, 0, 0, 1), WSANO_RECOVERY)
ERR_ROW(gfh_dirty_beats_socktype, GF_AW,  "127.0.0.1", NULL, HD(0, 0, 99, 0, 2), WSANO_RECOVERY)
ERR_ROW(gfh_dirty_beats_canonname_nonode, GF_ALL, NULL, "80", HD(AI_CANONNAME, 0, 0, 0, 3), WSANO_RECOVERY)
/* Same with a service only and a NULL node. */
ERR_ROW(gfh_dirty_addrlen_nonode, GF_ALL, NULL, "80", HD(0, AF_INET, 0, 0, 1), WSANO_RECOVERY)
ERR_ROW(gfh_dirty_next_nonode,    GF_ALL, NULL, "80", HD(0, AF_INET, 0, 0, 4), WSANO_RECOVERY)

/* ---- flag combinations ----------------------------------------------------------------------- */
/* AI_CANONNAME / AI_FQDN require a node name. */
ERR_ROW(gfh_canonname_nonode,        GF_ALL, NULL, "80", H(AI_CANONNAME, 0, 0, 0), WSAEINVAL)
ERR_ROW(gfh_canonname_nonode_inet,   GF_ALL, NULL, "80", H(AI_CANONNAME, AF_INET, 0, 0), WSAEINVAL)
ERR_ROW(gfh_canonname_nonode_inet6,  GF_ALL, NULL, "80", H(AI_CANONNAME, AF_INET6, 0, 0), WSAEINVAL)
ERR_ROW(gfh_canonname_nonode_passive,GF_ALL, NULL, "80", H(AI_CANONNAME | AI_PASSIVE, 0, 0, 0), WSAEINVAL)
ERR_ROW(gfh_canonname_nonode_noserv, GF_ALL, NULL, "",   H(AI_CANONNAME, 0, 0, 0), WSAEINVAL)
ERR_ROW(gfh_fqdn_nonode,             GF_ALL, NULL, "80", H(AI_FQDN, 0, 0, 0), WSAEINVAL)
ERR_ROW(gfh_fqdn_nonode_inet,        GF_ALL, NULL, "80", H(AI_FQDN, AF_INET, 0, 0), WSAEINVAL)
ERR_ROW(gfh_fqdn_nonode_passive,     GF_ALL, NULL, "80", H(AI_FQDN | AI_PASSIVE, 0, 0, 0), WSAEINVAL)
ERR_ROW(gfh_canon_fqdn_nonode,       GF_ALL, NULL, "80", H(AI_CANONNAME | AI_FQDN, 0, 0, 0), WSAEINVAL)
/* The flag check precedes the family check and the socket-type check. */
ERR_ROW(gfh_canonname_nonode_beats_family,   GF_ALL, NULL, "80", H(AI_CANONNAME, 1, 0, 0), WSAEINVAL)
ERR_ROW(gfh_canonname_nonode_beats_socktype, GF_AW,  NULL, "80", H(AI_CANONNAME, 0, 99, 0), WSAEINVAL)
ERR_ROW(gfh_fqdn_nonode_beats_family,        GF_ALL, NULL, "80", H(AI_FQDN, 1, 0, 0), WSAEINVAL)
/* The ANSI/wide pair refuses CANONNAME together with FQDN even when a node is given. */
ERR_ROW(gfh_canon_fqdn_together_literal4, GF_AW, "127.0.0.1", NULL, H(AI_CANONNAME | AI_FQDN, 0, 0, 0), WSAEINVAL)
ERR_ROW(gfh_canon_fqdn_together_literal6, GF_AW, "::1",       NULL, H(AI_CANONNAME | AI_FQDN, 0, 0, 0), WSAEINVAL)
ERR_ROW(gfh_canon_fqdn_together_numeric,  GF_AW, "127.0.0.1", NULL, H(AI_CANONNAME | AI_FQDN | AI_NUMERICHOST, 0, 0, 0), WSAEINVAL)
ERR_ROW(gfh_canon_fqdn_together_localhost,GF_AW, "localhost", NULL, H(AI_CANONNAME | AI_FQDN, 0, 0, 0), WSAEINVAL)
ERR_ROW(gfh_canon_fqdn_together_inet,     GF_AW, "127.0.0.1", NULL, H(AI_CANONNAME | AI_FQDN, AF_INET, 0, 0), WSAEINVAL)
/* ... while the extended pair accepts it and hands back the extended structure. */
OK_ROW(gfh_x_canon_fqdn_together_literal4, GF_XW | GF_XA, "127.0.0.1", NULL, H(AI_CANONNAME | AI_FQDN, 0, 0, 0), "127.0.0.1", 0, 1)
OK_ROW(gfh_x_canon_fqdn_together_literal6, GF_XW | GF_XA, "::1", NULL, H(AI_CANONNAME | AI_FQDN, 0, 0, 0), "0:0:0:0:0:0:0:1", 0, 1)

/* ---- family ---------------------------------------------------------------------------------- */
/* Only AF_UNSPEC, AF_INET and AF_INET6 are accepted. */
#define FAM_ROW(nm, fam) ERR_ROW(nm, GF_ALL, "127.0.0.1", NULL, H(0, fam, 0, 0), WSAEAFNOSUPPORT)
FAM_ROW(gfh_family_unix,      AF_UNIX)
FAM_ROW(gfh_family_implink,   AF_IMPLINK)
FAM_ROW(gfh_family_pup,       AF_PUP)
FAM_ROW(gfh_family_chaos,     AF_CHAOS)
FAM_ROW(gfh_family_ipx,       AF_IPX)
FAM_ROW(gfh_family_ns,        AF_NS)
FAM_ROW(gfh_family_iso,       AF_ISO)
FAM_ROW(gfh_family_ecma,      AF_ECMA)
FAM_ROW(gfh_family_datakit,   AF_DATAKIT)
FAM_ROW(gfh_family_ccitt,     AF_CCITT)
FAM_ROW(gfh_family_sna,       AF_SNA)
FAM_ROW(gfh_family_decnet,    AF_DECnet)
FAM_ROW(gfh_family_dli,       AF_DLI)
FAM_ROW(gfh_family_lat,       AF_LAT)
FAM_ROW(gfh_family_hylink,    AF_HYLINK)
FAM_ROW(gfh_family_appletalk, AF_APPLETALK)
FAM_ROW(gfh_family_netbios,   AF_NETBIOS)
FAM_ROW(gfh_family_irda,      26)
FAM_ROW(gfh_family_bth,       32)
FAM_ROW(gfh_family_24,        24)
FAM_ROW(gfh_family_max,       AF_MAX)
FAM_ROW(gfh_family_255,       255)
FAM_ROW(gfh_family_999,       999)
FAM_ROW(gfh_family_0x7fff,    0x7fff)
FAM_ROW(gfh_family_0x8000,    0x8000)
FAM_ROW(gfh_family_minus1,    -1)
FAM_ROW(gfh_family_3,         3)
FAM_ROW(gfh_family_22,        22)
FAM_ROW(gfh_family_21,        21)
/* The rejection does not depend on the node being a literal. */
ERR_ROW(gfh_family_unix_nonode,     GF_ALL, NULL, "80", H(0, AF_UNIX, 0, 0), WSAEAFNOSUPPORT)
ERR_ROW(gfh_family_unix_localhost,  GF_ALL, "localhost", NULL, H(0, AF_UNIX, 0, 0), WSAEAFNOSUPPORT)
ERR_ROW(gfh_family_unix_numeric,    GF_ALL, "127.0.0.1", NULL, H(AI_NUMERICHOST, AF_UNIX, 0, 0), WSAEAFNOSUPPORT)
ERR_ROW(gfh_family_netbios_passive, GF_ALL, NULL, "80", H(AI_PASSIVE, AF_NETBIOS, SOCK_STREAM, 0), WSAEAFNOSUPPORT)
/* Family is checked before socket type. */
ERR_ROW(gfh_family_beats_socktype,  GF_AW, "127.0.0.1", NULL, H(0, AF_UNIX, 99, 0), WSAEAFNOSUPPORT)

/* ---- socket type ------------------------------------------------------------------------------ */
/* ANSI/wide: ai_socktype above 3 is WSAESOCKTNOSUPPORT, even for a literal. */
#define ST_ROW(nm, st) ERR_ROW(nm, GF_AW, "127.0.0.1", NULL, H(0, 0, st, 0), WSAESOCKTNOSUPPORT)
ST_ROW(gfh_socktype_rdm,      SOCK_RDM)
ST_ROW(gfh_socktype_seqpacket,SOCK_SEQPACKET)
ST_ROW(gfh_socktype_6,        6)
ST_ROW(gfh_socktype_7,        7)
ST_ROW(gfh_socktype_8,        8)
ST_ROW(gfh_socktype_16,       16)
ST_ROW(gfh_socktype_255,      255)
ST_ROW(gfh_socktype_256,      256)
ST_ROW(gfh_socktype_999,      999)
ST_ROW(gfh_socktype_0x10000,  0x10000)
ST_ROW(gfh_socktype_minus1,   -1)
ST_ROW(gfh_socktype_intmax,   0x7fffffff)
ERR_ROW(gfh_socktype_rdm_nonode,   GF_AW, NULL, "80", H(0, 0, SOCK_RDM, 0), WSAESOCKTNOSUPPORT)
ERR_ROW(gfh_socktype_rdm_localhost,GF_AW, "localhost", NULL, H(0, 0, SOCK_RDM, 0), WSAESOCKTNOSUPPORT)
ERR_ROW(gfh_socktype_rdm_inet,     GF_AW, NULL, "80", H(0, AF_INET, SOCK_RDM, 0), WSAESOCKTNOSUPPORT)
ERR_ROW(gfh_socktype_rdm_inet6,    GF_AW, NULL, "80", H(AI_PASSIVE, AF_INET6, SOCK_RDM, 0), WSAESOCKTNOSUPPORT)
/* Socket types 0..3 are accepted and echoed in the entry. */
OK_ROW(gfh_socktype_0_accepted, GF_AW, "127.0.0.1", NULL, H(0, 0, 0, 0),           "127.0.0.1", 0, 1)
OK_ROW(gfh_socktype_1_accepted, GF_AW, "127.0.0.1", NULL, H(0, 0, SOCK_STREAM, 0), "127.0.0.1", 0, 1)
OK_ROW(gfh_socktype_2_accepted, GF_AW, "127.0.0.1", NULL, H(0, 0, SOCK_DGRAM, 0),  "127.0.0.1", 0, 1)
OK_ROW(gfh_socktype_3_accepted, GF_AW, "127.0.0.1", NULL, H(0, 0, SOCK_RAW, 0),    "127.0.0.1", 0, 1)

static void socktype_echo(int api, int st)
{
    struct gf_res r;
    gf_run(api, "127.0.0.1", NULL, H(0, 0, st, 0), &r);
    EXPECT_EQ(r.ret, 0);
    if (r.ret || r.n < 1) return;
    CHECKF(r.e[0].socktype == st, "%s socktype %d want %d", gf_api_name(api), r.e[0].socktype, st);
}
TEST(gfh_socktype_echo_all)
{
    int st;
    GFB_BEGIN(GF_AW);
    for (st = 0; st <= 3; st++) { socktype_echo(GF_A, st); socktype_echo(GF_W, st); }
    GFB_END();
}
/* The extended calls do not validate the socket type: it is copied to the entry as given. */
static void x_socktype(int st)
{
    int api;
    GF_EACH(api, GF_XW | GF_XA) {
        struct gf_res r;
        gf_run(api, "127.0.0.1", NULL, H(0, 0, st, 0), &r);
        CHECKF(r.ret == 0, "%s socktype %d ret %d", gf_api_name(api), st, r.ret);
        if (r.ret || r.n < 1) continue;
        CHECKF(r.e[0].socktype == st, "%s socktype %d echoed as %d", gf_api_name(api), st, r.e[0].socktype);
    }
}
TEST(gfh_x_socktype_4)   { GFB_BEGIN(GF_XW | GF_XA); x_socktype(4);   GFB_END(); }
TEST(gfh_x_socktype_5)   { GFB_BEGIN(GF_XW | GF_XA); x_socktype(5);   GFB_END(); }
TEST(gfh_x_socktype_999) { GFB_BEGIN(GF_XW | GF_XA); x_socktype(999); GFB_END(); }
TEST(gfh_x_socktype_neg) { GFB_BEGIN(GF_XW | GF_XA); x_socktype(-1);  GFB_END(); }

/* ---- protocol ---------------------------------------------------------------------------------- */
/* ai_protocol is never validated and is copied into every entry. */
static void protocol_echo(int pr)
{
    int api;
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, "127.0.0.1", NULL, H(0, 0, 0, pr), &r);
        CHECKF(r.ret == 0, "%s protocol %d ret %d", gf_api_name(api), pr, r.ret);
        if (r.ret || r.n < 1) continue;
        CHECKF(r.e[0].protocol == pr, "%s protocol %d echoed as %d", gf_api_name(api), pr, r.e[0].protocol);
    }
}
#define PR_TEST(nm, pr) TEST(nm) { GFB_BEGIN(GF_ALL); protocol_echo(pr); GFB_END(); }
PR_TEST(gfh_protocol_0,      0)
PR_TEST(gfh_protocol_icmp,   IPPROTO_ICMP)
PR_TEST(gfh_protocol_tcp,    IPPROTO_TCP)
PR_TEST(gfh_protocol_udp,    IPPROTO_UDP)
PR_TEST(gfh_protocol_ipv6,   IPPROTO_IPV6)
PR_TEST(gfh_protocol_raw,    IPPROTO_RAW)
PR_TEST(gfh_protocol_255,    255)
PR_TEST(gfh_protocol_999,    999)
PR_TEST(gfh_protocol_neg,    -1)
PR_TEST(gfh_protocol_intmax, 0x7fffffff)
PR_TEST(gfh_protocol_intmin, (int)0x80000000)

/* ---- family truncation quirk --------------------------------------------------------------------- */
/* The ANSI/wide pair look at the low 16 bits of ai_family only. */
TEST(gfh_aw_family_high_bits_ignored_inet)
{
    int api;
    GFB_BEGIN(GF_AW);
    GF_EACH(api, GF_AW) {
        struct gf_res r;
        gf_run(api, NULL, "80", H(0, 0x10000 | AF_INET, 0, 0), &r);
        CHECKF(r.ret == 0, "%s ret %d", gf_api_name(api), r.ret);
        if (r.ret || r.n < 1) continue;
        CHECKF(GF_N1(r.n) && r.e[0].family == AF_INET, "%s n=%d family=%d", gf_api_name(api), r.n, r.e[0].family);
    }
    GFB_END();
}
TEST(gfh_aw_family_high_bits_ignored_unspec)
{
    int api;
    GFB_BEGIN(GF_AW);
    GF_EACH(api, GF_AW) {
        struct gf_res r;
        gf_run(api, "127.0.0.1", NULL, H(0, 0x10000, 0, 0), &r);
        CHECKF(r.ret == 0, "%s ret %d", gf_api_name(api), r.ret);
    }
    GFB_END();
}
/* The extended pair compares the whole 32 bits. */
TEST(gfh_x_family_high_bits_not_ignored)
{
    GFB_BEGIN(GF_XW | GF_XA);
    gf_check_err(GF_XW | GF_XA, "127.0.0.1", NULL, H(0, 0x10000 | AF_INET, 0, 0), WSAEAFNOSUPPORT);
    GFB_END();
}

/* ---- flags that do not change a literal answer -------------------------------------------------- */
/* Flags with no effect on a numeric address string: the answer is the literal. */
#define FLAG_LIT(nm, fl) \
    OK_ROW(nm##_lit4, GF_ALL, "10.1.2.3", NULL, H(fl, 0, 0, 0), "10.1.2.3", 0, 1) \
    OK_ROW(nm##_lit6, GF_ALL, "2001:db8:0:0:0:0:0:5", NULL, H(fl, 0, 0, 0), "2001:db8:0:0:0:0:0:5", 0, 1)
FLAG_LIT(gfh_flag_passive,       AI_PASSIVE)
FLAG_LIT(gfh_flag_numerichost,   AI_NUMERICHOST)
FLAG_LIT(gfh_flag_numericserv,   AI_NUMERICSERV)
FLAG_LIT(gfh_flag_all,           AI_ALL)
FLAG_LIT(gfh_flag_addrconfig,    AI_ADDRCONFIG)
FLAG_LIT(gfh_flag_nonauth,       AI_NON_AUTHORITATIVE)
FLAG_LIT(gfh_flag_secure,        AI_SECURE)
FLAG_LIT(gfh_flag_prefnames,     AI_RETURN_PREFERRED_NAMES)
FLAG_LIT(gfh_flag_fileserver,    AI_FILESERVER)
FLAG_LIT(gfh_flag_noidn,         AI_DISABLE_IDN_ENCODING)
FLAG_LIT(gfh_flag_many,          (AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV | AI_ALL | AI_NON_AUTHORITATIVE | AI_FILESERVER))
/* AI_V4MAPPED does not alter a plain IPv4 literal in the ANSI/wide pair. */
OK_ROW(gfh_flag_v4mapped_lit4_aw, GF_AW, "10.1.2.3", NULL, H(AI_V4MAPPED, 0, 0, 0), "10.1.2.3", 0, 1)
OK_ROW(gfh_flag_v4mapped_lit6_aw, GF_AW, "2001:db8:0:0:0:0:0:5", NULL, H(AI_V4MAPPED, 0, 0, 0), "2001:db8:0:0:0:0:0:5", 0, 1)

/* ---- NULL node: synthetic loopback / wildcard answer --------------------------------------------- */
OK_ROW(gfh_nonode_inet_loopback,   GF_ALL, NULL, "80", H(0, AF_INET, 0, 0),             "127.0.0.1", 80, 1)
OK_ROW(gfh_nonode_inet_passive,    GF_ALL, NULL, "80", H(AI_PASSIVE, AF_INET, 0, 0),    "0.0.0.0", 80, 1)
OK_ROW(gfh_nonode_inet6_loopback,  GF_ALL, NULL, "80", H(0, AF_INET6, 0, 0),            "0:0:0:0:0:0:0:1", 80, 1)
OK_ROW(gfh_nonode_inet6_passive,   GF_ALL, NULL, "80", H(AI_PASSIVE, AF_INET6, 0, 0),   "0:0:0:0:0:0:0:0", 80, 1)
OK_ROW(gfh_nonode_inet_port0,      GF_ALL, NULL, "0",  H(0, AF_INET, 0, 0),             "127.0.0.1", 0, 1)
OK_ROW(gfh_nonode_inet_noserv_empty, GF_ALL, NULL, "", H(0, AF_INET, 0, 0),             "127.0.0.1", 0, 1)
OK_ROW(gfh_nonode_inet6_noserv_empty,GF_ALL, NULL, "", H(0, AF_INET6, 0, 0),            "0:0:0:0:0:0:0:1", 0, 1)
OK_ROW(gfh_nonode_inet_stream,     GF_ALL, NULL, "8080", H(0, AF_INET, SOCK_STREAM, IPPROTO_TCP), "127.0.0.1", 8080, 1)
OK_ROW(gfh_nonode_inet_dgram,      GF_ALL, NULL, "8080", H(0, AF_INET, SOCK_DGRAM, IPPROTO_UDP),  "127.0.0.1", 8080, 1)
OK_ROW(gfh_nonode_inet_numserv_flag, GF_ALL, NULL, "8080", H(AI_NUMERICSERV, AF_INET, 0, 0), "127.0.0.1", 8080, 1)
OK_ROW(gfh_nonode_inet_passive_numserv, GF_ALL, NULL, "8080", H(AI_PASSIVE | AI_NUMERICSERV, AF_INET, 0, 0), "0.0.0.0", 8080, 1)
/* An explicitly requested family succeeds whether or not the host reports that protocol as configured. */
OK_ROW(gfh_nonode_inet_addrconfig_ignored_flag, GF_ALL, NULL, "80", H(AI_ADDRCONFIG | AI_PASSIVE, AF_INET, 0, 0), "0.0.0.0", 80, 1)

static void nonode_pair(int api, int flags, int fam, const char *serv, int st, int pr, int *n6, int *n4, int *first_family)
{
    struct gf_res r;
    int i;
    *n6 = *n4 = 0; *first_family = 0;
    gf_run(api, NULL, serv, H(flags, fam, st, pr), &r);
    CHECKF(r.ret == 0, "%s ret %d", gf_api_name(api), r.ret);
    if (r.ret) return;
    for (i = 0; i < r.n; i++) {
        char txt[100];
        gf_fmt(&r.e[i], txt, sizeof txt);
        CHECKF(r.e[i].family == AF_INET || r.e[i].family == AF_INET6, "%s family %d", gf_api_name(api), r.e[i].family);
        if (r.e[i].family == AF_INET6) {
            (*n6)++;
            CHECKF(!strcmp(txt, flags & AI_PASSIVE ? "0:0:0:0:0:0:0:0" : "0:0:0:0:0:0:0:1"), "%s v6 \"%s\"", gf_api_name(api), txt);
            CHECKF((int)gf_port(&r.e[i]) == (serv && *serv ? atoi(serv) : 0), "%s v6 port %u", gf_api_name(api), gf_port(&r.e[i]));
        } else if (r.e[i].family == AF_INET) {
            (*n4)++;
            CHECKF(!strcmp(txt, flags & AI_PASSIVE ? "0.0.0.0" : "127.0.0.1"), "%s v4 \"%s\"", gf_api_name(api), txt);
        }
        CHECKF(r.e[i].socktype == st && r.e[i].protocol == pr, "%s type/proto %d/%d", gf_api_name(api), r.e[i].socktype, r.e[i].protocol);
    }
    if (r.n) *first_family = r.e[0].family;
    CHECKF(*n6 <= 1 && *n4 <= 1, "%s duplicate families %d/%d", gf_api_name(api), *n6, *n4);
}
/* AF_UNSPEC with no node yields at most one IPv6 and one IPv4 entry; when both exist IPv6 comes first. */
static void unspec_matrix(int flags)
{
    int api;
    GF_EACH(api, GF_ALL) {
        int n6, n4, ff;
        nonode_pair(api, flags, AF_UNSPEC, "80", 0, 0, &n6, &n4, &ff);
        CHECKF(n6 + n4 >= 1, "%s empty", gf_api_name(api));
        if (n6 && n4) CHECKF(ff == AF_INET6, "%s first family %d", gf_api_name(api), ff);
        else if (n6 + n4 == 1) t_note("%s: only one family configured with no node", gf_api_name(api));
    }
}
TEST(gfh_nonode_unspec_loopback_shape) { GFB_BEGIN(GF_ALL); unspec_matrix(0); GFB_END(); }
TEST(gfh_nonode_unspec_passive_shape)  { GFB_BEGIN(GF_ALL); unspec_matrix(AI_PASSIVE); GFB_END(); }
TEST(gfh_nonode_unspec_v6_before_v4_when_both)
{
    int api;
    GFB_BEGIN(GF_ALL);
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, NULL, "80", NULL, &r);
        CHECKF(r.ret == 0, "%s ret %d", gf_api_name(api), r.ret);
        if (r.ret) continue;
        if (r.n == 2) {
            CHECKF(r.e[0].family == AF_INET6 && r.e[1].family == AF_INET, "%s order %d,%d", gf_api_name(api), r.e[0].family, r.e[1].family);
        } else t_note("%s: %d entries", gf_api_name(api), r.n);
    }
    GFB_END();
}
/* The synthetic entries carry the requested socket type and protocol, family-independent. */
#define NN_ROW(nm, st, pr) \
    TEST(nm) { int api, n6, n4, ff; GFB_BEGIN(GF_ALL); \
        GF_EACH(api, GF_ALL) nonode_pair(api, 0, AF_UNSPEC, "80", st, pr, &n6, &n4, &ff); GFB_END(); }
NN_ROW(gfh_nonode_pair_stream_tcp,  SOCK_STREAM, IPPROTO_TCP)
NN_ROW(gfh_nonode_pair_dgram_udp,   SOCK_DGRAM,  IPPROTO_UDP)
NN_ROW(gfh_nonode_pair_raw_icmp,    SOCK_RAW,    IPPROTO_ICMP)
NN_ROW(gfh_nonode_pair_none_41,     0,           IPPROTO_IPV6)
NN_ROW(gfh_nonode_pair_stream_none, SOCK_STREAM, 0)
NN_ROW(gfh_nonode_pair_raw_255,     SOCK_RAW,    255)

/* Entry layout of the synthetic answers. */
static void layout_v4(int api, int flags)
{
    struct gf_res r;
    const struct gf_ent *e;
    int i;
    gf_run(api, NULL, "4660", H(flags, AF_INET, 0, 0), &r);
    CHECKF(r.ret == 0 && GF_N1(r.n), "%s ret %d n %d", gf_api_name(api), r.ret, r.n);
    if (r.ret || r.n < 1) return;
    e = &r.e[0];
    CHECKF(e->flags == 0, "%s flags 0x%x", gf_api_name(api), e->flags);
    EXPECT_EQ(e->family, AF_INET);
    EXPECT_EQ(e->addrlen, sizeof(SOCKADDR_IN));
    CHECK(e->has_addr);
    EXPECT_EQ(e->addr[0] | e->addr[1] << 8, AF_INET);
    EXPECT_EQ(gf_port(e), 4660);
    for (i = 8; i < 16; i++) EXPECT_EQ(e->addr[i], 0);           /* sin_zero */
    CHECK(!e->has_canon);
}
static void layout_v6(int api, int flags)
{
    struct gf_res r;
    const struct gf_ent *e;
    gf_run(api, NULL, "4660", H(flags, AF_INET6, 0, 0), &r);
    CHECKF(r.ret == 0 && GF_N1(r.n), "%s ret %d n %d", gf_api_name(api), r.ret, r.n);
    if (r.ret || r.n < 1) return;
    e = &r.e[0];
    CHECKF(e->flags == 0, "%s flags 0x%x", gf_api_name(api), e->flags);
    EXPECT_EQ(e->family, AF_INET6);
    EXPECT_EQ(e->addrlen, sizeof(SOCKADDR_IN6));
    CHECK(e->has_addr);
    EXPECT_EQ(e->addr[0] | e->addr[1] << 8, AF_INET6);
    EXPECT_EQ(gf_port(e), 4660);
    EXPECT_EQ(gf_v6_flow(e), 0);
    EXPECT_EQ(gf_v6_scope(e), 0);
    CHECK(!e->has_canon);
}
#define LAYOUT_TEST(nm, fn, api, fl) TEST(nm) { GFB_BEGIN(api); fn(api, fl); GFB_END(); }
LAYOUT_TEST(gfh_layout_v4_loopback_a,   layout_v4, GF_A,  0)
LAYOUT_TEST(gfh_layout_v4_loopback_w,   layout_v4, GF_W,  0)
LAYOUT_TEST(gfh_layout_v4_loopback_xw,  layout_v4, GF_XW, 0)
LAYOUT_TEST(gfh_layout_v4_loopback_xa,  layout_v4, GF_XA, 0)
LAYOUT_TEST(gfh_layout_v4_any_a,        layout_v4, GF_A,  AI_PASSIVE)
LAYOUT_TEST(gfh_layout_v4_any_w,        layout_v4, GF_W,  AI_PASSIVE)
LAYOUT_TEST(gfh_layout_v4_any_xw,       layout_v4, GF_XW, AI_PASSIVE)
LAYOUT_TEST(gfh_layout_v4_any_xa,       layout_v4, GF_XA, AI_PASSIVE)
LAYOUT_TEST(gfh_layout_v6_loopback_a,   layout_v6, GF_A,  0)
LAYOUT_TEST(gfh_layout_v6_loopback_w,   layout_v6, GF_W,  0)
LAYOUT_TEST(gfh_layout_v6_loopback_xw,  layout_v6, GF_XW, 0)
LAYOUT_TEST(gfh_layout_v6_loopback_xa,  layout_v6, GF_XA, 0)
LAYOUT_TEST(gfh_layout_v6_any_a,        layout_v6, GF_A,  AI_PASSIVE)
LAYOUT_TEST(gfh_layout_v6_any_w,        layout_v6, GF_W,  AI_PASSIVE)
LAYOUT_TEST(gfh_layout_v6_any_xw,       layout_v6, GF_XW, AI_PASSIVE)
LAYOUT_TEST(gfh_layout_v6_any_xa,       layout_v6, GF_XA, AI_PASSIVE)

/* Parity: the four front ends produce the same synthetic entries for the same query. */
TEST(gfh_nonode_parity_across_front_ends)
{
    struct gf_res a, w, xw, xa;
    GFB_BEGIN(GF_ALL);
    gf_run(GF_A, NULL, "9", H(AI_PASSIVE, 0, SOCK_STREAM, 6), &a);
    gf_run(GF_W, NULL, "9", H(AI_PASSIVE, 0, SOCK_STREAM, 6), &w);
    gf_run(GF_XW, NULL, "9", H(AI_PASSIVE, 0, SOCK_STREAM, 6), &xw);
    if (gf_api_ok(GF_XA)) gf_run(GF_XA, NULL, "9", H(AI_PASSIVE, 0, SOCK_STREAM, 6), &xa); else xa = xw;
    EXPECT_EQ(a.n, w.n);
    EXPECT_EQ(a.n, xw.n);
    EXPECT_EQ(a.n, xa.n);
    if (a.n == w.n && a.n == xw.n && a.n == xa.n) {
        int i;
        for (i = 0; i < a.n; i++) {
            EXPECT_EQ(a.e[i].family, w.e[i].family);
            EXPECT_EQ(a.e[i].family, xw.e[i].family);
            EXPECT_EQ(a.e[i].family, xa.e[i].family);
            EXPECT_EQ(a.e[i].addrlen, w.e[i].addrlen);
            EXPECT_EQ(a.e[i].addrlen, xw.e[i].addrlen);
            CHECK(!memcmp(a.e[i].addr, w.e[i].addr, a.e[i].addrlen));
            CHECK(!memcmp(a.e[i].addr, xw.e[i].addr, a.e[i].addrlen));
            CHECK(!memcmp(a.e[i].addr, xa.e[i].addr, a.e[i].addrlen));
        }
    }
    GFB_END();
}

/* ---- return value / last error conventions ----------------------------------------------------- */
/* Success clears the thread's last error (the pre-set marker is gone) for all four calls. */
TEST(gfh_success_clears_last_error)
{
    int api;
    GFB_BEGIN(GF_ALL);
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, NULL, "80", H(0, AF_INET, 0, 0), &r);
        CHECKF(r.ret == 0 && r.werr == 0, "%s ret %d werr %d", gf_api_name(api), r.ret, r.werr);
    }
    GFB_END();
}
/* A failing call returns the error code itself, not -1: the same value is in WSAGetLastError. */
TEST(gfh_failure_returns_code_not_minus_one)
{
    int api;
    GFB_BEGIN(GF_ALL);
    GF_EACH(api, GF_ALL) {
        struct gf_res r;
        gf_run(api, NULL, NULL, NULL, &r);
        CHECKF(r.ret != -1 && r.ret > 0, "%s ret %d", gf_api_name(api), r.ret);
        CHECKF(r.ret == r.werr, "%s ret %d werr %d", gf_api_name(api), r.ret, r.werr);
    }
    GFB_END();
}
/* Repeating a failing call gives the same answer (no sticky state). */
TEST(gfh_failure_repeatable)
{
    int i;
    GFB_BEGIN(GF_ALL);
    for (i = 0; i < 3; i++) gf_check_err(GF_ALL, "127.0.0.1", NULL, H(0, AF_UNIX, 0, 0), WSAEAFNOSUPPORT);
    GFB_END();
}
/* The hints structure is read-only input: the call must leave it unchanged. */
TEST(gfh_hints_not_modified)
{
    ADDRINFOA hint, before, *res = NULL;
    GFB_BEGIN(GF_A);
    memset(&hint, 0, sizeof hint);
    hint.ai_flags = AI_PASSIVE; hint.ai_family = AF_INET; hint.ai_socktype = SOCK_STREAM; hint.ai_protocol = IPPROTO_TCP;
    before = hint;
    EXPECT_EQ(U(getaddrinfo)(NULL, "80", &hint, &res), 0);
    CHECK(!memcmp(&hint, &before, sizeof hint));
    if (res) U(freeaddrinfo)(res);
    GFB_END();
}
TEST(gfh_hints_not_modified_wide)
{
    ADDRINFOW hint, before, *res = NULL;
    GFB_BEGIN(GF_W);
    memset(&hint, 0, sizeof hint);
    hint.ai_flags = AI_PASSIVE; hint.ai_family = AF_INET; hint.ai_socktype = SOCK_STREAM; hint.ai_protocol = IPPROTO_TCP;
    before = hint;
    EXPECT_EQ(U(GetAddrInfoW)(NULL, L"80", &hint, &res), 0);
    CHECK(!memcmp(&hint, &before, sizeof hint));
    if (res) U(FreeAddrInfoW)(res);
    GFB_END();
}
/* A pre-existing non-NULL result pointer is overwritten (never freed or read) on success, cleared on failure. */
TEST(gfh_result_pointer_overwritten_on_success)
{
    ADDRINFOA *res = (ADDRINFOA *)gf_sent;
    GFB_BEGIN(GF_A);
    EXPECT_EQ(U(getaddrinfo)(NULL, "80", NULL, &res), 0);
    CHECK(res != (ADDRINFOA *)gf_sent && res != NULL);
    if (res && res != (ADDRINFOA *)gf_sent) U(freeaddrinfo)(res);
    GFB_END();
}
TEST(gfh_ex_handle_cleared_by_sync_failure)
{
    ADDRINFOEXW *res = (ADDRINFOEXW *)gf_sent;
    int r;
    GFB_BEGIN(GF_XW);
    r = U(GetAddrInfoExW)(NULL, NULL, NS_DNS, NULL, NULL, &res, NULL, NULL, NULL, NULL);
    EXPECT_EQ(r, WSAHOST_NOT_FOUND);
    CHECK(res == NULL);
    GFB_END();
}
