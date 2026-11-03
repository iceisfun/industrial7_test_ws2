/* getprotobyname / getprotobynumber: the built-in IP protocol name table.
 * Measures: every entry of the table by canonical name, by its upper-case alias and by a fully
 * upper-cased name (lookup is case-insensitive), the canonical name and alias reported when looking
 * a number up, and that every other number from -1 to 256 is unknown (NULL). */
#include "l2.h"

static const struct { int num; const char *name; const char *alias; } proto_tab[] = {
    {  0, "ip", "IP" },           {  1, "icmp", "ICMP" },       {  3, "ggp", "GGP" },
    {  6, "tcp", "TCP" },         {  8, "egp", "EGP" },         { 12, "pup", "PUP" },
    { 17, "udp", "UDP" },         { 20, "hmp", "HMP" },         { 22, "xns-idp", "XNS-IDP" },
    { 27, "rdp", "RDP" },         { 41, "ipv6", "IPv6" },       { 43, "ipv6-route", "IPv6-Route" },
    { 44, "ipv6-frag", "IPv6-Frag" }, { 50, "esp", "ESP" },     { 51, "ah", "AH" },
    { 58, "ipv6-icmp", "IPv6-ICMP" }, { 59, "ipv6-nonxt", "IPv6-NoNxt" },
    { 60, "ipv6-opts", "IPv6-Opts" }, { 66, "rvd", "RVD" },
};

static int tab_index(int num) {
    unsigned i;
    for (i = 0; i < L2_COUNT(proto_tab); i++) if (proto_tab[i].num == num) return (int)i;
    return -1;
}

TEST(protoent_byname_canonical_and_alias_spelling) {
    unsigned i;
    REQUIRE(U(getprotobyname)); L2_NEED_WSA();
    for (i = 0; i < L2_COUNT(proto_tab); i++) {
        struct protoent *e;
        e = U(getprotobyname)(proto_tab[i].name);
        CHECKF(e && e->p_proto == proto_tab[i].num, "name %s: got %d", proto_tab[i].name, e ? e->p_proto : -1);
        e = U(getprotobyname)(proto_tab[i].alias);
        CHECKF(e && e->p_proto == proto_tab[i].num, "alias %s: got %d", proto_tab[i].alias, e ? e->p_proto : -1);
    }
}

TEST(protoent_byname_is_case_insensitive) {
    unsigned i;
    REQUIRE(U(getprotobyname)); L2_NEED_WSA();
    for (i = 0; i < L2_COUNT(proto_tab); i++) {
        char up[32]; size_t k; struct protoent *e;
        for (k = 0; proto_tab[i].name[k]; k++) {
            char c = proto_tab[i].name[k];
            up[k] = (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
        }
        up[k] = 0;
        e = U(getprotobyname)(up);
        CHECKF(e && e->p_proto == proto_tab[i].num, "name %s: got %d", up, e ? e->p_proto : -1);
    }
}

TEST(protoent_bynumber_name_and_alias) {
    unsigned i;
    REQUIRE(U(getprotobynumber)); L2_NEED_WSA();
    for (i = 0; i < L2_COUNT(proto_tab); i++) {
        struct protoent *e = U(getprotobynumber)(proto_tab[i].num);
        CHECKF(e != NULL, "number %d unknown", proto_tab[i].num);
        if (!e) continue;
        CHECKF(e->p_name && !strcmp(e->p_name, proto_tab[i].name), "number %d name %s", proto_tab[i].num, e->p_name ? e->p_name : "(null)");
        CHECKF(e->p_aliases && e->p_aliases[0] && !strcmp(e->p_aliases[0], proto_tab[i].alias), "number %d alias", proto_tab[i].num);
        CHECKF(e->p_proto == proto_tab[i].num, "number %d echo %d", proto_tab[i].num, e->p_proto);
    }
}

TEST(protoent_bynumber_unlisted_numbers_unknown) {
    int n;
    REQUIRE(U(getprotobynumber)); L2_NEED_WSA();
    for (n = -1; n <= 256; n++) {
        if (tab_index(n) >= 0) continue;
        CHECKF(U(getprotobynumber)(n) == NULL, "number %d unexpectedly defined", n);
    }
}

TEST(protoent_byname_unknown_name_null) {
    REQUIRE(U(getprotobyname)); REQUIRE(U(WSAGetLastError)); L2_NEED_WSA();
    CHECK(U(getprotobyname)("no-such-protocol-name") == NULL);
    EXPECT_EQ(U(WSAGetLastError)(), WSANO_DATA);
}
