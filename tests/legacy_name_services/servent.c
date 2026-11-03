/* getservbyname / getservbyport against the stock services database.
 * Measures: for each well-known entry of the services file the canonical name, the port (returned in network
 * byte order), the protocol and the alias list, in both directions; protocol filtering (case-insensitive,
 * NULL or empty meaning "any", the first listed protocol winning); alias and case-insensitive name lookup;
 * the failure paths (NULL name WSAEINVAL, unknown entry WSANO_DATA, WSANOTINITIALISED before startup);
 * the layout and the per-thread reuse of the result block. */
#include "lns.h"

/* name, protocol, port, canonical name, aliases (comma separated, in file order). One row per file entry. */
struct svc { const char *name, *proto; int port; const char *canon, *aliases; };

static int alias_string(struct servent *s, char *out, size_t cap)
{
    char **a; size_t n = 0;
    out[0] = 0;
    if (!s || !s->s_aliases) return -1;
    for (a = s->s_aliases; *a; a++) {
        size_t l = strlen(*a);
        if (n + l + 2 >= cap) return -1;
        if (n) out[n++] = ',';
        memcpy(out + n, *a, l); n += l; out[n] = 0;
    }
    return 0;
}

/* Verify one lookup result against a row; tag names the call for the message. */
static void check_row(struct servent *s, const struct svc *r, const char *tag)
{
    char al[256];
    CHECKF(s != NULL, "%s: %s/%s not found", tag, r->name, r->proto);
    if (!s) return;
    CHECKF(s->s_name && !strcmp(s->s_name, r->canon), "%s: canonical name %s want %s", tag, s->s_name ? s->s_name : "(null)", r->canon);
    CHECKF(s->s_proto && !strcmp(s->s_proto, r->proto), "%s: proto %s want %s", tag, s->s_proto ? s->s_proto : "(null)", r->proto);
    CHECKF((unsigned short)s->s_port == lns_swap16((unsigned short)r->port), "%s: port 0x%04x", tag, (unsigned short)s->s_port);
    CHECKF(alias_string(s, al, sizeof al) == 0 && !strcmp(al, r->aliases), "%s: aliases \"%s\" want \"%s\"", tag, al, r->aliases);
}

/* Two tests per row: forward lookup by the row's own name and the reverse lookup by port. For rows sharing a
 * port across protocols only the (port, protocol) pair is looked up, so every pair is unambiguous. */
#define ROW(id, nm, pr, pt, cn, al) \
TEST(servbyname_##id) { \
    static const struct svc r = { nm, pr, pt, cn, al }; \
    LNS_NEED(getservbyname); \
    check_row(U(getservbyname)(r.name, r.proto), &r, "byname"); \
    LNS_DONE(); \
} \
TEST(servbyport_##id) { \
    static const struct svc r = { nm, pr, pt, cn, al }; \
    LNS_NEED(getservbyport); \
    check_row(U(getservbyport)(lns_swap16((unsigned short)r.port), r.proto), &r, "byport"); \
    LNS_DONE(); \
}

ROW(echo_tcp, "echo", "tcp", 7, "echo", "")
ROW(echo_udp, "echo", "udp", 7, "echo", "")
ROW(discard_tcp, "discard", "tcp", 9, "discard", "sink,null")
ROW(discard_udp, "discard", "udp", 9, "discard", "sink,null")
ROW(systat_tcp, "systat", "tcp", 11, "systat", "users")
ROW(daytime_tcp, "daytime", "tcp", 13, "daytime", "")
ROW(daytime_udp, "daytime", "udp", 13, "daytime", "")
ROW(qotd_tcp, "qotd", "tcp", 17, "qotd", "quote")
ROW(chargen_tcp, "chargen", "tcp", 19, "chargen", "ttytst,source")
ROW(chargen_udp, "chargen", "udp", 19, "chargen", "ttytst,source")
ROW(ftp_data, "ftp-data", "tcp", 20, "ftp-data", "")
ROW(ftp, "ftp", "tcp", 21, "ftp", "")
ROW(ssh, "ssh", "tcp", 22, "ssh", "")
ROW(telnet, "telnet", "tcp", 23, "telnet", "")
ROW(smtp, "smtp", "tcp", 25, "smtp", "mail")
ROW(time_tcp, "time", "tcp", 37, "time", "timserver")
ROW(time_udp, "time", "udp", 37, "time", "timserver")
ROW(rlp, "rlp", "udp", 39, "rlp", "resource")
ROW(nameserver_tcp, "nameserver", "tcp", 42, "nameserver", "name")
ROW(nicname, "nicname", "tcp", 43, "nicname", "whois")
ROW(domain_tcp, "domain", "tcp", 53, "domain", "")
ROW(domain_udp, "domain", "udp", 53, "domain", "")
ROW(bootps, "bootps", "udp", 67, "bootps", "dhcps")
ROW(bootpc, "bootpc", "udp", 68, "bootpc", "dhcpc")
ROW(tftp, "tftp", "udp", 69, "tftp", "")
ROW(gopher, "gopher", "tcp", 70, "gopher", "")
ROW(finger, "finger", "tcp", 79, "finger", "")
ROW(http, "http", "tcp", 80, "http", "www,www-http")
ROW(kerberos_tcp, "kerberos", "tcp", 88, "kerberos", "krb5,kerberos-sec")
ROW(kerberos_udp, "kerberos", "udp", 88, "kerberos", "krb5,kerberos-sec")
ROW(hostname, "hostname", "tcp", 101, "hostname", "hostnames")
ROW(iso_tsap, "iso-tsap", "tcp", 102, "iso-tsap", "")
ROW(rtelnet, "rtelnet", "tcp", 107, "rtelnet", "")
ROW(pop2, "pop2", "tcp", 109, "pop2", "postoffice")
ROW(pop3, "pop3", "tcp", 110, "pop3", "")
ROW(sunrpc_tcp, "sunrpc", "tcp", 111, "sunrpc", "rpcbind,portmap")
ROW(sunrpc_udp, "sunrpc", "udp", 111, "sunrpc", "rpcbind,portmap")
ROW(auth, "auth", "tcp", 113, "auth", "ident,tap")
ROW(nntp, "nntp", "tcp", 119, "nntp", "usenet")
ROW(ntp, "ntp", "udp", 123, "ntp", "")
ROW(epmap_tcp, "epmap", "tcp", 135, "epmap", "loc-srv")
ROW(epmap_udp, "epmap", "udp", 135, "epmap", "loc-srv")
ROW(netbios_ns_tcp, "netbios-ns", "tcp", 137, "netbios-ns", "nbname")
ROW(netbios_ns_udp, "netbios-ns", "udp", 137, "netbios-ns", "nbname")
ROW(netbios_dgm, "netbios-dgm", "udp", 138, "netbios-dgm", "nbdatagram")
ROW(netbios_ssn, "netbios-ssn", "tcp", 139, "netbios-ssn", "nbsession")
ROW(imap, "imap", "tcp", 143, "imap", "imap4")
ROW(pcmail_srv, "pcmail-srv", "tcp", 158, "pcmail-srv", "")
ROW(snmp, "snmp", "udp", 161, "snmp", "")
ROW(snmptrap, "snmptrap", "udp", 162, "snmptrap", "snmp-trap")
ROW(print_srv, "print-srv", "tcp", 170, "print-srv", "")
ROW(bgp, "bgp", "tcp", 179, "bgp", "")
ROW(irc, "irc", "tcp", 194, "irc", "")
ROW(ipx, "ipx", "udp", 213, "ipx", "")
ROW(ldap, "ldap", "tcp", 389, "ldap", "")
ROW(https_tcp, "https", "tcp", 443, "https", "MCom")
ROW(https_udp, "https", "udp", 443, "https", "MCom")
ROW(microsoft_ds_tcp, "microsoft-ds", "tcp", 445, "microsoft-ds", "")
ROW(microsoft_ds_udp, "microsoft-ds", "udp", 445, "microsoft-ds", "")
ROW(kpasswd_tcp, "kpasswd", "tcp", 464, "kpasswd", "")
ROW(kpasswd_udp, "kpasswd", "udp", 464, "kpasswd", "")
ROW(isakmp, "isakmp", "udp", 500, "isakmp", "ike")
ROW(exec, "exec", "tcp", 512, "exec", "")
ROW(login, "login", "tcp", 513, "login", "")
ROW(cmd, "cmd", "tcp", 514, "cmd", "shell")
ROW(syslog, "syslog", "udp", 514, "syslog", "")
ROW(printer, "printer", "tcp", 515, "printer", "spooler")
ROW(talk, "talk", "udp", 517, "talk", "")
ROW(ntalk, "ntalk", "udp", 518, "ntalk", "")
ROW(efs, "efs", "tcp", 520, "efs", "")
ROW(router, "router", "udp", 520, "router", "route,routed")
ROW(timed, "timed", "udp", 525, "timed", "timeserver")
ROW(uucp, "uucp", "tcp", 540, "uucp", "uucpd")
ROW(klogin, "klogin", "tcp", 543, "klogin", "")
ROW(kshell, "kshell", "tcp", 544, "kshell", "krcmd")
ROW(rtsp_tcp, "rtsp", "tcp", 554, "rtsp", "")
ROW(rtsp_udp, "rtsp", "udp", 554, "rtsp", "")

/* ---- alias names resolve to the canonical entry ------------------------------------------------------ */

#define ALIAS(id, al, pr, pt, cn, als) \
TEST(servalias_##id) { \
    static const struct svc r = { al, pr, pt, cn, als }; \
    struct servent *s; \
    LNS_NEED(getservbyname); \
    s = U(getservbyname)(al, pr); \
    check_row(s, &r, "alias"); \
    LNS_DONE(); \
}
ALIAS(www, "www", "tcp", 80, "http", "www,www-http")
ALIAS(www_http, "www-http", "tcp", 80, "http", "www,www-http")
ALIAS(whois, "whois", "tcp", 43, "nicname", "whois")
ALIAS(mail, "mail", "tcp", 25, "smtp", "mail")
ALIAS(ident, "ident", "tcp", 113, "auth", "ident,tap")
ALIAS(shell, "shell", "tcp", 514, "cmd", "shell")
ALIAS(krb5_tcp, "krb5", "tcp", 88, "kerberos", "krb5,kerberos-sec")
ALIAS(krb5_udp, "krb5", "udp", 88, "kerberos", "krb5,kerberos-sec")
ALIAS(loc_srv, "loc-srv", "udp", 135, "epmap", "loc-srv")
ALIAS(imap4, "imap4", "tcp", 143, "imap", "imap4")
ALIAS(ike, "ike", "udp", 500, "isakmp", "ike")
ALIAS(route, "route", "udp", 520, "router", "route,routed")
ALIAS(routed, "routed", "udp", 520, "router", "route,routed")
ALIAS(rpcbind, "rpcbind", "udp", 111, "sunrpc", "rpcbind,portmap")
ALIAS(portmap, "portmap", "tcp", 111, "sunrpc", "rpcbind,portmap")
ALIAS(sink, "sink", "udp", 9, "discard", "sink,null")
ALIAS(null, "null", "tcp", 9, "discard", "sink,null")
ALIAS(quote, "quote", "tcp", 17, "qotd", "quote")
ALIAS(timserver, "timserver", "udp", 37, "time", "timserver")
ALIAS(usenet, "usenet", "tcp", 119, "nntp", "usenet")
ALIAS(nbname, "nbname", "udp", 137, "netbios-ns", "nbname")
ALIAS(mcom, "MCom", "tcp", 443, "https", "MCom")

/* ---- case rules --------------------------------------------------------------------------------------- */

static void ci_lookup(const char *name, const char *proto, const char *canon)
{
    struct servent *s = U(getservbyname)(name, proto);
    CHECKF(s != NULL, "%s/%s", name, proto ? proto : "(null)");
    if (s) CHECKF(!strcmp(s->s_name, canon), "canonical %s", s->s_name);
}
TEST(servcase_name_upper) { LNS_NEED(getservbyname); ci_lookup("HTTP", "tcp", "http"); ci_lookup("FTP", "tcp", "ftp"); ci_lookup("DOMAIN", "udp", "domain"); LNS_DONE(); }
TEST(servcase_name_mixed) { LNS_NEED(getservbyname); ci_lookup("Http", "tcp", "http"); ci_lookup("hTTp", "tcp", "http"); ci_lookup("Netbios-SSN", "tcp", "netbios-ssn"); LNS_DONE(); }
TEST(servcase_alias_upper) { LNS_NEED(getservbyname); ci_lookup("WWW", "tcp", "http"); ci_lookup("WWW-HTTP", "tcp", "http"); LNS_DONE(); }
TEST(servcase_alias_in_file_is_mixed_case)
{
    struct servent *s;
    LNS_NEED(getservbyname);
    s = U(getservbyname)("mcom", "tcp");
    CHECK(s != NULL);
    if (s) { CHECK(s->s_aliases && s->s_aliases[0] && !strcmp(s->s_aliases[0], "MCom")); }
    LNS_DONE();
}
TEST(servcase_proto_upper)
{
    struct servent *s;
    LNS_NEED(getservbyname);
    s = U(getservbyname)("http", "TCP");
    CHECK(s != NULL);
    /* The stored protocol spelling is returned, not the caller's. */
    if (s) CHECK(!strcmp(s->s_proto, "tcp"));
    s = U(getservbyname)("domain", "UDP");
    CHECK(s != NULL);
    if (s) CHECK(!strcmp(s->s_proto, "udp"));
    s = U(getservbyname)("domain", "Udp");
    CHECK(s != NULL);
    LNS_DONE();
}
TEST(servcase_port_proto_upper)
{
    struct servent *s;
    LNS_NEED(getservbyport);
    s = U(getservbyport)(lns_swap16(80), "TCP");
    CHECK(s != NULL);
    if (s) CHECK(!strcmp(s->s_proto, "tcp"));
    s = U(getservbyport)(lns_swap16(53), "Udp");
    CHECK(s != NULL);
    if (s) CHECK(!strcmp(s->s_proto, "udp"));
    LNS_DONE();
}

/* ---- protocol filter ------------------------------------------------------------------------------- */

TEST(servproto_null_means_any_and_picks_first_listed)
{
    struct servent *s;
    LNS_NEED(getservbyname);
    /* A name listed for both protocols comes back with tcp: tcp entries precede udp ones in the file. */
    s = U(getservbyname)("domain", NULL); CHECK(s != NULL); if (s) CHECK(!strcmp(s->s_proto, "tcp"));
    s = U(getservbyname)("echo", NULL);   CHECK(s != NULL); if (s) CHECK(!strcmp(s->s_proto, "tcp"));
    s = U(getservbyname)("kerberos", NULL); CHECK(s != NULL); if (s) CHECK(!strcmp(s->s_proto, "tcp"));
    LNS_DONE();
}
TEST(servproto_null_finds_udp_only_entries)
{
    static const char *udp_only[] = { "tftp", "ntp", "snmp", "bootps", "isakmp", "syslog", "talk", "timed", "ipx" };
    int i;
    LNS_NEED(getservbyname);
    for (i = 0; i < LNS_COUNT(udp_only); i++) {
        struct servent *s = U(getservbyname)(udp_only[i], NULL);
        CHECKF(s != NULL, "%s", udp_only[i]);
        if (s) CHECKF(!strcmp(s->s_proto, "udp"), "%s: %s", udp_only[i], s->s_proto);
    }
    LNS_DONE();
}
TEST(servproto_empty_string_means_any)
{
    struct servent *a, *b;
    LNS_NEED(getservbyname);
    a = U(getservbyname)("http", "");
    CHECK(a != NULL);
    if (a) { CHECK(!strcmp(a->s_proto, "tcp")); CHECK(!strcmp(a->s_name, "http")); }
    b = U(getservbyname)("syslog", "");
    CHECK(b != NULL);
    if (b) CHECK(!strcmp(b->s_proto, "udp"));
    LNS_DONE();
}
TEST(servproto_port_null_means_any_and_picks_first_listed)
{
    struct servent *s;
    LNS_NEED(getservbyport);
    s = U(getservbyport)(lns_swap16(53), NULL);  CHECK(s != NULL); if (s) CHECK(!strcmp(s->s_proto, "tcp") && !strcmp(s->s_name, "domain"));
    s = U(getservbyport)(lns_swap16(514), NULL); CHECK(s != NULL); if (s) CHECK(!strcmp(s->s_proto, "tcp") && !strcmp(s->s_name, "cmd"));
    s = U(getservbyport)(lns_swap16(520), NULL); CHECK(s != NULL); if (s) CHECK(!strcmp(s->s_proto, "tcp") && !strcmp(s->s_name, "efs"));
    s = U(getservbyport)(lns_swap16(123), NULL); CHECK(s != NULL); if (s) CHECK(!strcmp(s->s_proto, "udp") && !strcmp(s->s_name, "ntp"));
    LNS_DONE();
}
TEST(servproto_port_empty_string_means_any)
{
    struct servent *s;
    LNS_NEED(getservbyport);
    s = U(getservbyport)(lns_swap16(80), ""); CHECK(s != NULL); if (s) CHECK(!strcmp(s->s_name, "http"));
    LNS_DONE();
}
TEST(servproto_same_port_differs_by_protocol)
{
    struct servent *t, *u; char tn[64];
    LNS_NEED(getservbyport);
    t = U(getservbyport)(lns_swap16(514), "tcp"); CHECK(t != NULL);
    if (!t) { LNS_DONE(); return; }
    lstrcpynA(tn, t->s_name, sizeof tn);
    u = U(getservbyport)(lns_swap16(514), "udp"); CHECK(u != NULL);
    if (u) { CHECK(strcmp(tn, u->s_name) != 0); CHECK(!strcmp(u->s_name, "syslog")); }
    LNS_DONE();
}
TEST(servproto_name_not_listed_for_that_protocol)
{
    static const char *tcp_only[] = { "http", "ftp", "telnet", "smtp", "pop3", "imap", "ldap", "gopher", "finger", "nntp" };
    int i;
    LNS_NEED(getservbyname);
    for (i = 0; i < LNS_COUNT(tcp_only); i++) {
        LNS_SETERR(0);
        CHECKF(U(getservbyname)(tcp_only[i], "udp") == NULL, "%s/udp", tcp_only[i]);
        EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    }
    LNS_DONE();
}
TEST(servproto_udp_only_not_listed_for_tcp)
{
    static const char *udp_only[] = { "tftp", "ntp", "snmp", "bootps", "bootpc", "isakmp", "syslog", "talk", "ntalk", "timed", "ipx", "snmptrap", "rlp" };
    int i;
    LNS_NEED(getservbyname);
    for (i = 0; i < LNS_COUNT(udp_only); i++) {
        LNS_SETERR(0);
        CHECKF(U(getservbyname)(udp_only[i], "tcp") == NULL, "%s/tcp", udp_only[i]);
        EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    }
    LNS_DONE();
}
TEST(servproto_port_not_listed_for_that_protocol)
{
    static const struct { int port; const char *proto; } miss[] = { { 80, "udp" }, { 67, "tcp" }, { 69, "tcp" }, { 123, "tcp" }, { 161, "tcp" }, { 500, "tcp" } };
    int i;
    LNS_NEED(getservbyport);
    for (i = 0; i < LNS_COUNT(miss); i++) {
        LNS_SETERR(0);
        CHECKF(U(getservbyport)(lns_swap16((unsigned short)miss[i].port), miss[i].proto) == NULL, "%d/%s", miss[i].port, miss[i].proto);
        EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    }
    LNS_DONE();
}
/* The protocol must match as a whole word: neither a prefix nor an extension of a protocol name matches. */
#define BADPROTO(id, text) \
TEST(servproto_unknown_##id) { \
    LNS_NEED(getservbyname); \
    LNS_SETERR(0); \
    CHECK(U(getservbyname)("http", text) == NULL); \
    EXPECT_EQ(LNS_ERR(), LNS_E_NODATA); \
    LNS_DONE(); \
}
BADPROTO(icmp, "icmp")
BADPROTO(prefix, "tc")
BADPROTO(extended, "tcpx")
BADPROTO(trailing_space, "tcp ")
BADPROTO(leading_space, " tcp")
BADPROTO(ip, "ip")
BADPROTO(number, "6")

/* ---- not found / invalid ---------------------------------------------------------------------------- */

TEST(servname_null_name_is_invalid)
{
    LNS_NEED(getservbyname);
    LNS_SETERR(0);
    CHECK(U(getservbyname)(NULL, "tcp") == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_INVAL);
    LNS_SETERR(0);
    CHECK(U(getservbyname)(NULL, NULL) == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_INVAL);
    LNS_DONE();
}
TEST(servname_unknown_names_are_no_data)
{
    static const char *bad[] = { "no-such-service", "NO_SUCH", "80", "http ", " http", "ht", "httpx", "ftp-", "tcp", "service" };
    int i;
    LNS_NEED(getservbyname);
    for (i = 0; i < LNS_COUNT(bad); i++) {
        LNS_SETERR(0);
        CHECKF(U(getservbyname)(bad[i], "tcp") == NULL, "%s", bad[i]);
        EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
        LNS_SETERR(0);
        CHECKF(U(getservbyname)(bad[i], NULL) == NULL, "%s/any", bad[i]);
        EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    }
    LNS_DONE();
}
TEST(servname_empty_name_is_no_data)
{
    LNS_NEED(getservbyname);
    LNS_SETERR(0);
    CHECK(U(getservbyname)("", "tcp") == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    LNS_SETERR(0);
    CHECK(U(getservbyname)("", NULL) == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    LNS_DONE();
}
TEST(servname_very_long_name_is_no_data)
{
    char big[2000];
    LNS_NEED(getservbyname);
    memset(big, 'a', sizeof big - 1); big[sizeof big - 1] = 0;
    LNS_SETERR(0);
    CHECK(U(getservbyname)(big, "tcp") == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    LNS_SETERR(0);
    CHECK(U(getservbyname)("http", big) == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    LNS_DONE();
}
TEST(servport_unlisted_ports_are_no_data)
{
    static const int ports[] = { 0, 1, 2, 3, 65535, 65534, 1000, 4999, 33333 };
    int i;
    LNS_NEED(getservbyport);
    for (i = 0; i < LNS_COUNT(ports); i++) {
        LNS_SETERR(0);
        CHECKF(U(getservbyport)(lns_swap16((unsigned short)ports[i]), "tcp") == NULL, "port %d/tcp", ports[i]);
        EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
        LNS_SETERR(0);
        CHECKF(U(getservbyport)(lns_swap16((unsigned short)ports[i]), NULL) == NULL, "port %d/any", ports[i]);
        EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    }
    LNS_DONE();
}
TEST(servport_host_order_port_does_not_match)
{
    LNS_NEED(getservbyport);
    /* 80 in host order on a little-endian machine is network port 20480. */
    LNS_SETERR(0);
    CHECK(U(getservbyport)(80, "tcp") == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    LNS_DONE();
}
TEST(servport_network_order_matches_ntohs_view)
{
    struct servent *s;
    LNS_NEED(getservbyport);
    s = U(getservbyport)(0x5000, "tcp"); /* bytes 00 50 in memory: port 80 */
    CHECK(s != NULL);
    if (s) { CHECK(!strcmp(s->s_name, "http")); EXPECT_EQ((unsigned short)s->s_port, 0x5000); }
    LNS_DONE();
}
TEST(servport_low_byte_alone_is_not_enough)
{
    LNS_NEED(getservbyport);
    LNS_SETERR(0);
    CHECK(U(getservbyport)(0x50, "tcp") == NULL); /* network port 20480 */
    EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    LNS_DONE();
}
TEST(servport_unknown_proto)
{
    LNS_NEED(getservbyport);
    LNS_SETERR(0);
    CHECK(U(getservbyport)(lns_swap16(80), "icmp") == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NODATA);
    LNS_DONE();
}

/* ---- before WSAStartup -------------------------------------------------------------------------------- */

TEST(servname_before_startup_not_initialised)
{
    REQUIRE(U(getservbyname)); REQUIRE(U(WSACleanup)); REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    lns_force_down();
    LNS_SETERR(0);
    CHECK(U(getservbyname)("http", "tcp") == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}
TEST(servname_null_before_startup_not_initialised)
{
    REQUIRE(U(getservbyname)); REQUIRE(U(WSACleanup)); REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    lns_force_down();
    LNS_SETERR(0);
    CHECK(U(getservbyname)(NULL, NULL) == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}
TEST(servport_before_startup_not_initialised)
{
    REQUIRE(U(getservbyport)); REQUIRE(U(WSACleanup)); REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    lns_force_down();
    LNS_SETERR(0);
    CHECK(U(getservbyport)(lns_swap16(80), "tcp") == NULL);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}

/* ---- the result block ----------------------------------------------------------------------------------- */

TEST(servblock_aliases_list_is_null_terminated)
{
    struct servent *s;
    LNS_NEED(getservbyname);
    s = U(getservbyname)("http", "tcp");
    CHECK(s != NULL);
    if (s) { EXPECT_EQ(lns_list_len(s->s_aliases), 2); CHECK(s->s_aliases[2] == NULL); }
    s = U(getservbyname)("ftp", "tcp");
    CHECK(s != NULL);
    if (s) { CHECK(s->s_aliases != NULL); EXPECT_EQ(lns_list_len(s->s_aliases), 0); }
    LNS_DONE();
}
/* Everything the entry points at lives in one block with the struct: strings are not shared static data. */
TEST(servblock_pointers_stay_inside_one_small_block)
{
    struct servent *s; char **a;
    LNS_NEED(getservbyname);
    s = U(getservbyname)("http", "tcp");
    CHECK(s != NULL);
    if (s) {
        CHECK(lns_inside(s, 512, s->s_name, strlen(s->s_name) + 1));
        CHECK(lns_inside(s, 512, s->s_proto, strlen(s->s_proto) + 1));
        CHECK(lns_inside(s, 512, s->s_aliases, sizeof(char *) * 3));
        for (a = s->s_aliases; a && *a; a++) CHECK(lns_inside(s, 512, *a, strlen(*a) + 1));
    }
    LNS_DONE();
}
TEST(servblock_alias_array_directly_follows_struct)
{
    struct servent *s;
    LNS_NEED(getservbyname);
    s = U(getservbyname)("http", "tcp");
    CHECK(s != NULL);
    if (s) CHECK((char *)s->s_aliases == (char *)(s + 1));
    LNS_DONE();
}
TEST(servblock_strings_follow_alias_array)
{
    struct servent *s; char *after;
    LNS_NEED(getservbyname);
    s = U(getservbyname)("http", "tcp");
    CHECK(s != NULL);
    if (s) {
        after = (char *)(s->s_aliases + lns_list_len(s->s_aliases) + 1);
        CHECK((char *)s->s_aliases[0] >= after || lns_list_len(s->s_aliases) == 0);
        CHECK(s->s_name >= after);
        CHECK(s->s_proto >= after);
    }
    LNS_DONE();
}
TEST(servblock_repeated_lookups_reuse_one_block)
{
    struct servent *a, *b; int i;
    LNS_NEED(getservbyname);
    a = U(getservbyname)("http", "tcp");
    CHECK(a != NULL);
    for (i = 0; i < 40; i++) {
        b = U(getservbyname)(i & 1 ? "domain" : "telnet", i & 2 ? "udp" : "tcp");
        if (b) CHECK(b == a);
    }
    LNS_DONE();
}
TEST(servblock_name_and_port_lookups_share_a_block)
{
    struct servent *a, *b;
    LNS_NEED(getservbyport);
    REQUIRE(U(getservbyname));
    a = U(getservbyname)("http", "tcp");
    b = U(getservbyport)(lns_swap16(21), "tcp");
    CHECK(a != NULL && b != NULL);
    CHECK(a == b);
    LNS_DONE();
}
TEST(servblock_second_lookup_overwrites_first)
{
    struct servent *a, *b;
    LNS_NEED(getservbyname);
    a = U(getservbyname)("http", "tcp");
    CHECK(a != NULL && !strcmp(a->s_name, "http"));
    b = U(getservbyname)("ftp", "tcp");
    CHECK(b == a);
    if (a) { CHECK(!strcmp(a->s_name, "ftp")); EXPECT_EQ((unsigned short)a->s_port, lns_swap16(21)); EXPECT_EQ(lns_list_len(a->s_aliases), 0); }
    LNS_DONE();
}
TEST(servblock_failed_lookup_keeps_previous_result)
{
    struct servent *a;
    LNS_NEED(getservbyname);
    a = U(getservbyname)("http", "tcp");
    CHECK(a != NULL);
    CHECK(U(getservbyname)("no-such-service", "tcp") == NULL);
    CHECK(U(getservbyport)(lns_swap16(3), "tcp") == NULL);
    if (a) { CHECK(!strcmp(a->s_name, "http")); EXPECT_EQ((unsigned short)a->s_port, lns_swap16(80)); CHECK(!strcmp(a->s_proto, "tcp")); }
    LNS_DONE();
}
TEST(servblock_alias_count_follows_each_result)
{
    struct servent *a;
    LNS_NEED(getservbyname);
    a = U(getservbyname)("chargen", "tcp");
    CHECK(a != NULL);
    if (a) EXPECT_EQ(lns_list_len(a->s_aliases), 2);
    a = U(getservbyname)("echo", "tcp");
    CHECK(a != NULL);
    if (a) EXPECT_EQ(lns_list_len(a->s_aliases), 0);
    a = U(getservbyname)("router", "udp");
    CHECK(a != NULL);
    if (a) EXPECT_EQ(lns_list_len(a->s_aliases), 2);
    LNS_DONE();
}

struct sv_ctx { HANDLE ready, go; struct servent *blk; volatile LONG ok; };
static DWORD WINAPI serv_thread(void *p)
{
    struct sv_ctx *c = p; WSADATA d; struct servent *s;
    if (U(WSAStartup)(0x202, &d)) return 1;
    s = U(getservbyname)("smtp", "tcp");
    c->blk = s;
    SetEvent(c->ready);
    WaitForSingleObject(c->go, 10000);
    c->ok = s && !strcmp(s->s_name, "smtp") && (unsigned short)s->s_port == lns_swap16(25);
    U(WSACleanup)();
    return 0;
}
TEST(servblock_each_thread_has_its_own_block)
{
    struct sv_ctx c; HANDLE th; struct servent *mine;
    LNS_NEED(getservbyname);
    memset(&c, 0, sizeof c);
    c.ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    c.go = CreateEventW(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, serv_thread, &c, 0, NULL);
    CHECK(th != NULL);
    if (th) {
        EXPECT_EQ(WaitForSingleObject(c.ready, 10000), WAIT_OBJECT_0);
        mine = U(getservbyname)("pop3", "tcp");
        CHECK(mine != NULL);
        CHECK(mine != c.blk);
        SetEvent(c.go);
        EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
        CloseHandle(th);
        EXPECT_EQ(c.ok, 1);
        if (mine) CHECK(!strcmp(mine->s_name, "pop3"));
    }
    CloseHandle(c.ready); CloseHandle(c.go);
    LNS_DONE();
}

/* ---- every row, in one pass: name <-> port round trip ----------------------------------------------------- */

TEST(servround_every_port_of_common_services_maps_back)
{
    static const int ports[] = { 7, 9, 13, 21, 22, 23, 25, 53, 80, 110, 119, 135, 139, 143, 389, 443, 445 };
    int i;
    LNS_NEED(getservbyport);
    REQUIRE(U(getservbyname));
    for (i = 0; i < LNS_COUNT(ports); i++) {
        struct servent *s = U(getservbyport)(lns_swap16((unsigned short)ports[i]), "tcp");
        char nm[64];
        CHECKF(s != NULL, "port %d", ports[i]);
        if (!s) continue;
        lstrcpynA(nm, s->s_name, sizeof nm);
        s = U(getservbyname)(nm, "tcp");
        CHECKF(s && (unsigned short)s->s_port == lns_swap16((unsigned short)ports[i]), "round trip %s", nm);
    }
    LNS_DONE();
}

/* ---- wsock32 ---------------------------------------------------------------------------------------- */

TEST(servname_wsock32_forwards_to_ws2_32)
{
    FARPROC a = t_proc_in("ws2_32.dll", "getservbyname"), b = t_proc_in("wsock32.dll", "getservbyname");
    REQUIRE(a); REQUIRE(b);
    CHECK(a == b);
}
TEST(servport_wsock32_forwards_to_ws2_32)
{
    FARPROC a = t_proc_in("ws2_32.dll", "getservbyport"), b = t_proc_in("wsock32.dll", "getservbyport");
    REQUIRE(a); REQUIRE(b);
    CHECK(a == b);
}
