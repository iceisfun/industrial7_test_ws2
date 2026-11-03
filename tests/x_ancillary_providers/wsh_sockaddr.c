/* Socket-address classification and wildcard/broadcast address construction of the Winsock helper DLLs
 * (WSHGetSockaddrType, WSHGetWildcardSockaddr, WSHGetBroadcastSockaddr) for the IPv4, IPv6 and Bluetooth helpers.
 * Measures: the address-class and port-class pair for wildcard / loopback / broadcast / ordinary addresses and for
 * reserved ports, the length protocol (too short is WSAEFAULT, a foreign family is WSAEAFNOSUPPORT, outputs untouched
 * on failure) and the exact bytes and sizes of the constructed wildcard and broadcast addresses. */
#include "anc.h"

static anc_sockaddr_info sentinel_info(void) { anc_sockaddr_info i = { ANC_SENT, ANC_SENT }; return i; }

/* One classification call with its expectation. want_rc != 0 means the outputs must be left untouched. */
static void sat(const anc_wsh *h, const char *who, const void *sa, DWORD len, INT want_rc, DWORD want_addr, DWORD want_port, const char *what) {
    anc_sockaddr_info o = sentinel_info();
    INT r = h->GetSockaddrType((PSOCKADDR)sa, len, &o);
    CHECKF(r == want_rc, "%s %s: rc %d want %d", who, what, r, want_rc);
    if (want_rc == 0) {
        CHECKF(o.AddressInfo == want_addr, "%s %s: address class %lu want %lu", who, what, o.AddressInfo, want_addr);
        CHECKF(o.EndpointInfo == want_port, "%s %s: port class %lu want %lu", who, what, o.EndpointInfo, want_port);
    } else {
        CHECKF(o.AddressInfo == ANC_SENT && o.EndpointInfo == ANC_SENT, "%s %s: outputs written on failure", who, what);
    }
}

static SOCKADDR_IN v4(ULONG addr_le, unsigned port) { SOCKADDR_IN a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = addr_le; a.sin_port = htons(port); return a; }
static SOCKADDR_IN6 v6(const BYTE *a16, unsigned port, ULONG scope) {
    SOCKADDR_IN6 a; memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_port = htons(port); a.sin6_scope_id = scope;
    if (a16) memcpy(&a.sin6_addr, a16, 16);
    return a;
}

/* ---- IPv4 helper ---- */
TEST(sat_v4_address_and_port_classes) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    static const struct { ULONG addr; DWORD cls; const char *n; } addrs[] = {
        { 0x00000000, ADDR_WILDCARD, "0.0.0.0" }, { 0x0100007f, ADDR_LOOPBACK, "127.0.0.1" }, { 0xffffffff, ADDR_BROADCAST, "255.255.255.255" },
        { 0x0200a8c0, ADDR_NORMAL, "ordinary host a" }, { 0x01020304, ADDR_NORMAL, "ordinary host b" }, { 0x0000a8c0, ADDR_NORMAL, "ordinary host c" } };
    static const struct { unsigned port; DWORD cls; } ports[] = { { 0, PORT_WILDCARD }, { 1, PORT_RESERVED }, { 80, PORT_RESERVED }, { 1024, PORT_RESERVED },
        { 1999, PORT_RESERVED }, { 2000, PORT_NORMAL }, { 2001, PORT_NORMAL }, { 5000, PORT_NORMAL }, { 49152, PORT_NORMAL }, { 65535, PORT_NORMAL } };
    for (size_t i = 0; i < ANC_N(addrs); i++) for (size_t j = 0; j < ANC_N(ports); j++) {
        SOCKADDR_IN a = v4(addrs[i].addr, ports[j].port); char w[64]; sprintf(w, "%s:%u", addrs[i].n, ports[j].port);
        sat(&h, "wshtcpip", &a, 16, 0, addrs[i].cls, ports[j].cls, w);
    }
}

TEST(sat_v4_length_protocol) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    SOCKADDR_STORAGE ss; SOCKADDR_IN a = v4(0x0100007f, 5000); memset(&ss, 0, sizeof ss); memcpy(&ss, &a, sizeof a);
    for (DWORD l = 0; l <= 40; l++) {
        char w[32]; sprintf(w, "len %lu", l);
        if (l < 16) sat(&h, "wshtcpip", &ss, l, E_FAULT, 0, 0, w);
        else sat(&h, "wshtcpip", &ss, l, 0, ADDR_LOOPBACK, PORT_NORMAL, w);
    }
}

TEST(sat_v4_ignores_trailing_bytes_of_the_address) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    SOCKADDR_IN a = v4(0, 0); memset(a.sin_zero, 0xFF, sizeof a.sin_zero);   /* the zero padding is not inspected */
    sat(&h, "wshtcpip", &a, 16, 0, ADDR_WILDCARD, PORT_WILDCARD, "dirty sin_zero");
}

/* ---- families a helper does not serve ---- */
static const int foreign_all[] = { 0, 1, 3, 6, 11, 17, 18, 21, 22, 24, 31, 33, 100, 0xffff };
static void sat_foreign(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    SOCKADDR_STORAGE ss;
    for (size_t i = 0; i < ANC_N(foreign_all); i++) {
        char w[48]; memset(&ss, 0, sizeof ss); ss.ss_family = (ADDRESS_FAMILY)foreign_all[i]; sprintf(w, "family %d", foreign_all[i]);
        sat(&h, hi->tag, &ss, 32, E_AFNOSUPPORT, 0, 0, w);
    }
    int own_others[3] = { 2, 23, 32 };
    for (int k = 0; k < 3; k++) {
        if (own_others[k] == hi->af) continue;
        char w[48]; memset(&ss, 0, sizeof ss); ss.ss_family = (ADDRESS_FAMILY)own_others[k]; sprintf(w, "other helper's family %d", own_others[k]);
        sat(&h, hi->tag, &ss, 32, E_AFNOSUPPORT, 0, 0, w);
    }
}
H3(sat_foreign_families_rejected, sat_foreign)

/* The length check precedes the family check in the IP helpers, the family check comes first in the Bluetooth helper. */
TEST(sat_short_length_with_foreign_family_ip_helpers) {
    static const struct { const anc_hinfo *hi; int fam; } rows[] = { { &anc_tcp, 23 }, { &anc_tcp, 32 }, { &anc_ip6, 2 }, { &anc_ip6, 32 } };
    for (size_t i = 0; i < ANC_N(rows); i++) {
        anc_wsh h; if (!anc_load_wsh(&h, rows[i].hi->dll)) { t_note("%s absent", rows[i].hi->dll); continue; }
        SOCKADDR_STORAGE ss; memset(&ss, 0, sizeof ss); ss.ss_family = (ADDRESS_FAMILY)rows[i].fam;
        sat(&h, rows[i].hi->tag, &ss, 8, E_FAULT, 0, 0, "short, foreign");
        sat(&h, rows[i].hi->tag, &ss, 15, E_FAULT, 0, 0, "15, foreign");
        sat(&h, rows[i].hi->tag, &ss, 16, E_AFNOSUPPORT, 0, 0, "16, foreign");
    }
}

/* ---- IPv6 helper ---- */
static const BYTE loop6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
static const BYTE mapped_loop6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 };
static const BYTE mcast6[16] = { 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
static const BYTE ll6[16] = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
static const BYTE two6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

TEST(sat_v6_address_and_port_classes) {
    anc_wsh h; if (!anc_begin(&h, &anc_ip6)) return;
    static const struct { const BYTE *a; DWORD cls; const char *n; } addrs[] = { { NULL, ADDR_WILDCARD, "::" }, { loop6, ADDR_LOOPBACK, "::1" },
        { mapped_loop6, ADDR_NORMAL, "::ffff:127.0.0.1" }, { mcast6, ADDR_NORMAL, "ff02::1" }, { ll6, ADDR_NORMAL, "fe80::1" }, { two6, ADDR_NORMAL, "::2" } };
    static const struct { unsigned port; DWORD cls; } ports[] = { { 0, PORT_WILDCARD }, { 1, PORT_RESERVED }, { 1999, PORT_RESERVED }, { 2000, PORT_NORMAL }, { 40000, PORT_NORMAL } };
    for (size_t i = 0; i < ANC_N(addrs); i++) for (size_t j = 0; j < ANC_N(ports); j++) {
        SOCKADDR_IN6 a = v6(addrs[i].a, ports[j].port, 0); char w[64]; sprintf(w, "%s port %u", addrs[i].n, ports[j].port);
        sat(&h, "wship6", &a, 28, 0, addrs[i].cls, ports[j].cls, w);
    }
}

TEST(sat_v6_scope_and_flow_do_not_change_the_class) {
    anc_wsh h; if (!anc_begin(&h, &anc_ip6)) return;
    SOCKADDR_IN6 a = v6(loop6, 0, 7); a.sin6_flowinfo = 0x01020304;
    sat(&h, "wship6", &a, 28, 0, ADDR_LOOPBACK, PORT_WILDCARD, "::1%7 with flow");
    a = v6(NULL, 3000, 9);
    sat(&h, "wship6", &a, 28, 0, ADDR_WILDCARD, PORT_NORMAL, ":: scope 9");
}

TEST(sat_v6_length_protocol) {
    anc_wsh h; if (!anc_begin(&h, &anc_ip6)) return;
    SOCKADDR_STORAGE ss; SOCKADDR_IN6 a = v6(loop6, 0, 0); memset(&ss, 0, sizeof ss); memcpy(&ss, &a, sizeof a);
    for (DWORD l = 0; l <= 40; l++) {
        char w[32]; sprintf(w, "len %lu", l);
        if (l < 16) sat(&h, "wship6", &ss, l, E_FAULT, 0, 0, w);
        else sat(&h, "wship6", &ss, l, 0, ADDR_LOOPBACK, PORT_WILDCARD, w);   /* only the first 16 bytes are required up front */
    }
}

/* ---- Bluetooth helper ---- */
TEST(sat_bth_wildcard_and_port_classes) {
    anc_wsh h; if (!anc_begin(&h, &anc_bth)) return;
    anc_sockaddr_bth a; memset(&a, 0, sizeof a); a.family = 32;
    sat(&h, "wshbth", &a, 30, 0, 1, 1, "all zero");
    a.bt_addr = 0x112233445566ULL; sat(&h, "wshbth", &a, 30, 0, 0, 1, "address set");
    a.bt_addr = 0; a.port = 5; sat(&h, "wshbth", &a, 30, 0, 1, 0, "port set");
    a.bt_addr = 1; sat(&h, "wshbth", &a, 30, 0, 0, 0, "address and port set");
    a.bt_addr = 0; a.port = 0; a.service.Data1 = 0x1234; sat(&h, "wshbth", &a, 30, 0, 1, 1, "service class id is not inspected");
}

TEST(sat_bth_length_protocol) {
    anc_wsh h; if (!anc_begin(&h, &anc_bth)) return;
    BYTE buf[64]; memset(buf, 0, sizeof buf); *(USHORT *)buf = 32;
    for (DWORD l = 0; l <= 40; l++) {
        char w[32]; sprintf(w, "len %lu", l);
        if (l < 30) sat(&h, "wshbth", buf, l, E_FAULT, 0, 0, w);
        else sat(&h, "wshbth", buf, l, 0, 1, 1, w);
    }
}

TEST(sat_bth_family_check_precedes_length_check) {
    anc_wsh h; if (!anc_begin(&h, &anc_bth)) return;
    SOCKADDR_IN a = v4(0, 0);
    for (DWORD l = 0; l <= 32; l += 4) { char w[32]; sprintf(w, "v4 len %lu", l); sat(&h, "wshbth", &a, l, E_AFNOSUPPORT, 0, 0, w); }
}

/* ---- wildcard / broadcast address construction ---- */
static int all_zero(const BYTE *p, size_t n) { for (size_t i = 0; i < n; i++) if (p[i]) return 0; return 1; }
static int all_fill(const BYTE *p, size_t n) { for (size_t i = 0; i < n; i++) if (p[i] != ANC_FILL) return 0; return 1; }

/* Build into a 256-byte canvas of fill bytes and report; checks the result region and that nothing else moved. */
static void build(const anc_wsh *h, int bcast, PVOID ctx, INT inlen, INT want_rc, INT want_outlen, USHORT want_family, const char *who, const char *what) {
    BYTE buf[256]; INT len = inlen; memset(buf, ANC_FILL, sizeof buf);
    pWSHGetWildcardSockaddr f = bcast ? h->GetBroadcastSockaddr : h->GetWildcardSockaddr;
    INT r = f(ctx, (PSOCKADDR)buf, &len);
    CHECKF(r == want_rc, "%s %s: rc %d want %d", who, what, r, want_rc);
    CHECKF(len == want_outlen, "%s %s: length %d want %d", who, what, len, want_outlen);
    if (want_family == 0) { CHECKF(all_fill(buf, sizeof buf), "%s %s: buffer written on failure", who, what); return; }
    CHECKF(*(USHORT *)buf == want_family, "%s %s: family %u want %u", who, what, *(USHORT *)buf, want_family);
    CHECKF(all_fill(buf + want_outlen, sizeof buf - want_outlen), "%s %s: bytes beyond the result changed", who, what);
}

TEST(wild_v4_helper_sizes_and_bytes) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    PVOID ctxs[] = { (PVOID)(ULONG_PTR)AF_INET, NULL, (PVOID)(ULONG_PTR)99, (PVOID)(ULONG_PTR)1 };
    for (size_t c = 0; c < ANC_N(ctxs); c++) {
        for (INT l = 0; l < 16; l += 5) build(&h, 0, ctxs[c], l, E_FAULT, l, 0, "wshtcpip", "short buffer");
        build(&h, 0, ctxs[c], 15, E_FAULT, 15, 0, "wshtcpip", "15 bytes");
        BYTE buf[64]; INT len = 64; memset(buf, ANC_FILL, sizeof buf);
        CHECK(h.GetWildcardSockaddr(ctxs[c], (PSOCKADDR)buf, &len) == 0);
        CHECK(len == 16); CHECK(*(USHORT *)buf == AF_INET); CHECK(all_zero(buf + 2, 6)); CHECK(all_fill(buf + 8, 8)); CHECK(all_fill(buf + 16, 48));   /* family, port and address are written; the padding is not */
        len = 16; memset(buf, ANC_FILL, sizeof buf);
        CHECK(h.GetWildcardSockaddr(ctxs[c], (PSOCKADDR)buf, &len) == 0); CHECK(len == 16);
    }
}

TEST(wild_v4_helper_with_v6_context_builds_an_ipv6_wildcard) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    BYTE buf[64]; INT len = 128 > 64 ? 64 : 64; memset(buf, ANC_FILL, sizeof buf);
    CHECK(h.GetWildcardSockaddr((PVOID)(ULONG_PTR)AF_INET6, (PSOCKADDR)buf, &len) == 0);
    CHECK(len == 28); CHECK(*(USHORT *)buf == AF_INET6); CHECK(all_zero(buf + 2, 26)); CHECK(all_fill(buf + 28, 36));
    len = 27; memset(buf, ANC_FILL, sizeof buf);
    CHECK(h.GetWildcardSockaddr((PVOID)(ULONG_PTR)AF_INET6, (PSOCKADDR)buf, &len) == E_FAULT); CHECK(len == 27); CHECK(all_fill(buf, sizeof buf));
}

TEST(bcast_v4_helper_is_all_ones) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    PVOID ctxs[] = { (PVOID)(ULONG_PTR)AF_INET, NULL, (PVOID)(ULONG_PTR)99 };
    for (size_t c = 0; c < ANC_N(ctxs); c++) {
        BYTE buf[64]; INT len = 64; memset(buf, ANC_FILL, sizeof buf);
        CHECK(h.GetBroadcastSockaddr(ctxs[c], (PSOCKADDR)buf, &len) == 0);
        CHECK(len == 16); CHECK(*(USHORT *)buf == AF_INET); CHECK(all_zero(buf + 2, 2));
        CHECK(buf[4] == 0xff && buf[5] == 0xff && buf[6] == 0xff && buf[7] == 0xff); CHECK(all_zero(buf + 8, 8)); CHECK(all_fill(buf + 16, 48));
        build(&h, 1, ctxs[c], 15, E_FAULT, 15, 0, "wshtcpip", "bcast 15 bytes");
        build(&h, 1, ctxs[c], 0, E_FAULT, 0, 0, "wshtcpip", "bcast 0 bytes");
    }
}

TEST(bcast_v4_helper_rejects_a_v6_context) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    build(&h, 1, (PVOID)(ULONG_PTR)AF_INET6, 128, E_NOPROTOOPT, 128, 0, "wshtcpip", "bcast with v6 context");
    build(&h, 1, (PVOID)(ULONG_PTR)AF_INET6, 28, E_NOPROTOOPT, 28, 0, "wshtcpip", "bcast with v6 context, 28");
}

TEST(wild_v6_helper_sizes_and_bytes) {
    anc_wsh h; if (!anc_begin(&h, &anc_ip6)) return;
    PVOID ctx6 = (PVOID)(ULONG_PTR)AF_INET6;
    for (INT l = 0; l < 28; l += 3) build(&h, 0, ctx6, l, E_FAULT, l, 0, "wship6", "short buffer");
    build(&h, 0, ctx6, 27, E_FAULT, 27, 0, "wship6", "27 bytes");
    build(&h, 0, ctx6, 28, 0, 28, AF_INET6, "wship6", "28 bytes");
    build(&h, 0, ctx6, 29, 0, 28, AF_INET6, "wship6", "29 bytes");
    build(&h, 0, ctx6, 200, 0, 28, AF_INET6, "wship6", "200 bytes");
    BYTE buf[64]; INT len = 64; memset(buf, ANC_FILL, sizeof buf);
    CHECK(h.GetWildcardSockaddr(ctx6, (PSOCKADDR)buf, &len) == 0); CHECK(all_zero(buf + 2, 26));
}

TEST(wild_v6_helper_other_contexts_build_an_ipv4_wildcard) {
    anc_wsh h; if (!anc_begin(&h, &anc_ip6)) return;
    PVOID ctxs[] = { (PVOID)(ULONG_PTR)AF_INET, NULL, (PVOID)(ULONG_PTR)32, (PVOID)(ULONG_PTR)99 };
    for (size_t c = 0; c < ANC_N(ctxs); c++) {
        build(&h, 0, ctxs[c], 15, E_FAULT, 15, 0, "wship6", "v4-shaped, 15 bytes");
        build(&h, 0, ctxs[c], 16, 0, 16, AF_INET, "wship6", "v4-shaped, 16 bytes");
        build(&h, 0, ctxs[c], 100, 0, 16, AF_INET, "wship6", "v4-shaped, 100 bytes");
    }
}

TEST(wild_bth_helper_sizes_and_bytes) {
    anc_wsh h; if (!anc_begin(&h, &anc_bth)) return;
    PVOID ctxs[] = { NULL, (PVOID)(ULONG_PTR)AF_INET, (PVOID)(ULONG_PTR)AF_INET6 };
    for (size_t c = 0; c < ANC_N(ctxs); c++) {
        for (INT l = 0; l < 30; l += 4) build(&h, 0, ctxs[c], l, E_FAULT, l, 0, "wshbth", "short buffer");
        build(&h, 0, ctxs[c], 29, E_FAULT, 29, 0, "wshbth", "29 bytes");
        build(&h, 0, ctxs[c], 30, 0, 30, 32, "wshbth", "30 bytes");
        build(&h, 0, ctxs[c], 31, 0, 30, 32, "wshbth", "31 bytes");
        build(&h, 0, ctxs[c], 250, 0, 30, 32, "wshbth", "250 bytes");
    }
    BYTE buf[64]; INT len = 64; memset(buf, ANC_FILL, sizeof buf);
    CHECK(h.GetWildcardSockaddr(NULL, (PSOCKADDR)buf, &len) == 0); CHECK(all_zero(buf + 2, 28)); CHECK(all_fill(buf + 30, 34));
}

TEST(wild_bth_context_from_open_socket_is_accepted) {
    anc_wsh h; if (!anc_begin(&h, &anc_bth)) return;
    PVOID ctx = anc_open_ctx(&h, &anc_bth, SOCK_STREAM, 3);
    if (!ctx) { t_skip("could not open a helper context"); return; }
    build(&h, 0, ctx, 30, 0, 30, 32, "wshbth", "wildcard with context");
    build(&h, 1, ctx, 30, E_INVAL, 30, 32, "wshbth", "broadcast with context");
    anc_close_ctx(&h, ctx);
}

TEST(bcast_bth_helper_fails_with_invalid_argument_but_reports_the_size) {
    anc_wsh h; if (!anc_begin(&h, &anc_bth)) return;
    for (INT l = 0; l < 30; l += 5) build(&h, 1, NULL, l, E_FAULT, l, 0, "wshbth", "bcast short");
    build(&h, 1, NULL, 29, E_FAULT, 29, 0, "wshbth", "bcast 29");
    build(&h, 1, NULL, 30, E_INVAL, 30, 32, "wshbth", "bcast 30");
    build(&h, 1, NULL, 200, E_INVAL, 30, 32, "wshbth", "bcast 200");
}

TEST(wild_contexts_from_open_socket_select_the_family) {
    /* the context handed out by WSHOpenSocket2 drives the family of the wildcard address */
    anc_wsh t, v;
    if (anc_load_wsh(&t, "wshtcpip.dll")) {
        PVOID c = anc_open_ctx(&t, &anc_tcp, SOCK_DGRAM, 17);
        if (c) { build(&t, 0, c, 64, 0, 16, AF_INET, "wshtcpip", "ctx from open"); anc_close_ctx(&t, c); } else t_note("wshtcpip open failed");
    }
    if (anc_load_wsh(&v, "wship6.dll")) {
        PVOID c = anc_open_ctx(&v, &anc_ip6, SOCK_STREAM, 6);
        if (c) { build(&v, 0, c, 64, 0, 28, AF_INET6, "wship6", "ctx from open"); anc_close_ctx(&v, c); } else t_note("wship6 open failed");
    }
}
