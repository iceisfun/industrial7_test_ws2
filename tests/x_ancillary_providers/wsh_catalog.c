/* Catalogue data of the Winsock helper DLLs: WSHGetWinsockMapping (supported triples), WSHEnumProtocols (the
 * PROTOCOL_INFOW records), WSHGetProviderGuid and WSHGetWSAProtocolInfo (the catalogue entries the helper installs).
 * Measures: the mapping table size protocol and its exact triples, the record count / required-size / buffer layout
 * of the enumeration for every protocol filter (names are packed from the end of the buffer), the per-helper provider
 * GUIDs and their case-insensitive names, and the static WSAPROTOCOL_INFOW arrays. */
#include "anc.h"

/* ---- WSHGetWinsockMapping ---- */
typedef struct { DWORD rows, cols; DWORD t[8][3]; } map_expect;
static const map_expect map_tcp = { 8, 3, { { 2, 1, 6 }, { 2, 1, 0 }, { 2, 0, 6 }, { 2, 2, 17 }, { 2, 2, 0 }, { 2, 0, 17 }, { 2, 3, 255 }, { 2, 3, 0 } } };
static const map_expect map_ip6 = { 8, 3, { { 23, 1, 6 }, { 23, 1, 0 }, { 23, 0, 6 }, { 23, 2, 17 }, { 23, 2, 0 }, { 23, 0, 17 }, { 23, 3, 255 }, { 23, 3, 0 } } };
static const map_expect map_bth = { 4, 3, { { 32, 1, 256 }, { 32, 0, 256 }, { 32, 1, 3 }, { 32, 0, 3 } } };

static void mapping(const anc_hinfo *hi, const map_expect *e) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    DWORD need = 8 + e->rows * 12;
    DWORD buf[128];
    /* the return value is the size the full table needs, for every buffer size */
    for (DWORD l = 0; l < need; l += (l + 4 < need ? 4 : 1)) {
        memset(buf, 0xEE, sizeof buf);
        DWORD r = h.GetWinsockMapping(buf, l);
        CHECKF(r == need, "%s len %lu: returned %lu want %lu", hi->tag, l, r, need);
        CHECKF(buf[0] == 0xEEEEEEEEu && buf[1] == 0xEEEEEEEEu, "%s len %lu: table written into a short buffer", hi->tag, l);
    }
    DWORD sizes[] = { need, need + 1, need + 40, 400 };
    for (size_t k = 0; k < ANC_N(sizes); k++) {
        memset(buf, 0xEE, sizeof buf);
        DWORD r = h.GetWinsockMapping(buf, sizes[k]);
        CHECKF(r == need, "%s len %lu: returned %lu", hi->tag, sizes[k], r);
        CHECKF(buf[0] == e->rows && buf[1] == e->cols, "%s len %lu: header %lu x %lu", hi->tag, sizes[k], buf[0], buf[1]);
        for (DWORD i = 0; i < e->rows; i++) for (int c = 0; c < 3; c++)
            CHECKF(buf[2 + i * 3 + c] == e->t[i][c], "%s row %lu col %d: %lu want %lu", hi->tag, i, c, buf[2 + i * 3 + c], e->t[i][c]);
        CHECKF(buf[2 + e->rows * 3] == 0xEEEEEEEEu, "%s len %lu: wrote past the table", hi->tag, sizes[k]);
    }
}
TEST(mapping_wshtcpip) { mapping(&anc_tcp, &map_tcp); }
TEST(mapping_wship6) { mapping(&anc_ip6, &map_ip6); }
TEST(mapping_wshbth) { mapping(&anc_bth, &map_bth); }

TEST(mapping_sizes_are_header_plus_twelve_bytes_per_row) {
    anc_wsh t, v, b; DWORD buf[128];
    if (anc_load_wsh(&t, "wshtcpip.dll")) CHECK(t.GetWinsockMapping(buf, 0) == 0x68);
    if (anc_load_wsh(&v, "wship6.dll")) CHECK(v.GetWinsockMapping(buf, 0) == 0x68);
    if (anc_load_wsh(&b, "wshbth.dll")) CHECK(b.GetWinsockMapping(buf, 0) == 0x38);
}

/* ---- WSHEnumProtocols ---- */
typedef struct { INT proto; DWORD flags; INT af, maxsa, minsa, type; DWORD msg; const WCHAR *name; } enum_rec;
typedef struct {
    const anc_hinfo *hi; enum_rec tcp, udp; int has_udp;
    DWORD need_tcp, need_udp, need_both;
} enum_desc;

static const enum_desc ed_tcp = { &anc_tcp, { 6, 0x1066, 2, 16, 16, 1, 0, L"TCP/IP" }, { 17, 0x1609, 2, 16, 16, 2, 0xfff7, L"UDP/IP" }, 1, 0x36, 0x36, 0x6c };
static const enum_desc ed_ip6 = { &anc_ip6, { 6, 0x1066, 23, 28, 28, 1, 0, L"TCP/IPv6" }, { 17, 0x1609, 23, 28, 28, 2, 0xfff7, L"UDP/IPv6" }, 1, 0x3a, 0x3a, 0x74 };

static int rec_ok(const BYTE *base, DWORD buflen, const anc_protocol_info *r, const enum_rec *e, const char *who, const char *what) {
    int ok = 1;
    ok &= (r->service_flags == e->flags); ok &= (r->af == e->af); ok &= (r->max_sockaddr == e->maxsa); ok &= (r->min_sockaddr == e->minsa);
    ok &= (r->type == e->type); ok &= (r->proto == e->proto); ok &= (r->message_size == e->msg);
    ok &= (r->name != NULL && (BYTE *)r->name >= base && (BYTE *)r->name < base + buflen && !wcscmp(r->name, e->name));
    CHECKF(ok, "%s %s: record mismatch (flags %lx af %d type %d proto %d msg %lx)", who, what, r->service_flags, r->af, r->type, r->proto, r->message_size);
    return ok;
}

static void enum_case(const enum_desc *d, const INT *filter, int want_tcp, int want_udp, const char *fname) {
    anc_wsh h; if (!anc_begin(&h, d->hi)) return;
    int n = want_tcp + want_udp;
    DWORD need = n == 2 ? d->need_both : (n == 1 ? (want_tcp ? d->need_tcp : d->need_udp) : 0);
    BYTE buf[0x300];
    /* a buffer one byte short reports the size and the failure marker */
    if (n) {
        DWORD len = need - 1; memset(buf, 0xAB, sizeof buf);
        INT r = h.EnumProtocols((LPINT)filter, L"Tcpip", buf, &len);
        CHECKF(r == -1 && len == need, "%s %s: short buffer rc %d len %lu want %lu", d->hi->tag, fname, r, len, need);
        len = 0; r = h.EnumProtocols((LPINT)filter, L"Tcpip", buf, &len);
        CHECKF(r == -1 && len == need, "%s %s: zero buffer rc %d len %lu", d->hi->tag, fname, r, len);
    }
    DWORD lens[] = { need, need + 1, need + 50, 0x200 };
    for (size_t k = 0; k < ANC_N(lens); k++) {
        if (n && lens[k] < need) continue;
        DWORD len = lens[k]; memset(buf, 0xAB, sizeof buf);
        INT r = h.EnumProtocols((LPINT)filter, L"Tcpip", buf, &len);
        CHECKF(r == n, "%s %s len %lu: count %d want %d", d->hi->tag, fname, lens[k], r, n);
        CHECKF(len == need, "%s %s len %lu: required size %lu want %lu", d->hi->tag, fname, lens[k], len, need);
        if (!n) continue;
        anc_protocol_info *rec = (anc_protocol_info *)buf; int idx = 0; DWORD tail = lens[k];
        if (want_tcp) {
            rec_ok(buf, lens[k], &rec[idx], &d->tcp, d->hi->tag, fname);
            DWORD nb = (DWORD)(wcslen(d->tcp.name) + 1) * 2; tail -= nb;
            CHECKF((BYTE *)rec[idx].name == buf + tail, "%s %s: tcp name at %ld want %lu", d->hi->tag, fname, (long)((BYTE *)rec[idx].name - buf), tail);
            idx++;
        }
        if (want_udp) {
            rec_ok(buf, lens[k], &rec[idx], &d->udp, d->hi->tag, fname);
            DWORD nb = (DWORD)(wcslen(d->udp.name) + 1) * 2; tail -= nb;
            CHECKF((BYTE *)rec[idx].name == buf + tail, "%s %s: udp name at %ld want %lu", d->hi->tag, fname, (long)((BYTE *)rec[idx].name - buf), tail);
        }
        /* the gap between the records and the names is untouched */
        DWORD gap_from = n * 40, gap_to = tail;
        int clean = 1; for (DWORD q = gap_from; q < gap_to; q++) if (buf[q] != 0xAB) { clean = 0; break; }
        CHECKF(clean, "%s %s len %lu: bytes between records and names were written", d->hi->tag, fname, lens[k]);
    }
}

static const INT f_tcp[] = { 6, 0 }, f_udp[] = { 17, 0 }, f_both[] = { 6, 17, 0 }, f_both_r[] = { 17, 6, 0 }, f_dup[] = { 6, 6, 17, 0 };
static const INT f_tcp_x[] = { 1, 6, 58, 0 }, f_udp_x[] = { 1, 17, 255, 0 }, f_none1[] = { 1, 0 }, f_empty[] = { 0 }, f_none2[] = { 255, 3, 0 }, f_none3[] = { 0x100, 0 };

#define EN(prefix, dll_desc) \
    TEST(prefix##_all_protocols_for_null_filter) { enum_case(&dll_desc, NULL, 1, 1, "NULL filter"); } \
    TEST(prefix##_tcp_filter) { enum_case(&dll_desc, f_tcp, 1, 0, "{6}"); } \
    TEST(prefix##_udp_filter) { enum_case(&dll_desc, f_udp, 0, 1, "{17}"); } \
    TEST(prefix##_both_filter) { enum_case(&dll_desc, f_both, 1, 1, "{6,17}"); enum_case(&dll_desc, f_dup, 1, 1, "{6,6,17}"); } \
    TEST(prefix##_filter_order_does_not_reorder_records) { enum_case(&dll_desc, f_both_r, 1, 1, "{17,6}"); } \
    TEST(prefix##_filter_with_extra_unrelated_protocols) { enum_case(&dll_desc, f_tcp_x, 1, 0, "{1,6,58}"); enum_case(&dll_desc, f_udp_x, 0, 1, "{1,17,255}"); } \
    TEST(prefix##_filters_that_match_nothing) { enum_case(&dll_desc, f_none1, 0, 0, "{1}"); enum_case(&dll_desc, f_empty, 0, 0, "{}"); \
        enum_case(&dll_desc, f_none2, 0, 0, "{255,3}"); enum_case(&dll_desc, f_none3, 0, 0, "{256}"); }
EN(enum_wshtcpip, ed_tcp)
EN(enum_wship6, ed_ip6)

static void enum_key_ignored(const enum_desc *d) {
    anc_wsh h; if (!anc_begin(&h, d->hi)) return;
    static const WCHAR *keys[] = { L"Tcpip", L"Tcpip6", L"Bogus", L"", L"BthTdi" };
    for (size_t i = 0; i < ANC_N(keys); i++) {
        BYTE buf[0x200]; DWORD len = sizeof buf;
        INT r = h.EnumProtocols(NULL, (LPWSTR)keys[i], buf, &len);
        CHECKF(r == 2 && len == d->need_both, "%s key '%ls': rc %d len %lu", d->hi->tag, keys[i], r, len);
    }
    BYTE buf[0x200]; DWORD len = sizeof buf;
    CHECK(h.EnumProtocols(NULL, NULL, buf, &len) == 2); CHECK(len == d->need_both);
}
TEST(enum_transport_key_is_ignored_wshtcpip) { enum_key_ignored(&ed_tcp); }
TEST(enum_transport_key_is_ignored_wship6) { enum_key_ignored(&ed_ip6); }

TEST(enum_wshbth_reports_rfcomm_only_when_asked) {
    anc_wsh h; if (!anc_begin(&h, &anc_bth)) return;
    static const struct { INT f[4]; int want; } rows[] = { { { 3, 0 }, 1 }, { { 3, 6, 17, 0 }, 1 }, { { 1, 3, 0 }, 1 }, { { 6, 17, 0 }, 0 }, { { 0 }, 0 }, { { 0x100, 0 }, 0 }, { { 1, 0 }, 0 } };
    for (size_t i = 0; i < ANC_N(rows); i++) {
        BYTE buf[0x200]; DWORD len; INT r;
        memset(buf, 0xAB, sizeof buf); len = sizeof buf;
        r = h.EnumProtocols((LPINT)rows[i].f, NULL, buf, &len);
        CHECKF(r == rows[i].want, "row %zu: count %d want %d", i, r, rows[i].want);
        if (!rows[i].want) { CHECKF(len == 0, "row %zu: length %lu", i, len); continue; }
        CHECKF(len == 0x6c, "row %zu: required size %lu", i, len);
        anc_protocol_info *p = (anc_protocol_info *)buf;
        CHECK(p->service_flags == 6 && p->af == 32 && p->max_sockaddr == 30 && p->min_sockaddr == 30 && p->type == 1 && p->proto == 3 && p->message_size == 0);
        CHECK(p->name != NULL && (BYTE *)p->name == buf + sizeof buf - 14 && !wcscmp(p->name, L"RFCOMM"));
        len = 0x6b; r = h.EnumProtocols((LPINT)rows[i].f, NULL, buf, &len);
        CHECKF(r == -1 && len == 0x6c, "row %zu short: rc %d len %lu", i, r, len);
    }
    BYTE buf[0x200]; DWORD len = sizeof buf;
    CHECK(h.EnumProtocols(NULL, NULL, buf, &len) == 0); CHECK(len == 0);   /* no filter: nothing is enumerated */
}

/* ---- WSHGetProviderGuid ---- */
static void guid_case(const anc_wsh *h, const char *who, const WCHAR *name, int want_ok, const char *want) {
    GUID g; memset(&g, 0xEE, sizeof g);
    INT r = h->GetProviderGuid((LPWSTR)name, &g);
    char s[64]; anc_guid_str(s, &g);
    if (want_ok) { CHECKF(r == 0, "%s '%ls': rc %d", who, name, r); CHECKF(!strcmp(s, want), "%s '%ls': %s want %s", who, name, s, want); }
    else { CHECKF(r == E_INVAL, "%s '%ls': rc %d want WSAEINVAL", who, name, r); CHECKF(!strcmp(s, "{EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE}"), "%s '%ls': output written on failure", who, name); }
}
static const char *G_TCP = "{E70F1AA0-AB8B-11CF-8CA3-00805F48A192}", *G_IP6 = "{F9EAB0C0-26D4-11D0-BBBF-00AA006C34E4}";
static const char *G_BTH = "{42A6920F-E18B-4CD9-AC3C-ED490446EECB}", *G_RFC = "{9FC48064-7298-43E4-B7BD-181F2089792A}";

TEST(guid_wshtcpip_names) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    guid_case(&h, "wshtcpip", L"Tcpip", 1, G_TCP); guid_case(&h, "wshtcpip", L"TCPIP", 1, G_TCP); guid_case(&h, "wshtcpip", L"tcpip", 1, G_TCP);
    static const WCHAR *bad[] = { L"Tcpip6", L"BthTdi", L"RFCOMM", L"", L" Tcpip", L"Tcpip ", L"Tcp", L"Udp", L"Tcpipx", L"\\Device\\Tcp" };
    for (size_t i = 0; i < ANC_N(bad); i++) guid_case(&h, "wshtcpip", bad[i], 0, NULL);
}
TEST(guid_wship6_names) {
    anc_wsh h; if (!anc_begin(&h, &anc_ip6)) return;
    guid_case(&h, "wship6", L"Tcpip6", 1, G_IP6); guid_case(&h, "wship6", L"tcpip6", 1, G_IP6); guid_case(&h, "wship6", L"TCPIP6", 1, G_IP6); guid_case(&h, "wship6", L"TcpIp6", 1, G_IP6);
    static const WCHAR *bad[] = { L"Tcpip", L"BthTdi", L"RFCOMM", L"", L"Tcpip6x", L"Tcpip 6", L"Udp6", L"Tcpip6 " };
    for (size_t i = 0; i < ANC_N(bad); i++) guid_case(&h, "wship6", bad[i], 0, NULL);
}
TEST(guid_wshbth_names) {
    anc_wsh h; if (!anc_begin(&h, &anc_bth)) return;
    guid_case(&h, "wshbth", L"BthTdi", 1, G_BTH); guid_case(&h, "wshbth", L"bthtdi", 1, G_BTH); guid_case(&h, "wshbth", L"BTHTDI", 1, G_BTH);
    guid_case(&h, "wshbth", L"RFCOMM", 1, G_RFC); guid_case(&h, "wshbth", L"rfcomm", 1, G_RFC); guid_case(&h, "wshbth", L"RfComm", 1, G_RFC);
    static const WCHAR *bad[] = { L"Tcpip", L"Tcpip6", L"", L"Bth", L"BthTdi1", L"RFCOMM1", L"L2CAP" };
    for (size_t i = 0; i < ANC_N(bad); i++) guid_case(&h, "wshbth", bad[i], 0, NULL);
}
static void guid_null_args(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    GUID g; memset(&g, 0xEE, sizeof g);
    CHECK(h.GetProviderGuid(NULL, &g) == E_FAULT);
    CHECK(h.GetProviderGuid(hi->af == 32 ? L"BthTdi" : (hi->af == 23 ? L"Tcpip6" : L"Tcpip"), NULL) == E_FAULT);
    CHECK(h.GetProviderGuid(NULL, NULL) == E_FAULT);
    char s[64]; anc_guid_str(s, &g); CHECK(!strcmp(s, "{EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE}"));
}
H3(guid_null_arguments, guid_null_args)

TEST(guid_helpers_have_distinct_guids) {
    anc_wsh t, v, b; GUID g[4]; int n = 0;
    if (anc_load_wsh(&t, "wshtcpip.dll") && t.GetProviderGuid(L"Tcpip", &g[n]) == 0) n++;
    if (anc_load_wsh(&v, "wship6.dll") && v.GetProviderGuid(L"Tcpip6", &g[n]) == 0) n++;
    if (anc_load_wsh(&b, "wshbth.dll")) { if (b.GetProviderGuid(L"BthTdi", &g[n]) == 0) n++; if (b.GetProviderGuid(L"RFCOMM", &g[n]) == 0) n++; }
    for (int i = 0; i < n; i++) for (int j = i + 1; j < n; j++) CHECK(memcmp(&g[i], &g[j], sizeof(GUID)) != 0);
}

/* ---- WSHGetWSAProtocolInfo ---- */
static void proto_info_row(const WSAPROTOCOL_INFOW *p, const char *who, DWORD sf1, int af, int type, int proto, int maxoff, const WCHAR *name, DWORD pflags) {
    CHECKF(p->dwServiceFlags1 == sf1, "%s: service flags %lx want %lx", who, p->dwServiceFlags1, sf1);
    CHECKF(p->iAddressFamily == af && p->iSocketType == type && p->iProtocol == proto, "%s: (%d,%d,%d) want (%d,%d,%d)", who, p->iAddressFamily, p->iSocketType, p->iProtocol, af, type, proto);
    CHECKF(p->iVersion == 2 && p->iProtocolMaxOffset == maxoff, "%s: version %d maxoffset %d", who, p->iVersion, p->iProtocolMaxOffset);
    CHECKF(p->ProtocolChain.ChainLen == 1 && p->ProtocolChain.ChainEntries[0] == 0, "%s: chain length %d", who, p->ProtocolChain.ChainLen);
    CHECKF(!wcscmp(p->szProtocol, name), "%s: name '%ls' want '%ls'", who, p->szProtocol, name);
    CHECKF(p->dwProviderFlags == pflags && p->dwProviderReserved == 0, "%s: provider flags %lx reserved %lx", who, p->dwProviderFlags, p->dwProviderReserved);
}
TEST(wsa_protocol_info_wshtcpip) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    WSAPROTOCOL_INFOW *pi = (void *)1; DWORD n = 77;
    CHECK(h.GetWSAProtocolInfo(L"Tcpip", &pi, &n) == 0); CHECK(n == 3);
    if (n == 3 && pi != (void *)1) {
        proto_info_row(&pi[0], "tcp", 0x20066, 2, 1, 6, 0, L"@%SystemRoot%\\System32\\mswsock.dll,-60100", 8);
        proto_info_row(&pi[1], "udp", 0x20609, 2, 2, 17, 0, L"@%SystemRoot%\\System32\\mswsock.dll,-60101", 8);
        proto_info_row(&pi[2], "raw", 0x20609, 2, 3, 0, 255, L"@%SystemRoot%\\System32\\mswsock.dll,-60102", 0xc);
    }
    static const WCHAR *bad[] = { L"Tcpip6", L"BthTdi", L"RFCOMM", L"zz", L"" };
    for (size_t i = 0; i < ANC_N(bad); i++) { pi = (void *)1; n = 77; CHECKF(h.GetWSAProtocolInfo((LPWSTR)bad[i], &pi, &n) == E_INVAL, "'%ls'", bad[i]); CHECK(pi == (void *)1 && n == 77); }
}
TEST(wsa_protocol_info_wship6) {
    anc_wsh h; if (!anc_begin(&h, &anc_ip6)) return;
    WSAPROTOCOL_INFOW *pi = (void *)1; DWORD n = 77;
    CHECK(h.GetWSAProtocolInfo(L"Tcpip6", &pi, &n) == 0); CHECK(n == 3);
    if (n == 3 && pi != (void *)1) {
        proto_info_row(&pi[0], "tcp6", 0x20066, 23, 1, 6, 0, L"@%SystemRoot%\\System32\\mswsock.dll,-60200", 8);
        proto_info_row(&pi[1], "udp6", 0x20609, 23, 2, 17, 0, L"@%SystemRoot%\\System32\\mswsock.dll,-60201", 8);
        proto_info_row(&pi[2], "raw6", 0x20609, 23, 3, 0, 255, L"@%SystemRoot%\\System32\\mswsock.dll,-60202", 0xc);
    }
    static const WCHAR *bad[] = { L"Tcpip", L"BthTdi", L"RFCOMM", L"zz", L"" };
    for (size_t i = 0; i < ANC_N(bad); i++) { pi = (void *)1; n = 77; CHECKF(h.GetWSAProtocolInfo((LPWSTR)bad[i], &pi, &n) == E_INVAL, "'%ls'", bad[i]); CHECK(pi == (void *)1 && n == 77); }
}
TEST(wsa_protocol_info_wshbth) {
    anc_wsh h; if (!anc_begin(&h, &anc_bth)) return;
    WSAPROTOCOL_INFOW *pi = (void *)1; DWORD n = 77;
    CHECK(h.GetWSAProtocolInfo(L"BthTdi", &pi, &n) == 0); CHECK(n == 1);
    if (n == 1 && pi != (void *)1) proto_info_row(&pi[0], "l2cap", 0x20006, 32, 1, 256, 0, L"MSAFD L2CAP [Bluetooth]", 8);
    pi = (void *)1; n = 77;
    CHECK(h.GetWSAProtocolInfo(L"RFCOMM", &pi, &n) == 0); CHECK(n == 1);
    if (n == 1 && pi != (void *)1) proto_info_row(&pi[0], "rfcomm", 0x20026, 32, 1, 3, 0, L"MSAFD RfComm [Bluetooth]", 8);
    static const WCHAR *bad[] = { L"Tcpip", L"Tcpip6", L"zz", L"" };
    for (size_t i = 0; i < ANC_N(bad); i++) { pi = (void *)1; n = 77; CHECKF(h.GetWSAProtocolInfo((LPWSTR)bad[i], &pi, &n) == E_INVAL, "'%ls'", bad[i]); CHECK(pi == (void *)1 && n == 77); }
}
TEST(wsa_protocol_info_returns_the_same_static_array) {
    anc_wsh h; if (!anc_begin(&h, &anc_ip6)) return;
    WSAPROTOCOL_INFOW *a = NULL, *b = NULL; DWORD n = 0;
    CHECK(h.GetWSAProtocolInfo(L"Tcpip6", &a, &n) == 0); CHECK(h.GetWSAProtocolInfo(L"Tcpip6", &b, &n) == 0);
    CHECK(a != NULL && a == b);
}
