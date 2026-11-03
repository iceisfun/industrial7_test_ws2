/* socket_create: what a freshly created socket says about itself (SO_PROTOCOL_INFO), and creation driven by a
 * WSAPROTOCOL_INFO structure (WSASocket's lpProtocolInfo, the FROM_PROTOCOL_INFO sentinel of -1).
 *
 * Facts relied on:
 *  - the structure returned for a socket is the catalog entry that created it, byte for byte (WSAEnumProtocols
 *    reports the same record), including the provider GUID, the catalog id and the service flags;
 *  - when an lpProtocolInfo is given, WS2 selects the provider by dwCatalogEntryId alone; an id that is not in
 *    the catalog (including 0) fails with WSAEINVAL;
 *  - FROM_PROTOCOL_INFO (-1) for family/type/protocol means "take it from the structure"; without a structure
 *    the -1 values are ordinary (and unsupported) numbers;
 *  - the ANSI variant converts the same record (szProtocol narrowed). */
#include "sc.h"

/* ---- catalog helpers ---- */
static WSAPROTOCOL_INFOW *catalog(int *n) {
    DWORD sz = 0;
    WSAPROTOCOL_INFOW *p;
    *n = 0;
    U(WSAEnumProtocolsW)(NULL, NULL, &sz);
    if (!sz) return NULL;
    p = (WSAPROTOCOL_INFOW *)HeapAlloc(GetProcessHeap(), 0, sz);
    if (!p) return NULL;
    *n = U(WSAEnumProtocolsW)(NULL, p, &sz);
    if (*n <= 0) { HeapFree(GetProcessHeap(), 0, p); *n = 0; return NULL; }
    return p;
}
static void catalog_free(WSAPROTOCOL_INFOW *p) { if (p) HeapFree(GetProcessHeap(), 0, p); }
static const GUID guid_tcpip4 = {0xE70F1AA0, 0xAB8B, 0x11CF, {0x8C, 0xA3, 0x00, 0x80, 0x5F, 0x48, 0xA1, 0x92}};
static const GUID guid_tcpip6 = {0xF9EAB0C0, 0x26D4, 0x11D0, {0xBB, 0xBF, 0x00, 0xAA, 0x00, 0x6C, 0x34, 0xE4}};
static const GUID guid_unix   = {0xA00943D9, 0x9C2E, 0x4633, {0x9B, 0x59, 0x00, 0x57, 0xA3, 0x16, 0x09, 0x94}};

struct kind {
    const char *name;
    int af, ty, pr;                     /* request */
    int rpr, maxoff;                    /* reported protocol / range */
    DWORD pflags, sflags;
    DWORD msgsize;
    int minsa, maxsa;
    const GUID *guid;
    const wchar_t *wname;
};
static const struct kind kinds[] = {
    {"tcp4", AF_INET,  SOCK_STREAM, 0, 6,  0,   0x8, 0x20066, 0,     16, 16,  &guid_tcpip4, L"MSAFD Tcpip [TCP/IP]"},
    {"udp4", AF_INET,  SOCK_DGRAM,  0, 17, 0,   0x8, 0x20609, 65527, 16, 16,  &guid_tcpip4, L"MSAFD Tcpip [UDP/IP]"},
    {"tcp6", AF_INET6, SOCK_STREAM, 0, 6,  0,   0x8, 0x20066, 0,     28, 28,  &guid_tcpip6, L"MSAFD Tcpip [TCP/IPv6]"},
    {"udp6", AF_INET6, SOCK_DGRAM,  0, 17, 0,   0x8, 0x20609, 65527, 28, 28,  &guid_tcpip6, L"MSAFD Tcpip [UDP/IPv6]"},
    {"unix", AF_UNIX,  SOCK_STREAM, 0, 0,  0,   0x8, 0x20026, 0,     2,  110, &guid_unix,   L"AF_UNIX"},
};
static const struct kind raw_kinds[] = {
    {"raw4", AF_INET,  SOCK_RAW, IPPROTO_ICMP, 0, 255, 0xc, 0x20609, 32768, 16, 16, &guid_tcpip4, L"MSAFD Tcpip [RAW/IP]"},
    {"raw6", AF_INET6, SOCK_RAW, 58,           0, 255, 0xc, 0x20609, 32768, 28, 28, &guid_tcpip6, L"MSAFD Tcpip [RAW/IPv6]"},
};

static void check_kind(const struct kind *k) {
    SOCKET s;
    WSAPROTOCOL_INFOW pi;
    s = sc_make(k->af, k->ty, k->pr, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) {
        if (k->ty == SOCK_RAW && sc_err() == WSAEACCES) { t_skip("raw sockets need an elevated token"); return; }
        t_check(0, __FILE__, __LINE__, "creation", "%s error %d", k->name, sc_err());
        return;
    }
    CHECK(sc_getinfo(s, &pi) == 0);
    SC_EQ(pi.iVersion, 2);
    SC_EQ(pi.iAddressFamily, k->af);
    SC_EQ(pi.iSocketType, k->ty);
    SC_EQ(pi.iProtocol, k->rpr);
    SC_EQ(pi.iProtocolMaxOffset, k->maxoff);
    SC_EQ(pi.iNetworkByteOrder, BIGENDIAN);
    SC_EQ(pi.iSecurityScheme, SECURITY_PROTOCOL_NONE);
    SC_EQ(pi.iMinSockAddr, k->minsa);
    SC_EQ(pi.iMaxSockAddr, k->maxsa);
    SC_EQ(pi.dwProviderFlags, k->pflags);
    SC_EQ(pi.dwServiceFlags1, k->sflags);
    SC_EQ(pi.dwServiceFlags2, 0);
    SC_EQ(pi.dwServiceFlags3, 0);
    SC_EQ(pi.dwServiceFlags4, 0);
    SC_EQ(pi.dwMessageSize, k->msgsize);
    SC_EQ(pi.dwProviderReserved, 0);
    SC_EQ(pi.ProtocolChain.ChainLen, 1);            /* a base provider: a chain of one */
    SC_EQ(pi.ProtocolChain.ChainEntries[0], 0);
    CHECK(!memcmp(&pi.ProviderId, k->guid, sizeof(GUID)));
    CHECK(pi.dwCatalogEntryId != 0);
    EXPECT_WSTR(pi.szProtocol, k->wname);
    sc_close(s);
}
TEST(sockcreate_info_fields_tcp4) { SC_UP(); check_kind(&kinds[0]); }
TEST(sockcreate_info_fields_udp4) { SC_UP(); check_kind(&kinds[1]); }
TEST(sockcreate_info_fields_tcp6) { SC_UP(); check_kind(&kinds[2]); }
TEST(sockcreate_info_fields_udp6) { SC_UP(); check_kind(&kinds[3]); }
TEST(sockcreate_info_fields_unix) { SC_UP(); check_kind(&kinds[4]); }
TEST(sockcreate_info_fields_raw4) { SC_UP(); check_kind(&raw_kinds[0]); }
TEST(sockcreate_info_fields_raw6) { SC_UP(); check_kind(&raw_kinds[1]); }

/* the family-wide GUIDs: all Tcpip v4 entries share one provider id, v6 another, AF_UNIX has its own */
TEST(sockcreate_info_provider_guids_shared_per_family) {
    WSAPROTOCOL_INFOW a, b, c;
    SOCKET s1, s2, s3;
    SC_UP();
    s1 = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    s2 = sc_make(AF_INET, SOCK_DGRAM, 0, 1);
    s3 = sc_make(AF_INET6, SOCK_STREAM, 0, 1);
    CHECK(sc_getinfo(s1, &a) == 0 && sc_getinfo(s2, &b) == 0 && sc_getinfo(s3, &c) == 0);
    CHECK(!memcmp(&a.ProviderId, &b.ProviderId, sizeof(GUID)));
    CHECK(memcmp(&a.ProviderId, &c.ProviderId, sizeof(GUID)) != 0);
    CHECK(a.dwCatalogEntryId != b.dwCatalogEntryId);
    sc_close(s1); sc_close(s2); sc_close(s3);
}
/* each of the three protocol names stays pinned to the entry that serves it */
TEST(sockcreate_info_catalog_ids_differ_per_entry) {
    int n = 0, i, j;
    WSAPROTOCOL_INFOW *p;
    SC_UP();
    p = catalog(&n);
    CHECK(n >= 5);
    for (i = 0; i < n; i++)
        for (j = i + 1; j < n; j++)
            t_check(p[i].dwCatalogEntryId != p[j].dwCatalogEntryId, __FILE__, __LINE__, "catalog ids unique", "%d vs %d", i, j);
    catalog_free(p);
}

/* socket info == catalog record, for every entry reachable by its own (family, type, protocol) triple */
TEST(sockcreate_info_socket_record_equals_catalog_entry) {
    int n = 0, i, k, checked = 0;
    WSAPROTOCOL_INFOW *p;
    SC_UP();
    p = catalog(&n);
    for (i = 0; i < n; i++) {
        int first = 1;
        SOCKET s;
        WSAPROTOCOL_INFOW pi;
        if (p[i].iAddressFamily != AF_INET && p[i].iAddressFamily != AF_INET6 && p[i].iAddressFamily != AF_UNIX) continue;
        /* a later entry with the same triple (the RSVP duplicates) is shadowed by the earlier one */
        for (k = 0; k < i; k++)
            if (p[k].iAddressFamily == p[i].iAddressFamily && p[k].iSocketType == p[i].iSocketType && p[k].iProtocol == p[i].iProtocol) first = 0;
        if (!first) continue;
        s = sc_make(p[i].iAddressFamily, p[i].iSocketType, p[i].iProtocol, 0);
        t_check(s != INVALID_SOCKET, __FILE__, __LINE__, "creation by triple", "entry %d error %d", i, sc_err());
        if (s == INVALID_SOCKET) continue;
        CHECK(sc_getinfo(s, &pi) == 0);
        t_check(!memcmp(&pi, &p[i], sizeof pi), __FILE__, __LINE__, "record equals catalog entry", "entry %d", i);
        checked++;
        sc_close(s);
    }
    CHECK(checked >= 5);
    catalog_free(p);
}
TEST(sockcreate_info_shadowed_duplicate_triples_resolve_to_first_entry) {
    int n = 0, i, k, seen = 0;
    WSAPROTOCOL_INFOW *p;
    SC_UP();
    p = catalog(&n);
    for (i = 1; i < n; i++) {
        for (k = 0; k < i; k++)
            if (p[k].iAddressFamily == p[i].iAddressFamily && p[k].iSocketType == p[i].iSocketType &&
                p[k].iProtocol == p[i].iProtocol && (p[i].iAddressFamily == AF_INET || p[i].iAddressFamily == AF_INET6)) {
                SOCKET s = sc_make(p[i].iAddressFamily, p[i].iSocketType, p[i].iProtocol, 0);
                WSAPROTOCOL_INFOW pi;
                CHECK(s != INVALID_SOCKET);
                if (s == INVALID_SOCKET) break;
                CHECK(sc_getinfo(s, &pi) == 0);
                SC_EQ(pi.dwCatalogEntryId, p[k].dwCatalogEntryId);
                seen++;
                sc_close(s);
                break;
            }
    }
    if (!seen) t_skip("no shadowed entries in this catalog");
    catalog_free(p);
}
/* a socket created from an enumerated record carries that record */
TEST(sockcreate_info_from_catalog_record_roundtrip) {
    int n = 0, i, done = 0;
    WSAPROTOCOL_INFOW *p;
    SC_UP();
    p = catalog(&n);
    for (i = 0; i < n; i++) {
        SOCKET s;
        WSAPROTOCOL_INFOW pi;
        int af = p[i].iAddressFamily;
        if (af != AF_INET && af != AF_INET6 && af != AF_UNIX) continue;
        sc_seterr(0);
        s = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &p[i], 0, WSA_FLAG_OVERLAPPED);
        t_check(s != INVALID_SOCKET, __FILE__, __LINE__, "creation from record", "entry %d error %d", i, sc_err());
        if (s == INVALID_SOCKET) continue;
        CHECK(sc_getinfo(s, &pi) == 0);
        t_check(!memcmp(&pi, &p[i], sizeof pi), __FILE__, __LINE__, "record preserved", "entry %d", i);
        SC_EQ(sc_sotype(s), p[i].iSocketType);
        done++;
        sc_close(s);
    }
    CHECK(done >= 5);
    catalog_free(p);
}
TEST(sockcreate_info_from_socket_own_record_roundtrip) {
    static const int rows[][2] = {{AF_INET, SOCK_STREAM}, {AF_INET, SOCK_DGRAM}, {AF_INET6, SOCK_STREAM}, {AF_INET6, SOCK_DGRAM}, {AF_UNIX, SOCK_STREAM}};
    unsigned i;
    SC_UP();
    for (i = 0; i < 5; i++) {
        SOCKET a = sc_make(rows[i][0], rows[i][1], 0, 1), b;
        WSAPROTOCOL_INFOW ia, ib;
        CHECK(a != INVALID_SOCKET);
        if (a == INVALID_SOCKET) continue;
        CHECK(sc_getinfo(a, &ia) == 0);
        b = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &ia, 0, 1);
        CHECK(b != INVALID_SOCKET);
        if (b != INVALID_SOCKET) {
            CHECK(sc_getinfo(b, &ib) == 0);
            CHECK(!memcmp(&ia, &ib, sizeof ia));
            CHECK(a != b);
        }
        sc_close(a); sc_close(b);
    }
}

/* ---- the sentinel on its own ---- */
TEST(sockcreate_info_sentinel_value_is_minus_one) {
    CHECK(FROM_PROTOCOL_INFO == -1);
}
TEST(sockcreate_info_sentinel_without_structure_is_an_unsupported_type) {
    SC_UP();
    sc_seterr(0);
    CHECK(U(WSASocketW)(-1, -1, -1, NULL, 0, 0) == INVALID_SOCKET);
    SC_EQ(sc_err(), WSAESOCKTNOSUPPORT);
    sc_seterr(0);
    CHECK(U(WSASocketA)(-1, -1, -1, NULL, 0, 0) == INVALID_SOCKET);
    SC_EQ(sc_err(), WSAESOCKTNOSUPPORT);
    sc_seterr(0);
    CHECK(U(WSASocketW)(-1, SOCK_STREAM, 0, NULL, 0, 0) == INVALID_SOCKET);
    SC_EQ(sc_err(), WSAEAFNOSUPPORT);
    sc_seterr(0);
    CHECK(U(WSASocketW)(AF_INET, -1, 0, NULL, 0, 0) == INVALID_SOCKET);
    SC_EQ(sc_err(), WSAESOCKTNOSUPPORT);
    sc_seterr(0);
    CHECK(U(WSASocketW)(AF_INET, SOCK_STREAM, -1, NULL, 0, 0) == INVALID_SOCKET);
    SC_EQ(sc_err(), WSAEPROTONOSUPPORT);
}
TEST(sockcreate_info_sentinel_per_field_with_structure) {
    WSAPROTOCOL_INFOW pi;
    SOCKET s, t;
    int i;
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    CHECK(sc_getinfo(s, &pi) == 0);
    sc_close(s);
    for (i = 0; i < 7; i++) {
        int af = (i & 1) ? FROM_PROTOCOL_INFO : AF_INET;
        int ty = (i & 2) ? FROM_PROTOCOL_INFO : SOCK_STREAM;
        int pr = (i & 4) ? FROM_PROTOCOL_INFO : IPPROTO_TCP;
        sc_seterr(0);
        t = U(WSASocketW)(af, ty, pr, &pi, 0, 1);
        t_check(t != INVALID_SOCKET, __FILE__, __LINE__, "partial sentinel", "mask %d error %d", i + 1, sc_err());
        if (t != INVALID_SOCKET) SC_EQ(sc_sotype(t), SOCK_STREAM);
        sc_close(t);
    }
}

/* ---- the catalog id is the key ---- */
TEST(sockcreate_info_unknown_catalog_id_is_einval) {
    static const DWORD ids[] = {0, 1, 999, 0x7fffff00, 0xfffffffeu, 0xffffffffu};
    WSAPROTOCOL_INFOW pi;
    SOCKET s;
    unsigned i;
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    CHECK(sc_getinfo(s, &pi) == 0);
    sc_close(s);
    for (i = 0; i < sizeof ids / sizeof *ids; i++) {
        WSAPROTOCOL_INFOW m = pi;
        m.dwCatalogEntryId = ids[i];
        sc_seterr(0);
        s = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, &m, 0, 1);
        t_check(s == INVALID_SOCKET, __FILE__, __LINE__, "unknown id refused", "id %lu", ids[i]);
        t_check(sc_err() == WSAEINVAL, __FILE__, __LINE__, "error", "id %lu got %d", ids[i], sc_err());
        sc_close(s);
        sc_seterr(0);
        s = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &m, 0, 1);
        t_check(s == INVALID_SOCKET && sc_err() == WSAEINVAL, __FILE__, __LINE__, "sentinel form", "id %lu got %d", ids[i], sc_err());
        sc_close(s);
    }
}
TEST(sockcreate_info_ansi_unknown_catalog_id_is_einval) {
    WSAPROTOCOL_INFOA ia;
    SOCKET s;
    int n = sizeof ia;
    SC_UP();
    s = sc_make(AF_INET, SOCK_DGRAM, 0, 1);
    CHECK(sc_gso(s, SOL_SOCKET, SO_PROTOCOL_INFOA, &ia, &n) == 0);
    sc_close(s);
    ia.dwCatalogEntryId = 0;
    sc_seterr(0);
    s = U(WSASocketA)(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &ia, 0, 1);
    CHECK(s == INVALID_SOCKET);
    SC_EQ(sc_err(), WSAEINVAL);
    ia.dwCatalogEntryId = 0x7fffff00;
    sc_seterr(0);
    s = U(WSASocketA)(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &ia, 0, 1);
    CHECK(s == INVALID_SOCKET);
    SC_EQ(sc_err(), WSAEINVAL);
}
/* only the catalog id of the structure is consulted when the three arguments are explicit */
TEST(sockcreate_info_only_catalog_id_matters_with_explicit_arguments) {
    WSAPROTOCOL_INFOW pi, bare;
    SOCKET s, t;
    WSAPROTOCOL_INFOW got;
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    CHECK(sc_getinfo(s, &pi) == 0);
    sc_close(s);
    memset(&bare, 0, sizeof bare);
    bare.dwCatalogEntryId = pi.dwCatalogEntryId;
    t = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, &bare, 0, 1);
    CHECK(t != INVALID_SOCKET);
    if (t != INVALID_SOCKET) {
        CHECK(sc_getinfo(t, &got) == 0);
        SC_EQ(got.dwCatalogEntryId, pi.dwCatalogEntryId);
        EXPECT_WSTR(got.szProtocol, pi.szProtocol);
    }
    sc_close(t);
}
TEST(sockcreate_info_provider_guid_and_name_in_structure_are_ignored) {
    WSAPROTOCOL_INFOW pi;
    SOCKET s, t;
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    CHECK(sc_getinfo(s, &pi) == 0);
    sc_close(s);
    memset(&pi.ProviderId, 0, sizeof pi.ProviderId);
    lstrcpyW(pi.szProtocol, L"renamed");
    pi.dwServiceFlags1 = 0;
    pi.iVersion = 99;
    t = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, &pi, 0, 1);
    CHECK(t != INVALID_SOCKET);
    if (t != INVALID_SOCKET) {
        WSAPROTOCOL_INFOW got;
        CHECK(sc_getinfo(t, &got) == 0);
        EXPECT_WSTR(got.szProtocol, L"MSAFD Tcpip [TCP/IP]");      /* the catalog record, not the caller's copy */
        SC_EQ(got.iVersion, 2);
        SC_EQ(got.dwCatalogEntryId, pi.dwCatalogEntryId);
    }
    sc_close(t);
}
/* the structure selects the entry; the explicit type argument still decides SO_TYPE */
TEST(sockcreate_info_entry_from_structure_type_from_arguments) {
    WSAPROTOCOL_INFOW tcp;
    SOCKET s, t;
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    CHECK(sc_getinfo(s, &tcp) == 0);
    sc_close(s);
    t = U(WSASocketW)(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &tcp, 0, 1);
    CHECK(t != INVALID_SOCKET);
    if (t != INVALID_SOCKET) {
        WSAPROTOCOL_INFOW got;
        CHECK(sc_getinfo(t, &got) == 0);
        SC_EQ(got.dwCatalogEntryId, tcp.dwCatalogEntryId);
        SC_EQ(sc_sotype(t), SOCK_DGRAM);
    }
    sc_close(t);
}
TEST(sockcreate_info_structure_with_mismatched_zero_arguments) {
    WSAPROTOCOL_INFOW tcp;
    SOCKET s, t;
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    CHECK(sc_getinfo(s, &tcp) == 0);
    sc_close(s);
    sc_seterr(0);
    t = U(WSASocketW)(AF_UNSPEC, 0, IPPROTO_UDP, &tcp, 0, 1);     /* protocol 17 against the TCP entry */
    CHECK(t == INVALID_SOCKET);
    SC_EQ(sc_err(), WSAEPROTOTYPE);
    sc_close(t);
    t = U(WSASocketW)(AF_UNSPEC, 0, 0, &tcp, 0, 1);
    CHECK(t != INVALID_SOCKET);
    if (t != INVALID_SOCKET) SC_EQ(sc_sotype(t), SOCK_STREAM);
    sc_close(t);
    t = U(WSASocketW)(AF_INET, 0, 0, &tcp, 0, 1);
    CHECK(t != INVALID_SOCKET);
    if (t != INVALID_SOCKET) SC_EQ(sc_sotype(t), SOCK_STREAM);
    sc_close(t);
}
/* a hidden RAW entry has an id too, and its record can be used to open a raw socket */
TEST(sockcreate_info_hidden_raw_entry_reachable_by_id) {
    WSAPROTOCOL_INFOW raw, got;
    SOCKET s, t;
    SC_UP();
    s = sc_make(AF_INET, SOCK_RAW, IPPROTO_ICMP, 1);
    if (s == INVALID_SOCKET) { t_skip("raw sockets need an elevated token"); return; }
    CHECK(sc_getinfo(s, &raw) == 0);
    sc_close(s);
    sc_seterr(0);
    t = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &raw, 0, 1);
    if (!sc_elevated()) {
        /* the record carries protocol 0, which a non-elevated token may not open as a raw socket */
        CHECK(t == INVALID_SOCKET);
        SC_EQ(sc_err(), WSAEACCES);
        sc_close(t);
        return;
    }
    CHECK(t != INVALID_SOCKET);
    if (t != INVALID_SOCKET) {
        CHECK(sc_getinfo(t, &got) == 0);
        CHECK(!memcmp(&raw, &got, sizeof raw));
        SC_EQ(sc_sotype(t), SOCK_RAW);
    }
    sc_close(t);
}
/* the hidden entry is not part of the enumeration */
TEST(sockcreate_info_enumeration_hides_raw_entries) {
    int n = 0, i;
    WSAPROTOCOL_INFOW *p;
    SC_UP();
    p = catalog(&n);
    for (i = 0; i < n; i++) t_check(p[i].iSocketType != SOCK_RAW, __FILE__, __LINE__, "no raw in enumeration", "entry %d", i);
    for (i = 0; i < n; i++) t_check(!(p[i].dwProviderFlags & PFL_HIDDEN), __FILE__, __LINE__, "no hidden entries", "entry %d", i);
    catalog_free(p);
}

/* ---- the ANSI record ---- */
TEST(sockcreate_info_ansi_record_matches_wide_record) {
    static const int rows[][2] = {{AF_INET, SOCK_STREAM}, {AF_INET, SOCK_DGRAM}, {AF_INET6, SOCK_STREAM}, {AF_UNIX, SOCK_STREAM}};
    unsigned i;
    SC_UP();
    for (i = 0; i < 4; i++) {
        SOCKET s = sc_make(rows[i][0], rows[i][1], 0, 1);
        WSAPROTOCOL_INFOA a;
        WSAPROTOCOL_INFOW w;
        int na = sizeof a;
        char narrow[WSAPROTOCOL_LEN + 1];
        CHECK(s != INVALID_SOCKET);
        if (s == INVALID_SOCKET) continue;
        CHECK(sc_gso(s, SOL_SOCKET, SO_PROTOCOL_INFOA, &a, &na) == 0);
        CHECK(sc_getinfo(s, &w) == 0);
        SC_EQ(a.dwServiceFlags1, w.dwServiceFlags1);
        SC_EQ(a.dwProviderFlags, w.dwProviderFlags);
        SC_EQ(a.dwCatalogEntryId, w.dwCatalogEntryId);
        SC_EQ(a.iAddressFamily, w.iAddressFamily);
        SC_EQ(a.iSocketType, w.iSocketType);
        SC_EQ(a.iProtocol, w.iProtocol);
        SC_EQ(a.iMaxSockAddr, w.iMaxSockAddr);
        SC_EQ(a.dwMessageSize, w.dwMessageSize);
        CHECK(!memcmp(&a.ProviderId, &w.ProviderId, sizeof(GUID)));
        memset(narrow, 0, sizeof narrow);
        WideCharToMultiByte(CP_ACP, 0, w.szProtocol, -1, narrow, sizeof narrow, NULL, NULL);
        EXPECT_STR(a.szProtocol, narrow);
        sc_close(s);
    }
}
TEST(sockcreate_info_ansi_creation_from_ansi_record) {
    DWORD sz = 0;
    int n, i, done = 0;
    WSAPROTOCOL_INFOA *p;
    SC_UP();
    U(WSAEnumProtocolsA)(NULL, NULL, &sz);
    p = (WSAPROTOCOL_INFOA *)HeapAlloc(GetProcessHeap(), 0, sz);
    n = U(WSAEnumProtocolsA)(NULL, p, &sz);
    CHECK(n >= 5);
    for (i = 0; i < n; i++) {
        SOCKET s;
        int af = p[i].iAddressFamily;
        if (af != AF_INET && af != AF_INET6 && af != AF_UNIX) continue;
        s = U(WSASocketA)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &p[i], 0, 1);
        t_check(s != INVALID_SOCKET, __FILE__, __LINE__, "ansi record creation", "entry %d error %d", i, sc_err());
        if (s != INVALID_SOCKET) {
            WSAPROTOCOL_INFOW w;
            CHECK(sc_getinfo(s, &w) == 0);
            SC_EQ(w.dwCatalogEntryId, p[i].dwCatalogEntryId);
            done++;
        }
        sc_close(s);
    }
    CHECK(done >= 5);
    HeapFree(GetProcessHeap(), 0, p);
}

/* ---- buffer protocol of SO_PROTOCOL_INFO ---- */
TEST(sockcreate_info_short_buffer_is_efault) {
    SOCKET s;
    WSAPROTOCOL_INFOW w;
    WSAPROTOCOL_INFOA a;
    int n;
    SC_UP();
    s = sc_make(AF_INET, SOCK_STREAM, 0, 1);
    n = sizeof w - 1;
    sc_seterr(0);
    CHECK(sc_gso(s, SOL_SOCKET, SO_PROTOCOL_INFOW, &w, &n) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSAEFAULT);
    t_note("SO_PROTOCOL_INFOW short buffer: optlen after = %d (record is %d)", n, (int)sizeof w);
    n = sizeof a - 1;
    sc_seterr(0);
    CHECK(sc_gso(s, SOL_SOCKET, SO_PROTOCOL_INFOA, &a, &n) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSAEFAULT);
    t_note("SO_PROTOCOL_INFOA short buffer: optlen after = %d (record is %d)", n, (int)sizeof a);
    n = 0;
    sc_seterr(0);
    CHECK(sc_gso(s, SOL_SOCKET, SO_PROTOCOL_INFOW, &w, &n) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSAEFAULT);
    sc_close(s);
}
TEST(sockcreate_info_oversized_buffer_reports_exact_size) {
    struct { WSAPROTOCOL_INFOW w; char pad[64]; } big;
    SOCKET s;
    int n = sizeof big;
    SC_UP();
    s = sc_make(AF_INET6, SOCK_DGRAM, 0, 1);
    memset(&big, 0, sizeof big);
    CHECK(sc_gso(s, SOL_SOCKET, SO_PROTOCOL_INFOW, &big, &n) == 0);
    SC_EQ(n, sizeof(WSAPROTOCOL_INFOW));
    SC_EQ(big.w.iAddressFamily, AF_INET6);
    sc_close(s);
}
TEST(sockcreate_info_option_is_read_only) {
    SOCKET s;
    WSAPROTOCOL_INFOW w;
    SC_UP();
    s = sc_make(AF_INET, SOCK_DGRAM, 0, 1);
    CHECK(sc_getinfo(s, &w) == 0);
    sc_seterr(0);
    CHECK(sc_sso(s, SOL_SOCKET, SO_PROTOCOL_INFOW, &w, sizeof w) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSAEINVAL);
    sc_close(s);
}
