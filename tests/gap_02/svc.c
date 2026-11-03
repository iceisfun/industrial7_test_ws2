/* Service-class queries and service registration (A and W) against the catalog's real providers, using
 * only requests that cannot change anything: unknown class ids, throwaway ids, a name space that no
 * provider serves, and the DNS provider, which refuses registration.
 * Measures: which provider-selection path is taken for a given name space or provider id, which errors
 * come back unchanged from the provider, that the length argument and the output buffer are left alone
 * when a lookup fails, and that A and W entry points agree.
 * The class-name lookups by class id (A and W) are exercised only without start-up (see pre.c): with a started
 * library they ask every provider, and on this Windows 10 build the directory-service provider's class-info
 * routine faults for any id, so no valid post-start-up test exists for them.
 * Why: the registration entry point picks providers by name space (or by provider id when one is given,
 * ignoring the name space), never inspects dwSize or the operation code itself, and returns the error of
 * the provider it reaches; the DNS provider answers every registration call with ERROR_NOT_SUPPORTED. */
#include "g2.h"

static GUID unknown_class(void) { return g2_guid_throwaway; }

/* ---- class information per provider ---- */

TEST(gap2_svc_getinfo_w_unknown_class_fails_on_every_provider) {
    int n = 0, i; WSANAMESPACE_INFOW *c;
    G2_NEED();
    c = g2_catalog(&n);
    if (!c) { t_skip("no catalog"); return; }
    for (i = 0; i < n; i++) {
        GUID cls = unknown_class(); DWORD len = 0x400; BYTE out[0x400] = { 0 }; INT r;
        W_SETERR(0);
        r = WS(WSAGetServiceClassInfoW)(&c[i].NSProviderId, &cls, &len, (LPWSASERVICECLASSINFOW)out);
        CHECKF(r == SOCKET_ERROR, "name space %lu returned %d", (unsigned long)c[i].dwNameSpace, r);
        /* The DNS provider and the location-awareness provider keep no service classes. */
        if (c[i].dwNameSpace == NS_DNS || c[i].dwNameSpace == NS_NLA)
            CHECKF(W_ERR() == GE_OPNOTSUPP, "name space %lu error %d", (unsigned long)c[i].dwNameSpace, W_ERR());
        else
            t_note("class info, name space %lu: error %d", (unsigned long)c[i].dwNameSpace, W_ERR());
    }
    g2_free(c);
}

TEST(gap2_svc_getinfo_a_matches_w_error_on_every_provider) {
    int n = 0, i; WSANAMESPACE_INFOW *c;
    G2_NEED();
    c = g2_catalog(&n);
    if (!c) { t_skip("no catalog"); return; }
    for (i = 0; i < n; i++) {
        GUID cls = unknown_class(); DWORD lw = 0x400, la = 0x400; BYTE ow[0x400] = { 0 }, oa[0x400] = { 0 }; INT rw, ra; int ew, ea;
        W_SETERR(0);
        rw = WS(WSAGetServiceClassInfoW)(&c[i].NSProviderId, &cls, &lw, (LPWSASERVICECLASSINFOW)ow);
        ew = W_ERR();
        W_SETERR(0);
        ra = WS(WSAGetServiceClassInfoA)(&c[i].NSProviderId, &cls, &la, (LPWSASERVICECLASSINFOA)oa);
        ea = W_ERR();
        CHECKF(rw == ra, "name space %lu: W %d A %d", (unsigned long)c[i].dwNameSpace, rw, ra);
        CHECKF(ew == ea, "name space %lu: W error %d A error %d", (unsigned long)c[i].dwNameSpace, ew, ea);
    }
    g2_free(c);
}

/* The ANSI entry point allocates the caller's length as a work buffer; a zero length is a legal allocation and
 * the wide call underneath still reports its own error. */
TEST(gap2_svc_getinfo_a_zero_length_unregistered_provider) {
    GUID prov = g2_guid_throwaway, cls = g2_guid_throwaway; DWORD len = 0; BYTE out[16];
    G2_NEED();
    W_SETERR(0);
    EXPECT_EQ(WS(WSAGetServiceClassInfoA)(&prov, &cls, &len, (LPWSASERVICECLASSINFOA)out), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), GE_INVAL);
}

TEST(gap2_svc_getinfo_w_zero_length_unregistered_provider) {
    GUID prov = g2_guid_throwaway, cls = g2_guid_throwaway; DWORD len = 0; BYTE out[16];
    G2_NEED();
    W_SETERR(0);
    EXPECT_EQ(WS(WSAGetServiceClassInfoW)(&prov, &cls, &len, (LPWSASERVICECLASSINFOW)out), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), GE_INVAL);
    EXPECT_EQ(len, 0);
}

TEST(gap2_svc_getinfo_failure_leaves_length_and_buffer) {
    GUID prov = g2_guid_throwaway, cls = g2_guid_throwaway; DWORD len = 0x80; BYTE out[0x80]; int i, bad = 0;
    G2_NEED();
    memset(out, 0, sizeof out);
    EXPECT_EQ(WS(WSAGetServiceClassInfoW)(&prov, &cls, &len, (LPWSASERVICECLASSINFOW)out), SOCKET_ERROR);
    EXPECT_EQ(len, 0x80);
    /* The first member of the buffer is where the entry point hands the class id to the provider. */
    for (i = 8; i < 0x80; i++) if (out[i] != 0) bad++;
    CHECKF(bad == 0, "%d bytes behind the first member of the output buffer changed", bad);
}

/* ---- registration against the DNS provider ---- */

static WSAQUERYSETW *dns_set(WSAQUERYSETW *qs, DWORD ns) {
    static WCHAR nm[] = L"ws2t-throwaway-service";
    g2_qs_w(qs, nm, &g2_guid_throwaway, ns);
    return qs;
}

typedef struct { int op; DWORD flags; } op_row;
static const op_row op_rows[] = {
    { RNRSERVICE_REGISTER, 0 }, { RNRSERVICE_DEREGISTER, 0 }, { RNRSERVICE_DELETE, 0 },
    { 3, 0 }, { 0x7fffffff, 0 }, { -1, 0 },
    { RNRSERVICE_REGISTER, 1 }, { RNRSERVICE_REGISTER, 0xffffffffu }, { RNRSERVICE_DELETE, 0x80000000u },
};

TEST(gap2_svc_set_service_dns_every_operation_and_flag) {
    int i; GUID id;
    G2_NEED();
    if (!g2_provider_for(NS_DNS, &id)) { t_skip("no DNS provider"); return; }
    for (i = 0; i < G2_N(op_rows); i++) {
        WSAQUERYSETW qs;
        INT r;
        dns_set(&qs, NS_DNS);
        W_SETERR(0);
        r = WS(WSASetServiceW)(&qs, (WSAESETSERVICEOP)op_rows[i].op, op_rows[i].flags);
        CHECKF(r == SOCKET_ERROR, "row %d returned %d", i, r);
        CHECKF(W_ERR() == GE_NOTSUPP32, "row %d error %d", i, W_ERR());
    }
}

TEST(gap2_svc_set_service_a_dns_every_operation_and_flag) {
    int i; GUID id;
    G2_NEED();
    if (!g2_provider_for(NS_DNS, &id)) { t_skip("no DNS provider"); return; }
    for (i = 0; i < G2_N(op_rows); i++) {
        WSAQUERYSETA qs; static char nm[] = "ws2t-throwaway-service";
        INT r;
        g2_qs_a(&qs, nm, &g2_guid_throwaway, NS_DNS);
        W_SETERR(0);
        r = WS(WSASetServiceA)(&qs, (WSAESETSERVICEOP)op_rows[i].op, op_rows[i].flags);
        CHECKF(r == SOCKET_ERROR, "row %d returned %d", i, r);
        CHECKF(W_ERR() == GE_NOTSUPP32, "row %d error %d", i, W_ERR());
    }
}

/* The size member is not looked at by the registration entry point or the DNS provider. */
TEST(gap2_svc_set_service_w_size_member_is_not_validated) {
    static const DWORD sizes[] = { 0, 1, 0x10, 0x77, 0x78, 0x1000, 0xffffffffu };
    int i; GUID id;
    G2_NEED();
    if (!g2_provider_for(NS_DNS, &id)) { t_skip("no DNS provider"); return; }
    for (i = 0; i < G2_N(sizes); i++) {
        WSAQUERYSETW qs; INT r;
        dns_set(&qs, NS_DNS);
        qs.dwSize = sizes[i];
        W_SETERR(0);
        r = WS(WSASetServiceW)(&qs, RNRSERVICE_REGISTER, 0);
        CHECKF(r == SOCKET_ERROR && W_ERR() == GE_NOTSUPP32, "dwSize 0x%lx: r=%d err=%d", (unsigned long)sizes[i], r, W_ERR());
    }
}

TEST(gap2_svc_set_service_a_size_member_is_not_validated) {
    static const DWORD sizes[] = { 0, 1, 0x50, 0x70, 0xffffffffu };
    int i; GUID id;
    G2_NEED();
    if (!g2_provider_for(NS_DNS, &id)) { t_skip("no DNS provider"); return; }
    for (i = 0; i < G2_N(sizes); i++) {
        WSAQUERYSETA qs; static char nm[] = "ws2t-throwaway-service"; INT r;
        g2_qs_a(&qs, nm, &g2_guid_throwaway, NS_DNS);
        qs.dwSize = sizes[i];
        W_SETERR(0);
        r = WS(WSASetServiceA)(&qs, RNRSERVICE_REGISTER, 0);
        CHECKF(r == SOCKET_ERROR && W_ERR() == GE_NOTSUPP32, "dwSize 0x%lx: r=%d err=%d", (unsigned long)sizes[i], r, W_ERR());
    }
}

/* A provider id selects that provider alone and the name-space member is then ignored. */
TEST(gap2_svc_set_service_provider_id_overrides_namespace) {
    static const DWORD spaces[] = { 0, NS_DNS, NS_NLA, 0x7e57, 0xffffffffu };
    int i; GUID id;
    G2_NEED();
    if (!g2_provider_for(NS_DNS, &id)) { t_skip("no DNS provider"); return; }
    for (i = 0; i < G2_N(spaces); i++) {
        WSAQUERYSETW qs; INT r;
        dns_set(&qs, spaces[i]);
        qs.lpNSProviderId = &id;
        W_SETERR(0);
        r = WS(WSASetServiceW)(&qs, RNRSERVICE_REGISTER, 0);
        CHECKF(r == SOCKET_ERROR && W_ERR() == GE_NOTSUPP32, "name space 0x%lx: r=%d err=%d", (unsigned long)spaces[i], r, W_ERR());
    }
}

/* With a name space nobody serves, nothing else about the query matters. */
TEST(gap2_svc_set_service_unserved_namespace_ignores_other_members) {
    int i;
    G2_NEED();
    for (i = 0; i < 4; i++) {
        WSAQUERYSETW qs; INT r; GUID cls = g2_guid_throwaway;
        dns_set(&qs, 0x7e57);
        if (i == 0) qs.lpServiceClassId = NULL;
        if (i == 1) qs.lpszServiceInstanceName = NULL;
        if (i == 2) { qs.lpServiceClassId = NULL; qs.lpszServiceInstanceName = NULL; }
        if (i == 3) { qs.dwSize = 0; qs.lpServiceClassId = &cls; }
        W_SETERR(0);
        r = WS(WSASetServiceW)(&qs, RNRSERVICE_REGISTER, 0);
        CHECKF(r == SOCKET_ERROR && W_ERR() == GE_NODATA, "variant %d: r=%d err=%d", i, r, W_ERR());
    }
}

TEST(gap2_svc_set_service_a_unserved_namespace_with_sparse_query) {
    WSAQUERYSETA qs;
    G2_NEED();
    g2_qs_a(&qs, NULL, NULL, 0x7e57);
    W_SETERR(0);
    EXPECT_EQ(WS(WSASetServiceA)(&qs, RNRSERVICE_DELETE, 0), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), GE_NODATA);
}

TEST(gap2_svc_set_service_unserved_provider_id_beats_valid_namespace) {
    WSAQUERYSETW qs; GUID ghost = g2_guid_throwaway;
    G2_NEED();
    dns_set(&qs, NS_DNS);
    qs.lpNSProviderId = &ghost;
    W_SETERR(0);
    EXPECT_EQ(WS(WSASetServiceW)(&qs, RNRSERVICE_REGISTER, 0), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), GE_NODATA);   /* the id alone selects, and nobody has it */
}

TEST(gap2_svc_set_service_does_not_modify_query) {
    WSAQUERYSETW qs, before; GUID id;
    G2_NEED();
    if (!g2_provider_for(NS_DNS, &id)) { t_skip("no DNS provider"); return; }
    dns_set(&qs, NS_DNS);
    before = qs;
    WS(WSASetServiceW)(&qs, RNRSERVICE_REGISTER, 0);
    CHECK(!memcmp(&qs, &before, sizeof qs));
}

TEST(gap2_svc_set_service_a_does_not_modify_query) {
    WSAQUERYSETA qs, before; GUID id; static char nm[] = "ws2t-throwaway-service";
    G2_NEED();
    if (!g2_provider_for(NS_DNS, &id)) { t_skip("no DNS provider"); return; }
    g2_qs_a(&qs, nm, &g2_guid_throwaway, NS_DNS);
    before = qs;
    WS(WSASetServiceA)(&qs, RNRSERVICE_REGISTER, 0);
    CHECK(!memcmp(&qs, &before, sizeof qs));
    EXPECT_STR(nm, "ws2t-throwaway-service");
}

/* An unserved name space reports no data even for every operation code, including unknown ones. */
TEST(gap2_svc_set_service_unserved_namespace_every_operation) {
    int i;
    G2_NEED();
    for (i = 0; i < G2_N(op_rows); i++) {
        WSAQUERYSETW qs; INT r;
        dns_set(&qs, 0x7e57);
        W_SETERR(0);
        r = WS(WSASetServiceW)(&qs, (WSAESETSERVICEOP)op_rows[i].op, op_rows[i].flags);
        CHECKF(r == SOCKET_ERROR && W_ERR() == GE_NODATA, "row %d: r=%d err=%d", i, r, W_ERR());
    }
}

/* The error is the same through the wide and ANSI entry points for every unserved name space. */
TEST(gap2_svc_set_service_unserved_namespaces_table) {
    static const DWORD spaces[] = { 0x7e57, 0x1234, 0xfffffffeu, 0x7fffffff, 100, 255 };
    int i;
    G2_NEED();
    for (i = 0; i < G2_N(spaces); i++) {
        WSAQUERYSETW qw; WSAQUERYSETA qa; static char nma[] = "ws2t-throwaway-service"; INT rw, ra; int ew, ea;
        DWORD ns = spaces[i];
        int served = 0, k, n = 0; WSANAMESPACE_INFOW *c = g2_catalog(&n);
        for (k = 0; c && k < n; k++) if (c[k].dwNameSpace == ns) served = 1;
        g2_free(c);
        if (served) continue;
        dns_set(&qw, ns); g2_qs_a(&qa, nma, &g2_guid_throwaway, ns);
        W_SETERR(0); rw = WS(WSASetServiceW)(&qw, RNRSERVICE_REGISTER, 0); ew = W_ERR();
        W_SETERR(0); ra = WS(WSASetServiceA)(&qa, RNRSERVICE_REGISTER, 0); ea = W_ERR();
        CHECKF(rw == SOCKET_ERROR && ra == SOCKET_ERROR && ew == GE_NODATA && ea == GE_NODATA,
               "name space %lu: W %d/%d A %d/%d", (unsigned long)ns, rw, ew, ra, ea);
    }
}

/* ---- ANSI-to-wide conversion of the query set: every combination of present strings ---- */

/* The four string members (instance name, comment, context, query string) in every present/absent mix:
 * conversion never changes the outcome, which depends only on the name space. */
TEST(gap2_svc_set_service_a_string_member_combinations_unserved_namespace) {
    int mask;
    G2_NEED();
    for (mask = 0; mask < 16; mask++) {
        WSAQUERYSETA qs; char n[] = "ws2t-name", c[] = "ws2t-comment", x[] = "\\", q[] = "ws2t=1"; INT r;
        g2_qs_a(&qs, (mask & 1) ? n : NULL, &g2_guid_throwaway, 0x7e57);
        qs.lpszComment = (mask & 2) ? c : NULL;
        qs.lpszContext = (mask & 4) ? x : NULL;
        qs.lpszQueryString = (mask & 8) ? q : NULL;
        W_SETERR(0);
        r = WS(WSASetServiceA)(&qs, RNRSERVICE_REGISTER, 0);
        CHECKF(r == SOCKET_ERROR && W_ERR() == GE_NODATA, "mask %d: r=%d err=%d", mask, r, W_ERR());
    }
}

TEST(gap2_svc_set_service_a_string_member_combinations_dns_namespace) {
    int mask; GUID id;
    G2_NEED();
    if (!g2_provider_for(NS_DNS, &id)) { t_skip("no DNS provider"); return; }
    for (mask = 0; mask < 16; mask++) {
        WSAQUERYSETA qs; char n[] = "ws2t-name", c[] = "ws2t-comment", x[] = "\\", q[] = "ws2t=1"; INT r;
        g2_qs_a(&qs, (mask & 1) ? n : NULL, &g2_guid_throwaway, NS_DNS);
        qs.lpszComment = (mask & 2) ? c : NULL;
        qs.lpszContext = (mask & 4) ? x : NULL;
        qs.lpszQueryString = (mask & 8) ? q : NULL;
        W_SETERR(0);
        r = WS(WSASetServiceA)(&qs, RNRSERVICE_REGISTER, 0);
        CHECKF(r == SOCKET_ERROR && W_ERR() == GE_NOTSUPP32, "mask %d: r=%d err=%d", mask, r, W_ERR());
    }
}

/* A protocol array and a version record are carried through the conversion without changing the outcome. */
TEST(gap2_svc_set_service_a_with_protocols_and_version_unserved_namespace) {
    WSAQUERYSETA qs; static char nm[] = "ws2t-name"; AFPROTOCOLS ap[2] = { { AF_INET, IPPROTO_TCP }, { AF_INET6, IPPROTO_UDP } };
    WSAVERSION ver; INT r;
    G2_NEED();
    g2_qs_a(&qs, nm, &g2_guid_throwaway, 0x7e57);
    qs.dwNumberOfProtocols = 2; qs.lpafpProtocols = ap;
    memset(&ver, 0, sizeof ver); ver.dwVersion = 1; ver.ecHow = COMP_EQUAL;
    qs.lpVersion = &ver;
    W_SETERR(0);
    r = WS(WSASetServiceA)(&qs, RNRSERVICE_REGISTER, 0);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), GE_NODATA);
}
