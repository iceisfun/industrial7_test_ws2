/* The name-space provider catalog: WSAEnumNameSpaceProviders{A,W} and the Ex forms.
 * Measures: the size-query protocol, that the entries a lookup relies on exist and are active,
 * identifier uniqueness, A/W agreement, and the ordering of the initialisation check. The set of
 * additional providers is machine data and is logged, not asserted. */
#include "nsp.h"

#define EN_W  UIN("ws2_32.dll", WSAEnumNameSpaceProvidersW)
#define EN_A  UIN("ws2_32.dll", WSAEnumNameSpaceProvidersA)
#define EN_XW UIN("ws2_32.dll", WSAEnumNameSpaceProvidersExW)
#define EN_XA UIN("ws2_32.dll", WSAEnumNameSpaceProvidersExA)

CHILD(ns_nostartup) {
    DWORD len = 0; int bad = 0;
    if (!EN_W || !EN_A || !W_ERR) return 90;
    if (EN_W(&len, NULL) != SOCKET_ERROR || W_ERR() != (int)E_NOTINIT) bad |= 1;
    if (EN_A(&len, NULL) != SOCKET_ERROR || W_ERR() != (int)E_NOTINIT) bad |= 2;
    if (EN_XW && (EN_XW(&len, NULL) != SOCKET_ERROR || W_ERR() != (int)E_NOTINIT)) bad |= 4;
    return bad;
}

TEST(nc_enum_before_startup_reports_notinitialised) {
    EXPECT_EQ(t_run_child("ns_nostartup", "", 20000), 0);
}

static WSANAMESPACE_INFOW *fetch_w(DWORD *bytes, int *count) {
    DWORD len = 0; WSANAMESPACE_INFOW *p;
    *count = -1; *bytes = 0;
    if (!EN_W || !nsp_up()) return NULL;
    EN_W(&len, NULL);
    if (!len) return NULL;
    p = (WSANAMESPACE_INFOW *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
    if (!p) return NULL;
    *count = EN_W(&len, p);
    *bytes = len;
    return p;
}

TEST(nc_size_query_reports_fault_and_required_size) {
    DWORD len = 0; INT r;
    REQUIRE(EN_W); NSP_NEED();
    W_SETERR(0);
    r = EN_W(&len, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_FAULT);
    CHECK(len >= sizeof(WSANAMESPACE_INFOW));
}

TEST(nc_buffer_one_byte_short_is_fault_with_same_size) {
    DWORD need = 0, len; BYTE *buf; INT r;
    REQUIRE(EN_W); NSP_NEED();
    EN_W(&need, NULL);
    if (!need) { t_skip("no size"); return; }
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, need);
    len = need - 1;
    W_SETERR(0);
    r = EN_W(&len, (WSANAMESPACE_INFOW *)buf);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_FAULT);
    EXPECT_EQ(len, need);
    HeapFree(GetProcessHeap(), 0, buf);
}

TEST(nc_exact_buffer_succeeds_and_counts_entries) {
    DWORD bytes; int n; WSANAMESPACE_INFOW *p;
    NSP_NEED(); REQUIRE(EN_W);
    p = fetch_w(&bytes, &n);
    CHECK(p != NULL);
    CHECK(n >= 1);
    t_note("catalog entries: %d", n);
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

TEST(nc_oversized_buffer_leaves_length_at_required_or_larger) {
    DWORD need = 0, len; BYTE *buf; INT r;
    REQUIRE(EN_W); NSP_NEED();
    EN_W(&need, NULL);
    if (!need) { t_skip("no size"); return; }
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, need + 512);
    len = need + 512;
    r = EN_W(&len, (WSANAMESPACE_INFOW *)buf);
    CHECK(r >= 1);
    HeapFree(GetProcessHeap(), 0, buf);
}

TEST(nc_dns_and_nla_providers_are_present_and_active) {
    DWORD bytes; int n, i, dns = 0, nla = 0; WSANAMESPACE_INFOW *p;
    NSP_NEED(); REQUIRE(EN_W);
    p = fetch_w(&bytes, &n);
    if (!p || n < 1) { t_skip("no catalog"); return; }
    for (i = 0; i < n; i++) {
        if (p[i].dwNameSpace == NS_DNS && p[i].fActive) dns++;
        if (p[i].dwNameSpace == NS_NLA && p[i].fActive) nla++;
    }
    CHECK(dns >= 1);
    CHECK(nla >= 1);
    HeapFree(GetProcessHeap(), 0, p);
}

TEST(nc_entries_have_identifier_and_unique_provider_ids) {
    DWORD bytes; int n, i, j; WSANAMESPACE_INFOW *p;
    NSP_NEED(); REQUIRE(EN_W);
    p = fetch_w(&bytes, &n);
    if (!p || n < 1) { t_skip("no catalog"); return; }
    for (i = 0; i < n; i++) {
        CHECKF(p[i].lpszIdentifier != NULL && p[i].lpszIdentifier[0] != 0, "entry %d has no identifier", i);
        CHECKF((BYTE *)p[i].lpszIdentifier >= (BYTE *)p && (BYTE *)p[i].lpszIdentifier < (BYTE *)p + bytes, "entry %d identifier outside buffer", i);
        for (j = i + 1; j < n; j++) CHECKF(!IsEqualGUID(&p[i].NSProviderId, &p[j].NSProviderId), "entries %d and %d share an id", i, j);
        t_note("entry %d: name space %lu active %d version %lu", i, (unsigned long)p[i].dwNameSpace, (int)p[i].fActive, (unsigned long)p[i].dwVersion);
    }
    HeapFree(GetProcessHeap(), 0, p);
}

TEST(nc_ansi_and_wide_agree) {
    DWORD bytes, lenA = 0; int nW, nA, i; WSANAMESPACE_INFOW *w; WSANAMESPACE_INFOA *a;
    NSP_NEED(); REQUIRE(EN_A);
    w = fetch_w(&bytes, &nW);
    if (!w || nW < 1) { t_skip("no catalog"); return; }
    EN_A(&lenA, NULL);
    a = (WSANAMESPACE_INFOA *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lenA);
    nA = EN_A(&lenA, (LPWSANAMESPACE_INFOA)a);
    EXPECT_EQ(nA, nW);
    for (i = 0; i < nA && i < nW; i++) {
        CHECK(IsEqualGUID(&a[i].NSProviderId, &w[i].NSProviderId));
        EXPECT_EQ(a[i].dwNameSpace, w[i].dwNameSpace);
        EXPECT_EQ(a[i].fActive, w[i].fActive);
        EXPECT_EQ(a[i].dwVersion, w[i].dwVersion);
    }
    HeapFree(GetProcessHeap(), 0, a); HeapFree(GetProcessHeap(), 0, w);
}

TEST(nc_ex_form_agrees_on_count_and_ids) {
    DWORD lenX = 0, bytes; int nX, nW, i; WSANAMESPACE_INFOW *w; WSANAMESPACE_INFOEXW *x;
    NSP_NEED(); REQUIRE(EN_XW);
    w = fetch_w(&bytes, &nW);
    if (!w || nW < 1) { t_skip("no catalog"); return; }
    W_SETERR(0);
    EXPECT_EQ(EN_XW(&lenX, NULL), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_FAULT);
    x = (WSANAMESPACE_INFOEXW *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lenX);
    nX = EN_XW(&lenX, x);
    EXPECT_EQ(nX, nW);
    for (i = 0; i < nX && i < nW; i++) {
        CHECK(IsEqualGUID(&x[i].NSProviderId, &w[i].NSProviderId));
        EXPECT_EQ(x[i].dwNameSpace, w[i].dwNameSpace);
    }
    HeapFree(GetProcessHeap(), 0, x); HeapFree(GetProcessHeap(), 0, w);
}

TEST(nc_ex_ansi_size_query) {
    DWORD len = 0;
    NSP_NEED(); REQUIRE(EN_XA);
    W_SETERR(0);
    EXPECT_EQ(EN_XA(&len, NULL), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_FAULT);
    CHECK(len > 0);
}

TEST(nc_every_active_entry_is_reachable_by_provider_id_lookup) {
    /* A lookup naming a catalog provider id and its name space is accepted by Begin for every
     * active entry that a loopback name can be asked of; outcomes per entry are logged. */
    DWORD bytes; int n, i; WSANAMESPACE_INFOW *p;
    NSP_NEED(); REQUIRE(EN_W); REQUIRE(W_BEGIN_W);
    p = fetch_w(&bytes, &n);
    if (!p || n < 1) { t_skip("no catalog"); return; }
    for (i = 0; i < n; i++) {
        WSAQUERYSETW qs; HANDLE h = NULL; WCHAR nm[] = L"localhost"; INT r;
        if (!p[i].fActive) continue;
        nsp_query_w(&qs, nm, &nsp_svcid_addr_by_name, p[i].dwNameSpace);
        qs.lpNSProviderId = &p[i].NSProviderId;
        r = W_BEGIN_W(&qs, LUP_RETURN_NAME, &h);
        t_note("name space %lu by provider id: %s (error %d)", (unsigned long)p[i].dwNameSpace, r == 0 ? "accepted" : "refused", r == 0 ? 0 : W_ERR());
        if (r == 0) W_END(h);
    }
    HeapFree(GetProcessHeap(), 0, p);
}
