/* WSCEnumProtocols / WSCEnumProtocols32 / WSCEnumProtocolsEx: the service-provider-side catalog listing.
 * Measures: the buffer-size protocol with the separate error-code out parameter, the relation to the
 * application-side listing (WSAEnumProtocolsW is the WSC list minus hidden entries and layered placeholders,
 * same order, same bytes), the protocol-number filter rule (a number matches an entry when it lies in
 * [iProtocol, iProtocol + iProtocolMaxOffset]) including the hidden raw entries that the application-side
 * list suppresses, enumeration without WSAStartup (the SPI functions do not need it) and the undocumented Ex
 * form rejecting a missing target description. */
#include "pc.h"
#include <stdlib.h>

typedef INT (WSPAPI *enum_c_fn)(LPINT, LPWSAPROTOCOL_INFOW, LPDWORD, LPINT);

static enum_c_fn wscfn(int which) { return (enum_c_fn)t_proc_in("ws2_32.dll", which == 1 ? "WSCEnumProtocols" : "WSCEnumProtocols32"); }

#define WTEST(nm, ...) \
    static void nm##_impl(int which); \
    TEST(wscenum_native_##nm) { PC_NEED_WSA(); REQUIRE(wscfn(1)); nm##_impl(1); } \
    TEST(wscenum_wow_##nm) { PC_NEED_WSA(); REQUIRE(wscfn(2)); nm##_impl(2); } \
    static void nm##_impl(int which) __VA_ARGS__

WTEST(null_buffer_is_size_query, {
    enum_c_fn f = wscfn(which); DWORD len = 0; INT err = 0, r;
    r = f(NULL, NULL, &len, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAENOBUFS);
    CHECK(len > 0);
    EXPECT_EQ(len % PC_INFOW_SIZE, 0);
})

WTEST(zero_length_with_buffer_is_size_query, {
    enum_c_fn f = wscfn(which); DWORD len = 0, want = 0; INT err = 0, r; WSAPROTOCOL_INFOW one;
    f(NULL, NULL, &want, &err);
    err = 0;
    r = f(NULL, &one, &len, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAENOBUFS);
    EXPECT_EQ(len, want);
})

WTEST(null_buffer_big_length_replaced_by_need, {
    enum_c_fn f = wscfn(which); DWORD len = 500000, want = 0; INT err = 0, r;
    f(NULL, NULL, &want, &err);
    err = 0;
    r = f(NULL, NULL, &len, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(len, want);
})

WTEST(one_byte_short_fails, {
    enum_c_fn f = wscfn(which); DWORD len = 0, want = 0; INT err = 0, r; WSAPROTOCOL_INFOW *b;
    f(NULL, NULL, &want, &err);
    b = calloc(1, want);
    REQUIRE(b);
    len = want - 1; err = 0;
    r = f(NULL, b, &len, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAENOBUFS);
    EXPECT_EQ(len, want);
    free(b);
})

WTEST(exact_length_returns_count, {
    enum_c_fn f = wscfn(which); DWORD len = 0, want = 0; INT err = 0, r; WSAPROTOCOL_INFOW *b;
    f(NULL, NULL, &want, &err);
    b = calloc(1, want);
    REQUIRE(b);
    len = want;
    r = f(NULL, b, &len, &err);
    EXPECT_EQ((DWORD)r, want / PC_INFOW_SIZE);
    free(b);
})

WTEST(success_leaves_length, {
    enum_c_fn f = wscfn(which); DWORD len = 0, want = 0; INT err = 0; WSAPROTOCOL_INFOW *b;
    f(NULL, NULL, &want, &err);
    b = calloc(1, want + 3 * PC_INFOW_SIZE);
    REQUIRE(b);
    len = want + 3 * PC_INFOW_SIZE;
    CHECK(f(NULL, b, &len, &err) > 0);
    EXPECT_EQ(len, want + 3 * PC_INFOW_SIZE);
    free(b);
})

WTEST(listing_is_stable, {
    pc_list a, b;
    CHECK(pc_enum_w(which, NULL, &a) > 0);
    CHECK(pc_enum_w(which, NULL, &b) > 0);
    EXPECT_EQ(a.n, b.n);
    if (a.n == b.n && a.n > 0) CHECK(memcmp(a.e, b.e, a.bytes) == 0);
    pc_free(&a); pc_free(&b);
})

WTEST(filter_only_terminator_selects_nothing, {
    enum_c_fn f = wscfn(which); INT filt[] = { 0 }; DWORD len = 0; INT err = 0x1234, r;
    r = f(filt, NULL, &len, &err);
    EXPECT_EQ(r, 0);
})

WTEST(filter_unassigned_protocol_selects_nothing, {
    enum_c_fn f = wscfn(which); INT filt[] = { 0xdead, 0 }; DWORD len = 0; INT err = 0x1234, r;
    r = f(filt, NULL, &len, &err);
    EXPECT_EQ(r, 0);
})

/* The filter rule, evaluated against the unfiltered list, for a spread of protocol numbers. */
static void filter_rule(int which, int proto)
{
    pc_list all, got; INT filt[2]; int i, k, want = 0;
    filt[0] = proto; filt[1] = 0;
    if (pc_enum_w(which, NULL, &all) < 0) { t_skip("enumeration failed"); return; }
    for (i = 0; i < all.n; i++) if (pc_in_range(&all.e[i], proto)) want++;
    pc_enum_w(which, filt, &got);
    EXPECT_EQ(got.n, want);
    for (i = 0, k = 0; i < all.n && k < got.n; i++)
        if (pc_in_range(&all.e[i], proto)) {
            CHECKF(got.e[k].dwCatalogEntryId == all.e[i].dwCatalogEntryId, "proto %d: slot %d is entry %lu want %lu", proto, k, got.e[k].dwCatalogEntryId, all.e[i].dwCatalogEntryId);
            k++;
        }
    pc_free(&all); pc_free(&got);
}

#define FILTER_CASE(nm, proto) \
    TEST(wscenum_native_filter_rule_##nm) { PC_NEED_WSA(); REQUIRE(wscfn(1)); filter_rule(1, proto); } \
    TEST(wscenum_wow_filter_rule_##nm) { PC_NEED_WSA(); REQUIRE(wscfn(2)); filter_rule(2, proto); }

FILTER_CASE(icmp, IPPROTO_ICMP)
FILTER_CASE(igmp, IPPROTO_IGMP)
FILTER_CASE(tcp, IPPROTO_TCP)
FILTER_CASE(udp, IPPROTO_UDP)
FILTER_CASE(icmpv6, IPPROTO_ICMPV6)
FILTER_CASE(raw, IPPROTO_RAW)
FILTER_CASE(one_past_raw_range, 256)
FILTER_CASE(gre, 47)
FILTER_CASE(esp, 50)
FILTER_CASE(max_ip_protocol, 255)

/* A zero is the list terminator, never a value: a list that starts with it is empty even though raw
 * entries have iProtocol 0. */
WTEST(zero_first_means_empty_list, {
    pc_list l; INT filt[] = { 0, IPPROTO_TCP, 0 };
    CHECK(pc_enum_w(which, filt, &l) == 0);
    pc_free(&l);
})

TEST(wscenum_native_filter_icmp_selects_hidden_raw)
{
    pc_list l; INT filt[] = { IPPROTO_ICMP, 0 }; int i, raw4 = 0, raw6 = 0;
    PC_NEED_WSA();
    if (pc_enum_w(1, filt, &l) < 0) { t_skip("enumeration failed"); return; }
    for (i = 0; i < l.n; i++) {
        if (l.e[i].iSocketType == SOCK_RAW && l.e[i].iAddressFamily == AF_INET) raw4++;
        if (l.e[i].iSocketType == SOCK_RAW && l.e[i].iAddressFamily == AF_INET6) raw6++;
    }
    CHECK(raw4 >= 1);
    CHECK(raw6 >= 1);
    pc_free(&l);
}

TEST(wscenum_native_filter_icmp_hides_raw_from_api_list)
{
    pc_list l; INT filt[] = { IPPROTO_ICMP, 0 }; int i;
    PC_NEED_WSA();
    if (pc_enum_w(0, filt, &l) < 0) { l.n = 0; l.e = NULL; }
    for (i = 0; i < l.n; i++) CHECKF(l.e[i].iSocketType != SOCK_RAW, "visible raw entry %lu", l.e[i].dwCatalogEntryId);
    pc_free(&l);
}

/* ---- relation to the application-side list --------------------------------------------------- */
TEST(wscenum_api_list_is_filtered_spi_list)
{
    pc_list api, spi; int i, k = 0;
    PC_NEED_WSA();
    REQUIRE(wscfn(1));
    CHECK(pc_enum_w(0, NULL, &api) > 0);
    CHECK(pc_enum_w(1, NULL, &spi) > 0);
    for (i = 0; i < spi.n; i++) {
        if (spi.e[i].dwProviderFlags & PFL_HIDDEN) continue;
        if (spi.e[i].ProtocolChain.ChainLen == 0) continue;
        if (k >= api.n) { CHECKF(0, "api list ends before spi entry %lu", spi.e[i].dwCatalogEntryId); break; }
        CHECKF(memcmp(&api.e[k], &spi.e[i], offsetof(WSAPROTOCOL_INFOW, szProtocol)) == 0 && lstrcmpW(api.e[k].szProtocol, spi.e[i].szProtocol) == 0,
               "spi entry %lu differs from api slot %d", spi.e[i].dwCatalogEntryId, k);
        k++;
    }
    EXPECT_EQ(k, api.n);
    pc_free(&api); pc_free(&spi);
}

TEST(wscenum_spi_list_is_superset_in_count)
{
    pc_list api, spi;
    PC_NEED_WSA();
    REQUIRE(wscfn(1));
    CHECK(pc_enum_w(0, NULL, &api) > 0);
    CHECK(pc_enum_w(1, NULL, &spi) > 0);
    CHECK(spi.n >= api.n);
    pc_free(&api); pc_free(&spi);
}

TEST(wscenum_spi_lists_hidden_entries)
{
    pc_list spi; int i, hidden = 0;
    PC_NEED_WSA();
    REQUIRE(wscfn(1));
    CHECK(pc_enum_w(1, NULL, &spi) > 0);
    for (i = 0; i < spi.n; i++) if (spi.e[i].dwProviderFlags & PFL_HIDDEN) hidden++;
    CHECKF(hidden >= 2, "only %d hidden entries (raw v4 and v6 expected)", hidden);
    pc_free(&spi);
}

TEST(wscenum_spi_hidden_flag_never_in_api_list)
{
    pc_list api; int i;
    PC_NEED_WSA();
    CHECK(pc_enum_w(0, NULL, &api) > 0);
    for (i = 0; i < api.n; i++) CHECKF(!(api.e[i].dwProviderFlags & PFL_HIDDEN), "entry %d hidden", i);
    pc_free(&api);
}

TEST(wscenum_api_list_has_no_layered_placeholders)
{
    pc_list api; int i;
    PC_NEED_WSA();
    CHECK(pc_enum_w(0, NULL, &api) > 0);
    for (i = 0; i < api.n; i++) CHECKF(api.e[i].ProtocolChain.ChainLen != LAYERED_PROTOCOL, "entry %d is a layered placeholder", i);
    pc_free(&api);
}

/* ---- no WSAStartup needed --------------------------------------------------------------------- */
CHILD(wsc_no_startup)
{
    enum_c_fn f = wscfn(1), g = wscfn(2); DWORD len = 0; INT err = 0, r;
    if (!f || !g) return 90;
    r = f(NULL, NULL, &len, &err);
    if (r != SOCKET_ERROR || err != WSAENOBUFS) return 10;
    if (len == 0 || len % PC_INFOW_SIZE) return 11;
    len = 0; err = 0;
    r = g(NULL, NULL, &len, &err);
    if (r != SOCKET_ERROR || err != WSAENOBUFS) return 12;
    if (len == 0) return 13;
    return 0;
}
TEST(wscenum_works_without_wsastartup) { EXPECT_EQ(t_run_child("wsc_no_startup", "", 30000), 0); }

CHILD(wsa_no_startup_w)
{
    typedef INT (WSAAPI *wfn)(LPINT, LPWSAPROTOCOL_INFOW, LPDWORD);
    wfn f = (wfn)t_proc_in("ws2_32.dll", "WSAEnumProtocolsW"); DWORD len = 0; INT r;
    if (!f) return 90;
    r = f(NULL, NULL, &len);
    if (r != SOCKET_ERROR) return 10;
    if (U(WSAGetLastError)() != WSANOTINITIALISED) return 11;
    return 0;
}
TEST(wsaenum_w_before_startup_is_notinitialised) { EXPECT_EQ(t_run_child("wsa_no_startup_w", "", 30000), 0); }

/* ---- the extended entry point ----------------------------------------------------------------- */
typedef INT (WSPAPI *enum_ex_fn)(LPINT, LPWSAPROTOCOL_INFOW, LPDWORD, LPINT, void *);
TEST(wscenum_ex_without_target_is_einval)
{
    enum_ex_fn f = (enum_ex_fn)t_proc_in("ws2_32.dll", "WSCEnumProtocolsEx"); DWORD len = 0; INT err = 0, r;
    REQUIRE(f);
    r = f(NULL, NULL, &len, &err, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
}

/* Catalog layout facts that hold in every installation. */
TEST(wscenum_entries_names_fit_the_array)
{
    pc_list l; int i, j;
    PC_NEED_WSA();
    CHECK(pc_enum_w(1, NULL, &l) > 0);
    for (i = 0; i < l.n; i++) {
        for (j = 0; j < WSAPROTOCOL_LEN + 1 && l.e[i].szProtocol[j]; j++) ;
        CHECKF(j < WSAPROTOCOL_LEN + 1, "entry %d name not terminated", i);
    }
    pc_free(&l);
}

TEST(wscenum_native_and_wow_both_nonempty)
{
    pc_list a, b;
    PC_NEED_WSA();
    CHECK(pc_enum_w(1, NULL, &a) > 0);
    CHECK(pc_enum_w(2, NULL, &b) > 0);
    t_note("native entries %d, 32-bit entries %d", a.n, b.n);
    pc_free(&a); pc_free(&b);
}
