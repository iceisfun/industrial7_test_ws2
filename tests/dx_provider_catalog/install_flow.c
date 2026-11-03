/* WSCInstallProvider, WSCInstallProvider64_32 and WSCDeinstallProvider: the successful paths.
 *
 * Measures what an installed record looks like when read back through the SPI list (WSCEnumProtocols) and the
 * API lists (WSAEnumProtocolsW/A): the catalog id is assigned by the catalog (the caller's value is ignored),
 * the provider id is the one passed to the call (the one inside the record is ignored), records are appended at
 * the end, a chain-length-0 record is forced hidden, hidden records stay out of the API lists, chains keep their
 * member ids, and removing a provider removes every chain that depends on it. The 64_32 variant writes the
 * same record to the 32-bit catalog. All identities are throwaway; the baseline is restored after each test
 * (dx_end checks it). Skipped unless elevated. */
#include "dx.h"
#include <wchar.h>

/* Install a placeholder (idx), a base provider (idx+1) and a chain over them (idx+2). Ids returned. */
typedef struct { GUID gl, gb, gc; DWORD il, ib, ic; } trio;
static int make_trio(trio *t, unsigned idx)
{
    WSAPROTOCOL_INFOW l, b, c;
    t->gl = dx_guid(idx); t->gb = dx_guid(idx + 1); t->gc = dx_guid(idx + 2);
    dx_layered_entry(&l, idx); dx_base_entry(&b, idx);
    if (dx_install_one(&t->gl, &l) || dx_install_one(&t->gb, &b)) return 0;
    t->il = dx_id_of(0, &t->gl); t->ib = dx_id_of(0, &t->gb);
    dx_chain_entry(&c, idx, t->il, t->ib);
    if (dx_install_one(&t->gc, &c)) return 0;
    t->ic = dx_id_of(0, &t->gc);
    return t->il && t->ib && t->ic;
}

/* ---- a base provider read back ---- */

TEST(dxflow_base_appears_in_spi_list)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); dx_list l;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_enum(0, &l) >= 0);
    EXPECT_EQ(dx_count_guid(&l, &g), 1);
    dx_free(&l);
    dx_end();
}
TEST(dxflow_base_fields_round_trip)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); dx_list l; const WSAPROTOCOL_INFOW *e;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    p.dwProviderReserved = 0x13572468; p.dwMessageSize = 0x4000; p.iProtocolMaxOffset = 3;
    p.iNetworkByteOrder = LITTLEENDIAN; p.iSecurityScheme = 0; p.iSocketType = SOCK_DGRAM; p.iProtocol = 17;
    p.dwServiceFlags1 |= XP1_CONNECTIONLESS | XP1_MESSAGE_ORIENTED; p.dwServiceFlags2 = 0x22; p.dwServiceFlags3 = 0x33; p.dwServiceFlags4 = 0x44;
    p.dwProviderFlags = PFL_MATCHES_PROTOCOL_ZERO;
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_enum(0, &l) >= 0);
    e = dx_first_guid(&l, &g);
    CHECK(e != NULL);
    if (e) {
        EXPECT_EQ(e->dwServiceFlags1, p.dwServiceFlags1);
        EXPECT_EQ(e->dwServiceFlags2, 0x22);
        EXPECT_EQ(e->dwServiceFlags3, 0x33);
        EXPECT_EQ(e->dwServiceFlags4, 0x44);
        EXPECT_EQ(e->dwProviderFlags, PFL_MATCHES_PROTOCOL_ZERO);
        EXPECT_EQ(e->ProtocolChain.ChainLen, 1);
        EXPECT_EQ(e->iVersion, 2);
        EXPECT_EQ(e->iAddressFamily, DX_AF_BASE + 1);
        EXPECT_EQ(e->iMaxSockAddr, 16);
        EXPECT_EQ(e->iMinSockAddr, 16);
        EXPECT_EQ(e->iSocketType, SOCK_DGRAM);
        EXPECT_EQ(e->iProtocol, 17);
        EXPECT_EQ(e->iProtocolMaxOffset, 3);
        EXPECT_EQ(e->iNetworkByteOrder, LITTLEENDIAN);
        EXPECT_EQ(e->iSecurityScheme, 0);
        EXPECT_EQ(e->dwMessageSize, 0x4000);
        EXPECT_EQ(e->dwProviderReserved, 0x13572468);
        EXPECT_WSTR(e->szProtocol, L"ws2t dx base");
    }
    dx_free(&l);
    dx_end();
}
TEST(dxflow_name_of_255_units_round_trips)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); dx_list l; const WSAPROTOCOL_INFOW *e;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    for (int i = 0; i < 255; i++) p.szProtocol[i] = (WCHAR)(L'a' + i % 26);
    p.szProtocol[255] = 0;
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_enum(0, &l) >= 0);
    e = dx_first_guid(&l, &g);
    CHECK(e != NULL);
    if (e) EXPECT_WSTR(e->szProtocol, p.szProtocol);
    dx_free(&l);
    dx_end();
}
TEST(dxflow_unicode_name_round_trips)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); dx_list l; const WSAPROTOCOL_INFOW *e;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    lstrcpyW(p.szProtocol, L"ws2t \x00e9\x4e2d\x6587 dx");
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_enum(0, &l) >= 0);
    e = dx_first_guid(&l, &g);
    CHECK(e != NULL);
    if (e) EXPECT_WSTR(e->szProtocol, p.szProtocol);
    dx_free(&l);
    dx_end();
}
TEST(dxflow_catalog_id_is_assigned_not_supplied)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); DWORD id;
    DX_BEGIN();
    dx_base_entry(&p, 1);              /* supplies the id 0xDEADBEEF */
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    id = dx_id_of(0, &g);
    EXPECT_NE(id, 0);
    EXPECT_NE(id, 0xDEADBEEFu);
    dx_end();
}
TEST(dxflow_catalog_id_zero_supplied_is_replaced)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); DWORD id;
    DX_BEGIN();
    dx_base_entry(&p, 1); p.dwCatalogEntryId = 0;
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    id = dx_id_of(0, &g);
    EXPECT_NE(id, 0);
    dx_end();
}
TEST(dxflow_catalog_id_of_existing_entry_supplied_is_ignored)
{
    /* Passing the id of a stock entry must not alias or replace it. */
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); dx_list before, after; DWORD stock;
    DX_BEGIN();
    CHECK(dx_enum(0, &before) > 0);
    stock = before.e[0].dwCatalogEntryId;
    dx_base_entry(&p, 1); p.dwCatalogEntryId = stock;
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_enum(0, &after) >= 0);
    EXPECT_EQ(after.n, before.n + 1);
    EXPECT_NE(dx_id_of(0, &g), stock);
    CHECK(dx_by_id(&after, stock) != NULL);
    dx_free(&before); dx_free(&after);
    dx_end();
}
TEST(dxflow_catalog_ids_stay_unique)
{
    WSAPROTOCOL_INFOW p[4]; GUID g = dx_guid(1); INT err = 0; dx_list l;
    DX_BEGIN();
    for (int i = 0; i < 4; i++) dx_base_entry(&p[i], 1 + i);
    EXPECT_EQ(DX_INSTALL(&g, dx_dll_path(), p, 4, &err), 0);
    CHECK(dx_enum(0, &l) >= 0);
    for (int i = 0; i < l.n; i++)
        for (int j = i + 1; j < l.n; j++)
            if (l.e[i].dwCatalogEntryId == l.e[j].dwCatalogEntryId) CHECKF(0, "duplicate catalog id at %d/%d", i, j);
    dx_free(&l);
    dx_end();
}
TEST(dxflow_later_install_gets_higher_id)
{
    WSAPROTOCOL_INFOW a, b; GUID ga = dx_guid(1), gb = dx_guid(2); DWORD ia, ib;
    DX_BEGIN();
    dx_base_entry(&a, 1); dx_base_entry(&b, 2);
    EXPECT_EQ(dx_install_one(&ga, &a), 0);
    EXPECT_EQ(dx_install_one(&gb, &b), 0);
    ia = dx_id_of(0, &ga); ib = dx_id_of(0, &gb);
    CHECK(ib > ia);
    dx_end();
}
TEST(dxflow_ids_are_not_reused_after_deinstall)
{
    WSAPROTOCOL_INFOW a; GUID ga = dx_guid(1), gb = dx_guid(2); DWORD ia, ib; INT err = 0;
    DX_BEGIN();
    dx_base_entry(&a, 1);
    EXPECT_EQ(dx_install_one(&ga, &a), 0);
    ia = dx_id_of(0, &ga);
    EXPECT_EQ(DX_DEINSTALL(&ga, &err), 0);
    EXPECT_EQ(dx_install_one(&gb, &a), 0);
    ib = dx_id_of(0, &gb);
    CHECK(ib > ia);
    dx_end();
}
TEST(dxflow_batch_ids_ascend_in_record_order)
{
    WSAPROTOCOL_INFOW p[3]; GUID g = dx_guid(1); INT err = 0; dx_list l; int k = 0; DWORD last = 0;
    DX_BEGIN();
    for (int i = 0; i < 3; i++) { dx_base_entry(&p[i], 1 + i); p[i].iProtocol = 100 + i; }
    EXPECT_EQ(DX_INSTALL(&g, dx_dll_path(), p, 3, &err), 0);
    CHECK(dx_enum(0, &l) >= 0);
    for (int i = 0; i < l.n; i++)
        if (!memcmp(&l.e[i].ProviderId, &g, sizeof g)) {
            EXPECT_EQ(l.e[i].iProtocol, 100 + k);
            CHECK(l.e[i].dwCatalogEntryId > last);
            last = l.e[i].dwCatalogEntryId; k++;
        }
    EXPECT_EQ(k, 3);
    dx_free(&l);
    dx_end();
}
TEST(dxflow_record_provider_id_is_replaced_by_argument)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1), other = dx_guid(99);
    DX_BEGIN();
    dx_base_entry(&p, 1); p.ProviderId = other;
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_has_guid(0, &g));
    CHECK(!dx_has_guid(0, &other));
    dx_end();
}
TEST(dxflow_install_appends_at_end)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); dx_list before, after;
    DX_BEGIN();
    CHECK(dx_enum(0, &before) > 0);
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_enum(0, &after) >= 0);
    EXPECT_EQ(after.n, before.n + 1);
    if (after.n == before.n + 1) {
        EXPECT_EQ(memcmp(&after.e[after.n - 1].ProviderId, &g, sizeof g), 0);
        for (int i = 0; i < before.n; i++) EXPECT_EQ(after.e[i].dwCatalogEntryId, before.e[i].dwCatalogEntryId);
    }
    dx_free(&before); dx_free(&after);
    dx_end();
}
TEST(dxflow_second_install_appends_after_first)
{
    WSAPROTOCOL_INFOW a, b; GUID ga = dx_guid(1), gb = dx_guid(2); dx_list l;
    DX_BEGIN();
    dx_base_entry(&a, 1); dx_base_entry(&b, 2);
    EXPECT_EQ(dx_install_one(&ga, &a), 0);
    EXPECT_EQ(dx_install_one(&gb, &b), 0);
    CHECK(dx_enum(0, &l) >= 2);
    if (l.n >= 2) {
        EXPECT_EQ(memcmp(&l.e[l.n - 2].ProviderId, &ga, sizeof ga), 0);
        EXPECT_EQ(memcmp(&l.e[l.n - 1].ProviderId, &gb, sizeof gb), 0);
    }
    dx_free(&l);
    dx_end();
}
TEST(dxflow_install_leaves_other_entries_untouched)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); dx_list before, after;
    DX_BEGIN();
    CHECK(dx_enum(0, &before) > 0);
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_enum(0, &after) > 0);
    if (after.n == before.n + 1)
        for (int i = 0; i < before.n; i++)
            CHECKF(!memcmp(&before.e[i], &after.e[i], sizeof(WSAPROTOCOL_INFOW)), "stock entry %d changed", i);
    dx_free(&before); dx_free(&after);
    dx_end();
}
TEST(dxflow_provider_path_is_stored_as_given)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); WCHAR path[MAX_PATH]; int r;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    r = dx_path_of(&g, path, MAX_PATH);
    EXPECT_EQ(r, 0);
    if (r == 0) CHECKF(!lstrcmpiW(path, dx_dll_path()), "stored path differs");
    dx_end();
}
TEST(dxflow_provider_path_absolute_form_stored_as_given)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); WCHAR path[MAX_PATH], abs_[MAX_PATH + 16]; INT err = 0; int r;
    DX_BEGIN();
    GetSystemDirectoryW(abs_, MAX_PATH); lstrcatW(abs_, L"\\mswsock.dll");
    dx_base_entry(&p, 1);
    EXPECT_EQ(DX_INSTALL(&g, abs_, &p, 1, &err), 0);
    r = dx_path_of(&g, path, MAX_PATH);
    EXPECT_EQ(r, 0);
    if (r == 0) CHECKF(!lstrcmpiW(path, abs_), "stored path differs");
    dx_end();
}

/* ---- visibility in the API lists ---- */

TEST(dxflow_base_visible_in_api_list)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_api_wait_guid(&g, 1));
    dx_end();
}
TEST(dxflow_base_gone_from_api_list_after_deinstall)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); INT err = 0;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_api_wait_guid(&g, 1));
    EXPECT_EQ(DX_DEINSTALL(&g, &err), 0);
    CHECK(dx_api_wait_guid(&g, 0));
    dx_end();
}
TEST(dxflow_hidden_base_stays_out_of_api_list)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_base_entry(&p, 1); p.dwProviderFlags |= PFL_HIDDEN;
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_has_guid(0, &g));
    CHECK(!dx_has_guid(2, &g));
    dx_end();
}
TEST(dxflow_api_record_matches_spi_record)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    EXPECT_EQ(dx_child_query("same 1"), 0);
    dx_end();
}
TEST(dxflow_api_ansi_name_matches)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_base_entry(&p, 1); p.iProtocol = 211;
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    EXPECT_EQ(dx_child_query("ansi 1 211"), 0);
    dx_end();
}
TEST(dxflow_api_lists_entry_once)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    EXPECT_EQ(dx_child_query("count 1 1"), 0);
    dx_end();
}
TEST(dxflow_api_filter_by_protocol)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_base_entry(&p, 1); p.iProtocol = 211;
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    EXPECT_EQ(dx_child_query("filt 211 1"), 0);
    EXPECT_EQ(dx_child_query("filt 212 1"), 1);
    dx_end();
}
TEST(dxflow_api_filter_uses_protocol_max_offset)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_base_entry(&p, 1); p.iProtocol = 220; p.iProtocolMaxOffset = 5;
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    EXPECT_EQ(dx_child_query("filt 225 1"), 0);
    EXPECT_EQ(dx_child_query("filt 226 1"), 1);
    EXPECT_EQ(dx_child_query("filt 219 1"), 1);
    dx_end();
}
TEST(dxflow_spi_filter_by_protocol)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); INT filter[2] = { 211, 0 }; dx_list l;
    DX_BEGIN();
    dx_base_entry(&p, 1); p.iProtocol = 211;
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_enum_f(0, filter, &l) >= 0);
    EXPECT_EQ(dx_count_guid(&l, &g), 1);
    dx_free(&l);
    filter[0] = 210;
    CHECK(dx_enum_f(0, filter, &l) >= 0);
    EXPECT_EQ(dx_count_guid(&l, &g), 0);
    dx_free(&l);
    dx_end();
}
TEST(dxflow_spi_filter_uses_protocol_max_offset)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); INT filter[2] = { 0, 0 }; dx_list l;
    DX_BEGIN();
    dx_base_entry(&p, 1); p.iProtocol = 220; p.iProtocolMaxOffset = 5;
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    filter[0] = 225;
    CHECK(dx_enum_f(0, filter, &l) >= 0);
    EXPECT_EQ(dx_count_guid(&l, &g), 1);
    dx_free(&l);
    filter[0] = 226;
    CHECK(dx_enum_f(0, filter, &l) >= 0);
    EXPECT_EQ(dx_count_guid(&l, &g), 0);
    dx_free(&l);
    dx_end();
}
TEST(dxflow_in_process_api_list_refresh_logged)
{
    /* Whether the process that changed the catalog sees the change in its own API list at once is not
     * part of what is asserted; the persisted state is read in a new process by the other tests. */
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); dx_list l; int seen;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_enum(2, &l) >= 0);
    seen = dx_count_guid(&l, &g) > 0;
    dx_free(&l);
    t_note("API list in the installing process %s the new entry immediately", seen ? "shows" : "does not show");
    dx_end();
}

/* ---- layered placeholders ---- */

TEST(dxflow_placeholder_is_forced_hidden)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); dx_list l; const WSAPROTOCOL_INFOW *e;
    DX_BEGIN();
    dx_layered_entry(&p, 1); p.dwProviderFlags = 0;
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_enum(0, &l) >= 0);
    e = dx_first_guid(&l, &g);
    CHECK(e != NULL);
    if (e) { CHECK((e->dwProviderFlags & PFL_HIDDEN) != 0); EXPECT_EQ(e->ProtocolChain.ChainLen, 0); }
    dx_free(&l);
    dx_end();
}
TEST(dxflow_placeholder_keeps_other_provider_flags)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); dx_list l; const WSAPROTOCOL_INFOW *e;
    DX_BEGIN();
    dx_layered_entry(&p, 1); p.dwProviderFlags = PFL_MATCHES_PROTOCOL_ZERO;
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_enum(0, &l) >= 0);
    e = dx_first_guid(&l, &g);
    CHECK(e != NULL);
    if (e) EXPECT_EQ(e->dwProviderFlags, PFL_MATCHES_PROTOCOL_ZERO | PFL_HIDDEN);
    dx_free(&l);
    dx_end();
}
TEST(dxflow_placeholder_not_in_api_list)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_layered_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_has_guid(0, &g));
    CHECK(!dx_has_guid(2, &g));
    dx_end();
}
TEST(dxflow_base_not_forced_hidden)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); dx_list l; const WSAPROTOCOL_INFOW *e;
    DX_BEGIN();
    dx_base_entry(&p, 1); p.dwProviderFlags = 0;
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_enum(0, &l) >= 0);
    e = dx_first_guid(&l, &g);
    CHECK(e != NULL);
    if (e) CHECK((e->dwProviderFlags & PFL_HIDDEN) == 0);
    dx_free(&l);
    dx_end();
}
TEST(dxflow_placeholder_with_bad_path_refused)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); INT err = 0;
    DX_BEGIN();
    dx_layered_entry(&p, 1);
    EXPECT_EQ(DX_INSTALL(&g, L"C:\\ws2t_dx_catalog_dir\\none.dll", &p, 1, &err), SOCKET_ERROR);
    EXPECT_EQ(err, DXE_PROVFAILED);
    dx_end();
}

/* ---- chains ---- */

TEST(dxflow_chain_members_are_read_back)
{
    trio t; dx_list l; const WSAPROTOCOL_INFOW *e;
    DX_BEGIN();
    if (!make_trio(&t, 10)) { t_skip("setup install failed"); dx_end(); return; }
    CHECK(dx_enum(0, &l) >= 0);
    e = dx_first_guid(&l, &t.gc);
    CHECK(e != NULL);
    if (e) {
        EXPECT_EQ(e->ProtocolChain.ChainLen, 2);
        EXPECT_EQ(e->ProtocolChain.ChainEntries[0], t.il);
        EXPECT_EQ(e->ProtocolChain.ChainEntries[1], t.ib);
        EXPECT_EQ(e->dwCatalogEntryId, t.ic);
    }
    dx_free(&l);
    dx_end();
}
TEST(dxflow_chain_id_follows_its_members)
{
    trio t;
    DX_BEGIN();
    if (!make_trio(&t, 10)) { t_skip("setup install failed"); dx_end(); return; }
    CHECK(t.ic > t.il);
    CHECK(t.ic > t.ib);
    CHECK(t.ib > t.il);
    dx_end();
}
TEST(dxflow_chain_visible_in_api_list_members_hidden)
{
    trio t;
    DX_BEGIN();
    if (!make_trio(&t, 10)) { t_skip("setup install failed"); dx_end(); return; }
    CHECK(dx_api_wait_guid(&t.gc, 1));
    CHECK(dx_has_guid(2, &t.gb));
    CHECK(!dx_has_guid(2, &t.gl));
    dx_end();
}
TEST(dxflow_chain_over_stock_base_provider)
{
    /* A chain may sit on a stock base provider; the stock entry is only referenced, never changed. */
    WSAPROTOCOL_INFOW l, c; GUID gl = dx_guid(10), gc = dx_guid(11); dx_list before, after; DWORD stock = 0, il;
    DX_BEGIN();
    CHECK(dx_enum(0, &before) > 0);
    for (int i = 0; i < before.n && !stock; i++)
        if (before.e[i].ProtocolChain.ChainLen == 1 && before.e[i].iAddressFamily == AF_INET && before.e[i].iSocketType == SOCK_STREAM)
            stock = before.e[i].dwCatalogEntryId;
    if (!stock) { dx_free(&before); t_skip("no stock IPv4 stream provider"); dx_end(); return; }
    dx_layered_entry(&l, 10);
    EXPECT_EQ(dx_install_one(&gl, &l), 0);
    il = dx_id_of(0, &gl);
    dx_chain_entry(&c, 10, il, stock);
    EXPECT_EQ(dx_install_one(&gc, &c), 0);
    CHECK(dx_enum(0, &after) >= 0);
    EXPECT_EQ(after.n, before.n + 2);
    for (int i = 0; i < before.n; i++) CHECK(!memcmp(&before.e[i], &after.e[i], sizeof(WSAPROTOCOL_INFOW)));
    dx_free(&before); dx_free(&after);
    dx_end();
}

/* ---- deinstall ---- */

TEST(dxflow_deinstall_returns_zero)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); INT err = 0x4321;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    EXPECT_EQ(DX_DEINSTALL(&g, &err), 0);
    CHECK(!dx_has_guid(0, &g));
    EXPECT_EQ(err, 0);
    dx_end();
}
TEST(dxflow_deinstall_unknown_id_fails)
{
    GUID g = dx_guid(1); INT err = 0;
    DX_BEGIN();
    EXPECT_EQ(DX_DEINSTALL(&g, &err), SOCKET_ERROR);
    EXPECT_EQ(err, DXE_FAULT);
    dx_end();
}
TEST(dxflow_deinstall_twice_second_fails)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); INT err = 0;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    EXPECT_EQ(DX_DEINSTALL(&g, &err), 0);
    err = 0;
    EXPECT_EQ(DX_DEINSTALL(&g, &err), SOCKET_ERROR);
    EXPECT_EQ(err, DXE_FAULT);
    dx_end();
}
TEST(dxflow_deinstall_removes_every_entry_of_the_provider)
{
    WSAPROTOCOL_INFOW p[3]; GUID g = dx_guid(1); INT err = 0;
    DX_BEGIN();
    for (int i = 0; i < 3; i++) dx_base_entry(&p[i], 1 + i);
    EXPECT_EQ(DX_INSTALL(&g, dx_dll_path(), p, 3, &err), 0);
    EXPECT_EQ(DX_DEINSTALL(&g, &err), 0);
    CHECK(!dx_has_guid(0, &g));
    dx_end();
}
TEST(dxflow_deinstall_leaves_neighbours)
{
    WSAPROTOCOL_INFOW a, b; GUID ga = dx_guid(1), gb = dx_guid(2); INT err = 0;
    DX_BEGIN();
    dx_base_entry(&a, 1); dx_base_entry(&b, 2);
    EXPECT_EQ(dx_install_one(&ga, &a), 0);
    EXPECT_EQ(dx_install_one(&gb, &b), 0);
    EXPECT_EQ(DX_DEINSTALL(&ga, &err), 0);
    CHECK(!dx_has_guid(0, &ga));
    CHECK(dx_has_guid(0, &gb));
    dx_end();
}
TEST(dxflow_deinstall_restores_baseline)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); INT err = 0;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(!dx_native_matches_baseline());
    EXPECT_EQ(DX_DEINSTALL(&g, &err), 0);
    CHECK(dx_native_matches_baseline());
    dx_end();
}
TEST(dxflow_deinstall_placeholder_removes_dependent_chain)
{
    trio t; INT err = 0;
    DX_BEGIN();
    if (!make_trio(&t, 10)) { t_skip("setup install failed"); dx_end(); return; }
    EXPECT_EQ(DX_DEINSTALL(&t.gl, &err), 0);
    CHECK(!dx_has_guid(0, &t.gl));
    CHECK(!dx_has_guid(0, &t.gc));
    CHECK(dx_has_guid(0, &t.gb));
    dx_end();
}
TEST(dxflow_deinstall_base_removes_dependent_chain)
{
    trio t; INT err = 0;
    DX_BEGIN();
    if (!make_trio(&t, 10)) { t_skip("setup install failed"); dx_end(); return; }
    EXPECT_EQ(DX_DEINSTALL(&t.gb, &err), 0);
    CHECK(!dx_has_guid(0, &t.gb));
    CHECK(!dx_has_guid(0, &t.gc));
    CHECK(dx_has_guid(0, &t.gl));
    dx_end();
}
TEST(dxflow_deinstall_chain_leaves_members)
{
    trio t; INT err = 0;
    DX_BEGIN();
    if (!make_trio(&t, 10)) { t_skip("setup install failed"); dx_end(); return; }
    EXPECT_EQ(DX_DEINSTALL(&t.gc, &err), 0);
    CHECK(!dx_has_guid(0, &t.gc));
    CHECK(dx_has_guid(0, &t.gl));
    CHECK(dx_has_guid(0, &t.gb));
    dx_end();
}
TEST(dxflow_pruned_chain_cannot_be_deinstalled_again)
{
    trio t; INT err = 0;
    DX_BEGIN();
    if (!make_trio(&t, 10)) { t_skip("setup install failed"); dx_end(); return; }
    EXPECT_EQ(DX_DEINSTALL(&t.gl, &err), 0);
    err = 0;
    EXPECT_EQ(DX_DEINSTALL(&t.gc, &err), SOCKET_ERROR);
    EXPECT_EQ(err, DXE_FAULT);
    dx_end();
}
TEST(dxflow_middle_layer_removal_shortens_three_chain)
{
    WSAPROTOCOL_INFOW l1, l2, b, c; GUID g1 = dx_guid(30), g2 = dx_guid(31), gb = dx_guid(32), gc = dx_guid(33);
    DWORD i1, i2, ib; INT err = 0; dx_list l; const WSAPROTOCOL_INFOW *e;
    DX_BEGIN();
    dx_layered_entry(&l1, 30); dx_layered_entry(&l2, 30); dx_base_entry(&b, 30);
    EXPECT_EQ(dx_install_one(&g1, &l1), 0);
    EXPECT_EQ(dx_install_one(&g2, &l2), 0);
    EXPECT_EQ(dx_install_one(&gb, &b), 0);
    i1 = dx_id_of(0, &g1); i2 = dx_id_of(0, &g2); ib = dx_id_of(0, &gb);
    dx_chain_entry(&c, 30, i1, ib);
    c.ProtocolChain.ChainLen = 3;
    c.ProtocolChain.ChainEntries[0] = i1; c.ProtocolChain.ChainEntries[1] = i2; c.ProtocolChain.ChainEntries[2] = ib;
    EXPECT_EQ(dx_install_one(&gc, &c), 0);
    EXPECT_EQ(DX_DEINSTALL(&g2, &err), 0);
    CHECK(dx_enum(0, &l) >= 0);
    e = dx_first_guid(&l, &gc);
    CHECK(e != NULL);              /* the chain survives; the removed middle layer is spliced out */
    if (e) {
        EXPECT_EQ(e->ProtocolChain.ChainLen, 2);
        EXPECT_EQ(e->ProtocolChain.ChainEntries[0], i1);
        EXPECT_EQ(e->ProtocolChain.ChainEntries[1], ib);
    }
    dx_free(&l);
    dx_end();
}

/* ---- the 32-bit catalog ---- */

TEST(dxflow_64_32_base_lands_in_both_catalogs)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN();
    if (!dx_wow_available()) { t_skip("no 32-bit catalog"); dx_end(); return; }
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install64_32_one(&g, &p), 0);
    CHECK(dx_has_guid(0, &g));
    CHECK(dx_has_guid(1, &g));
    dx_end();
}
TEST(dxflow_64_32_entry_has_same_id_in_both)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN();
    if (!dx_wow_available()) { t_skip("no 32-bit catalog"); dx_end(); return; }
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install64_32_one(&g, &p), 0);
    EXPECT_EQ(dx_id_of(0, &g), dx_id_of(1, &g));
    EXPECT_NE(dx_id_of(0, &g), 0);
    dx_end();
}
TEST(dxflow_64_32_fields_match_in_both)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); dx_list a, b; const WSAPROTOCOL_INFOW *ea, *eb;
    DX_BEGIN();
    if (!dx_wow_available()) { t_skip("no 32-bit catalog"); dx_end(); return; }
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install64_32_one(&g, &p), 0);
    CHECK(dx_enum(0, &a) >= 0); CHECK(dx_enum(1, &b) >= 0);
    ea = dx_first_guid(&a, &g); eb = dx_first_guid(&b, &g);
    CHECK(ea && eb);
    if (ea && eb) {
        EXPECT_EQ(ea->dwServiceFlags1, eb->dwServiceFlags1);
        EXPECT_EQ(ea->iAddressFamily, eb->iAddressFamily);
        EXPECT_EQ(ea->iSocketType, eb->iSocketType);
        EXPECT_EQ(ea->ProtocolChain.ChainLen, eb->ProtocolChain.ChainLen);
        EXPECT_WSTR(ea->szProtocol, eb->szProtocol);
    }
    dx_free(&a); dx_free(&b);
    dx_end();
}
TEST(dxflow_native_install_does_not_touch_32_bit_catalog)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN();
    if (!dx_wow_available()) { t_skip("no 32-bit catalog"); dx_end(); return; }
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(!dx_has_guid(1, &g));
    CHECK(dx_wow_matches_baseline());
    dx_end();
}
TEST(dxflow_native_deinstall_leaves_32_bit_entry)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); INT err = 0;
    DX_BEGIN();
    if (!dx_wow_available()) { t_skip("no 32-bit catalog"); dx_end(); return; }
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install64_32_one(&g, &p), 0);
    EXPECT_EQ(DX_DEINSTALL(&g, &err), 0);
    CHECK(!dx_has_guid(0, &g));
    CHECK(dx_has_guid(1, &g));
    dx_end();
}
TEST(dxflow_32_bit_deinstall_leaves_native_entry)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); INT err = 0;
    DX_BEGIN();
    if (!dx_wow_available()) { t_skip("no 32-bit catalog"); dx_end(); return; }
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install64_32_one(&g, &p), 0);
    EXPECT_EQ(DX_DEINSTALL32(&g, &err), 0);
    CHECK(dx_has_guid(0, &g));
    CHECK(!dx_has_guid(1, &g));
    dx_end();
}
TEST(dxflow_32_bit_deinstall_unknown_fails)
{
    GUID g = dx_guid(1); INT err = 0;
    DX_BEGIN();
    if (!dx_wow_available()) { t_skip("no 32-bit catalog"); dx_end(); return; }
    EXPECT_EQ(DX_DEINSTALL32(&g, &err), SOCKET_ERROR);
    EXPECT_EQ(err, DXE_FAULT);
    dx_end();
}
TEST(dxflow_64_32_duplicate_refused)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN();
    if (!dx_wow_available()) { t_skip("no 32-bit catalog"); dx_end(); return; }
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install64_32_one(&g, &p), 0);
    EXPECT_EQ(dx_install64_32_one(&g, &p), DXE_NO_RECOVERY);
    dx_end();
}
TEST(dxflow_64_32_bad_record_refused)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN();
    if (!dx_wow_available()) { t_skip("no 32-bit catalog"); dx_end(); return; }
    dx_base_entry(&p, 1); p.iMinSockAddr = 1;
    EXPECT_EQ(dx_install64_32_one(&g, &p), DXE_INVALIDPROC);
    CHECK(!dx_has_guid(0, &g));
    CHECK(!dx_has_guid(1, &g));
    dx_end();
}
TEST(dxflow_64_32_placeholder_outcome_logged)
{
    /* Only base providers are guaranteed to be accepted by the dual install; anything else needs the two
     * catalogs to be in step. Record the outcome. */
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); int r;
    DX_BEGIN();
    if (!dx_wow_available()) { t_skip("no 32-bit catalog"); dx_end(); return; }
    dx_layered_entry(&p, 1);
    r = dx_install64_32_one(&g, &p);
    CHECKF(r == 0 || r == DXE_NO_RECOVERY, "error %d", r);
    t_note("dual install of a chain-length-0 record: %s", r == 0 ? "accepted" : "refused (catalogs not in step)");
    dx_end();
}
TEST(dxflow_32_bit_catalog_unchanged_by_native_chain)
{
    trio t;
    DX_BEGIN();
    if (!dx_wow_available()) { t_skip("no 32-bit catalog"); dx_end(); return; }
    if (!make_trio(&t, 10)) { t_skip("setup install failed"); dx_end(); return; }
    CHECK(dx_wow_matches_baseline());
    dx_end();
}

/* ---- empty and degenerate calls ---- */

TEST(dxflow_zero_entries_outcome_logged)
{
    GUID g = dx_guid(1); INT err = 0; INT r; WSAPROTOCOL_INFOW p;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    r = DX_INSTALL(&g, dx_dll_path(), &p, 0, &err);
    t_note("install of zero records: %s", r == 0 ? "accepted" : "refused");
    CHECK(!dx_has_guid(0, &g));
    dx_end();
}
