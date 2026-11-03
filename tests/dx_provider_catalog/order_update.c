/* WSCWriteProviderOrder(32) and WSCUpdateProvider(32): permuting and rewriting throwaway catalog entries.
 *
 * Order: the call takes the catalog ids of every entry, hidden placeholders included, in the wanted order.
 * It returns the error number itself (not SOCKET_ERROR) and writes nothing unless the list names every
 * catalog entry exactly once. Update: records of one provider are rewritten in place, matched to the
 * catalog by catalog id; the call fails (with the no-recovery error, whatever the underlying cause) unless the
 * number of rewritten records equals dwNumberOfEntries. Only entries created by the test are moved or rewritten;
 * the original order is rewritten at the end of every test and checked by dx_end. Skipped unless elevated. */
#include "dx.h"

static DWORD *ids_of(const dx_list *l)
{
    DWORD *a = (DWORD *)calloc(l->n ? l->n : 1, sizeof(DWORD));
    for (int i = 0; i < l->n; i++) a[i] = l->e[i].dwCatalogEntryId;
    return a;
}
static int install_n(int n, unsigned first)
{
    for (int i = 0; i < n; i++) {
        WSAPROTOCOL_INFOW p; GUID g = dx_guid(first + i);
        dx_base_entry(&p, first + i);
        if (dx_install_one(&g, &p)) return 0;
    }
    return 1;
}
/* Position of an entry of ours in the SPI list, -1 when absent. */
static int pos_of(const GUID *g)
{
    dx_list l; int at = -1;
    if (dx_enum(0, &l) < 0) return -1;
    for (int i = 0; i < l.n; i++) if (!memcmp(&l.e[i].ProviderId, g, sizeof *g)) { at = i; break; }
    dx_free(&l);
    return at;
}
static int same_ids(const dx_list *a, const dx_list *b)
{
    if (a->n != b->n) return 0;
    for (int i = 0; i < a->n; i++) if (a->e[i].dwCatalogEntryId != b->e[i].dwCatalogEntryId) return 0;
    return 1;
}

/* ---- provider order ---- */

TEST(dxord_same_order_succeeds)
{
    dx_list l; DWORD *ids;
    DX_BEGIN();
    CHECK(install_n(2, 1));
    CHECK(dx_enum(0, &l) > 0);
    ids = ids_of(&l);
    EXPECT_EQ(DX_ORDER(ids, (DWORD)l.n), 0);
    { dx_list m; CHECK(dx_enum(0, &m) >= 0); CHECK(same_ids(&l, &m)); dx_free(&m); }
    free(ids); dx_free(&l);
    dx_end();
}
TEST(dxord_swap_two_of_ours)
{
    dx_list l; DWORD *ids; GUID g1 = dx_guid(1), g2 = dx_guid(2); int a, b;
    DX_BEGIN();
    CHECK(install_n(2, 1));
    CHECK(dx_enum(0, &l) > 2);
    ids = ids_of(&l);
    a = pos_of(&g1); b = pos_of(&g2);
    CHECK(a >= 0 && b == a + 1);
    { DWORD t = ids[a]; ids[a] = ids[b]; ids[b] = t; }
    EXPECT_EQ(DX_ORDER(ids, (DWORD)l.n), 0);
    CHECK(pos_of(&g2) < pos_of(&g1));
    free(ids); dx_free(&l);
    dx_end();
}
TEST(dxord_reverse_three_of_ours)
{
    dx_list l; DWORD *ids; GUID g[3]; int p[3];
    DX_BEGIN();
    CHECK(install_n(3, 1));
    for (int i = 0; i < 3; i++) g[i] = dx_guid(1 + i);
    CHECK(dx_enum(0, &l) > 3);
    ids = ids_of(&l);
    for (int i = 0; i < 3; i++) p[i] = pos_of(&g[i]);
    { DWORD t = ids[p[0]]; ids[p[0]] = ids[p[2]]; ids[p[2]] = t; }
    EXPECT_EQ(DX_ORDER(ids, (DWORD)l.n), 0);
    CHECK(pos_of(&g[2]) < pos_of(&g[1]));
    CHECK(pos_of(&g[1]) < pos_of(&g[0]));
    free(ids); dx_free(&l);
    dx_end();
}
TEST(dxord_move_ours_to_front)
{
    dx_list l; DWORD *ids; GUID g = dx_guid(1); int a;
    DX_BEGIN();
    CHECK(install_n(1, 1));
    CHECK(dx_enum(0, &l) > 1);
    ids = ids_of(&l);
    a = pos_of(&g);
    CHECK(a > 0);
    { DWORD mine = ids[a]; for (int i = a; i > 0; i--) ids[i] = ids[i - 1]; ids[0] = mine; }
    EXPECT_EQ(DX_ORDER(ids, (DWORD)l.n), 0);
    EXPECT_EQ(pos_of(&g), 0);
    free(ids); dx_free(&l);
    dx_end();
}
TEST(dxord_front_move_does_not_change_ids)
{
    dx_list l, m; DWORD *ids; GUID g = dx_guid(1); int a;
    DX_BEGIN();
    CHECK(install_n(1, 1));
    CHECK(dx_enum(0, &l) > 1);
    ids = ids_of(&l);
    a = pos_of(&g);
    { DWORD mine = ids[a]; for (int i = a; i > 0; i--) ids[i] = ids[i - 1]; ids[0] = mine; }
    EXPECT_EQ(DX_ORDER(ids, (DWORD)l.n), 0);
    CHECK(dx_enum(0, &m) >= 0);
    EXPECT_EQ(m.n, l.n);
    for (int i = 0; i < l.n; i++) {
        const WSAPROTOCOL_INFOW *x = dx_by_id(&l, ids[i]);
        const WSAPROTOCOL_INFOW *y = dx_by_id(&m, ids[i]);
        CHECK(x && y);
        if (x && y) CHECK(!memcmp(x, y, sizeof *x));
    }
    free(ids); dx_free(&l); dx_free(&m);
    dx_end();
}
TEST(dxord_reorder_visible_in_api_list)
{
    dx_list l; DWORD *ids; GUID g1 = dx_guid(1), g2 = dx_guid(2); int a, b;
    DX_BEGIN();
    CHECK(install_n(2, 1));
    EXPECT_EQ(dx_child_query("before 1 2"), 0);
    CHECK(dx_enum(0, &l) > 2);
    ids = ids_of(&l);
    a = pos_of(&g1); b = pos_of(&g2);
    { DWORD t = ids[a]; ids[a] = ids[b]; ids[b] = t; }
    EXPECT_EQ(DX_ORDER(ids, (DWORD)l.n), 0);
    EXPECT_EQ(dx_child_query("before 2 1"), 0);
    EXPECT_EQ(dx_child_query("before 1 2"), 1);
    free(ids); dx_free(&l);
    dx_end();
}
TEST(dxord_hidden_entries_belong_in_the_list)
{
    /* A placeholder is part of the catalog; a list that leaves it out is not a full ordering. */
    WSAPROTOCOL_INFOW l_, b_; GUID gl = dx_guid(1), gb = dx_guid(2); dx_list l; DWORD *ids; int k = 0; DWORD hid;
    DX_BEGIN();
    dx_layered_entry(&l_, 1); dx_base_entry(&b_, 2);
    EXPECT_EQ(dx_install_one(&gl, &l_), 0);
    EXPECT_EQ(dx_install_one(&gb, &b_), 0);
    hid = dx_id_of(0, &gl);
    CHECK(dx_enum(0, &l) > 2);
    ids = ids_of(&l);
    for (int i = 0; i < l.n; i++) if (ids[i] != hid) ids[k++] = ids[i];
    EXPECT_EQ(DX_ORDER(ids, (DWORD)k), DXE_INVAL);
    free(ids); dx_free(&l);
    dx_end();
}

/* A list that is not a permutation of the catalog is rejected whole and leaves the order alone. */
static void run_bad_order(int mode)
{
    dx_list l, m; DWORD *ids; int n; int r;
    DX_BEGIN();
    CHECK(install_n(2, 1));
    CHECK(dx_enum(0, &l) > 2);
    n = l.n;
    ids = (DWORD *)calloc(n + 2, sizeof(DWORD));
    for (int i = 0; i < n; i++) ids[i] = l.e[i].dwCatalogEntryId;
    switch (mode) {
    case 0: r = DX_ORDER(ids, (DWORD)(n - 1)); break;                                   /* one id short */
    case 1: ids[n] = 0x7e7e7e7e; r = DX_ORDER(ids, (DWORD)(n + 1)); break;               /* one unknown id too many */
    case 2: ids[n - 1] = ids[n - 2]; r = DX_ORDER(ids, (DWORD)n); break;                 /* a repeat replaces an id */
    case 3: ids[n - 1] = 0x7e7e7e7e; r = DX_ORDER(ids, (DWORD)n); break;                 /* an unknown id replaces an id */
    case 4: r = DX_ORDER(ids, 0); break;                                                 /* empty list */
    case 5: ids[n] = ids[0]; r = DX_ORDER(ids, (DWORD)(n + 1)); break;                   /* one id twice, extra slot */
    case 6: r = DX_ORDER(ids, 1); break;                                                 /* a single id */
    default: ids[0] = 0; r = DX_ORDER(ids, (DWORD)n); break;                             /* id zero replaces the first */
    }
    EXPECT_EQ(r, DXE_INVAL);
    CHECK(dx_enum(0, &m) >= 0);
    CHECK(same_ids(&l, &m));
    free(ids); dx_free(&l); dx_free(&m);
    dx_end();
}
TEST(dxord_missing_one_id_refused) { run_bad_order(0); }
TEST(dxord_unknown_extra_id_refused) { run_bad_order(1); }
TEST(dxord_repeated_id_refused) { run_bad_order(2); }
TEST(dxord_unknown_replacing_id_refused) { run_bad_order(3); }
TEST(dxord_empty_list_refused) { run_bad_order(4); }
TEST(dxord_duplicate_with_extra_slot_refused) { run_bad_order(5); }
TEST(dxord_single_id_refused) { run_bad_order(6); }
TEST(dxord_zero_id_refused) { run_bad_order(7); }

TEST(dxord_failure_returns_error_number_not_minus_one)
{
    dx_list l; DWORD *ids; INT r;
    DX_BEGIN();
    CHECK(dx_enum(0, &l) > 0);
    ids = ids_of(&l);
    r = DX_ORDER(ids, (DWORD)(l.n - 1));
    CHECK(r != SOCKET_ERROR);
    CHECK(r > 0);
    free(ids); dx_free(&l);
    dx_end();
}
TEST(dxord_removed_entry_cannot_be_listed)
{
    dx_list l; DWORD *ids; GUID g = dx_guid(1); INT err = 0; DWORD gone;
    DX_BEGIN();
    CHECK(install_n(1, 1));
    gone = dx_id_of(0, &g);
    EXPECT_EQ(DX_DEINSTALL(&g, &err), 0);
    CHECK(dx_enum(0, &l) > 0);
    ids = (DWORD *)calloc(l.n + 1, sizeof(DWORD));
    for (int i = 0; i < l.n; i++) ids[i] = l.e[i].dwCatalogEntryId;
    ids[l.n] = gone;
    EXPECT_EQ(DX_ORDER(ids, (DWORD)l.n + 1), DXE_INVAL);
    free(ids); dx_free(&l);
    dx_end();
}
TEST(dxord_chain_before_its_members_is_accepted)
{
    /* The order call does not check chain dependencies. */
    WSAPROTOCOL_INFOW l_, b_, c_; GUID gl = dx_guid(1), gb = dx_guid(2), gc = dx_guid(3);
    dx_list l; DWORD *ids; int a;
    DX_BEGIN();
    dx_layered_entry(&l_, 1); dx_base_entry(&b_, 1);
    EXPECT_EQ(dx_install_one(&gl, &l_), 0);
    EXPECT_EQ(dx_install_one(&gb, &b_), 0);
    dx_chain_entry(&c_, 1, dx_id_of(0, &gl), dx_id_of(0, &gb));
    EXPECT_EQ(dx_install_one(&gc, &c_), 0);
    CHECK(dx_enum(0, &l) > 3);
    ids = ids_of(&l);
    a = pos_of(&gc);
    { DWORD mine = ids[a]; for (int i = a; i > 0; i--) ids[i] = ids[i - 1]; ids[0] = mine; }
    EXPECT_EQ(DX_ORDER(ids, (DWORD)l.n), 0);
    EXPECT_EQ(pos_of(&gc), 0);
    free(ids); dx_free(&l);
    dx_end();
}
TEST(dxord_repeated_permutation_is_stable)
{
    dx_list l; DWORD *ids; GUID g1 = dx_guid(1), g2 = dx_guid(2);
    DX_BEGIN();
    CHECK(install_n(2, 1));
    CHECK(dx_enum(0, &l) > 2);
    ids = ids_of(&l);
    for (int round = 0; round < 4; round++) {
        int a = pos_of(&g1), b = pos_of(&g2);
        DWORD t = ids[a]; ids[a] = ids[b]; ids[b] = t;
        EXPECT_EQ(DX_ORDER(ids, (DWORD)l.n), 0);
        CHECK((round % 2 == 0) ? pos_of(&g2) < pos_of(&g1) : pos_of(&g1) < pos_of(&g2));
    }
    free(ids); dx_free(&l);
    dx_end();
}
TEST(dxord_32_bit_catalog_swap)
{
    WSAPROTOCOL_INFOW a, b; GUID g1 = dx_guid(1), g2 = dx_guid(2); dx_list l; DWORD *ids; int pa = -1, pb = -1;
    DX_BEGIN();
    if (!dx_wow_available()) { t_skip("no 32-bit catalog"); dx_end(); return; }
    dx_base_entry(&a, 1); dx_base_entry(&b, 2);
    EXPECT_EQ(dx_install64_32_one(&g1, &a), 0);
    EXPECT_EQ(dx_install64_32_one(&g2, &b), 0);
    CHECK(dx_enum(1, &l) > 2);
    ids = ids_of(&l);
    for (int i = 0; i < l.n; i++) {
        if (!memcmp(&l.e[i].ProviderId, &g1, sizeof g1)) pa = i;
        if (!memcmp(&l.e[i].ProviderId, &g2, sizeof g2)) pb = i;
    }
    CHECK(pa >= 0 && pb >= 0);
    if (pa >= 0 && pb >= 0) {
        DWORD t = ids[pa]; ids[pa] = ids[pb]; ids[pb] = t;
        EXPECT_EQ(DX_ORDER32(ids, (DWORD)l.n), 0);
        { dx_list m; int qa = -1, qb = -1;
          CHECK(dx_enum(1, &m) >= 0);
          for (int i = 0; i < m.n; i++) {
              if (!memcmp(&m.e[i].ProviderId, &g1, sizeof g1)) qa = i;
              if (!memcmp(&m.e[i].ProviderId, &g2, sizeof g2)) qb = i;
          }
          CHECK(qb >= 0 && qb < qa);
          dx_free(&m); }
        CHECK(pos_of(&g1) < pos_of(&g2));     /* the native catalog kept its order */
    }
    free(ids); dx_free(&l);
    dx_end();
}
TEST(dxord_32_bit_refuses_native_only_id)
{
    WSAPROTOCOL_INFOW a; GUID g = dx_guid(1); dx_list l; DWORD *ids;
    DX_BEGIN();
    if (!dx_wow_available()) { t_skip("no 32-bit catalog"); dx_end(); return; }
    dx_base_entry(&a, 1);
    EXPECT_EQ(dx_install_one(&g, &a), 0);            /* native catalog only */
    CHECK(dx_enum(1, &l) > 0);
    ids = (DWORD *)calloc(l.n + 1, sizeof(DWORD));
    for (int i = 0; i < l.n; i++) ids[i] = l.e[i].dwCatalogEntryId;
    ids[l.n] = dx_id_of(0, &g);
    EXPECT_EQ(DX_ORDER32(ids, (DWORD)l.n + 1), DXE_INVAL);
    free(ids); dx_free(&l);
    dx_end();
}

/* ---- update ---- */

static int update_one(const GUID *g, const WCHAR *path, WSAPROTOCOL_INFOW *recs, DWORD n)
{
    INT err = 0;
    dx_update_fn f = DX_UPDATE;
    if (!f) return -1;
    if (f(g, path ? path : dx_dll_path(), recs, n, &err) == 0) return 0;
    return err ? err : -2;
}
static void fetch(const GUID *g, WSAPROTOCOL_INFOW *out)
{
    dx_list l; const WSAPROTOCOL_INFOW *e;
    memset(out, 0, sizeof *out);
    if (dx_enum(0, &l) < 0) return;
    e = dx_first_guid(&l, g);
    if (e) *out = *e;
    dx_free(&l);
}

TEST(dxupd_changes_name)
{
    WSAPROTOCOL_INFOW p, cur; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    fetch(&g, &cur);
    lstrcpyW(cur.szProtocol, L"ws2t dx renamed");
    EXPECT_EQ(update_one(&g, NULL, &cur, 1), 0);
    fetch(&g, &cur);
    EXPECT_WSTR(cur.szProtocol, L"ws2t dx renamed");
    dx_end();
}
TEST(dxupd_keeps_catalog_id_and_position)
{
    WSAPROTOCOL_INFOW p, cur; GUID g = dx_guid(1); DWORD id; int at;
    DX_BEGIN();
    CHECK(install_n(2, 2));
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    id = dx_id_of(0, &g); at = pos_of(&g);
    fetch(&g, &cur);
    cur.szProtocol[0] = L'Z';
    EXPECT_EQ(update_one(&g, NULL, &cur, 1), 0);
    EXPECT_EQ(dx_id_of(0, &g), id);
    EXPECT_EQ(pos_of(&g), at);
    dx_end();
}
TEST(dxupd_changes_flags_and_sizes)
{
    WSAPROTOCOL_INFOW p, cur; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    fetch(&g, &cur);
    cur.dwServiceFlags1 |= XP1_MESSAGE_ORIENTED | XP1_CONNECTIONLESS;
    cur.dwMessageSize = 1234; cur.iProtocol = 99; cur.iMaxSockAddr = 32; cur.iMinSockAddr = 8;
    cur.iSocketType = SOCK_DGRAM; cur.dwProviderReserved = 77;
    EXPECT_EQ(update_one(&g, NULL, &cur, 1), 0);
    fetch(&g, &cur);
    EXPECT_EQ(cur.dwMessageSize, 1234);
    EXPECT_EQ(cur.iProtocol, 99);
    EXPECT_EQ(cur.iMaxSockAddr, 32);
    EXPECT_EQ(cur.iMinSockAddr, 8);
    EXPECT_EQ(cur.iSocketType, SOCK_DGRAM);
    EXPECT_EQ(cur.dwProviderReserved, 77);
    CHECK((cur.dwServiceFlags1 & XP1_MESSAGE_ORIENTED) != 0);
    dx_end();
}
TEST(dxupd_record_provider_id_is_ignored)
{
    WSAPROTOCOL_INFOW p, cur; GUID g = dx_guid(1), other = dx_guid(55);
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    fetch(&g, &cur);
    cur.ProviderId = other;
    EXPECT_EQ(update_one(&g, NULL, &cur, 1), 0);
    CHECK(dx_has_guid(0, &g));
    CHECK(!dx_has_guid(0, &other));
    dx_end();
}
TEST(dxupd_changes_provider_path)
{
    WSAPROTOCOL_INFOW p, cur; GUID g = dx_guid(1); WCHAR abs_[MAX_PATH + 16], got[MAX_PATH];
    DX_BEGIN();
    GetSystemDirectoryW(abs_, MAX_PATH); lstrcatW(abs_, L"\\mswsock.dll");
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    fetch(&g, &cur);
    EXPECT_EQ(update_one(&g, abs_, &cur, 1), 0);
    EXPECT_EQ(dx_path_of(&g, got, MAX_PATH), 0);
    EXPECT_WSTR(got, abs_);
    dx_end();
}
TEST(dxupd_unloadable_path_is_refused)
{
    WSAPROTOCOL_INFOW p, cur; GUID g = dx_guid(1); WCHAR got[MAX_PATH];
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    fetch(&g, &cur);
    EXPECT_EQ(update_one(&g, L"C:\\ws2t_dx_catalog_dir\\none.dll", &cur, 1), DXE_NO_RECOVERY);
    EXPECT_EQ(dx_path_of(&g, got, MAX_PATH), 0);
    EXPECT_WSTR(got, dx_dll_path());
    dx_end();
}
TEST(dxupd_invalid_record_is_refused_and_changes_nothing)
{
    WSAPROTOCOL_INFOW p, cur, back; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    fetch(&g, &cur);
    cur.iMinSockAddr = 1; lstrcpyW(cur.szProtocol, L"never stored");
    EXPECT_EQ(update_one(&g, NULL, &cur, 1), DXE_NO_RECOVERY);
    fetch(&g, &back);
    EXPECT_WSTR(back.szProtocol, L"ws2t dx base");
    EXPECT_EQ(back.iMinSockAddr, 16);
    dx_end();
}
TEST(dxupd_unknown_provider_is_refused)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(update_one(&g, NULL, &p, 1), DXE_NO_RECOVERY);
    dx_end();
}
TEST(dxupd_count_too_large_is_refused)
{
    WSAPROTOCOL_INFOW p[2], cur; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_base_entry(&p[0], 1);
    EXPECT_EQ(dx_install_one(&g, &p[0]), 0);
    fetch(&g, &cur);
    p[0] = cur; p[1] = cur; p[1].dwCatalogEntryId = 0x7e7e7e7e;
    EXPECT_EQ(update_one(&g, NULL, p, 2), DXE_NO_RECOVERY);
    dx_end();
}
TEST(dxupd_record_for_other_id_is_refused)
{
    WSAPROTOCOL_INFOW p, cur; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    fetch(&g, &cur);
    cur.dwCatalogEntryId += 1000;
    EXPECT_EQ(update_one(&g, NULL, &cur, 1), DXE_NO_RECOVERY);
    dx_end();
}
TEST(dxupd_zero_records_is_a_no_op)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); int r;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    r = update_one(&g, NULL, &p, 0);
    CHECKF(r == 0 || r == DXE_NO_RECOVERY, "error %d", r);
    t_note("update with zero records: %s", r == 0 ? "accepted" : "refused");
    dx_end();
}
TEST(dxupd_subset_of_a_multi_entry_provider)
{
    WSAPROTOCOL_INFOW p[2], cur; GUID g = dx_guid(1); INT err = 0; dx_list l; int k = 0;
    DX_BEGIN();
    for (int i = 0; i < 2; i++) { dx_base_entry(&p[i], 1 + i); p[i].iProtocol = 150 + i; }
    EXPECT_EQ(DX_INSTALL(&g, dx_dll_path(), p, 2, &err), 0);
    CHECK(dx_enum(0, &l) >= 2);
    for (int i = 0; i < l.n; i++)
        if (!memcmp(&l.e[i].ProviderId, &g, sizeof g) && l.e[i].iProtocol == 151) cur = l.e[i];
    lstrcpyW(cur.szProtocol, L"second renamed");
    EXPECT_EQ(update_one(&g, NULL, &cur, 1), 0);
    dx_free(&l);
    CHECK(dx_enum(0, &l) >= 2);
    for (int i = 0; i < l.n; i++)
        if (!memcmp(&l.e[i].ProviderId, &g, sizeof g)) {
            k++;
            if (l.e[i].iProtocol == 151) EXPECT_WSTR(l.e[i].szProtocol, L"second renamed");
            else EXPECT_WSTR(l.e[i].szProtocol, L"ws2t dx base");
        }
    EXPECT_EQ(k, 2);
    dx_free(&l);
    dx_end();
}
TEST(dxupd_all_entries_of_a_provider)
{
    WSAPROTOCOL_INFOW p[2], cur[2]; GUID g = dx_guid(1); INT err = 0; dx_list l; int k = 0;
    DX_BEGIN();
    for (int i = 0; i < 2; i++) dx_base_entry(&p[i], 1 + i);
    EXPECT_EQ(DX_INSTALL(&g, dx_dll_path(), p, 2, &err), 0);
    CHECK(dx_enum(0, &l) >= 2);
    for (int i = 0; i < l.n && k < 2; i++)
        if (!memcmp(&l.e[i].ProviderId, &g, sizeof g)) { cur[k] = l.e[i]; lstrcpyW(cur[k].szProtocol, k ? L"B" : L"A"); k++; }
    dx_free(&l);
    EXPECT_EQ(update_one(&g, NULL, cur, 2), 0);
    CHECK(dx_enum(0, &l) >= 2);
    for (int i = 0; i < l.n; i++)
        if (!memcmp(&l.e[i].ProviderId, &g, sizeof g)) CHECK(l.e[i].szProtocol[0] == L'A' || l.e[i].szProtocol[0] == L'B');
    dx_free(&l);
    dx_end();
}
TEST(dxupd_can_hide_a_base_provider)
{
    WSAPROTOCOL_INFOW p, cur; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    CHECK(dx_api_wait_guid(&g, 1));
    fetch(&g, &cur);
    cur.dwProviderFlags |= PFL_HIDDEN;
    EXPECT_EQ(update_one(&g, NULL, &cur, 1), 0);
    CHECK(dx_api_wait_guid(&g, 0));
    CHECK(dx_has_guid(0, &g));
    dx_end();
}
TEST(dxupd_placeholder_stays_hidden)
{
    WSAPROTOCOL_INFOW p, cur; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_layered_entry(&p, 1);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    fetch(&g, &cur);
    cur.dwProviderFlags = 0;
    EXPECT_EQ(update_one(&g, NULL, &cur, 1), 0);
    fetch(&g, &cur);
    CHECK((cur.dwProviderFlags & PFL_HIDDEN) != 0);
    dx_end();
}
TEST(dxupd_chain_members_are_revalidated)
{
    WSAPROTOCOL_INFOW l_, b_, c_, cur; GUID gl = dx_guid(1), gb = dx_guid(2), gc = dx_guid(3);
    DX_BEGIN();
    dx_layered_entry(&l_, 1); dx_base_entry(&b_, 1);
    EXPECT_EQ(dx_install_one(&gl, &l_), 0);
    EXPECT_EQ(dx_install_one(&gb, &b_), 0);
    dx_chain_entry(&c_, 1, dx_id_of(0, &gl), dx_id_of(0, &gb));
    EXPECT_EQ(dx_install_one(&gc, &c_), 0);
    fetch(&gc, &cur);
    cur.ProtocolChain.ChainEntries[1] = 0x7e7e7e7e;
    EXPECT_EQ(update_one(&gc, NULL, &cur, 1), DXE_NO_RECOVERY);
    fetch(&gc, &cur);
    EXPECT_EQ(cur.ProtocolChain.ChainEntries[1], dx_id_of(0, &gb));
    dx_end();
}
TEST(dxupd_does_not_touch_other_providers)
{
    WSAPROTOCOL_INFOW a, b, cur; GUID ga = dx_guid(1), gb = dx_guid(2);
    WSAPROTOCOL_INFOW other_before, other_after;
    DX_BEGIN();
    dx_base_entry(&a, 1); dx_base_entry(&b, 2);
    EXPECT_EQ(dx_install_one(&ga, &a), 0);
    EXPECT_EQ(dx_install_one(&gb, &b), 0);
    fetch(&gb, &other_before);
    fetch(&ga, &cur);
    lstrcpyW(cur.szProtocol, L"changed");
    EXPECT_EQ(update_one(&ga, NULL, &cur, 1), 0);
    fetch(&gb, &other_after);
    CHECK(!memcmp(&other_before, &other_after, sizeof other_before));
    dx_end();
}
TEST(dxupd_32_bit_updates_only_32_bit_copy)
{
    WSAPROTOCOL_INFOW p, cur; GUID g = dx_guid(1); dx_list l; const WSAPROTOCOL_INFOW *e; INT err = 0;
    DX_BEGIN();
    if (!dx_wow_available() || !DX_UPDATE32) { t_skip("no 32-bit catalog"); dx_end(); return; }
    dx_base_entry(&p, 1);
    EXPECT_EQ(dx_install64_32_one(&g, &p), 0);
    CHECK(dx_enum(1, &l) > 0);
    e = dx_first_guid(&l, &g);
    CHECK(e != NULL);
    if (e) {
        cur = *e; lstrcpyW(cur.szProtocol, L"only in 32");
        EXPECT_EQ(DX_UPDATE32(&g, dx_dll_path(), &cur, 1, &err), 0);
    }
    dx_free(&l);
    fetch(&g, &cur);
    EXPECT_WSTR(cur.szProtocol, L"ws2t dx base");
    CHECK(dx_enum(1, &l) > 0);
    e = dx_first_guid(&l, &g);
    CHECK(e != NULL);
    if (e) EXPECT_WSTR(e->szProtocol, L"only in 32");
    dx_free(&l);
    dx_end();
}
TEST(dxupd_32_bit_unknown_provider_refused)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); INT err = 0;
    DX_BEGIN();
    if (!dx_wow_available() || !DX_UPDATE32) { t_skip("no 32-bit catalog"); dx_end(); return; }
    dx_base_entry(&p, 1);
    EXPECT_EQ(DX_UPDATE32(&g, dx_dll_path(), &p, 1, &err), SOCKET_ERROR);
    EXPECT_EQ(err, DXE_NO_RECOVERY);
    dx_end();
}
TEST(dxupd_failure_returns_socket_error)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); INT err = 0;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    EXPECT_EQ(DX_UPDATE(&g, dx_dll_path(), &p, 1, &err), SOCKET_ERROR);
    EXPECT_EQ(err, DXE_NO_RECOVERY);
    dx_end();
}
