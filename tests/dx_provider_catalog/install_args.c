/* WSCInstallProvider / WSCInstallProvider64_32: what the install refuses, and with which error.
 *
 * Measures the validation that runs on every record before the catalog is written: the service-flag
 * combination check, the socket-address size window, the byte-order field, the chain length bound, the
 * provider DLL path (length, expansion, loadability, WSPStartup export) and the chain-entry rules (members must
 * exist, only the last member is a base provider, no repeats, first member shares the DLL path). A refused
 * install returns SOCKET_ERROR, reports the reason through lpErrno, and writes nothing: each test checks that the
 * catalog is unchanged afterwards. Every record uses a private address family and a throwaway provider id;
 * the stock entries are only ever read. Skipped unless elevated. */
#include "dx.h"

static int install_with_path(const GUID *g, const WCHAR *path, const WSAPROTOCOL_INFOW *p, DWORD n)
{
    INT err = 0;
    dx_install_fn f = DX_INSTALL;
    if (!f) return -1;
    if (f(g, path, p, n, &err) == 0) return 0;
    return err ? err : -2;
}

/* ---- field validation: one mutation of a valid base record, one expected error ---- */

static void run_bad(void (*mut)(WSAPROTOCOL_INFOW *), int want)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); int r;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    mut(&p);
    r = dx_install_one(&g, &p);
    EXPECT_EQ(r, want);
    CHECK(!dx_has_guid(0, &g));
    dx_end();
}
static void run_good(void (*mut)(WSAPROTOCOL_INFOW *))
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); int r;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    mut(&p);
    r = dx_install_one(&g, &p);
    EXPECT_EQ(r, 0);
    CHECK(dx_has_guid(0, &g));
    dx_end();
}
#define BAD(name, stmt, err) \
    static void m_##name(WSAPROTOCOL_INFOW *p) { stmt; } \
    TEST(dxpc_bad_##name) { run_bad(m_##name, err); }
#define GOOD(name, stmt) \
    static void m_##name(WSAPROTOCOL_INFOW *p) { stmt; } \
    TEST(dxpc_ok_##name) { run_good(m_##name); }

/* UNI_SEND and UNI_RECV together describe no usable provider. */
BAD(uni_send_and_recv, p->dwServiceFlags1 |= XP1_UNI_SEND | XP1_UNI_RECV, DXE_INVALIDPROC)
GOOD(uni_send_only, p->dwServiceFlags1 |= XP1_UNI_SEND)
GOOD(uni_recv_only, p->dwServiceFlags1 |= XP1_UNI_RECV)

/* Socket address size window: 2 <= min <= max <= 128. */
BAD(max_sockaddr_negative, p->iMaxSockAddr = -1, DXE_INVALIDPROC)
BAD(max_sockaddr_129, p->iMaxSockAddr = 129, DXE_INVALIDPROC)
BAD(max_sockaddr_below_min, p->iMinSockAddr = 17, DXE_INVALIDPROC)
BAD(min_sockaddr_one, p->iMinSockAddr = 1, DXE_INVALIDPROC)
BAD(min_sockaddr_zero, p->iMinSockAddr = 0, DXE_INVALIDPROC)
/* A negative minimum is not refused on genuine Windows 10; the window check only rejects 0 and 1. */
TEST(dxpc_obs_min_sockaddr_negative)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); int r;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    p.iMinSockAddr = -5;
    r = dx_install_one(&g, &p);
    CHECKF(r == 0 || r == DXE_INVALIDPROC, "error %d", r);
    t_note("negative minimum socket address size: %s", r == 0 ? "accepted" : "refused");
    dx_end();
}
BAD(both_sockaddr_zero, p->iMaxSockAddr = 0; p->iMinSockAddr = 0, DXE_INVALIDPROC)
GOOD(sockaddr_max_128, p->iMaxSockAddr = 128)
GOOD(sockaddr_min_two, p->iMinSockAddr = 2)
GOOD(sockaddr_both_two, p->iMaxSockAddr = 2; p->iMinSockAddr = 2)
GOOD(sockaddr_both_128, p->iMaxSockAddr = 128; p->iMinSockAddr = 128)

/* Network byte order is 0 (big) or 1 (little). */
BAD(byte_order_two, p->iNetworkByteOrder = 2, DXE_INVALIDPROC)
BAD(byte_order_negative, p->iNetworkByteOrder = -1, DXE_INVALIDPROC)
GOOD(byte_order_little, p->iNetworkByteOrder = LITTLEENDIAN)

/* Chain length is bounded by the seven member slots of the record. */
BAD(chain_len_8, p->ProtocolChain.ChainLen = 8, DXE_INVALIDPROC)
BAD(chain_len_huge, p->ProtocolChain.ChainLen = 0x7fffffff, DXE_INVALIDPROC)
BAD(chain_len_negative, p->ProtocolChain.ChainLen = -1, DXE_INVALIDPROC)

/* Fields the install never validates. */
GOOD(socket_type_zero, p->iSocketType = 0)
GOOD(socket_type_unknown, p->iSocketType = 77)
GOOD(address_family_zero, p->iAddressFamily = 0x7e90)
GOOD(address_family_negative, p->iAddressFamily = -12345)
GOOD(protocol_zero, p->iProtocol = 0)
GOOD(protocol_max_offset, p->iProtocolMaxOffset = 9)
GOOD(message_size_large, p->dwMessageSize = 0xffffffffu)
GOOD(security_scheme_other, p->iSecurityScheme = 5)
GOOD(version_zero, p->iVersion = 0)
GOOD(no_service_flags_but_ifs, p->dwServiceFlags1 = XP1_IFS_HANDLES)
GOOD(provider_flags_all, p->dwProviderFlags = PFL_MULTIPLE_PROTO_ENTRIES | PFL_RECOMMENDED_PROTO_ENTRY | PFL_HIDDEN | PFL_MATCHES_PROTOCOL_ZERO)
GOOD(empty_protocol_name, p->szProtocol[0] = 0)
GOOD(reserved_nonzero, p->dwProviderReserved = 0x12345678)

/* ---- provider path ---- */

static void run_bad_path(const WCHAR *path, int want)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(2); int r;
    DX_BEGIN();
    dx_base_entry(&p, 2);
    r = install_with_path(&g, path, &p, 1);
    EXPECT_EQ(r, want);
    CHECK(!dx_has_guid(0, &g));
    dx_end();
}
static void run_good_path(const WCHAR *path)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(2); int r;
    DX_BEGIN();
    dx_base_entry(&p, 2);
    r = install_with_path(&g, path, &p, 1);
    EXPECT_EQ(r, 0);
    CHECK(dx_has_guid(0, &g));
    dx_end();
}

/* A path the loader cannot resolve, or a library without a provider entry point, is a failed init. */
TEST(dxpc_path_missing_file) { run_bad_path(L"C:\\ws2t_dx_catalog_dir\\no_such_provider.dll", DXE_PROVFAILED); }
TEST(dxpc_path_empty) { run_bad_path(L"", DXE_PROVFAILED); }
TEST(dxpc_path_undefined_variable) { run_bad_path(L"%WS2T_DX_NO_SUCH_VARIABLE%\\mswsock.dll", DXE_PROVFAILED); }
TEST(dxpc_path_library_without_wspstartup) { run_bad_path(L"%SystemRoot%\\system32\\kernel32.dll", DXE_PROVFAILED); }
TEST(dxpc_path_ws2_32_has_no_wspstartup) { run_bad_path(L"%SystemRoot%\\system32\\ws2_32.dll", DXE_PROVFAILED); }
TEST(dxpc_path_directory) { run_bad_path(L"%SystemRoot%\\system32", DXE_PROVFAILED); }

TEST(dxpc_path_environment_form_loads) { run_good_path(L"%SystemRoot%\\system32\\mswsock.dll"); }
TEST(dxpc_path_environment_form_any_case)
{
    /* The variable name is matched without regard to case. */
    run_good_path(L"%systemroot%\\system32\\mswsock.dll");
}
TEST(dxpc_path_absolute_loads)
{
    WCHAR p[MAX_PATH + 16];
    UINT n = GetSystemDirectoryW(p, MAX_PATH);
    REQUIRE(n > 0);
    lstrcatW(p, L"\\mswsock.dll");
    run_good_path(p);
}
TEST(dxpc_path_bare_name_loads)
{
    /* No directory part: the loader finds the system library. */
    run_good_path(L"mswsock.dll");
}

/* The path field holds 260 UTF-16 units including the terminator; a longer string is refused as a bad
 * argument before the loader is consulted. */
TEST(dxpc_path_too_long_is_invalid)
{
    WCHAR *p = (WCHAR *)calloc(300, sizeof(WCHAR));
    REQUIRE(p);
    for (int i = 0; i < 260; i++) p[i] = L'a';
    run_bad_path(p, DXE_INVAL);
    free(p);
}
TEST(dxpc_path_far_too_long_is_invalid)
{
    WCHAR *p = (WCHAR *)calloc(1200, sizeof(WCHAR));
    REQUIRE(p);
    for (int i = 0; i < 1100; i++) p[i] = L'b';
    run_bad_path(p, DXE_INVAL);
    free(p);
}
TEST(dxpc_path_longest_nonexistent_is_failed_init)
{
    /* 259 units fit the record; it simply names nothing loadable. */
    WCHAR *p = (WCHAR *)calloc(300, sizeof(WCHAR));
    REQUIRE(p);
    for (int i = 0; i < 259; i++) p[i] = L'c';
    run_bad_path(p, DXE_PROVFAILED);
    free(p);
}

/* ---- error reporting convention ---- */

TEST(dxpc_failure_returns_socket_error)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); INT err = 0; INT r;
    DX_BEGIN();
    dx_base_entry(&p, 1); p.iMinSockAddr = 1;
    r = DX_INSTALL(&g, dx_dll_path(), &p, 1, &err);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(err, DXE_INVALIDPROC);
    dx_end();
}
TEST(dxpc_success_returns_zero_and_leaves_errno)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1); INT err = 0x1234; INT r;
    DX_BEGIN();
    dx_base_entry(&p, 1);
    r = DX_INSTALL(&g, dx_dll_path(), &p, 1, &err);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(err, 0x1234);
    dx_end();
}
TEST(dxpc_failure_is_repeatable)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(1);
    DX_BEGIN();
    dx_base_entry(&p, 1); p.ProtocolChain.ChainLen = 9;
    for (int i = 0; i < 3; i++) EXPECT_EQ(dx_install_one(&g, &p), DXE_INVALIDPROC);
    CHECK(!dx_has_guid(0, &g));
    dx_end();
}

/* ---- duplicate provider ids ---- */

TEST(dxpc_duplicate_provider_id_refused)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(3); int r;
    DX_BEGIN();
    dx_base_entry(&p, 3);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    r = dx_install_one(&g, &p);
    EXPECT_EQ(r, DXE_NO_RECOVERY);
    { dx_list l; if (dx_enum(0, &l) >= 0) { EXPECT_EQ(dx_count_guid(&l, &g), 1); dx_free(&l); } }
    dx_end();
}
TEST(dxpc_duplicate_provider_id_with_different_record_refused)
{
    WSAPROTOCOL_INFOW a, b; GUID g = dx_guid(3);
    DX_BEGIN();
    dx_base_entry(&a, 3); dx_base_entry(&b, 4);
    EXPECT_EQ(dx_install_one(&g, &a), 0);
    EXPECT_EQ(dx_install_one(&g, &b), DXE_NO_RECOVERY);
    dx_end();
}
TEST(dxpc_stock_provider_id_cannot_be_reinstalled)
{
    /* The id of the stock IPv4 provider is taken; the refused install must leave the catalog alone. */
    static const GUID tcp4 = {0xE70F1AA0, 0xAB8B, 0x11CF, {0x8C, 0xA3, 0x00, 0x80, 0x5F, 0x48, 0xA1, 0x92}};
    WSAPROTOCOL_INFOW p;
    DX_BEGIN();
    dx_base_entry(&p, 5);
    if (!dx_has_guid(0, &tcp4)) { t_skip("no stock IPv4 provider id in the catalog"); dx_end(); return; }
    EXPECT_EQ(dx_install_one(&tcp4, &p), DXE_NO_RECOVERY);
    dx_end();
}
TEST(dxpc_provider_id_free_again_after_deinstall)
{
    WSAPROTOCOL_INFOW p; GUID g = dx_guid(3); INT err = 0;
    DX_BEGIN();
    dx_base_entry(&p, 3);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    EXPECT_EQ(DX_DEINSTALL(&g, &err), 0);
    EXPECT_EQ(dx_install_one(&g, &p), 0);
    dx_end();
}

/* ---- several records in one call ---- */

TEST(dxpc_batch_all_valid_installs_all)
{
    WSAPROTOCOL_INFOW p[3]; GUID g = dx_guid(6); INT err = 0;
    DX_BEGIN();
    for (int i = 0; i < 3; i++) dx_base_entry(&p[i], 6 + i);
    EXPECT_EQ(DX_INSTALL(&g, dx_dll_path(), p, 3, &err), 0);
    { dx_list l;
      if (dx_enum(0, &l) >= 0) { EXPECT_EQ(dx_count_guid(&l, &g), 3); dx_free(&l); } }
    dx_end();
}
TEST(dxpc_batch_one_invalid_installs_none)
{
    /* The catalog is written once at the end, so a late failure leaves nothing behind. */
    WSAPROTOCOL_INFOW p[3]; GUID g = dx_guid(6); INT err = 0;
    DX_BEGIN();
    for (int i = 0; i < 3; i++) dx_base_entry(&p[i], 6 + i);
    p[2].iMinSockAddr = 1;
    EXPECT_EQ(DX_INSTALL(&g, dx_dll_path(), p, 3, &err), SOCKET_ERROR);
    EXPECT_EQ(err, DXE_INVALIDPROC);
    CHECK(!dx_has_guid(0, &g));
    dx_end();
}
TEST(dxpc_batch_first_invalid_installs_none)
{
    WSAPROTOCOL_INFOW p[2]; GUID g = dx_guid(6); INT err = 0;
    DX_BEGIN();
    for (int i = 0; i < 2; i++) dx_base_entry(&p[i], 6 + i);
    p[0].ProtocolChain.ChainLen = 8;
    EXPECT_EQ(DX_INSTALL(&g, dx_dll_path(), p, 2, &err), SOCKET_ERROR);
    EXPECT_EQ(err, DXE_INVALIDPROC);
    CHECK(!dx_has_guid(0, &g));
    dx_end();
}
TEST(dxpc_batch_shares_one_provider_id)
{
    WSAPROTOCOL_INFOW p[2]; GUID g = dx_guid(6); INT err = 0;
    DX_BEGIN();
    for (int i = 0; i < 2; i++) dx_base_entry(&p[i], 6 + i);
    p[0].ProviderId = dx_guid(77); p[1].ProviderId = dx_guid(78);   /* caller-supplied ids are replaced */
    EXPECT_EQ(DX_INSTALL(&g, dx_dll_path(), p, 2, &err), 0);
    { dx_list l;
      if (dx_enum(0, &l) >= 0) {
          EXPECT_EQ(dx_count_guid(&l, &g), 2);
          dx_free(&l);
      } }
    { GUID other = dx_guid(77); CHECK(!dx_has_guid(0, &other)); }
    dx_end();
}

/* ---- chain-entry rules ---- */

static int ids_for(DWORD *layered, DWORD *base, unsigned idx)
{
    /* Install a placeholder (id idx) and a base provider (id idx+1); report their assigned catalog ids. */
    WSAPROTOCOL_INFOW l, b; GUID gl = dx_guid(idx), gb = dx_guid(idx + 1);
    dx_layered_entry(&l, idx); dx_base_entry(&b, idx);
    if (dx_install_one(&gl, &l) || dx_install_one(&gb, &b)) return 0;
    *layered = dx_id_of(0, &gl); *base = dx_id_of(0, &gb);
    return *layered && *base;
}
TEST(dxpc_chain_members_must_exist)
{
    WSAPROTOCOL_INFOW c; GUID g = dx_guid(20);
    DX_BEGIN();
    dx_chain_entry(&c, 20, 0x7e7e7e01, 0x7e7e7e02);
    EXPECT_EQ(dx_install_one(&g, &c), DXE_INVALIDPROC);
    dx_end();
}
TEST(dxpc_chain_unknown_base_member)
{
    DWORD l, b; WSAPROTOCOL_INFOW c; GUID g = dx_guid(20);
    DX_BEGIN();
    if (!ids_for(&l, &b, 10)) { t_skip("setup install failed"); dx_end(); return; }
    dx_chain_entry(&c, 10, l, 0x7e7e7e02);
    EXPECT_EQ(dx_install_one(&g, &c), DXE_INVALIDPROC);
    dx_end();
}
TEST(dxpc_chain_unknown_first_member)
{
    DWORD l, b; WSAPROTOCOL_INFOW c; GUID g = dx_guid(20);
    DX_BEGIN();
    if (!ids_for(&l, &b, 10)) { t_skip("setup install failed"); dx_end(); return; }
    dx_chain_entry(&c, 10, 0x7e7e7e01, b);
    EXPECT_EQ(dx_install_one(&g, &c), DXE_INVALIDPROC);
    dx_end();
}
TEST(dxpc_chain_first_member_may_not_be_base)
{
    DWORD l, b; WSAPROTOCOL_INFOW c; GUID g = dx_guid(20);
    DX_BEGIN();
    if (!ids_for(&l, &b, 10)) { t_skip("setup install failed"); dx_end(); return; }
    dx_chain_entry(&c, 10, b, b);
    EXPECT_EQ(dx_install_one(&g, &c), DXE_INVALIDPROC);
    dx_end();
}
TEST(dxpc_chain_last_member_must_be_base)
{
    DWORD l, b; WSAPROTOCOL_INFOW c; GUID g = dx_guid(20);
    DX_BEGIN();
    if (!ids_for(&l, &b, 10)) { t_skip("setup install failed"); dx_end(); return; }
    dx_chain_entry(&c, 10, l, l);
    EXPECT_EQ(dx_install_one(&g, &c), DXE_INVALIDPROC);
    dx_end();
}
TEST(dxpc_chain_members_swapped)
{
    DWORD l, b; WSAPROTOCOL_INFOW c; GUID g = dx_guid(20);
    DX_BEGIN();
    if (!ids_for(&l, &b, 10)) { t_skip("setup install failed"); dx_end(); return; }
    dx_chain_entry(&c, 10, b, l);
    EXPECT_EQ(dx_install_one(&g, &c), DXE_INVALIDPROC);
    dx_end();
}
TEST(dxpc_chain_valid_pair_installs)
{
    DWORD l, b; WSAPROTOCOL_INFOW c; GUID g = dx_guid(20);
    DX_BEGIN();
    if (!ids_for(&l, &b, 10)) { t_skip("setup install failed"); dx_end(); return; }
    dx_chain_entry(&c, 10, l, b);
    EXPECT_EQ(dx_install_one(&g, &c), 0);
    dx_end();
}
TEST(dxpc_chain_repeated_member_refused)
{
    /* Three members where the first two resolve to the same layer. */
    DWORD l, b; WSAPROTOCOL_INFOW c; GUID g = dx_guid(20);
    DX_BEGIN();
    if (!ids_for(&l, &b, 10)) { t_skip("setup install failed"); dx_end(); return; }
    dx_chain_entry(&c, 10, l, b);
    c.ProtocolChain.ChainLen = 3;
    c.ProtocolChain.ChainEntries[0] = l; c.ProtocolChain.ChainEntries[1] = l; c.ProtocolChain.ChainEntries[2] = b;
    EXPECT_EQ(dx_install_one(&g, &c), DXE_INVALIDPROC);
    dx_end();
}
TEST(dxpc_chain_of_three_through_two_layers)
{
    WSAPROTOCOL_INFOW l1, l2, b, c; GUID g1 = dx_guid(30), g2 = dx_guid(31), gb = dx_guid(32), gc = dx_guid(33);
    DWORD i1, i2, ib;
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
    { dx_list l; const WSAPROTOCOL_INFOW *e;
      if (dx_enum(0, &l) >= 0) {
          e = dx_first_guid(&l, &gc);
          CHECK(e != NULL);
          if (e) {
              EXPECT_EQ(e->ProtocolChain.ChainLen, 3);
              EXPECT_EQ(e->ProtocolChain.ChainEntries[0], i1);
              EXPECT_EQ(e->ProtocolChain.ChainEntries[1], i2);
              EXPECT_EQ(e->ProtocolChain.ChainEntries[2], ib);
          }
          dx_free(&l);
      } }
    dx_end();
}
TEST(dxpc_chain_path_must_match_first_member)
{
    DWORD l, b; WSAPROTOCOL_INFOW c; GUID g = dx_guid(20);
    DX_BEGIN();
    if (!ids_for(&l, &b, 10)) { t_skip("setup install failed"); dx_end(); return; }
    dx_chain_entry(&c, 10, l, b);
    EXPECT_EQ(install_with_path(&g, L"C:\\ws2t_dx_catalog_dir\\other_layer.dll", &c, 1), DXE_PROVFAILED);
    dx_end();
}
TEST(dxpc_chain_path_spelling_compared_after_expansion)
{
    /* The member's recorded path and the new one are compared after environment expansion. */
    DWORD l, b; WSAPROTOCOL_INFOW c; GUID g = dx_guid(20); WCHAR abs_[MAX_PATH + 16];
    DX_BEGIN();
    if (!ids_for(&l, &b, 10)) { t_skip("setup install failed"); dx_end(); return; }
    GetSystemDirectoryW(abs_, MAX_PATH); lstrcatW(abs_, L"\\mswsock.dll");
    dx_chain_entry(&c, 10, l, b);
    { WCHAR e1[MAX_PATH], e2[MAX_PATH];
      ExpandEnvironmentStringsW(dx_dll_path(), e1, MAX_PATH);
      lstrcpyW(e2, abs_);
      if (lstrcmpW(e1, e2)) { t_skip("system directory spelling differs from the expanded variable"); dx_end(); return; } }
    EXPECT_EQ(install_with_path(&g, abs_, &c, 1), 0);
    dx_end();
}
TEST(dxpc_chain_path_comparison_is_case_sensitive)
{
    DWORD l, b; WSAPROTOCOL_INFOW c; GUID g = dx_guid(20);
    DX_BEGIN();
    if (!ids_for(&l, &b, 10)) { t_skip("setup install failed"); dx_end(); return; }
    dx_chain_entry(&c, 10, l, b);
    EXPECT_EQ(install_with_path(&g, L"%SystemRoot%\\SYSTEM32\\MSWSOCK.DLL", &c, 1), DXE_PROVFAILED);
    dx_end();
}
