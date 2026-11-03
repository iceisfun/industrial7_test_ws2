/* Guarded destructive area: install, update, reorder and remove a throwaway base provider.
 *
 * Every test is skipped unless the process is elevated, uses a provider id that no catalog contains, and
 * leaves the protocol catalog exactly as found (compared by entry id and order before and after, and the
 * throwaway id is removed again at the start of each test in case an earlier run was killed). The new
 * entry is a copy of the stock IPv4 UDP base entry with the installable-file-system bit set, so no helper
 * service configuration is touched, and it is always placed behind the stock entries.
 *
 * Contract observed here: install appends one entry with a fresh catalog id and the given provider id;
 * enumeration shows it; reordering with a complete list is accepted and visible; removal drops exactly that
 * entry; removing it again fails with WSAEFAULT in the error out-parameter. */
#include "dxqm.h"

UDECL(int, WSCDeinstallProvider, (LPGUID, LPINT));
UDECL(int, WSCWriteProviderOrder, (LPDWORD, DWORD));
UDECL(int, WSCUpdateProvider, (LPGUID, const WCHAR *, const WSAPROTOCOL_INFOW *, DWORD, LPINT));
UDECL(int, WSCInstallProvider, (LPGUID, const WCHAR *, const WSAPROTOCOL_INFOW *, DWORD, LPINT));
UDECL(int, WSCEnumProtocols, (LPINT, LPWSAPROTOCOL_INFOW, LPDWORD, LPINT));
UDECL(int, WSCGetProviderPath, (LPGUID, WCHAR *, LPINT, LPINT));

static const WCHAR kdll[] = L"%SystemRoot%\\system32\\mswsock.dll";
#define NO_ERRNO 0x5A5A5A5A

typedef struct { WSAPROTOCOL_INFOW *e; int n; } cat_t;

static int cat_load(cat_t *c)
{
    DWORD len = 0; int e = 0;
    c->e = NULL; c->n = 0;
    /* The writers see every catalog row, including the ones the public enumeration hides. */
    if (UN(WSCEnumProtocols)(NULL, NULL, &len, &e) != SOCKET_ERROR || len == 0) return 0;
    c->e = malloc(len);
    c->n = UN(WSCEnumProtocols)(NULL, c->e, &len, &e);
    if (c->n <= 0) { free(c->e); c->e = NULL; c->n = 0; return 0; }
    return 1;
}
static void cat_free(cat_t *c) { free(c->e); c->e = NULL; c->n = 0; }
static int cat_find(const cat_t *c, const GUID *g)
{
    for (int i = 0; i < c->n; i++) if (qm_guid_eq(&c->e[i].ProviderId, g)) return i;
    return -1;
}
static int cat_same(const cat_t *a, const cat_t *b)
{
    if (a->n != b->n) return 0;
    for (int i = 0; i < a->n; i++) if (a->e[i].dwCatalogEntryId != b->e[i].dwCatalogEntryId) return 0;
    return 1;
}

/* Common prologue: elevated, exports present, stack up, throwaway id absent. Fills `before`. */
static int begin(cat_t *before, WSAPROTOCOL_INFOW *tmpl)
{
    int err = 0; GUID g = qm_guid_a;
    if (t_is_wine()) { t_skip("catalog writers are stubs in the emulated stack"); return 0; }
    if (!qm_elevated()) { t_skip("needs an elevated token"); return 0; }
    if (!UN(WSCInstallProvider) || !UN(WSCDeinstallProvider) || !UN(WSCWriteProviderOrder) || !UN(WSCUpdateProvider)) { t_skip("missing export"); return 0; }
    if (qm_up() != 0) { t_skip("WSAStartup failed"); return 0; }
    UN(WSCDeinstallProvider)(&g, &err);             /* stale remnant of a killed run, if any */
    if (!cat_load(before)) { t_skip("catalog unreadable"); return 0; }
    int found = 0;
    for (int i = 0; i < before->n; i++) {
        const WSAPROTOCOL_INFOW *e = &before->e[i];
        if (e->iAddressFamily == AF_INET && e->iSocketType == SOCK_DGRAM && e->iProtocol == IPPROTO_UDP && e->ProtocolChain.ChainLen == 1 && (e->dwServiceFlags1 & XP1_IFS_HANDLES)) { *tmpl = *e; found = 1; break; }
    }
    if (!found) { cat_free(before); t_skip("no stock IPv4 UDP base entry"); return 0; }
    wcscpy(tmpl->szProtocol, L"ws2t throwaway provider");
    tmpl->ProviderId = qm_guid_a;
    return 1;
}
static int install(const WSAPROTOCOL_INFOW *tmpl, int *err)
{
    GUID g = qm_guid_a;
    *err = NO_ERRNO;
    return UN(WSCInstallProvider)(&g, kdll, tmpl, 1, err);
}
static void remove_it(void) { GUID g = qm_guid_a; int err = 0; UN(WSCDeinstallProvider)(&g, &err); }

TEST(dx_install_appears_in_the_catalog_and_removal_restores_it)
{
    cat_t before, mid, after; WSAPROTOCOL_INFOW t; int err;
    if (!begin(&before, &t)) return;
    EXPECT_EQ(install(&t, &err), 0);
    if (cat_load(&mid)) {
        EXPECT_EQ(mid.n, before.n + 1);
        int at = cat_find(&mid, &qm_guid_a);
        CHECK(at >= 0);
        if (at >= 0) {
            CHECK(mid.e[at].dwCatalogEntryId != 0);
            CHECK(mid.e[at].iAddressFamily == AF_INET && mid.e[at].iSocketType == SOCK_DGRAM);
            CHECK(!lstrcmpW(mid.e[at].szProtocol, L"ws2t throwaway provider"));
            for (int i = 0; i < before.n; i++) CHECK(mid.e[at].dwCatalogEntryId != before.e[i].dwCatalogEntryId);
            EXPECT_EQ(at, mid.n - 1);               /* appended behind the stock entries */
        }
        cat_free(&mid);
    }
    GUID g = qm_guid_a; err = NO_ERRNO;
    EXPECT_EQ(UN(WSCDeinstallProvider)(&g, &err), 0);
    CHECK(cat_load(&after));
    CHECK(cat_same(&before, &after));
    cat_free(&before); cat_free(&after);
}
TEST(dx_install_same_id_twice_is_refused)
{
    cat_t before, after; WSAPROTOCOL_INFOW t; int err;
    if (!begin(&before, &t)) return;
    EXPECT_EQ(install(&t, &err), 0);
    int r2 = install(&t, &err);
    EXPECT_EQ(r2, -1);
    EXPECT_EQ(err, 11003);
    remove_it();
    CHECK(cat_load(&after));
    CHECK(cat_same(&before, &after));
    cat_free(&before); cat_free(&after);
}
TEST(dx_removal_twice_second_fails_with_efault)
{
    cat_t before; WSAPROTOCOL_INFOW t; int err;
    if (!begin(&before, &t)) return;
    EXPECT_EQ(install(&t, &err), 0);
    GUID g = qm_guid_a; err = NO_ERRNO;
    EXPECT_EQ(UN(WSCDeinstallProvider)(&g, &err), 0);
    err = NO_ERRNO;
    EXPECT_EQ(UN(WSCDeinstallProvider)(&g, &err), -1);
    EXPECT_EQ(err, WSAEFAULT);
    cat_free(&before);
}
TEST(dx_update_changes_the_protocol_name_in_place)
{
    cat_t before, mid, after; WSAPROTOCOL_INFOW t; int err;
    if (!begin(&before, &t)) return;
    EXPECT_EQ(install(&t, &err), 0);
    if (cat_load(&mid)) {
        int at = cat_find(&mid, &qm_guid_a);
        CHECK(at >= 0);
        if (at >= 0) {
            WSAPROTOCOL_INFOW u = mid.e[at];
            wcscpy(u.szProtocol, L"ws2t throwaway renamed");
            GUID g = qm_guid_a; err = NO_ERRNO;
            int r = UN(WSCUpdateProvider)(&g, kdll, &u, 1, &err);
            EXPECT_EQ(r, 0);
            cat_t upd;
            if (cat_load(&upd)) {
                EXPECT_EQ(upd.n, mid.n);
                int k = cat_find(&upd, &qm_guid_a);
                CHECK(k >= 0);
                if (k >= 0) {
                    CHECK(!lstrcmpW(upd.e[k].szProtocol, L"ws2t throwaway renamed"));
                    EXPECT_EQ(upd.e[k].dwCatalogEntryId, mid.e[at].dwCatalogEntryId);
                }
                cat_free(&upd);
            }
        }
        cat_free(&mid);
    }
    remove_it();
    CHECK(cat_load(&after));
    CHECK(cat_same(&before, &after));
    cat_free(&before); cat_free(&after);
}
TEST(dx_write_order_moves_the_entry_to_the_front_and_back)
{
    cat_t before, mid, after; WSAPROTOCOL_INFOW t; int err;
    if (!begin(&before, &t)) return;
    EXPECT_EQ(install(&t, &err), 0);
    if (cat_load(&mid)) {
        DWORD *ids = malloc(mid.n * sizeof(DWORD));
        int at = cat_find(&mid, &qm_guid_a);
        if (at >= 0) {
            ids[0] = mid.e[at].dwCatalogEntryId;
            int k = 1;
            for (int i = 0; i < mid.n; i++) if (i != at) ids[k++] = mid.e[i].dwCatalogEntryId;
            EXPECT_EQ(UN(WSCWriteProviderOrder)(ids, mid.n), 0);
            cat_t o;
            if (cat_load(&o)) {
                CHECK(o.n == mid.n);
                CHECK(o.e[0].dwCatalogEntryId == ids[0]);
                CHECK(qm_guid_eq(&o.e[0].ProviderId, &qm_guid_a));
                cat_free(&o);
            }
            /* restore the original order (stock entries first, throwaway last) */
            for (int i = 0; i < mid.n; i++) ids[i] = mid.e[i].dwCatalogEntryId;
            EXPECT_EQ(UN(WSCWriteProviderOrder)(ids, mid.n), 0);
        }
        free(ids);
        cat_free(&mid);
    }
    remove_it();
    CHECK(cat_load(&after));
    CHECK(cat_same(&before, &after));
    cat_free(&before); cat_free(&after);
}
TEST(dx_provider_path_roundtrip)
{
    cat_t before; WSAPROTOCOL_INFOW t; int err;
    if (!begin(&before, &t)) return;
    EXPECT_EQ(install(&t, &err), 0);
    if (UN(WSCGetProviderPath)) {
        WCHAR path[MAX_PATH] = { 0 }; int len = MAX_PATH; GUID g = qm_guid_a; err = NO_ERRNO;
        EXPECT_EQ(UN(WSCGetProviderPath)(&g, path, &len, &err), 0);
        CHECK(len > 0 && len == (int)lstrlenW(path));          /* the reported length excludes the terminator */
        CHECK(wcsstr(path, L"mswsock") != NULL || wcsstr(path, L"MSWSOCK") != NULL || wcsstr(path, L"Mswsock") != NULL);
    }
    remove_it();
    cat_free(&before);
}
TEST(dx_installed_entry_creates_sockets_by_catalog_id)
{
    /* Creating a socket from the entry (FROM_PROTOCOL_INFO) goes through the new provider id. */
    cat_t before, mid; WSAPROTOCOL_INFOW t; int err;
    if (!begin(&before, &t)) return;
    EXPECT_EQ(install(&t, &err), 0);
    if (cat_load(&mid)) {
        int at = cat_find(&mid, &qm_guid_a);
        if (at >= 0) {
            SOCKET s = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &mid.e[at], 0, 0);
            CHECK(s != INVALID_SOCKET);
            if (s != INVALID_SOCKET) {
                WSAPROTOCOL_INFOW got; int n = sizeof got;
                if (U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&got, &n) == 0)
                    CHECK(got.dwCatalogEntryId == mid.e[at].dwCatalogEntryId);
                U(closesocket)(s);
            }
        }
        cat_free(&mid);
    }
    remove_it();
    cat_free(&before);
}
TEST(dx_not_elevated_leaves_everything_alone)
{
    if (qm_elevated()) { t_skip("only meaningful for a plain token"); return; }
    if (!UN(WSCDeinstallProvider)) { t_skip("missing export"); return; }
    GUID g = qm_guid_a; int err = NO_ERRNO;
    EXPECT_EQ(UN(WSCDeinstallProvider)(&g, &err), -1);
    CHECK(err != 0 && err != NO_ERRNO);
}

/* ---- namespace order ---------------------------------------------------------------------------------- */

UDECL(int, WSCWriteNameSpaceOrder, (LPGUID, DWORD));

TEST(dx_namespace_order_empty_list_is_accepted_and_changes_nothing)
{
    /* Unlike the protocol catalog (where an incomplete list is refused), the namespace order writer takes an
     * empty list as a successful no-op. The namespace catalog read back afterwards is identical. */
    if (t_is_wine()) { t_skip("catalog writers are stubs in the emulated stack"); return; }
    if (!qm_elevated()) { t_skip("needs an elevated token"); return; }
    if (!UN(WSCWriteNameSpaceOrder)) { t_skip("missing export"); return; }
    if (qm_up() != 0) { t_skip("WSAStartup failed"); return; }
    DWORD l1 = 0, l2 = 0;
    CHECK(U(WSAEnumNameSpaceProvidersW)(&l1, NULL) == SOCKET_ERROR && l1 > 0);
    WSANAMESPACE_INFOW *a = malloc(l1 ? l1 : 1), *b;
    int na = U(WSAEnumNameSpaceProvidersW)(&l1, a);
    EXPECT_EQ(UN(WSCWriteNameSpaceOrder)(NULL, 0), 0);
    U(WSAEnumNameSpaceProvidersW)(&l2, NULL);
    b = malloc(l2 ? l2 : 1);
    int nb = U(WSAEnumNameSpaceProvidersW)(&l2, b);
    EXPECT_EQ(na, nb);
    if (na == nb && na > 0)
        for (int i = 0; i < na; i++) CHECK(qm_guid_eq(&a[i].NSProviderId, &b[i].NSProviderId));
    free(a); free(b);
}
