/* GetAddrInfoExA: a synchronous-only front end. A timeout, an OVERLAPPED, a completion routine or a cancel
 * handle is refused; the hint structure is copied by declared version only when AI_EXTENDED is present
 * (versions 2, 3 and 4 only); results come back converted to ANSI. Loopback data only. */
#include "gx.h"

#define NSDNS 12
#define NEED_A() \
    do { if (!GXA() || !U(FreeAddrInfoEx) || !U(WSAGetLastError) || !U(WSASetLastError)) { t_skip("no GetAddrInfoExA"); return; } \
         if (gx_up()) { t_skip("WSAStartup failed"); return; } } while (0)

static int acall(const char *name, const char *svc, DWORD ns, const GXEX *hint, GXEXA **res)
{
    *res = (GXEXA *)&gx_sentinel_ex;
    SETWSERR(0x7777);
    return GXA()(name, svc, ns, NULL, hint, (void **)res, NULL, NULL, NULL, NULL);
}
static void afree(GXEXA *r) { if (r && r != (GXEXA *)&gx_sentinel_ex) U(FreeAddrInfoEx)((PADDRINFOEXA)r); }

TEST(xansi_async_arguments_are_einval)
{
    static const char *const names[] = {"127.0.0.1", "localhost", "", "::1"};
    unsigned i; int variant;
    NEED_A();
    for (variant = 0; variant < 4; variant++) for (i = 0; i < NARR(names); i++) {
        struct timeval tv = {5, 0};
        OVERLAPPED ov;
        HANDLE h = NULL;
        GXEXA *res = (GXEXA *)&gx_sentinel_ex;
        int r;
        memset(&ov, 0, sizeof ov);
        SETWSERR(0x7777);
        r = GXA()(names[i], NULL, NSDNS, NULL, NULL, (void **)&res, variant == 0 ? &tv : NULL, variant == 1 ? &ov : NULL,
                  variant == 2 ? (PVOID)gx_cb_routine : NULL, variant == 3 ? &h : NULL);
        CHECKF(r == WSAEINVAL && WSERR() == WSAEINVAL, "variant %d '%s' ret=%d", variant, names[i], r);
        CHECK(res == NULL);
    }
    gx_down();
}
TEST(xansi_null_name_and_selector_errors_clear_result)
{
    static const struct { const char *n; DWORD ns; int err; } rows[] = {
        {NULL, NSDNS, WSAHOST_NOT_FOUND}, {"127.0.0.1", 15, WSASERVICE_NOT_FOUND}, {"127.0.0.1", 38, WSAEINVAL},
        {"0x7f.1", NSDNS, WSAHOST_NOT_FOUND}, {"localhost", 99, WSASERVICE_NOT_FOUND},
    };
    unsigned i;
    NEED_A();
    for (i = 0; i < NARR(rows); i++) {
        GXEXA *res;
        int r = acall(rows[i].n, NULL, rows[i].ns, NULL, &res);
        CHECKF(r == rows[i].err && WSERR() == rows[i].err && res == NULL, "row %u ret=%d", i, r);
    }
    gx_down();
}
/* Without AI_EXTENDED the declared version is never read. */
TEST(xansi_version_ignored_without_extended_flag)
{
    int v;
    NEED_A();
    for (v = -1; v <= 9; v++) {
        GXEX h = gx_hint(0, AF_INET, 0, 0);
        GXEXA *res;
        h.ai_version = v;
        CHECKF(acall("localhost", NULL, NSDNS, &h, &res) == 0 && res && res->ai_family == AF_INET && res->ai_next == NULL, "v%d", v);
        afree(res);
    }
    gx_down();
}
/* With AI_EXTENDED only versions 2, 3 and 4 are accepted. */
TEST(xansi_extended_hint_accepts_only_versions_2_to_4)
{
    int v;
    NEED_A();
    for (v = -1; v <= 9; v++) {
        GXEX h = gx_hint((int)0x80000000u, AF_INET, 0, 0);
        GXEXA *res;
        int r;
        h.ai_version = v;
        r = acall("127.0.0.1", NULL, NSDNS, &h, &res);
        if (v >= 2 && v <= 4) { CHECKF(r == 0 && res, "v%d accepted, ret=%d", v, r); afree(res); }
        else { CHECKF(r == WSAEINVAL && res == NULL && WSERR() == WSAEINVAL, "v%d rejected, ret=%d", v, r); afree(res); }
    }
    gx_down();
}
TEST(xansi_dirty_hint_refused)
{
    NEED_A();
    {
        GXEX h = gx_hint(0, 0, 0, 0);
        GXEXA *res;
        h.ai_addrlen = 4;
        CHECK(acall("localhost", NULL, NSDNS, &h, &res) == WSANO_RECOVERY && res == NULL);
        h = gx_hint(0, 0, 0, 0); h.ai_next = &h;
        CHECK(acall("localhost", NULL, NSDNS, &h, &res) == WSANO_RECOVERY && res == NULL);
    }
    gx_down();
}
/* The front end always asks the wide worker for a resolution handle; for a host name the entries therefore come
 * back as version-4 extended entries; a numeric literal keeps its plain numeric flags. */
TEST(xansi_result_flags_for_names_and_literals)
{
    GXEXA *res, *e;
    NEED_A();
    GX_EQ(acall("localhost", NULL, NSDNS, NULL, &res), 0);
    for (e = res == (GXEXA *)&gx_sentinel_ex ? NULL : res; e; e = e->ai_next) {
        CHECKF((unsigned)e->ai_flags == 0x80000000u, "localhost flags %x", e->ai_flags);
        CHECKF(e->ai_version == 4, "localhost version %d", e->ai_version);
    }
    afree(res);
    GX_EQ(acall("127.0.0.1", NULL, NSDNS, NULL, &res), 0);
    for (e = res == (GXEXA *)&gx_sentinel_ex ? NULL : res; e; e = e->ai_next) GX_EQ(e->ai_flags, AI_NUMERICHOST);
    afree(res);
    gx_down();
}
TEST(xansi_family_and_order_match_wide)
{
    GXEXA *res, *e;
    char fams[32] = "";
    NEED_A();
    GX_EQ(acall("localhost", NULL, NSDNS, NULL, &res), 0);
    for (e = res == (GXEXA *)&gx_sentinel_ex ? NULL : res; e; e = e->ai_next) { char t[8]; snprintf(t, sizeof t, "%s%d", fams[0] ? "," : "", e->ai_family); strcat(fams, t); }
    EXPECT_STR(fams, "23,2");
    afree(res);
    gx_down();
}
TEST(xansi_service_and_port_follow_wide_rules)
{
    GXEXA *res;
    NEED_A();
    GX_EQ(acall("127.0.0.1", "ftp", NSDNS, NULL, &res), 0);
    if (res != (GXEXA *)&gx_sentinel_ex && res) { GX_EQ(gx_port(res->ai_addr), 21); GX_EQ(res->ai_socktype, SOCK_STREAM); }
    afree(res);
    GX_EQ(acall("127.0.0.1", "domain", NSDNS, NULL, &res), 0);
    if (res != (GXEXA *)&gx_sentinel_ex && res) GX_EQ(gx_port(res->ai_addr), 53);
    afree(res);
    gx_down();
}
