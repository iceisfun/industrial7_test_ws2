/* Equivalents and edges around GetAddrInfoEx: the same host query through WSALookupServiceBegin/Next on the
 * host-name service class, SetAddrInfoEx argument rejection (no registration is ever performed),
 * FreeAddrInfoEx(W) with NULL, and calls made without WSAStartup. */
#include "gx.h"

#define NSALL 0
#define NSDNS 12

/* ---- WSALookupService with SVCID_HOSTNAME ------------------------------------------------------------- */
/* Result of one Begin/Next/Next/End sequence. */
typedef struct { int begin_ret, begin_err; int items; int next_ret, next_err; DWORD ncsa; DWORD ns; char name[300]; int fam; } lk_res;
static lk_res lookup(const char *name, DWORD ns)
{
    lk_res o;
    WSAQUERYSETW qs;
    GUID g = gx_svcid_hostname;
    HANDLE h = NULL;
    char buf[3000];
    memset(&o, 0, sizeof o);
    memset(&qs, 0, sizeof qs);
    qs.dwSize = sizeof qs;
    qs.lpszServiceInstanceName = (LPWSTR)gx_w(name);
    qs.lpServiceClassId = &g;
    qs.dwNameSpace = ns;
    SETWSERR(0x7777);
    o.begin_ret = U(WSALookupServiceBeginW)(&qs, LUP_RETURN_NAME | LUP_RETURN_ADDR | LUP_RETURN_BLOB, &h);
    o.begin_err = o.begin_ret ? WSERR() : 0;
    if (o.begin_ret == 0) {
        for (;;) {
            DWORD len = sizeof buf;
            WSAQUERYSETW *q = (WSAQUERYSETW *)buf;
            SETWSERR(0x7777);
            int rr = U(WSALookupServiceNextW)(h, LUP_RETURN_NAME | LUP_RETURN_ADDR, &len, q);
            if (rr) { o.next_ret = rr; o.next_err = WSERR(); break; }
            if (o.items == 0) {
                o.ncsa = q->dwNumberOfCsAddrs; o.ns = q->dwNameSpace;
                snprintf(o.name, sizeof o.name, "%s", gx_s(q->lpszServiceInstanceName));
                if (q->dwNumberOfCsAddrs && q->lpcsaBuffer) o.fam = q->lpcsaBuffer[0].RemoteAddr.lpSockaddr ? q->lpcsaBuffer[0].RemoteAddr.lpSockaddr->sa_family : 0;
            }
            if (++o.items > 8) break;
        }
        U(WSALookupServiceEnd)(h);
    }
    return o;
}
#define NEED_LK() \
    do { if (!U(WSALookupServiceBeginW) || !U(WSALookupServiceNextW) || !U(WSALookupServiceEnd) || !U(WSAGetLastError) || !U(WSASetLastError)) { t_skip("missing export"); return; } \
         if (gx_up()) { t_skip("WSAStartup failed"); return; } } while (0)

TEST(xmisc_lookup_literal_hosts_one_item_dns_namespace)
{
    static const struct { const char *n; int fam; } rows[] = {{"127.0.0.1", AF_INET}};
    unsigned i; int ns;
    NEED_LK();
    for (ns = 0; ns < 2; ns++) for (i = 0; i < NARR(rows); i++) {
        lk_res o = lookup(rows[i].n, ns ? NSDNS : NSALL);
        CHECKF(o.begin_ret == 0, "%s ns=%d begin %d/%d", rows[i].n, ns, o.begin_ret, o.begin_err);
        GX_EQ(o.items, 1);
        GX_EQ(o.next_ret, -1);
        GX_EQ(o.next_err, WSA_E_NO_MORE);
        GX_EQ(o.ncsa, 1);
        GX_EQ(o.ns, NSDNS);                        /* the answer is attributed to the DNS provider either way */
        EXPECT_STR(o.name, rows[i].n);
        GX_EQ(o.fam, rows[i].fam);
    }
    gx_down();
}
TEST(xmisc_lookup_localhost_one_item_named_after_machine)
{
    NEED_LK();
    lk_res o = lookup("localhost", NSDNS);
    GX_EQ(o.begin_ret, 0);
    GX_EQ(o.items, 1);                              /* one item although getaddrinfo style calls give two addresses */
    GX_EQ(o.next_err, WSA_E_NO_MORE);
    GX_EQ(o.ncsa, 1);
    {
        WCHAR a[300], w[300]; DWORD la = 300;
        MultiByteToWideChar(CP_ACP, 0, o.name, -1, w, 300);
        CHECK(GetComputerNameExW(ComputerNameDnsHostname, a, &la));
        CHECKF(!lstrcmpiW(a, w), "item name '%s'", o.name);
    }
    gx_down();
}
TEST(xmisc_lookup_unresolvable_names_not_found_at_next)
{
    static const char *const names[] = {"nosuch.invalid", "::1", "0x7f.1"};
    unsigned i; int ns;
    NEED_LK();
    for (ns = 0; ns < 2; ns++) for (i = 0; i < NARR(names); i++) {
        lk_res o = lookup(names[i], ns ? NSDNS : NSALL);
        CHECKF(o.begin_ret == 0, "%s begin %d", names[i], o.begin_ret);       /* Begin succeeds; the miss shows at Next */
        GX_EQ(o.items, 0);
        CHECKF(o.next_ret == -1 && o.next_err == WSAHOST_NOT_FOUND, "%s next %d/%d", names[i], o.next_ret, o.next_err);
    }
    gx_down();
}
TEST(xmisc_lookup_nla_namespace_has_no_hostname_provider)
{
    static const char *const names[] = {"127.0.0.1", "localhost", "nosuch.invalid"};
    unsigned i;
    NEED_LK();
    for (i = 0; i < NARR(names); i++) {
        lk_res o = lookup(names[i], 15);
        CHECKF(o.begin_ret == -1 && o.begin_err == WSASERVICE_NOT_FOUND, "%s begin %d/%d", names[i], o.begin_ret, o.begin_err);
    }
    gx_down();
}
TEST(xmisc_lookup_agrees_with_getaddrinfoex_on_the_address)
{
    NEED_LK();
    if (!GXW() || !U(FreeAddrInfoExW) || !UN(GetAddrInfoExOverlappedResult)) { t_skip("missing export"); gx_down(); return; }
    {
        gx_res r = gx_call("127.0.0.1", NULL, NSDNS, NULL);
        lk_res o = lookup("127.0.0.1", NSDNS);
        GX_EQ(r.ret, 0); GX_EQ(o.items, 1);
        GX_EQ(o.fam, r.res->ai_family);
        gx_release(&r);
    }
    gx_down();
}

/* ---- SetAddrInfoEx ------------------------------------------------------------------------------------ */
/* Only the argument checks that run before anything is registered: a timeout, an OVERLAPPED, a completion
 * routine or a cancel handle is invalid (the value is returned, the thread error slot is not set); an
 * unknown service name is rejected. */
typedef int (WINAPI *set_fn)(PCWSTR, PCWSTR, SOCKET_ADDRESS *, DWORD, LPBLOB, DWORD, DWORD, LPGUID, struct timeval *, LPOVERLAPPED, PVOID, HANDLE *);
#define NEED_SET() set_fn setf = (set_fn)t_proc("SetAddrInfoExW"); \
    do { if (!setf || !U(WSAGetLastError) || !U(WSASetLastError)) { t_skip("missing export"); return; } if (gx_up()) { t_skip("WSAStartup failed"); return; } } while (0)

TEST(xmisc_setaddr_timeout_is_einval)
{
    struct timeval tv = {1, 0};
    NEED_SET();
    SETWSERR(0x7777);
    GX_EQ(setf(gx_w("gx-throwaway.invalid"), NULL, NULL, 0, NULL, 0, NSDNS, NULL, &tv, NULL, NULL, NULL), WSAEINVAL);
    GX_EQ(WSERR(), 0x7777);                         /* returned directly, error slot untouched */
    gx_down();
}
TEST(xmisc_setaddr_overlapped_is_einval)
{
    OVERLAPPED ov;
    NEED_SET();
    memset(&ov, 0, sizeof ov);
    SETWSERR(0x7777);
    GX_EQ(setf(gx_w("gx-throwaway.invalid"), NULL, NULL, 0, NULL, 0, NSDNS, NULL, NULL, &ov, NULL, NULL), WSAEINVAL);
    GX_EQ(WSERR(), 0x7777);
    gx_down();
}
TEST(xmisc_setaddr_completion_routine_is_einval)
{
    NEED_SET();
    GX_EQ(setf(gx_w("gx-throwaway.invalid"), NULL, NULL, 0, NULL, 0, NSDNS, NULL, NULL, NULL, (PVOID)gx_cb_routine, NULL), WSAEINVAL);
    gx_down();
}
TEST(xmisc_setaddr_cancel_handle_is_einval)
{
    HANDLE h = NULL;
    NEED_SET();
    GX_EQ(setf(gx_w("gx-throwaway.invalid"), NULL, NULL, 0, NULL, 0, NSDNS, NULL, NULL, NULL, NULL, &h), WSAEINVAL);
    gx_down();
}
TEST(xmisc_setaddr_unknown_service_name_rejected)
{
    NEED_SET();
    GX_EQ(setf(gx_w("gx-throwaway.invalid"), gx_w("nosuchsvc"), NULL, 0, NULL, 0, NSDNS, NULL, NULL, NULL, NULL, NULL), WSATYPE_NOT_FOUND);
    gx_down();
}
TEST(xmisc_setaddr_unsupported_namespace_rejected)
{
    int r;
    NEED_SET();
    r = setf(gx_w("gx-throwaway.invalid"), NULL, NULL, 0, NULL, 0, 99, NULL, NULL, NULL, NULL, NULL);
    CHECKF(r != 0, "namespace 99 ret %d", r);
    gx_down();
}

/* ---- FreeAddrInfoEx with NULL ------------------------------------------------------------------------- */
TEST(xmisc_free_null_is_harmless)
{
    GX_BEGIN();
    U(FreeAddrInfoExW)(NULL);
    if (U(FreeAddrInfoEx)) U(FreeAddrInfoEx)(NULL);
    CHECK(1);
    GX_END();
}
TEST(xmisc_free_does_not_touch_error_slot)
{
    GX_BEGIN();
    gx_res r = gx_call("localhost", NULL, NSDNS, NULL);
    SETWSERR(0x4321);
    GXFREE(r.res);
    GX_EQ(WSERR(), 0x4321);
    GX_END();
}

/* ---- ANSI front end ------------------------------------------------------------------------------------ */
TEST(xmisc_ansi_matches_wide_for_loopback)
{
    static const char *const names[] = {"localhost", "127.0.0.1", "::1", "nosuch.invalid", "0x7f.1"};
    unsigned i;
    GX_BEGIN();
    if (!GXA() || !U(FreeAddrInfoEx)) { t_skip("no GetAddrInfoExA"); return; }
    for (i = 0; i < NARR(names); i++) {
        GXEXA *a = NULL, *e;
        gx_res w = gx_call(names[i], NULL, NSDNS, NULL);
        int ra = GXA()(names[i], NULL, NSDNS, NULL, NULL, (void **)&a, NULL, NULL, NULL, NULL);
        CHECKF(ra == w.ret, "%s ansi %d wide %d", names[i], ra, w.ret);
        if (ra == 0 && w.ret == 0) {
            GXEX *x = w.res;
            for (e = a; e && x; e = e->ai_next, x = x->ai_next) {
                GX_EQ(e->ai_family, x->ai_family); GX_EQ(e->ai_addrlen, x->ai_addrlen);
                CHECK(!memcmp(e->ai_addr, x->ai_addr, x->ai_addrlen));
            }
            CHECK(e == NULL && x == NULL);
        }
        if (a) U(FreeAddrInfoEx)((PADDRINFOEXA)a);
        gx_release(&w);
    }
    GX_END();
}
TEST(xmisc_ansi_null_name_and_selector_errors)
{
    GX_BEGIN();
    if (!GXA()) { t_skip("no GetAddrInfoExA"); return; }
    {
        GXEXA *a = (GXEXA *)&gx_sentinel_ex;
        GX_EQ(GXA()(NULL, NULL, NSDNS, NULL, NULL, (void **)&a, NULL, NULL, NULL, NULL), WSAHOST_NOT_FOUND);
        CHECK(a == NULL);
        a = (GXEXA *)&gx_sentinel_ex;
        GX_EQ(GXA()("127.0.0.1", NULL, 15, NULL, NULL, (void **)&a, NULL, NULL, NULL, NULL), WSASERVICE_NOT_FOUND);
        CHECK(a == NULL);
        a = (GXEXA *)&gx_sentinel_ex;
        GX_EQ(GXA()("127.0.0.1", NULL, 38, NULL, NULL, (void **)&a, NULL, NULL, NULL, NULL), WSAEINVAL);
        CHECK(a == NULL);
    }
    GX_END();
}

/* ---- startup state -------------------------------------------------------------------------------------- */
TEST(xmisc_overlapped_pending_lookup_survives_nothing_special_cleanup_balance)
{
    /* a startup/cleanup bracket around a completed asynchronous query leaves the process usable */
    int i;
    GX_BEGIN();
    for (i = 0; i < 3; i++) {
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        OVERLAPPED ov; GXEX *res = NULL;
        memset(&ov, 0, sizeof ov); ov.hEvent = ev;
        GX_EQ(GXW()(gx_localhost, NULL, NSDNS, NULL, NULL, (void **)&res, NULL, &ov, NULL, NULL), ERROR_IO_PENDING);
        GX_EQ(gx_wait(ev), WAIT_OBJECT_0);
        if (res) GXFREE(res);
        CloseHandle(ev);
        gx_down();
        GX_EQ(gx_up(), 0);
    }
    GX_END();
}
