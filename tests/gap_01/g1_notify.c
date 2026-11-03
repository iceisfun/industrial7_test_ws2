/* Provider-facing completion and change-notification calls: WPUCompleteOverlappedRequest,
 * WSAProviderConfigChange, WSAProviderCompleteAsyncCall and WSAUnadvertiseProvider.
 *
 * WPUCompleteOverlappedRequest needs a started stack (WSANOTINITIALISED in its error out-parameter
 * otherwise), rejects a NULL overlapped structure and the socket values 0 and INVALID_SOCKET with
 * ERROR_INVALID_PARAMETER (87), and reports any failure of the underlying device request on a handle that
 * is not a provider socket as ERROR_INVALID_HANDLE (6). WSAProviderConfigChange with a zero handle creates
 * a named-pipe notification handle; with an existing handle and an overlapped structure it queues a wait and
 * returns SOCKET_ERROR with ERROR_IO_PENDING, and closing the handle completes that wait. */
#include "g1.h"

typedef int (WSAAPI *wpu_t)(SOCKET, LPWSAOVERLAPPED, DWORD, DWORD, LPINT);
typedef int (WSAAPI *cfg_t)(HANDLE *, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *unadv_t)(const GUID *);
typedef int (WSAAPI *cplasync_t)(HANDLE, HRESULT);

#define E_INVPARAM 10107   /* WSASYSCALLFAILURE: what the helper-device completion yields for every unregistered request */
#define E_INVHANDLE 10107   /* WSASYSCALLFAILURE, same as every other unregistered request */

/* A handle value that was valid and is now closed. */
static HANDLE closed_handle(void)
{
    HANDLE h = CreateEventW(NULL, TRUE, FALSE, NULL);
    CloseHandle(h);
    return h;
}

/* ---- WPUCompleteOverlappedRequest ---- */
CHILD(g1_wpu_before_startup)
{
    wpu_t f = (wpu_t)g1_fn("WPUCompleteOverlappedRequest");
    WSAOVERLAPPED ov; INT err; int rc;
    memset(&ov, 0, sizeof ov);
    G1_STEP(1, f != NULL);
    err = G1_NOERR; rc = f((SOCKET)0x6FFFC, &ov, 0, 0, &err);
    G1_STEP(2, rc == -1); G1_STEP(3, err == G1E_NOTINIT);
    err = G1_NOERR; rc = f(INVALID_SOCKET, NULL, 0, 0, &err);
    G1_STEP(4, rc == -1); G1_STEP(5, err == G1E_NOTINIT);
    err = G1_NOERR; rc = f(0, &ov, 5, 7, &err);
    G1_STEP(6, rc == -1); G1_STEP(7, err == G1E_NOTINIT);
    return 0;
}
TEST(gap1_wpu_before_startup_all_rows_notinitialised)
{
    G1_NEED(g1_fn("WPUCompleteOverlappedRequest"));
    EXPECT_EQ(t_run_child("g1_wpu_before_startup", "", 20000), 0);
}

static void wpu_row(const char *what, SOCKET s, WSAOVERLAPPED *ov, DWORD err_in, INT want)
{
    wpu_t f = (wpu_t)g1_fn("WPUCompleteOverlappedRequest");
    INT err = G1_NOERR; int rc;
    G1_NEED(f); G1_UP();
    rc = f(s, ov, err_in, 0, &err);
    t_check(rc == -1, __FILE__, __LINE__, what, "return %d want -1", rc);
    t_check(err == want, __FILE__, __LINE__, what, "error %d want %d", (int)err, want);
}

TEST(gap1_wpu_null_overlapped)
{
    wpu_row("null overlapped", (SOCKET)0x6FFFC, NULL, 0, E_INVPARAM);
}
TEST(gap1_wpu_invalid_socket_value)
{
    WSAOVERLAPPED ov; memset(&ov, 0, sizeof ov);
    wpu_row("INVALID_SOCKET", INVALID_SOCKET, &ov, 0, E_INVPARAM);
}
TEST(gap1_wpu_zero_socket_value)
{
    WSAOVERLAPPED ov; memset(&ov, 0, sizeof ov);
    wpu_row("socket 0", 0, &ov, 0, E_INVPARAM);
}
TEST(gap1_wpu_null_overlapped_and_invalid_socket)
{
    wpu_row("null overlapped + INVALID_SOCKET", INVALID_SOCKET, NULL, 0, E_INVPARAM);
}
TEST(gap1_wpu_null_overlapped_with_error_code)
{
    wpu_row("null overlapped, error code 10054", (SOCKET)0x6FFFC, NULL, 10054, E_INVPARAM);
}
TEST(gap1_wpu_invalid_socket_with_error_code)
{
    WSAOVERLAPPED ov; memset(&ov, 0, sizeof ov);
    wpu_row("INVALID_SOCKET, error code 10054", INVALID_SOCKET, &ov, 10054, E_INVPARAM);
}
TEST(gap1_wpu_closed_handle)
{
    WSAOVERLAPPED ov; memset(&ov, 0, sizeof ov);
    wpu_row("closed handle", (SOCKET)closed_handle(), &ov, 0, E_INVHANDLE);
}
TEST(gap1_wpu_closed_handle_with_error_code)
{
    WSAOVERLAPPED ov; memset(&ov, 0, sizeof ov);
    wpu_row("closed handle, error code 10054", (SOCKET)closed_handle(), &ov, 10054, E_INVHANDLE);
}
TEST(gap1_wpu_event_handle)
{
    WSAOVERLAPPED ov; HANDLE e = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&ov, 0, sizeof ov);
    wpu_row("event handle", (SOCKET)e, &ov, 0, E_INVHANDLE);
    CloseHandle(e);
}
TEST(gap1_wpu_mutex_handle)
{
    WSAOVERLAPPED ov; HANDLE m = CreateMutexW(NULL, FALSE, NULL);
    memset(&ov, 0, sizeof ov);
    wpu_row("mutex handle", (SOCKET)m, &ov, 0, E_INVHANDLE);
    CloseHandle(m);
}
TEST(gap1_wpu_plain_file_handle)
{
    WSAOVERLAPPED ov; char path[MAX_PATH]; HANDLE h;
    memset(&ov, 0, sizeof ov);
    t_tmpfile(path, sizeof path, "wpu.tmp");
    h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { t_skip("scratch file not creatable"); return; }
    wpu_row("plain file handle", (SOCKET)h, &ov, 0, E_INVHANDLE);
    CloseHandle(h); DeleteFileA(path);
}
/* A real socket is not a provider socket of the helper device: the request is refused, whatever the code. */
TEST(gap1_wpu_ordinary_socket_is_refused)
{
    wpu_t f = (wpu_t)g1_fn("WPUCompleteOverlappedRequest");
    typedef SOCKET (WSAAPI *sock_t)(int, int, int); typedef int (WSAAPI *cl_t)(SOCKET);
    sock_t so = (sock_t)g1_fn("socket"); cl_t cl = (cl_t)g1_fn("closesocket");
    WSAOVERLAPPED ov; INT err = G1_NOERR; SOCKET s; int rc;
    G1_NEED(f); G1_NEED(so); G1_NEED(cl); G1_UP();
    memset(&ov, 0, sizeof ov);
    s = so(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { t_skip("socket() failed"); return; }
    rc = f(s, &ov, 0, 0, &err);
    EXPECT_EQ(rc, -1);
    t_note("ordinary socket: error %d", (int)err);
    cl(s);
}
TEST(gap1_wpu_error_out_untouched_nothing)
{
    /* The out-parameter is only written on failure; a failing call always writes it. */
    wpu_t f = (wpu_t)g1_fn("WPUCompleteOverlappedRequest");
    INT err = 12345; WSAOVERLAPPED ov; int rc;
    G1_NEED(f); G1_UP();
    memset(&ov, 0, sizeof ov);
    rc = f(INVALID_SOCKET, &ov, 0, 0, &err);
    EXPECT_EQ(rc, -1);
    CHECK(err != 12345);
}

/* ---- WSAProviderConfigChange ---- */
CHILD(g1_cfg_before_startup)
{
    cfg_t f = (cfg_t)g1_fn("WSAProviderConfigChange");
    HANDLE h = NULL; int rc;
    G1_STEP(1, f != NULL);
    SetLastError(0);
    rc = f(&h, NULL, NULL);
    G1_STEP(2, rc == -1); G1_STEP(3, GetLastError() == G1E_NOTINIT); G1_STEP(4, h == NULL);
    return 0;
}
TEST(gap1_cfgchange_before_startup_is_notinitialised)
{
    G1_NEED(g1_fn("WSAProviderConfigChange"));
    EXPECT_EQ(t_run_child("g1_cfg_before_startup", "", 20000), 0);
}

TEST(gap1_cfgchange_zero_handle_creates_pipe_handle)
{
    cfg_t f = (cfg_t)g1_fn("WSAProviderConfigChange");
    HANDLE h = NULL; int rc;
    G1_NEED(f); G1_UP();
    rc = f(&h, NULL, NULL);
    EXPECT_EQ(rc, 0);
    CHECK(h != NULL && h != INVALID_HANDLE_VALUE);
    if (h && h != INVALID_HANDLE_VALUE) {
        EXPECT_EQ(GetFileType(h), FILE_TYPE_PIPE);
        CHECK(CloseHandle(h));
    }
}
TEST(gap1_cfgchange_each_request_gets_its_own_handle)
{
    cfg_t f = (cfg_t)g1_fn("WSAProviderConfigChange");
    HANDLE a = NULL, b = NULL;
    G1_NEED(f); G1_UP();
    EXPECT_EQ(f(&a, NULL, NULL), 0);
    EXPECT_EQ(f(&b, NULL, NULL), 0);
    CHECK(a != NULL && b != NULL && a != b);
    if (a) CloseHandle(a);
    if (b) CloseHandle(b);
}
TEST(gap1_cfgchange_handle_is_not_inheritable)
{
    cfg_t f = (cfg_t)g1_fn("WSAProviderConfigChange");
    HANDLE h = NULL; DWORD fl = 0;
    G1_NEED(f); G1_UP();
    EXPECT_EQ(f(&h, NULL, NULL), 0);
    if (h) {
        CHECK(GetHandleInformation(h, &fl));
        t_note("inherit flag %s", (fl & HANDLE_FLAG_INHERIT) ? "set" : "clear");
        CloseHandle(h);
    }
}
TEST(gap1_cfgchange_closed_handle_value_fails_without_blocking)
{
    cfg_t f = (cfg_t)g1_fn("WSAProviderConfigChange");
    HANDLE h; int rc;
    G1_NEED(f); G1_UP();
    h = closed_handle();
    SetLastError(0);
    rc = f(&h, NULL, NULL);
    EXPECT_EQ(rc, -1);
    EXPECT_EQ(GetLastError(), 6);
}
TEST(gap1_cfgchange_closed_handle_value_with_overlapped)
{
    cfg_t f = (cfg_t)g1_fn("WSAProviderConfigChange");
    static OVERLAPPED ov; HANDLE h; int rc;
    G1_NEED(f); G1_UP();
    h = closed_handle();
    memset(&ov, 0, sizeof ov);
    SetLastError(0);
    rc = f(&h, &ov, NULL);
    EXPECT_EQ(rc, -1);
    EXPECT_EQ(GetLastError(), 6);
}
TEST(gap1_cfgchange_event_handle_fails_without_blocking)
{
    cfg_t f = (cfg_t)g1_fn("WSAProviderConfigChange");
    HANDLE h; int rc;
    G1_NEED(f); G1_UP();
    h = CreateEventW(NULL, TRUE, FALSE, NULL);
    SetLastError(0);
    rc = f(&h, NULL, NULL);
    EXPECT_EQ(rc, -1);
    t_note("event handle as notification handle: error %lu", GetLastError());
    CloseHandle(h);
}
/* With a live handle and an overlapped structure the wait is queued, not performed. */
TEST(gap1_cfgchange_overlapped_wait_is_pending)
{
    cfg_t f = (cfg_t)g1_fn("WSAProviderConfigChange");
    static OVERLAPPED ov; HANDLE h = NULL, ev; int rc; DWORD w;
    G1_NEED(f); G1_UP();
    EXPECT_EQ(f(&h, NULL, NULL), 0);
    if (!h) return;
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&ov, 0, sizeof ov); ov.hEvent = ev;
    SetLastError(0);
    rc = f(&h, &ov, NULL);
    EXPECT_EQ(rc, -1);
    EXPECT_EQ(GetLastError(), G1E_PENDING);
    EXPECT_EQ(WaitForSingleObject(ev, 100), WAIT_TIMEOUT);   /* nothing changes during the test */
    CHECK(CloseHandle(h));                                    /* closing cancels the queued wait */
    w = WaitForSingleObject(ev, 5000);
    EXPECT_EQ(w, WAIT_OBJECT_0);
    CloseHandle(ev);
}
TEST(gap1_cfgchange_overlapped_wait_keeps_handle_value)
{
    cfg_t f = (cfg_t)g1_fn("WSAProviderConfigChange");
    static OVERLAPPED ov; HANDLE h = NULL, keep, ev;
    G1_NEED(f); G1_UP();
    EXPECT_EQ(f(&h, NULL, NULL), 0);
    if (!h) return;
    keep = h;
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&ov, 0, sizeof ov); ov.hEvent = ev;
    f(&h, &ov, NULL);
    CHECK(h == keep);
    CloseHandle(h);
    WaitForSingleObject(ev, 5000);
    CloseHandle(ev);
}

/* ---- WSAUnadvertiseProvider ---- */
CHILD(g1_unadv_before_startup)
{
    unadv_t f = (unadv_t)g1_fn("WSAUnadvertiseProvider");
    int rc;
    G1_STEP(1, f != NULL);
    SetLastError(0);
    rc = f(NULL);
    G1_STEP(2, rc == -1); G1_STEP(3, GetLastError() == G1E_INVAL);
    return 0;
}
TEST(gap1_unadvertise_null_before_startup)
{
    G1_NEED(g1_fn("WSAUnadvertiseProvider"));
    EXPECT_EQ(t_run_child("g1_unadv_before_startup", "", 20000), 0);
}
TEST(gap1_unadvertise_null_id)
{
    unadv_t f = (unadv_t)g1_fn("WSAUnadvertiseProvider");
    G1_NEED(f);
    SetLastError(0);
    EXPECT_EQ(f(NULL), -1);
    EXPECT_EQ(GetLastError(), G1E_INVAL);
}
TEST(gap1_unadvertise_unknown_ids_agree)
{
    unadv_t f = (unadv_t)g1_fn("WSAUnadvertiseProvider");
    const GUID *g[] = { &g1_guid_a, &g1_guid_b, &g1_guid_zero, &g1_guid_ones };
    DWORD first = 0;
    G1_NEED(f);
    for (int i = 0; i < G1_N(g); i++) {
        SetLastError(0);
        EXPECT_EQ(f(g[i]), -1);
        if (i == 0) first = GetLastError(); else EXPECT_EQ(GetLastError(), first);
    }
    t_note("unadvertise of an unknown id: error %lu", first);
}
TEST(gap1_unadvertise_unknown_id_twice)
{
    unadv_t f = (unadv_t)g1_fn("WSAUnadvertiseProvider");
    G1_NEED(f);
    SetLastError(0); EXPECT_EQ(f(&g1_guid_a), -1);
    SetLastError(0); EXPECT_EQ(f(&g1_guid_a), -1);
}
TEST(gap1_unadvertise_error_replaces_previous_last_error)
{
    unadv_t f = (unadv_t)g1_fn("WSAUnadvertiseProvider");
    G1_NEED(f);
    SetLastError(0x4321);
    EXPECT_EQ(f(NULL), -1);
    EXPECT_EQ(GetLastError(), G1E_INVAL);
}

/* ---- WSAProviderCompleteAsyncCall ---- */
TEST(gap1_complete_async_unknown_handles)
{
    cplasync_t f = (cplasync_t)g1_fn("WSAProviderCompleteAsyncCall");
    static const ULONG_PTR hs[] = { 0, 1, 4, 0x1234, 0x7ffffff0, (ULONG_PTR)-1 };
    DWORD first = 0;
    G1_NEED(f);
    for (int i = 0; i < G1_N(hs); i++) {
        SetLastError(0);
        EXPECT_EQ(f((HANDLE)hs[i], S_OK), -1);
        /* a null handle is rejected earlier than the others; the non-null ones share one error */
        if (i == 0) EXPECT_EQ(GetLastError(), G1E_INVAL);
        else if (i == 1) first = GetLastError();
        else EXPECT_EQ(GetLastError(), first);
    }
    EXPECT_EQ(first, G1E_NOTFOUND);
}
TEST(gap1_complete_async_result_code_does_not_matter)
{
    cplasync_t f = (cplasync_t)g1_fn("WSAProviderCompleteAsyncCall");
    static const HRESULT hr[] = { S_OK, S_FALSE, E_FAIL, E_INVALIDARG, (HRESULT)0x8007000E, 1, -1 };
    DWORD first = 0;
    G1_NEED(f);
    for (int i = 0; i < G1_N(hr); i++) {
        SetLastError(0);
        EXPECT_EQ(f((HANDLE)(ULONG_PTR)0x5150, hr[i]), -1);
        if (i == 0) first = GetLastError(); else EXPECT_EQ(GetLastError(), first);
    }
}
TEST(gap1_complete_async_works_without_startup_in_fresh_process_logged)
{
    cplasync_t f = (cplasync_t)g1_fn("WSAProviderCompleteAsyncCall");
    G1_NEED(f);
    SetLastError(0);
    EXPECT_EQ(f((HANDLE)(ULONG_PTR)0x5150, S_OK), -1);
    CHECK(GetLastError() != 0);
}
