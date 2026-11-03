/* Argument validation and handle lifecycle of WSALookupServiceBegin/Next/End (W and A).
 * Measures: which check wins when several are wrong (initialisation, NULL buffer, handle), the
 * error each rejected shape returns, that a handle dies after End, and that the name-space
 * providers reject malformed query sets with their own codes. Only the DNS name space on
 * loopback names is ever queried; no result count is asserted that depends on the machine. */
#include "nsp.h"

/* ---- before WSAStartup (separate process: this exe may already have started Winsock) ---- */

CHILD(ls_nostartup) {
    WSAQUERYSETW qs; HANDLE h = NULL; DWORD len = 0; int bad = 0;
    WCHAR nm[] = L"localhost";
    if (!W_BEGIN_W || !W_NEXT_W || !W_END || !W_ERR) return 90;
    nsp_query_w(&qs, nm, &nsp_svcid_addr_by_name, NS_DNS);
    if (W_BEGIN_W(&qs, 0, &h) != SOCKET_ERROR || W_ERR() != (int)E_NOTINIT) bad |= 1;
    if (W_NEXT_W((HANDLE)0, 0, &len, NULL) != SOCKET_ERROR || W_ERR() != (int)E_NOTINIT) bad |= 2;
    if (W_END(NULL) != SOCKET_ERROR || W_ERR() != (int)E_NOTINIT) bad |= 4;
    return bad;
}

TEST(ls_calls_before_startup_report_notinitialised) {
    /* Begin, Next and End all run the per-process prologue first; without WSAStartup each fails
     * with WSANOTINITIALISED even for a NULL handle (which would otherwise be a handle error). */
    EXPECT_EQ(t_run_child("ls_nostartup", "", 20000), 0);
}

CHILD(ls_nostartup_order) {
    int bad = 0;
    typeof(&WSAInstallServiceClassW) ins = UIN("ws2_32.dll", WSAInstallServiceClassW);
    typeof(&WSARemoveServiceClass) rem = UIN("ws2_32.dll", WSARemoveServiceClass);
    typeof(&WSASetServiceW) set = UIN("ws2_32.dll", WSASetServiceW);
    typeof(&WSAGetServiceClassInfoW) gi = UIN("ws2_32.dll", WSAGetServiceClassInfoW);
    DWORD len = 0; WSASERVICECLASSINFOW sc;
    if (!ins || !rem || !set || !gi || !W_ERR) return 90;
    /* The prologue runs before the NULL check for these two. */
    if (ins(NULL) != SOCKET_ERROR || W_ERR() != (int)E_NOTINIT) bad |= 1;
    if (rem(NULL) != SOCKET_ERROR || W_ERR() != (int)E_NOTINIT) bad |= 2;
    /* WSASetService checks its NULL argument before the prologue. */
    if (set(NULL, RNRSERVICE_REGISTER, 0) != SOCKET_ERROR || W_ERR() != (int)E_FAULT) bad |= 4;
    /* WSAGetServiceClassInfo checks its four pointers first and rejects with WSAEINVAL. */
    if (gi(NULL, NULL, &len, &sc) != SOCKET_ERROR || W_ERR() != (int)E_INVAL) bad |= 8;
    return bad;
}

TEST(ls_service_class_calls_before_startup_check_order) {
    EXPECT_EQ(t_run_child("ls_nostartup_order", "", 20000), 0);
}

/* ---- Next argument order ---- */

TEST(ls_next_null_buffer_with_size_is_fault_before_handle_check) {
    DWORD len = 100; INT r;
    REQUIRE(W_NEXT_W); NSP_NEED();
    W_SETERR(0);
    r = W_NEXT_W(NULL, 0, &len, NULL);   /* NULL buffer + nonzero size: WSAEFAULT wins over the NULL handle */
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_FAULT);
}

TEST(ls_next_null_handle_zero_size_is_invalid_handle) {
    DWORD len = 0; INT r;
    REQUIRE(W_NEXT_W); NSP_NEED();
    W_SETERR(0);
    r = W_NEXT_W(NULL, 0, &len, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_BADHANDLE);
}

TEST(ls_next_null_handle_with_buffer_is_invalid_handle) {
    BYTE buf[256]; DWORD len = sizeof buf; INT r;
    REQUIRE(W_NEXT_W); NSP_NEED();
    memset(buf, 0, sizeof buf);
    W_SETERR(0);
    r = W_NEXT_W(NULL, 0, &len, (WSAQUERYSETW *)buf);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_BADHANDLE);
}

TEST(ls_next_ansi_null_handle_is_invalid_handle) {
    DWORD len = 0; INT r;
    REQUIRE(W_NEXT_A); NSP_NEED();
    /* NextA converts through NextW, so a NULL handle produces the same error. */
    W_SETERR(0);
    r = W_NEXT_A(NULL, 0, &len, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_BADHANDLE);
}

/* ---- Begin against the DNS name space: provider-side validation ---- */

typedef struct {
    const char *what;
    DWORD size;           /* dwSize written into the set (0 = real size) */
    DWORD flags;
    int use_class;        /* give the set a service class id */
    LPWSTR ctx;           /* lpszContext */
    DWORD nproto;         /* dwNumberOfProtocols with a non-NULL array */
    int want_err;
} begin_case;

static const begin_case begin_cases[] = {
    { "short dwSize",                 0x10, 0,      1, NULL,  0, E_FAULT  },
    { "dwSize one below minimum",     0x77, 0,      1, NULL,  0, E_FAULT  },
    { "no service class",             0,    0,      0, NULL,  0, E_BADPARAM },
    { "no service class, return all", 0,    LUP_RETURN_ALL, 0, NULL, 0, E_BADPARAM },
    { "CONTAINERS|NOCONTAINERS",      0,    LUP_CONTAINERS | LUP_NOCONTAINERS, 1, NULL, 0, E_BADPARAM },
    { "CONTAINERS alone (a host is not a container)", 0, LUP_CONTAINERS, 1, NULL, 0, E_NODATA },
    { "flag 0x4000",                  0,    0x4000, 1, NULL,  0, E_BADPARAM },
    { "flag 0x10000",                 0,    0x10000, 1, NULL, 0, E_BADPARAM },
    { "flag 0x40000",                 0,    0x40000, 1, NULL, 0, E_BADPARAM },
    { "flag 0x80000",                 0,    0x80000, 1, NULL, 0, E_BADPARAM },
    { "flag 0x04000000",              0,    0x04000000, 1, NULL, 0, E_BADPARAM },
    { "flag 0x08000000",              0,    0x08000000, 1, NULL, 0, E_BADPARAM },
    { "flag 0x10000000",              0,    0x10000000, 1, NULL, 0, E_BADPARAM },
    { "flag 0x20000000",              0,    0x20000000, 1, NULL, 0, E_BADPARAM },
    { "flag 0x40000000",              0,    0x40000000, 1, NULL, 0, E_BADPARAM },
};

TEST(ls_begin_dns_rejections_table) {
    size_t i; WCHAR nm[] = L"localhost";
    REQUIRE(W_BEGIN_W); REQUIRE(W_ERR); NSP_NEED();
    for (i = 0; i < NSP_N(begin_cases); i++) {
        WSAQUERYSETW qs; HANDLE h = (HANDLE)(ULONG_PTR)0x1; INT r;
        nsp_query_w(&qs, nm, begin_cases[i].use_class ? &nsp_svcid_addr_by_name : NULL, NS_DNS);
        if (begin_cases[i].size) qs.dwSize = begin_cases[i].size;
        W_SETERR(0);
        r = W_BEGIN_W(&qs, begin_cases[i].flags, &h);
        CHECKF(r == SOCKET_ERROR, "%s: Begin returned %d", begin_cases[i].what, r);
        if (r == 0) { W_END(h); continue; }
        CHECKF(W_ERR() == (int)begin_cases[i].want_err, "%s: error %d want %u", begin_cases[i].what, W_ERR(), begin_cases[i].want_err);
        CHECKF(h == NULL, "%s: handle not cleared (%p)", begin_cases[i].what, (void *)h);
    }
}

TEST(ls_begin_failure_clears_handle_out_param) {
    WSAQUERYSETW qs; HANDLE h = (HANDLE)(ULONG_PTR)0x1234; WCHAR nm[] = L"localhost";
    REQUIRE(W_BEGIN_W); NSP_NEED();
    nsp_query_w(&qs, nm, NULL, NS_DNS);   /* class id missing: rejected */
    EXPECT_EQ(W_BEGIN_W(&qs, 0, &h), SOCKET_ERROR);
    EXPECT_EQ(h, NULL);
}

TEST(ls_begin_context_must_be_empty_or_backslash) {
    /* lpszContext other than NULL, "" or "\\" has no match in the DNS provider: WSANO_DATA. */
    static WCHAR bad[] = L"somewhere", empty[] = L"", slash[] = L"\\", nm[] = L"localhost";
    LPWSTR ctxs[] = { bad, empty, slash, NULL };
    int want_ok[] = { 0, 1, 1, 1 };
    size_t i;
    REQUIRE(W_BEGIN_W); NSP_NEED();
    for (i = 0; i < NSP_N(ctxs); i++) {
        WSAQUERYSETW qs; HANDLE h = NULL; INT r;
        nsp_query_w(&qs, nm, &nsp_svcid_addr_by_name, NS_DNS);
        qs.lpszContext = ctxs[i];
        r = W_BEGIN_W(&qs, LUP_RETURN_NAME, &h);
        if (want_ok[i]) { CHECKF(r == 0, "context #%zu rejected (err %d)", i, W_ERR()); if (r == 0) W_END(h); }
        else { EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(W_ERR(), E_NODATA); }
    }
}

TEST(ls_begin_protocol_array_without_entries_is_nodata) {
    /* A non-NULL protocol array with zero entries leaves the provider no transport to answer for. */
    WSAQUERYSETW qs; HANDLE h = NULL; WCHAR nm[] = L"localhost"; AFPROTOCOLS ap = { AF_INET, IPPROTO_TCP };
    REQUIRE(W_BEGIN_W); NSP_NEED();
    nsp_query_w(&qs, nm, &nsp_svcid_addr_by_name, NS_DNS);
    qs.lpafpProtocols = &ap; qs.dwNumberOfProtocols = 0;
    EXPECT_EQ(W_BEGIN_W(&qs, LUP_RETURN_NAME, &h), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_NODATA);
}

TEST(ls_begin_protocol_array_with_unknown_protocol_is_nodata) {
    WSAQUERYSETW qs; HANDLE h = NULL; WCHAR nm[] = L"localhost"; AFPROTOCOLS ap = { AF_INET, IPPROTO_ICMP };
    REQUIRE(W_BEGIN_W); NSP_NEED();
    nsp_query_w(&qs, nm, &nsp_svcid_addr_by_name, NS_DNS);
    qs.lpafpProtocols = &ap; qs.dwNumberOfProtocols = 1;
    EXPECT_EQ(W_BEGIN_W(&qs, LUP_RETURN_NAME, &h), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_NODATA);
}

TEST(ls_begin_protocol_array_tcp_or_udp_accepted) {
    AFPROTOCOLS one[2] = { { AF_INET, IPPROTO_TCP }, { AF_INET, IPPROTO_UDP } };
    size_t i; WCHAR nm[] = L"localhost";
    REQUIRE(W_BEGIN_W); NSP_NEED();
    for (i = 0; i < 2; i++) {
        WSAQUERYSETW qs; HANDLE h = NULL; INT r;
        nsp_query_w(&qs, nm, &nsp_svcid_addr_by_name, NS_DNS);
        qs.lpafpProtocols = &one[i]; qs.dwNumberOfProtocols = 1;
        r = W_BEGIN_W(&qs, LUP_RETURN_NAME, &h);
        CHECKF(r == 0, "protocol #%zu rejected (err %d)", i, W_ERR());
        if (r == 0) W_END(h);
    }
}

/* ---- handle lifecycle ---- */

static HANDLE open_localhost(DWORD flags) {
    WSAQUERYSETW qs; HANDLE h = NULL; static WCHAR nm[] = L"localhost";
    nsp_query_w(&qs, nm, &nsp_svcid_addr_by_name, NS_DNS);
    if (W_BEGIN_W(&qs, flags, &h) != 0) return NULL;
    return h;
}

TEST(ls_begin_accepts_valid_query_and_returns_handle) {
    HANDLE h;
    REQUIRE(W_BEGIN_W); REQUIRE(W_END); NSP_NEED();
    h = open_localhost(LUP_RETURN_NAME | LUP_RETURN_ADDR);
    CHECKF(h != NULL, "Begin failed (err %d)", W_ERR());
    if (h) EXPECT_EQ(W_END(h), 0);
}

TEST(ls_handles_from_two_begins_are_distinct) {
    HANDLE a, b;
    REQUIRE(W_BEGIN_W); REQUIRE(W_END); NSP_NEED();
    a = open_localhost(LUP_RETURN_NAME); b = open_localhost(LUP_RETURN_NAME);
    CHECK(a && b);
    if (a && b) CHECK(a != b);
    if (a) W_END(a);
    if (b) W_END(b);
}

TEST(ls_end_twice_second_is_invalid_handle) {
    HANDLE h;
    REQUIRE(W_END); NSP_NEED();
    h = open_localhost(LUP_RETURN_NAME);
    if (!h) { t_skip("no lookup handle"); return; }
    EXPECT_EQ(W_END(h), 0);
    W_SETERR(0);
    EXPECT_EQ(W_END(h), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_BADHANDLE);
}

TEST(ls_next_after_end_is_invalid_handle) {
    HANDLE h; BYTE buf[512]; DWORD len = sizeof buf;
    REQUIRE(W_NEXT_W); REQUIRE(W_END); NSP_NEED();
    h = open_localhost(LUP_RETURN_NAME);
    if (!h) { t_skip("no lookup handle"); return; }
    EXPECT_EQ(W_END(h), 0);
    W_SETERR(0);
    EXPECT_EQ(W_NEXT_W(h, 0, &len, (WSAQUERYSETW *)buf), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_BADHANDLE);
}

TEST(ls_end_without_draining_results_succeeds) {
    HANDLE h;
    REQUIRE(W_END); NSP_NEED();
    h = open_localhost(LUP_RETURN_NAME | LUP_RETURN_ADDR);
    if (!h) { t_skip("no lookup handle"); return; }
    EXPECT_EQ(W_END(h), 0);
}

TEST(ls_end_after_exhausting_results_succeeds) {
    HANDLE h; nsp_buf b = {0}; int guard = 0, e;
    REQUIRE(W_END); NSP_NEED();
    h = open_localhost(LUP_RETURN_NAME);
    if (!h) { t_skip("no lookup handle"); return; }
    while (guard++ < 32 && (e = nsp_next_w(h, 0, &b, NULL)) == 0) {}
    nsp_buf_free(&b);
    EXPECT_EQ(W_END(h), 0);
}

/* ---- Next buffer protocol ---- */

TEST(ls_next_small_buffer_reports_required_size_and_keeps_result) {
    HANDLE h; DWORD len = 0; BYTE small[16]; nsp_buf b = {0}; int g;
    REQUIRE(W_NEXT_W); REQUIRE(W_END); NSP_NEED();
    h = open_localhost(LUP_RETURN_NAME | LUP_RETURN_ADDR);
    if (!h) { t_skip("no lookup handle"); return; }
    W_SETERR(0);
    EXPECT_EQ(W_NEXT_W(h, 0, &len, NULL), SOCKET_ERROR);   /* size query: NULL buffer, size 0 */
    EXPECT_EQ(W_ERR(), E_FAULT);
    CHECK(len >= NSP_SZ_QS_W);
    len = sizeof small;
    W_SETERR(0);
    EXPECT_EQ(W_NEXT_W(h, 0, &len, (WSAQUERYSETW *)small), SOCKET_ERROR);   /* below the fixed part: no write */
    EXPECT_EQ(W_ERR(), E_FAULT);
    CHECK(len >= NSP_SZ_QS_W);
    /* The refused calls consumed nothing: a properly sized call still yields the first result. */
    EXPECT_EQ(nsp_next_w(h, 0, &b, &g), 0);
    nsp_buf_free(&b);
    W_END(h);
}

TEST(ls_next_required_size_is_stable_across_repeats) {
    HANDLE h; DWORD l1 = 0, l2 = 0;
    REQUIRE(W_NEXT_W); REQUIRE(W_END); NSP_NEED();
    h = open_localhost(LUP_RETURN_NAME | LUP_RETURN_ADDR);
    if (!h) { t_skip("no lookup handle"); return; }
    EXPECT_EQ(W_NEXT_W(h, 0, &l1, NULL), SOCKET_ERROR);
    EXPECT_EQ(W_NEXT_W(h, 0, &l2, NULL), SOCKET_ERROR);
    EXPECT_EQ(l1, l2);
    W_END(h);
}

TEST(ls_next_exact_required_size_succeeds) {
    HANDLE h; DWORD len = 0; BYTE *buf;
    REQUIRE(W_NEXT_W); REQUIRE(W_END); NSP_NEED();
    h = open_localhost(LUP_RETURN_NAME | LUP_RETURN_ADDR);
    if (!h) { t_skip("no lookup handle"); return; }
    EXPECT_EQ(W_NEXT_W(h, 0, &len, NULL), SOCKET_ERROR);
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
    if (buf) {
        DWORD l = len;
        EXPECT_EQ(W_NEXT_W(h, 0, &l, (WSAQUERYSETW *)buf), 0);
        CHECK(l <= len);
        HeapFree(GetProcessHeap(), 0, buf);
    }
    W_END(h);
}

TEST(ls_next_exhausted_reports_no_more) {
    HANDLE h; nsp_buf b = {0}; int guard = 0, e = 0;
    REQUIRE(W_NEXT_W); REQUIRE(W_END); NSP_NEED();
    h = open_localhost(LUP_RETURN_NAME);
    if (!h) { t_skip("no lookup handle"); return; }
    while (guard++ < 32 && (e = nsp_next_w(h, 0, &b, NULL)) == 0) {}
    EXPECT_EQ(e, E_NO_MORE);
    /* Asking again stays at the end. */
    e = nsp_next_w(h, 0, &b, NULL);
    EXPECT_EQ(e, E_NO_MORE);
    nsp_buf_free(&b);
    W_END(h);
}

TEST(ls_next_tiny_sizes_are_treated_as_zero) {
    /* Sizes 1..0x77 are clamped to zero before the provider sees them: the answer is the same
     * WSAEFAULT with a required size as for size 0, and the (non-NULL) buffer is not written. */
    HANDLE h; DWORD sizes[] = { 1, 8, 0x77 }; size_t i;
    REQUIRE(W_NEXT_W); REQUIRE(W_END); NSP_NEED();
    h = open_localhost(LUP_RETURN_NAME);
    if (!h) { t_skip("no lookup handle"); return; }
    for (i = 0; i < NSP_N(sizes); i++) {
        BYTE buf[0x80]; DWORD len = sizes[i];
        memset(buf, 0xA5, sizeof buf);
        W_SETERR(0);
        EXPECT_EQ(W_NEXT_W(h, 0, &len, (WSAQUERYSETW *)buf), SOCKET_ERROR);
        EXPECT_EQ(W_ERR(), E_FAULT);
        CHECK(len >= NSP_SZ_QS_W);
        CHECK(buf[0] == 0xA5 && buf[0x40] == 0xA5);
    }
    W_END(h);
}

/* ---- ANSI entry points ---- */

TEST(ls_ansi_begin_maps_to_wide_validation) {
    WSAQUERYSETA qs; HANDLE h = (HANDLE)(ULONG_PTR)0x1; char nm[] = "localhost";
    REQUIRE(W_BEGIN_A); NSP_NEED();
    nsp_query_a(&qs, nm, NULL, NS_DNS);    /* class id missing */
    W_SETERR(0);
    EXPECT_EQ(W_BEGIN_A(&qs, 0, &h), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_BADPARAM);
}

TEST(ls_ansi_begin_short_size_is_fault) {
    WSAQUERYSETA qs; HANDLE h = NULL; char nm[] = "localhost";
    REQUIRE(W_BEGIN_A); NSP_NEED();
    nsp_query_a(&qs, nm, &nsp_svcid_addr_by_name, NS_DNS);
    /* The ANSI front end converts the set before dispatch; a short dwSize is not read back as a
     * valid size. The failure is reported, never a handle. */
    qs.dwSize = 0x10;
    W_SETERR(0);
    EXPECT_EQ(W_BEGIN_A(&qs, 0, &h), SOCKET_ERROR);
    CHECK(h == NULL);
}

TEST(ls_ansi_roundtrip_localhost) {
    WSAQUERYSETA qs; HANDLE h = NULL; char nm[] = "localhost"; nsp_buf b = {0}; int e;
    REQUIRE(W_BEGIN_A); REQUIRE(W_END); NSP_NEED();
    nsp_query_a(&qs, nm, &nsp_svcid_addr_by_name, NS_DNS);
    if (W_BEGIN_A(&qs, LUP_RETURN_NAME | LUP_RETURN_ADDR, &h) != 0) { t_skip("A begin failed %d", W_ERR()); return; }
    e = nsp_next_a(h, 0, &b, NULL);
    EXPECT_EQ(e, 0);
    if (e == 0) {
        WSAQUERYSETA *r = (WSAQUERYSETA *)b.p;
        EXPECT_EQ(r->dwSize, sizeof(WSAQUERYSETA));
        CHECK(r->lpszServiceInstanceName != NULL);
    }
    nsp_buf_free(&b);
    W_END(h);
}

TEST(ls_ansi_next_small_buffer_asks_for_wide_size_plus_slack) {
    /* The ANSI Next converts from a wide result, and on a too-small buffer reports the wide
     * requirement plus 0x12 bytes of conversion slack. */
    HANDLE hw, ha; DWORD lw = 0, la = 0; WSAQUERYSETA qa; char nm[] = "localhost";
    REQUIRE(W_NEXT_A); REQUIRE(W_BEGIN_A); REQUIRE(W_END); NSP_NEED();
    hw = open_localhost(LUP_RETURN_NAME | LUP_RETURN_ADDR);
    nsp_query_a(&qa, nm, &nsp_svcid_addr_by_name, NS_DNS);
    if (!hw || W_BEGIN_A(&qa, LUP_RETURN_NAME | LUP_RETURN_ADDR, &ha) != 0) { t_skip("setup failed"); if (hw) W_END(hw); return; }
    EXPECT_EQ(W_NEXT_W(hw, 0, &lw, NULL), SOCKET_ERROR);
    EXPECT_EQ(W_NEXT_A(ha, 0, &la, NULL), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_FAULT);
    EXPECT_EQ(la, lw + 0x12);
    W_END(hw); W_END(ha);
}
