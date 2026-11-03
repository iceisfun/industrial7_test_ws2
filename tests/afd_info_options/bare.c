/* Information requests on endpoints opened directly on the device (no provider involved): no context
 * blob, never bound. Records how they differ from provider-created sockets, plus the IPv6 forms. */
#include "aio.h"

static const ULONG g_classes[] = { AI_MAX_SEND_SIZE, AI_SENDS_PENDING, AI_MAX_PATH_SEND, AI_RECEIVE_WINDOW, AI_SEND_WINDOW, AI_CONNECT_TIME, AI_GROUP_ID_TYPE, AI_DELIVERY_STATUS };
static const char *const g_kind[] = { "tcp4", "udp4", "raw4", "tcp6", "udp6" };

/* What a bare endpoint reports per class: { kind, max send size (class 3 and 5), connect time, group } */
static const struct { int kind; ULONG max_send; } g_bare_max[] = {
    { AIOK_TCP4, 0xffffffffu }, { AIOK_UDP4, 65507 }, { AIOK_RAW4, 65515 }, { AIOK_TCP6, 0xffffffffu }, { AIOK_UDP6, 65527 },
};
TEST(aio_bare_max_send_size_by_kind)
{
    AIO_BEGIN();
    unsigned i;
    for (i = 0; i < sizeof g_bare_max / sizeof g_bare_max[0]; i++) {
        HANDLE h = aio_open_raw(g_bare_max[i].kind, NULL);
        aio_info_t a, b;
        if (!h) { if (!t_is_wine()) CHECKF(0, "open of a bare %s endpoint failed", g_kind[g_bare_max[i].kind]); continue; }
        EXPECT_NTS(aio_get_info((SOCKET)h, AI_MAX_SEND_SIZE, &a), NTS_SUCCESS);
        EXPECT_NTS(aio_get_info((SOCKET)h, AI_MAX_PATH_SEND, &b), NTS_SUCCESS);
        t_check(a.V.Ulong == g_bare_max[i].max_send, __FILE__, __LINE__, "bare max send size", "%s: 0x%lx", g_kind[g_bare_max[i].kind], (unsigned long)a.V.Ulong);
        t_check(b.V.Ulong == g_bare_max[i].max_send, __FILE__, __LINE__, "bare max path send size", "%s: 0x%lx", g_kind[g_bare_max[i].kind], (unsigned long)b.V.Ulong);
        aio_close_raw(h);
    }
}
TEST(aio_bare_idle_values_of_the_other_classes)
{
    AIO_BEGIN();
    int k;
    for (k = AIOK_TCP4; k <= AIOK_UDP6; k++) {
        HANDLE h = aio_open_raw(k, NULL);
        aio_info_t o;
        if (!h) { if (!t_is_wine()) CHECKF(0, "open of a bare %s endpoint failed", g_kind[k]); continue; }
        EXPECT_NTS(aio_get_info((SOCKET)h, AI_SENDS_PENDING, &o), NTS_SUCCESS);
        EXPECT_EQ(o.V.Large, 0);
        EXPECT_NTS(aio_get_info((SOCKET)h, AI_CONNECT_TIME, &o), NTS_SUCCESS);
        EXPECT_EQ(o.V.Ulong, 0xffffffffu);
        EXPECT_NTS(aio_get_info((SOCKET)h, AI_GROUP_ID_TYPE, &o), NTS_SUCCESS);
        EXPECT_EQ(o.V.Large, 0);
        EXPECT_NTS(aio_get_info((SOCKET)h, AI_DELIVERY_STATUS, &o), NTS_INVALID_DEVICE_REQ);
        EXPECT_NTS(aio_get_info((SOCKET)h, AI_INLINE_MODE, &o), NTS_INVALID_PARAMETER);
        aio_close_raw(h);
    }
}
TEST(aio_bare_max_send_size_matches_provider_socket)
{
    AIO_BEGIN();
    HANDLE h = aio_open_raw(AIOK_UDP4, NULL);
    SOCKET s = aio_udp();
    aio_info_t a, b;
    if (!h) return;
    EXPECT_NTS(aio_get_info((SOCKET)h, AI_MAX_SEND_SIZE, &a), NTS_SUCCESS);
    EXPECT_NTS(aio_get_info(s, AI_MAX_SEND_SIZE, &b), NTS_SUCCESS);
    EXPECT_EQ(a.V.Ulong, b.V.Ulong);
    aio_close(s); aio_close_raw(h);
}
TEST(aio_bare_set_information_matrix_matches_provider_socket)
{
    AIO_BEGIN();
    int cls;
    HANDLE h = aio_open_raw(AIOK_TCP4, NULL);
    SOCKET s = aio_tcp();
    if (!h) return;
    for (cls = 0; cls < 18; cls++) {
        aio_info_t in; LONG a, b;
        memset(&in, 0, sizeof in); in.Class = cls; in.V.Ulong = 1;
        a = aio_ctl((SOCKET)h, IOC_SET_INFO, &in, 16, NULL, 0, NULL, NULL);
        b = aio_ctl(s, IOC_SET_INFO, &in, 16, NULL, 0, NULL, NULL);
        t_check(a == b, __FILE__, __LINE__, "bare vs provider SET_INFORMATION", "class %d: bare 0x%08lx provider 0x%08lx", cls, (unsigned long)a, (unsigned long)b);
    }
    aio_close(s); aio_close_raw(h);
}
TEST(aio_v6_max_send_size)
{
    AIO_BEGIN();
    SOCKET u = W.WSASocketW(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
    SOCKET t = W.WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    aio_info_t o;
    if (u == INVALID_SOCKET || t == INVALID_SOCKET) { t_skip("no IPv6 stack"); return; }
    EXPECT_NTS(aio_get_info(u, AI_MAX_SEND_SIZE, &o), NTS_SUCCESS);
    EXPECT_EQ(o.V.Ulong, 65527);   /* 65535 minus the 8-byte UDP header */
    EXPECT_NTS(aio_get_info(t, AI_MAX_SEND_SIZE, &o), NTS_SUCCESS);
    EXPECT_EQ(o.V.Ulong, 0xffffffffu);
    aio_close(u); aio_close(t);
}
TEST(aio_udp_recvinfo_after_datagram)
{
    AIO_BEGIN();
    SOCKET a = aio_bound(SOCK_DGRAM), b = aio_bound(SOCK_DGRAM);
    struct sockaddr_in to; int n = sizeof to;
    ULONG v[2];
    DWORD t0;
    CHECK(W.getsockname(b, (struct sockaddr *)&to, &n) == 0);
    CHECK(W.sendto(a, "1234567", 7, 0, (struct sockaddr *)&to, sizeof to) == 7);
    t0 = GetTickCount();
    do {
        v[0] = v[1] = 0;
        aio_ctl(b, IOC_QUERY_RECV_INFO, NULL, 0, v, 8, NULL, NULL);
        if (v[0]) break;
        Sleep(5);
    } while (GetTickCount() - t0 < 3000);
    EXPECT_EQ(v[0], 7);   /* size of the first queued datagram */
    EXPECT_EQ(v[1], 0);
    aio_close(a); aio_close(b);
}

/* ---- endpoints that name the legacy transport device ----------------------------------------------- */
/* Opening with an explicit transport device name selects the older request path; a few requests behave
 * differently there (larger option storage, no pause support, 0x3fffffff stream send limit). */
static HANDLE tdi_ep(int kind)
{
    LONG st;
    HANDLE h = aio_open_tdi(kind, &st);
    if (!h && !t_is_wine()) CHECKF(0, "open with a transport name failed 0x%08lx", (unsigned long)st);
    return h;
}
TEST(aio_tdi_max_send_size_of_stream)
{
    AIO_BEGIN();
    HANDLE h = tdi_ep(AIOK_TCP4);
    aio_info_t o;
    if (!h) return;
    EXPECT_NTS(aio_get_info((SOCKET)h, AI_MAX_SEND_SIZE, &o), NTS_SUCCESS);
    EXPECT_EQ(o.V.Ulong, 0x3fffffff);
    aio_close_raw(h);
}
TEST(aio_tdi_set_class_15_not_supported)
{
    AIO_BEGIN();
    HANDLE h = tdi_ep(AIOK_TCP4);
    aio_info_t in;
    if (!h) return;
    memset(&in, 0, sizeof in); in.Class = 15; in.V.Ulong = 1;
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_INFO, &in, 16, NULL, 0, NULL, NULL), NTS_NOT_SUPPORTED);
    aio_close_raw(h);
}
TEST(aio_tdi_connect_data_set_then_size_then_get)
{
    AIO_BEGIN();
    HANDLE h = tdi_ep(AIOK_TCP4);
    unsigned char d[8], o[0x80];
    ULONG sz = 0x40;
    IO_STATUS_BLOCK io;
    if (!h) return;
    memset(d, 0x11, sizeof d);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SET_CONN_DATA, NULL, 0, d, 8, NULL, NULL), NTS_SUCCESS);
    memset(o, 0x5a, sizeof o);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_GET_CONN_DATA, NULL, 0, o, sizeof o, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 0);   /* SET stores the data to send; GET reads the received-data slot, which is empty */
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SIZE_CONN_DATA, NULL, 0, &sz, 4, NULL, NULL), NTS_SUCCESS);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_GET_CONN_DATA, NULL, 0, o, sizeof o, &io, NULL), NTS_SUCCESS);
    EXPECT_EQ(io.Information, 0x40);   /* SIZE reserved a zeroed receive slot of that size */
    { int i, nz = 0; for (i = 0; i < 0x40; i++) nz |= o[i]; CHECK(nz == 0); CHECK(o[0x40] == 0x5a); }
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_GET_CONN_DATA, NULL, 0, o, 0x10, &io, NULL), NTS_BUFFER_TOO_SMALL);
    aio_close_raw(h);
}
TEST(aio_tdi_size_request_needs_its_buffer)
{
    /* on the legacy path the size request validates its 4-byte buffer (the provider path ignores it) */
    AIO_BEGIN();
    HANDLE h = tdi_ep(AIOK_TCP4);
    ULONG sz = 0x20;
    if (!h) return;
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SIZE_CONN_DATA, NULL, 0, NULL, 0, NULL, NULL), NTS_INVALID_PARAMETER);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SIZE_CONN_DATA, NULL, 0, &sz, 3, NULL, NULL), NTS_INVALID_PARAMETER);
    EXPECT_NTS(aio_ctl((SOCKET)h, IOC_SIZE_CONN_DATA, NULL, 0, &sz, 4, NULL, NULL), NTS_SUCCESS);
    aio_close_raw(h);
}
/* The legacy-path endpoint answers like the provider-path one except for the differences pinned above.
 * Rows: control code and the six request shapes of sweep.c (letters as there). */
TEST(aio_tdi_stream_endpoint_status_rows)
{
    AIO_BEGIN();
    static const struct { ULONG code; const char *row; } t[] = {
        { 0x12037, "TPPTTT" }, { 0x1203b, "TPPPTT" }, { 0x1207b, "TPPTTT" }, { 0x1204b, "SPPPSP" },
        { 0x1205b, "SPPPSP" }, { 0x1206b, "PPPPSP" }, { 0x12043, "PPPPPP" }, { 0x12047, "SPPSPP" },
        { 0x12098, "TTTTST" }, { 0x12094, "TTTSTT" }, { 0x1207f, "PPCCPP" }, { 0x120c3, "CCCCCC" },
        { 0x12087, "PSSSPP" }, { 0x1208b, "PPHPSP" }, { 0x1203f, "CCCCCC" }, { 0x12033, "TSSTST" },
    };
    static const ULONG sin[6] = { 0, 16, 64, 256, 0, 4 }, sout[6] = { 0, 16, 64, 0, 256, 4 };
    unsigned i; int sh;
    for (i = 0; i < sizeof t / sizeof t[0]; i++)
        for (sh = 0; sh < 6; sh++) {
            HANDLE h = aio_open_tdi(AIOK_TCP4, NULL);
            unsigned char in[256], out[256];
            LONG st, want;
            if (!h) { if (!t_is_wine()) CHECK(0); return; }
            switch (t[i].row[sh]) {
            case 'S': want = NTS_SUCCESS; break; case 'P': want = NTS_INVALID_PARAMETER; break;
            case 'T': want = NTS_BUFFER_TOO_SMALL; break; case 'C': want = NTS_INVALID_CONNECTION; break;
            default: want = NTS_INVALID_HANDLE; break;   /* 'H' */
            }
            memset(in, 0, sizeof in); memset(out, 0, sizeof out);
            st = aio_ctl((SOCKET)h, t[i].code, sin[sh] ? in : NULL, sin[sh], sout[sh] ? out : NULL, sout[sh], NULL, NULL);
            t_check(st == want, __FILE__, __LINE__, "TDI-path status", "code 0x%05lx shape %d: got 0x%08lx want 0x%08lx", (unsigned long)t[i].code, sh, (unsigned long)st, (unsigned long)want);
            aio_close_raw(h);
        }
}
