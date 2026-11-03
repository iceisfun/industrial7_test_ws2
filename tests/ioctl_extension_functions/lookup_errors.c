/* SIO_GET_EXTENSION_FUNCTION_POINTER, the failing side: exact error codes and what is left untouched for
 * bad sockets, short or missing buffers, unknown GUIDs, and the precedence between the checks.
 *
 * Order of checks in the base provider handler: the input buffer must be at least a GUID long and non-NULL, the
 * output buffer at least pointer-sized and non-NULL (all four failures are WSAEFAULT, nothing written); only then
 * is the GUID compared (16 bytes, by value) and an unknown one is WSAEINVAL. A handle ws2_32 does not know
 * is rejected earlier still, with WSAENOTSOCK; an uninitialised Winsock earlier than that. */
#include "xf.h"

#define SENT 0xCC

/* One lookup with explicit buffers. */
static int ioc(SOCKET s, const void *in, DWORD inlen, void *out, DWORD outlen, DWORD *bytes)
{
    return WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, (LPVOID)in, inlen, out, outlen, bytes, NULL, NULL);
}

#define TCP(s) SOCKET s; do { NEED_NET(); s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); \
    if (s == INVALID_SOCKET) { t_skip("socket"); return; } } while (0)

/* ---- the socket handle ---------------------------------------------------------------------------------- */

static void notsock_case(SOCKET s, const char *what)
{
    GUID g = WSAID_ACCEPTEX; void *p = NULL; DWORD n = (DWORD)XF_POISON; int r;
    WSASetLastError(0);
    r = ioc(s, &g, sizeof g, &p, sizeof p, &n);
    CHECKF(r == SOCKET_ERROR, "%s: lookup succeeded", what);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    CHECKF(p == NULL, "%s: output written", what);
    CHECKF(n == (DWORD)XF_POISON, "%s: byte count written (%lu)", what, n);
}
TEST(xf_lookup_err_invalid_socket)        { NEED_NET(); notsock_case(INVALID_SOCKET, "INVALID_SOCKET"); }
TEST(xf_lookup_err_zero_handle)           { NEED_NET(); notsock_case((SOCKET)0, "0"); }
TEST(xf_lookup_err_small_unused_handle)   { NEED_NET(); notsock_case((SOCKET)4, "4"); }
TEST(xf_lookup_err_closed_socket)
{
    TCP(s);
    closesocket(s);
    notsock_case(s, "closed");
}
TEST(xf_lookup_err_closed_twice_value)
{
    SOCKET s; NEED_NET();
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(s != INVALID_SOCKET);
    closesocket(s);
    CHECK(closesocket(s) == SOCKET_ERROR);
    notsock_case(s, "closed datagram");
}
TEST(xf_lookup_err_file_handle)
{
    HANDLE h; NEED_NET();
    h = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    REQUIRE(h != INVALID_HANDLE_VALUE);
    notsock_case((SOCKET)h, "NUL device handle");
    CloseHandle(h);
}
TEST(xf_lookup_err_event_handle)
{
    HANDLE h; NEED_NET();
    h = CreateEventA(NULL, TRUE, FALSE, NULL);
    REQUIRE(h);
    notsock_case((SOCKET)h, "event handle");
    CloseHandle(h);
}
TEST(xf_lookup_err_current_process_pseudo_handle)
{
    NEED_NET();
    notsock_case((SOCKET)GetCurrentProcess(), "pseudo handle");
}

/* The socket check precedes the buffer checks: a bad socket with bad buffers still reports WSAENOTSOCK. */
TEST(xf_lookup_err_bad_socket_wins_over_bad_buffers)
{
    int r; NEED_NET();
    WSASetLastError(0);
    r = ioc(INVALID_SOCKET, NULL, 0, NULL, 0, NULL);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
}

/* Without WSAStartup nothing works: the prolog fails the call first. */
CHILD(xf_nostartup)
{
    GUID g = WSAID_ACCEPTEX; void *p = NULL; DWORD n = 0; int r, e1, e2;
    r = WSAIoctl((SOCKET)0x1234, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &p, sizeof p, &n, NULL, NULL);
    e1 = WSAGetLastError();
    r |= WSAIoctl(INVALID_SOCKET, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &p, sizeof p, &n, NULL, NULL) == 0;
    e2 = WSAGetLastError();
    if (r != SOCKET_ERROR) return 1;
    if (e1 != WSANOTINITIALISED) return 2;
    if (e2 != WSANOTINITIALISED) return 3;
    return 0;
}
TEST(xf_lookup_err_before_startup_is_notinitialised)
{
    DWORD rc = t_run_child("xf_nostartup", "", 30000);
    CHECKF(rc == 0, "child result %lu", rc);
}

CHILD(xf_aftercleanup)
{
    WSADATA d; GUID g = WSAID_ACCEPTEX; void *p = NULL; DWORD n = 0; SOCKET s; int r;
    if (WSAStartup(MAKEWORD(2, 2), &d)) return 1;
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 2;
    if (WSACleanup()) return 3;
    r = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &p, sizeof p, &n, NULL, NULL);
    if (r != SOCKET_ERROR) return 4;
    if (WSAGetLastError() != WSANOTINITIALISED) return 5;
    return 0;
}
TEST(xf_lookup_err_after_cleanup_is_notinitialised)
{
    DWORD rc = t_run_child("xf_aftercleanup", "", 30000);
    CHECKF(rc == 0, "child result %lu", rc);
}

/* ---- input buffer --------------------------------------------------------------------------------------- */

TEST(xf_lookup_err_input_shorter_than_guid)
{
    DWORD len; TCP(s);
    for (len = 0; len < sizeof(GUID); len++) {
        BYTE in[16]; void *p = NULL; DWORD n = (DWORD)XF_POISON; int r;
        { GUID g0 = WSAID_ACCEPTEX; memcpy(in, &g0, 16); }
        WSASetLastError(0);
        r = ioc(s, in, len, &p, sizeof p, &n);
        CHECKF(r == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "len %lu: r=%d err=%d", len, r, WSAGetLastError());
        CHECKF(p == NULL && n == (DWORD)XF_POISON, "len %lu: output/count written", len);
    }
    closesocket(s);
}
TEST(xf_lookup_err_input_null_pointer)
{
    void *p = NULL; DWORD n = (DWORD)XF_POISON; int r; TCP(s);
    WSASetLastError(0);
    r = ioc(s, NULL, sizeof(GUID), &p, sizeof p, &n);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    CHECK(p == NULL && n == (DWORD)XF_POISON);
    closesocket(s);
}
TEST(xf_lookup_err_input_null_pointer_zero_length)
{
    void *p = NULL; DWORD n = (DWORD)XF_POISON; int r; TCP(s);
    WSASetLastError(0);
    r = ioc(s, NULL, 0, &p, sizeof p, &n);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    closesocket(s);
}
TEST(xf_lookup_err_input_exactly_guid_ok_and_one_less_fails)
{
    GUID g = WSAID_CONNECTEX; BYTE in[17]; void *p = NULL; DWORD n = 0; TCP(s);
    memcpy(in, &g, 16); in[16] = 0x55;
    CHECK(ioc(s, in, 16, &p, sizeof p, &n) == 0);
    p = NULL;
    CHECK(ioc(s, in, 15, &p, sizeof p, &n) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    p = NULL;
    CHECK(ioc(s, in, 17, &p, sizeof p, &n) == 0 && p != NULL);
    closesocket(s);
}
TEST(xf_lookup_input_unaligned_guid)
{
    BYTE raw[40]; unsigned off; TCP(s);
    for (off = 1; off < 8; off++) {
        GUID g = WSAID_DISCONNECTEX; void *p = NULL, *ref = xf_fn(&g); DWORD n = 0; int r;
        memcpy(raw + off, &g, sizeof g);
        r = ioc(s, raw + off, sizeof g, &p, sizeof p, &n);
        CHECKF(r == 0 && p == ref, "offset %u: r=%d err=%d", off, r, WSAGetLastError());
    }
    closesocket(s);
}
TEST(xf_lookup_input_buffer_not_modified)
{
    GUID g = WSAID_TRANSMITFILE, copy; void *p = NULL; DWORD n = 0; TCP(s);
    copy = g;
    CHECK(ioc(s, &g, sizeof g, &p, sizeof p, &n) == 0);
    CHECK(!memcmp(&g, &copy, sizeof g));
    closesocket(s);
}

/* ---- output buffer -------------------------------------------------------------------------------------- */

TEST(xf_lookup_err_output_shorter_than_pointer)
{
    DWORD len; TCP(s);
    for (len = 0; len < sizeof(void *); len++) {
        GUID g = WSAID_ACCEPTEX; BYTE out[16]; DWORD n = (DWORD)XF_POISON; int r;
        memset(out, SENT, sizeof out);
        WSASetLastError(0);
        r = ioc(s, &g, sizeof g, out, len, &n);
        CHECKF(r == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "len %lu: r=%d err=%d", len, r, WSAGetLastError());
        { unsigned i; int clean = 1; for (i = 0; i < sizeof out; i++) if (out[i] != SENT) clean = 0;
          CHECKF(clean, "len %lu: output written", len); }
        CHECKF(n == (DWORD)XF_POISON, "len %lu: byte count written", len);
    }
    closesocket(s);
}
TEST(xf_lookup_err_output_null_pointer)
{
    GUID g = WSAID_ACCEPTEX; DWORD n = (DWORD)XF_POISON; int r; TCP(s);
    WSASetLastError(0);
    r = ioc(s, &g, sizeof g, NULL, sizeof(void *), &n);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    CHECK(n == (DWORD)XF_POISON);
    closesocket(s);
}
TEST(xf_lookup_err_output_null_pointer_zero_length)
{
    GUID g = WSAID_ACCEPTEX; DWORD n = (DWORD)XF_POISON; int r; TCP(s);
    WSASetLastError(0);
    r = ioc(s, &g, sizeof g, NULL, 0, &n);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    closesocket(s);
}
TEST(xf_lookup_output_longer_than_pointer_writes_exactly_eight)
{
    static const DWORD lens[] = {9, 12, 16, 64, 4096};
    unsigned i; TCP(s);
    for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        GUID g = WSAID_ACCEPTEX; BYTE out[4096]; DWORD n = 0; int r; void *ref = xf_fn(&g); unsigned j; int tail_clean = 1;
        memset(out, SENT, sizeof out);
        r = ioc(s, &g, sizeof g, out, lens[i], &n);
        CHECKF(r == 0 && n == sizeof(void *), "len %lu: r=%d n=%lu", lens[i], r, n);
        CHECKF(!memcmp(out, &ref, sizeof ref), "len %lu: wrong pointer", lens[i]);
        for (j = sizeof(void *); j < sizeof out; j++) if (out[j] != SENT) tail_clean = 0;
        CHECKF(tail_clean, "len %lu: wrote past the pointer", lens[i]);
    }
    closesocket(s);
}
TEST(xf_lookup_output_exactly_pointer_sized)
{
    GUID g = WSAID_TRANSMITPACKETS; BYTE out[9]; DWORD n = 0; TCP(s);
    memset(out, SENT, sizeof out);
    CHECK(ioc(s, &g, sizeof g, out, 8, &n) == 0);
    EXPECT_EQ(n, 8);
    EXPECT_EQ(out[8], SENT);
    closesocket(s);
}
TEST(xf_lookup_output_unaligned)
{
    BYTE raw[24]; unsigned off; TCP(s);
    for (off = 1; off < 8; off++) {
        GUID g = WSAID_WSARECVMSG; void *ref = xf_fn(&g), *got; DWORD n = 0; int r;
        memset(raw, 0, sizeof raw);
        r = ioc(s, &g, sizeof g, raw + off, 8, &n);
        memcpy(&got, raw + off, 8);
        CHECKF(r == 0 && got == ref, "offset %u: r=%d err=%d", off, r, WSAGetLastError());
    }
    closesocket(s);
}
TEST(xf_lookup_output_overwritten_on_each_call)
{
    GUID a = WSAID_ACCEPTEX, b = WSAID_CONNECTEX; void *p = NULL, *pa, *pb; DWORD n; TCP(s);
    ioc(s, &a, sizeof a, &p, sizeof p, &n); pa = p;
    ioc(s, &b, sizeof b, &p, sizeof p, &n); pb = p;
    CHECK(pa != pb);
    EXPECT_EQ(pb, xf_fn(&b));
    closesocket(s);
}

/* ---- the GUID itself -------------------------------------------------------------------------------------- */

static void unknown_guid(SOCKET s, const GUID *g, const char *what)
{
    void *p = NULL; DWORD n = (DWORD)XF_POISON; int r;
    WSASetLastError(0);
    r = ioc(s, g, sizeof *g, &p, sizeof p, &n);
    CHECKF(r == SOCKET_ERROR, "%s: lookup succeeded", what);
    CHECKF(WSAGetLastError() == WSAEINVAL, "%s: error %d want WSAEINVAL", what, WSAGetLastError());
    CHECKF(p == NULL, "%s: output written", what);
}
TEST(xf_lookup_err_zero_guid)   { GUID g; TCP(s); memset(&g, 0, sizeof g); unknown_guid(s, &g, "zero"); closesocket(s); }
TEST(xf_lookup_err_ones_guid)   { GUID g; TCP(s); memset(&g, 0xFF, sizeof g); unknown_guid(s, &g, "all ones"); closesocket(s); }
TEST(xf_lookup_err_text_in_guid_slot)
{
    BYTE b[16]; TCP(s);
    memcpy(b, "ws2_32 mswsock!!", 16);
    unknown_guid(s, (GUID *)b, "ascii");
    closesocket(s);
}
TEST(xf_lookup_err_one_flipped_byte_in_every_known_guid)
{
    unsigned g, i; TCP(s);
    for (g = 0; g < XF_NGUIDS; g++)
        for (i = 0; i < 16; i++) {
            GUID x = XF_GUIDS[g].g;
            ((BYTE *)&x)[i] ^= 0x80;
            unknown_guid(s, &x, XF_GUIDS[g].name);
        }
    closesocket(s);
}
TEST(xf_lookup_err_swapped_halves_of_known_guid)
{
    unsigned g; TCP(s);
    for (g = 0; g < XF_NGUIDS; g++) {
        GUID x; BYTE *b = (BYTE *)&x;
        memcpy(&x, &XF_GUIDS[g].g, 16);
        { unsigned long long lo, hi; memcpy(&lo, b, 8); memcpy(&hi, b + 8, 8);
          if (lo == hi) continue;
          memcpy(b, &hi, 8); memcpy(b + 8, &lo, 8); }
        unknown_guid(s, &x, XF_GUIDS[g].name);
    }
    closesocket(s);
}
TEST(xf_lookup_err_guid_with_only_first_half_matching)
{
    unsigned g; TCP(s);
    for (g = 0; g < XF_NGUIDS; g++) {
        GUID x; memset(&x, 0, sizeof x);
        memcpy(&x, &XF_GUIDS[g].g, 8);
        unknown_guid(s, &x, XF_GUIDS[g].name);
    }
    closesocket(s);
}
TEST(xf_lookup_err_guid_with_only_second_half_matching)
{
    unsigned g; TCP(s);
    for (g = 0; g < XF_NGUIDS; g++) {
        GUID x; memset(&x, 0, sizeof x);
        memcpy((BYTE *)&x + 8, (BYTE *)&XF_GUIDS[g].g + 8, 8);
        unknown_guid(s, &x, XF_GUIDS[g].name);
    }
    closesocket(s);
}
TEST(xf_lookup_err_well_known_interface_ids)
{
    static const GUID unknown_com = {0x00000000, 0, 0, {0xC0, 0, 0, 0, 0, 0, 0, 0x46}};   /* IID_IUnknown */
    static const GUID transport = {0x2c8dfda2, 0x2fe7, 0x4a4e, {0x9a, 0x00, 0x56, 0xb6, 0x33, 0x2e, 0x74, 0x60}};
    TCP(s);
    unknown_guid(s, &unknown_com, "IUnknown");
    unknown_guid(s, &transport, "arbitrary");
    closesocket(s);
}
TEST(xf_lookup_err_unknown_guid_on_each_socket_kind)
{
    unsigned k; GUID bad = {0x12345678, 0x1234, 0x5678, {1, 2, 3, 4, 5, 6, 7, 8}};
    NEED_NET();
    for (k = 0; k < XF_NKINDS; k++) {
        SOCKET s;
        if (XF_KINDS[k].af == AF_INET6 && !xf_ipv6_ok()) continue;
        s = socket(XF_KINDS[k].af, XF_KINDS[k].type, XF_KINDS[k].proto);
        if (s == INVALID_SOCKET) continue;
        unknown_guid(s, &bad, XF_KINDS[k].name);
        closesocket(s);
    }
}
TEST(xf_lookup_err_does_not_poison_following_lookup)
{
    GUID bad = {1, 2, 3, {4, 5, 6, 7, 8, 9, 10, 11}}, ok = WSAID_ACCEPTEX; void *p = NULL; DWORD n = 0; TCP(s);
    unknown_guid(s, &bad, "unknown");
    WSASetLastError(0);
    CHECK(ioc(s, &ok, sizeof ok, &p, sizeof p, &n) == 0);
    CHECK(p != NULL);
    EXPECT_EQ(WSAGetLastError(), 0);
    closesocket(s);
}
TEST(xf_lookup_err_leaves_socket_usable)
{
    GUID bad = {9, 9, 9, {9, 9, 9, 9, 9, 9, 9, 9}}; struct sockaddr_in a; int len = sizeof a; TCP(s);
    unknown_guid(s, &bad, "unknown");
    xf_loop4(&a);
    CHECK(bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(getsockname(s, (struct sockaddr *)&a, &len) == 0);
    closesocket(s);
}

/* ---- precedence of the checks ------------------------------------------------------------------------------- */

TEST(xf_lookup_err_short_output_wins_over_unknown_guid)
{
    GUID bad = {1, 1, 1, {1, 1, 1, 1, 1, 1, 1, 1}}; BYTE out[8]; DWORD n = 0; int r; TCP(s);
    WSASetLastError(0);
    r = ioc(s, &bad, sizeof bad, out, 4, &n);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    closesocket(s);
}
TEST(xf_lookup_err_short_input_wins_over_short_output)
{
    BYTE in[16] = {0}; BYTE out[8]; DWORD n = 0; int r; TCP(s);
    WSASetLastError(0);
    r = ioc(s, in, 3, out, 3, &n);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    closesocket(s);
}
TEST(xf_lookup_err_null_buffers_both)
{
    DWORD n = 0; int r; TCP(s);
    WSASetLastError(0);
    r = ioc(s, NULL, 0, NULL, 0, &n);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    closesocket(s);
}

/* ---- overlapped and completion routine forms ------------------------------------------------------------------ */

TEST(xf_lookup_overlapped_short_buffers_fail_synchronously)
{
    GUID g = WSAID_ACCEPTEX; BYTE out[8]; DWORD n = (DWORD)XF_POISON; int r; WSAOVERLAPPED ov; TCP(s);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = WSACreateEvent();
    REQUIRE(ov.hEvent);
    WSASetLastError(0);
    r = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, 8, out, sizeof out, &n, &ov, NULL);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    WSASetLastError(0);
    r = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, out, 4, &n, &ov, NULL);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    CHECK(n == (DWORD)XF_POISON);
    CHECK(WaitForSingleObject(ov.hEvent, 0) == WAIT_TIMEOUT);   /* nothing was queued */
    WSACloseEvent(ov.hEvent);
    closesocket(s);
}
TEST(xf_lookup_overlapped_writes_pointer_before_returning)
{
    GUID g = WSAID_CONNECTEX; void *p = NULL, *ref = xf_fn(&g); DWORD n = 0; int r; WSAOVERLAPPED ov; TCP(s);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = WSACreateEvent();
    REQUIRE(ov.hEvent);
    r = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &p, sizeof p, &n, &ov, NULL);
    CHECKF(r == 0, "r=%d err=%d", r, WSAGetLastError());
    EXPECT_EQ(p, ref);
    EXPECT_EQ(n, 8);
    t_note("event signalled after inline overlapped lookup: %s", WaitForSingleObject(ov.hEvent, 0) == WAIT_OBJECT_0 ? "yes" : "no");
    WSACloseEvent(ov.hEvent);
    closesocket(s);
}
TEST(xf_lookup_overlapped_unknown_guid_leaves_event_unsignalled)
{
    GUID bad = {7, 7, 7, {7, 7, 7, 7, 7, 7, 7, 7}}; void *p = NULL; DWORD n = (DWORD)XF_POISON; int r; WSAOVERLAPPED ov; TCP(s);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = WSACreateEvent();
    REQUIRE(ov.hEvent);
    r = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &bad, sizeof bad, &p, sizeof p, &n, &ov, NULL);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    CHECK(WaitForSingleObject(ov.hEvent, 0) == WAIT_TIMEOUT);
    WSACloseEvent(ov.hEvent);
    closesocket(s);
}
TEST(xf_lookup_overlapped_missing_byte_count_is_efault_for_every_guid)
{
    unsigned i; WSAOVERLAPPED ov; TCP(s);
    memset(&ov, 0, sizeof ov);
    for (i = 0; i < XF_NCORE; i++) {
        void *p = NULL; int r;
        WSASetLastError(0);
        r = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, (LPVOID)&XF_GUIDS[i].g, sizeof(GUID), &p, sizeof p, NULL, &ov, NULL);
        CHECKF(r == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "%s: r=%d err=%d", XF_GUIDS[i].name, r, WSAGetLastError());
        CHECKF(p == NULL, "%s: output written", XF_GUIDS[i].name);
    }
    closesocket(s);
}

/* ---- ioctlsocket takes no buffers: the control code is not a valid argument there ---------------------------- */
TEST(xf_lookup_via_ioctlsocket_is_rejected)
{
    u_long arg = 0; int r; TCP(s);
    WSASetLastError(0);
    r = ioctlsocket(s, (long)SIO_GET_EXTENSION_FUNCTION_POINTER, &arg);
    CHECK(r == SOCKET_ERROR);
    t_note("ioctlsocket with the lookup code: error %d", WSAGetLastError());
    closesocket(s);
}
