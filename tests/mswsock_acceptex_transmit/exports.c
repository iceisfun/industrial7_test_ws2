/* Where the extension functions live: which DLLs export which, the legacy wsock32 forwarders, and that the
 * exported GetAcceptExSockaddrs agrees with the pointer handed out by the provider once the export machinery has
 * been initialised by an AcceptEx call. */
#include "mx.h"

static FARPROC gp(const char *dll, const char *name, DWORD *err)
{
    FARPROC p;
    SetLastError(0);
    p = GetProcAddress(t_module(dll), name);
    *err = GetLastError();
    return p;
}

TEST(exports_mswsock_exports_the_four_legacy_entry_points)
{
    static const char *names[] = { "AcceptEx", "GetAcceptExSockaddrs", "TransmitFile", "WSARecvEx" };
    unsigned i;
    for (i = 0; i < 4; i++) {
        DWORD e;
        FARPROC p = gp("mswsock.dll", names[i], &e);
        t_check(p != NULL, __FILE__, __LINE__, names[i], "not exported by mswsock.dll");
    }
}

/* ConnectEx, DisconnectEx and TransmitPackets are reachable only through SIO_GET_EXTENSION_FUNCTION_POINTER
 * (ws2_32 does export WSASendMsg, so only the names with no export anywhere are listed). */
TEST(exports_modern_extension_functions_have_no_named_export)
{
    static const char *dlls[] = { "mswsock.dll", "ws2_32.dll", "wsock32.dll" };
    static const char *names[] = { "ConnectEx", "DisconnectEx", "TransmitPackets", "WSARecvMsg" };
    unsigned i, j;
    for (i = 0; i < 3; i++) for (j = 0; j < 4; j++) {
        DWORD e;
        FARPROC p = gp(dlls[i], names[j], &e);
        t_check(p == NULL && e == ERROR_PROC_NOT_FOUND, __FILE__, __LINE__, names[j], "%s: ptr %p err %lu", dlls[i], (void *)p, e);
    }
}

/* ws2_32 itself exports none of the mswsock-era helpers. */
TEST(exports_ws2_32_does_not_export_mswsock_helpers)
{
    static const char *names[] = { "AcceptEx", "GetAcceptExSockaddrs", "TransmitFile", "WSARecvEx" };
    unsigned i;
    for (i = 0; i < 4; i++) {
        DWORD e;
        FARPROC p = gp("ws2_32.dll", names[i], &e);
        t_check(p == NULL && e == ERROR_PROC_NOT_FOUND, __FILE__, __LINE__, names[i], "ptr %p err %lu", (void *)p, e);
    }
}

/* wsock32 exports the same four names as forwarders into mswsock: the resolved address is the target's. */
TEST(exports_wsock32_forwards_the_four_helpers_to_mswsock)
{
    static const char *names[] = { "AcceptEx", "GetAcceptExSockaddrs", "TransmitFile", "WSARecvEx" };
    unsigned i;
    for (i = 0; i < 4; i++) {
        DWORD e1, e2;
        FARPROC a = gp("wsock32.dll", names[i], &e1), b = gp("mswsock.dll", names[i], &e2);
        t_check(a != NULL && a == b, __FILE__, __LINE__, names[i], "wsock32 %p mswsock %p", (void *)a, (void *)b);
    }
}

TEST(exports_wsock32_acceptex_forwarder_reports_notsock_for_an_invalid_listener)
{
    LPFN_ACCEPTEX fn = UIN("wsock32.dll", AcceptEx);
    unsigned char buf[64];
    DWORD n = 0;
    OVERLAPPED ov;
    NEED_NET();
    REQUIRE(fn);
    memset(&ov, 0, sizeof ov);
    mx_WSASetLastError(0);
    MX_EQ(fn(INVALID_SOCKET, INVALID_SOCKET, buf, 0, 32, 32, &n, &ov), FALSE);
    MX_EQ(mx_WSAGetLastError(), WSAENOTSOCK);
}

TEST(exports_wsock32_transmitfile_forwarder_reports_notsock_for_an_invalid_socket)
{
    LPFN_TRANSMITFILE fn = UIN("wsock32.dll", TransmitFile);
    NEED_NET();
    REQUIRE(fn);
    mx_WSASetLastError(0);
    MX_EQ(fn(INVALID_SOCKET, NULL, 0, 0, NULL, NULL, 0), FALSE);
    MX_EQ(mx_WSAGetLastError(), WSAENOTSOCK);
}

TEST(exports_wsock32_wsarecvex_forwarder_reports_notsock_and_clears_flags)
{
    int (WINAPI *fn)(SOCKET, char *, int, int *) = (void *)UIN("wsock32.dll", WSARecvEx);
    char c;
    int flags = 0x1234;
    NEED_NET();
    REQUIRE(fn);
    MX_EQ(fn(INVALID_SOCKET, &c, 1, &flags), SOCKET_ERROR);
    MX_EQ(mx_WSAGetLastError(), WSAENOTSOCK);
    MX_EQ(flags, 0);   /* the flags word is cleared before the receive is attempted */
}

/* ---- GetAcceptExSockaddrs: export versus pointer ---------------------------------------------------------- */

/* Make the exported AcceptEx initialise its internal copy of the provider's GetAcceptExSockaddrs pointer; the
 * call itself fails on the accept socket argument, after the pointers have been cached. */
static int prime_export(struct mx_ext *x)
{
    LPFN_ACCEPTEX fn = UIN("mswsock.dll", AcceptEx);
    struct sockaddr_in a;
    SOCKET l;
    unsigned char buf[128];
    OVERLAPPED ov;
    DWORD n = 0;
    if (!fn || !mx_load_ext(x)) return 0;
    l = mx_listener(&a, 2);
    if (l == INVALID_SOCKET) return 0;
    memset(&ov, 0, sizeof ov);
    fn(l, INVALID_SOCKET, buf, 0, 32, 32, &n, &ov);
    mx_closesocket(l);
    return 1;
}

struct gaes_row { DWORD rl, ll, rr; };

TEST(exports_getacceptexsockaddrs_export_and_pointer_agree_on_a_synthetic_buffer)
{
    static const struct gaes_row rows[] = {
        { 0, 32, 32 }, { 10, 32, 32 }, { 0, 44, 44 }, { 7, 64, 20 }, { 0, 0, 32 }, { 0, 32, 0 }, { 100, 3, 5 },
    };
    LPFN_GETACCEPTEXSOCKADDRS exp = UIN("mswsock.dll", GetAcceptExSockaddrs);
    struct mx_ext x;
    unsigned char buf[512];
    unsigned i;
    NEED_NET();
    REQUIRE(exp);
    if (!prime_export(&x)) { t_skip("extension functions not offered"); return; }
    for (i = 0; i < sizeof buf; i++) buf[i] = (unsigned char)(i * 7 + 3);
    for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        struct sockaddr *l1 = (void *)1, *r1 = (void *)1, *l2 = (void *)1, *r2 = (void *)1;
        int ll1 = -7, rl1 = -7, ll2 = -7, rl2 = -7;
        exp(buf, rows[i].rl, rows[i].ll, rows[i].rr, &l1, &ll1, &r1, &rl1);
        x.gaes(buf, rows[i].rl, rows[i].ll, rows[i].rr, &l2, &ll2, &r2, &rl2);
        t_check(l1 == l2 && r1 == r2 && ll1 == ll2 && rl1 == rl2, __FILE__, __LINE__, "export agrees with pointer",
                "row %u: local %p/%p remote %p/%p llen %d/%d rlen %d/%d", i, (void *)l1, (void *)l2, (void *)r1, (void *)r2, ll1, ll2, rl1, rl2);
    }
}

/* With both slot lengths zero the provider function reads and writes nothing, so even NULL outputs are safe. */
TEST(exports_getacceptexsockaddrs_both_slots_zero_accepts_null_outputs)
{
    LPFN_GETACCEPTEXSOCKADDRS exp = UIN("mswsock.dll", GetAcceptExSockaddrs);
    struct mx_ext x;
    unsigned char buf[16] = {0};
    NEED_NET();
    REQUIRE(exp);
    if (!prime_export(&x)) { t_skip("extension functions not offered"); return; }
    exp(buf, 4, 0, 0, NULL, NULL, NULL, NULL);
    x.gaes(buf, 4, 0, 0, NULL, NULL, NULL, NULL);
    CHECK(1);
}

/* The slot length is read from the final two bytes of the slot as an unsigned 16-bit value, little-endian. */
TEST(exports_getacceptexsockaddrs_length_is_the_last_two_bytes_of_the_slot)
{
    LPFN_GETACCEPTEXSOCKADDRS exp = UIN("mswsock.dll", GetAcceptExSockaddrs);
    struct mx_ext x;
    unsigned char buf[256];
    struct sockaddr *l = NULL, *r = NULL;
    int ll = 0, rl = 0;
    NEED_NET();
    REQUIRE(exp);
    if (!prime_export(&x)) { t_skip("extension functions not offered"); return; }
    memset(buf, 0, sizeof buf);
    buf[30] = 0x34; buf[31] = 0x12;         /* local slot [0,32): 0x1234 */
    buf[62] = 0xFE; buf[63] = 0xCA;         /* remote slot [32,64): 0xCAFE */
    exp(buf, 0, 32, 32, &l, &ll, &r, &rl);
    CHECK(l == (struct sockaddr *)buf);
    CHECK(r == (struct sockaddr *)(buf + 32));
    MX_EQ(ll, 0x1234);
    MX_EQ(rl, 0xCAFE);
}
