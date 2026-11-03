/* Measures the entry points around the socket I/O controls: the legacy wsock32 forwarder for ioctlsocket,
 * the namespace-provider control WSANSPIoctl (argument validation only; no lookup handle exists), and the
 * helper-library control stubs exported by the Microsoft provider DLL. */
#include "ib.h"

IBTEST(ib_export_wsock32_ioctlsocket_forwards_to_ws2_32)
{
    FARPROC a = t_proc_in("wsock32.dll", "ioctlsocket"), b = t_proc_in("ws2_32.dll", "ioctlsocket");
    REQUIRE(a && b);
    CHECK(a == b);
}

IBTEST(ib_export_wsock32_ioctlsocket_works)
{
    int (WINAPI *f)(SOCKET, long, u_long *) = (int (WINAPI *)(SOCKET, long, u_long *))t_proc_in("wsock32.dll", "ioctlsocket");
    IB_PAIR(c, s);
    u_long v = 1;
    int e;
    REQUIRE(f);
    CHECK(f(c, FIONBIO, &v) == 0);
    {
        char b[2];
        int r = U(recv)(c, b, 1, 0);
        e = ib_err();
        CHECKF(r == SOCKET_ERROR && e == WSAEWOULDBLOCK, "r=%d err=%d", r, e);
    }
    v = 0xdeadbeef;
    CHECK(f(INVALID_SOCKET, FIONREAD, &v) == SOCKET_ERROR);
    CHECK(ib_err() == WSAENOTSOCK);
    ib_close(c); ib_close(s);
}

IBTEST(ib_export_wsaioctl_and_ioctlsocket_resolve_in_ws2_32_only)
{
    CHECK(t_proc_in("ws2_32.dll", "WSAIoctl") != NULL);
    CHECK(t_proc_in("ws2_32.dll", "WSANSPIoctl") != NULL);
    SetLastError(0);
    CHECK(t_proc_in("wsock32.dll", "WSAIoctl") == NULL);
}

IBTEST(ib_wsanspioctl_null_lookup_handle_is_invalid_handle)
{
    int (WINAPI *f)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPVOID) =
        (int (WINAPI *)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPVOID))t_proc_in("ws2_32.dll", "WSANSPIoctl");
    DWORD n = IB_UNSET;
    int r;
    REQUIRE(f);
    ib_seterr(0);
    r = f(NULL, 0x12345, NULL, 0, NULL, 0, &n, NULL);
    CHECKF(r == SOCKET_ERROR && ib_err() == WSA_INVALID_HANDLE, "r=%d err=%d", r, ib_err());
    CHECKF(n == IB_UNSET, "byte count %lu", n);
}

IBTEST(ib_wsanspioctl_missing_byte_count_is_invalid_argument)
{
    /* The byte count pointer is validated before the lookup handle. */
    int (WINAPI *f)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPVOID) =
        (int (WINAPI *)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPVOID))t_proc_in("ws2_32.dll", "WSANSPIoctl");
    int r;
    REQUIRE(f);
    ib_seterr(0);
    r = f(NULL, 0x12345, NULL, 0, NULL, 0, NULL, NULL);
    CHECKF(r == SOCKET_ERROR && ib_err() == WSAEINVAL, "r=%d err=%d", r, ib_err());
}

CHILD(ib_nspioctl_no_startup)
{
    int (WINAPI *f)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPVOID) =
        (int (WINAPI *)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPVOID))t_proc_in("ws2_32.dll", "WSANSPIoctl");
    DWORD n = 0;
    int r;
    if (!f) return 10;
    r = f(NULL, 0, NULL, 0, NULL, 0, &n, NULL);
    if (r != SOCKET_ERROR) return 11;
    return U(WSAGetLastError)() == WSANOTINITIALISED ? 0 : 20;
}

IBTEST(ib_wsanspioctl_before_startup_is_notinitialised)
{
    EXPECT_EQ(t_run_child("ib_nspioctl_no_startup", "", 20000), 0);
}

IBTEST(ib_mswsock_wship_ioctl_stubs_answer_invalid)
{
    /* The helper-library control entry points of the TCP/IP helper are placeholders that report an invalid
     * argument whatever they are given; both families share one implementation. */
    typedef DWORD (WINAPI *stub_t)(void *, void *, void *, void *, void *, void *, void *, void *, void *);
    stub_t a = (stub_t)t_proc_in("mswsock.dll", "Tcpip4_WSHIoctl"), b = (stub_t)t_proc_in("mswsock.dll", "Tcpip6_WSHIoctl");
    REQUIRE(a && b);
    CHECK(a == b);
    CHECK(a(0, 0, 0, 0, 0, 0, 0, 0, 0) == WSAEINVAL);
    CHECK(b((void *)1, 0, 0, 0, 0, 0, 0, 0, 0) == WSAEINVAL);
}
