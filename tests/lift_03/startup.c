/* WSAStartup version negotiation and WSACleanup reference counting, plus WSAProviderConfigChange and an
 * address-list-change ioctl bound to a completion port.
 *
 * The negotiation rows run in a child process so that a requested version below 2.2 cannot influence the
 * name-resolution behaviour of the other tests in this executable. */
#include "lift03.h"

static const struct { WORD ask; WORD got; } kRows[] = {
    {MAKEWORD(0, 0), MAKEWORD(2, 2)},   {MAKEWORD(0, 1), MAKEWORD(2, 2)},
    {MAKEWORD(1, 0), MAKEWORD(1, 0)},   {MAKEWORD(1, 1), MAKEWORD(1, 1)},
    {MAKEWORD(1, 2), MAKEWORD(1, 1)},   {MAKEWORD(1, 0xff), MAKEWORD(1, 1)},
    {MAKEWORD(2, 0), MAKEWORD(2, 0)},   {MAKEWORD(2, 1), MAKEWORD(2, 1)},
    {MAKEWORD(2, 2), MAKEWORD(2, 2)},   {MAKEWORD(2, 3), MAKEWORD(2, 2)},
    {MAKEWORD(2, 0xff), MAKEWORD(2, 2)},{MAKEWORD(3, 0), MAKEWORD(2, 2)},
    {MAKEWORD(0xff, 0), MAKEWORD(2, 2)},
};

static int g_bad;
#define KCHK(cond, what) do { if (!(cond)) { g_bad++; printf("  startup row %d: %s\n", row, what); } } while (0)

/* argv[1] = row index */
CHILD(startup_row)
{
    int row = argc > 1 ? atoi(argv[1]) : 0;
    if (row < 0 || row >= (int)ARRSZ(kRows)) return 99;
    WORD ask = kRows[row].ask;
    WSADATA d;
    int r;
    g_bad = 0;
    if (!U(WSAStartup) || !U(WSACleanup) || !U(WSAGetLastError) || !U(WSASetLastError)) return 98;

    memset(&d, 0xcc, sizeof d);
    d.lpVendorInfo = (char *)&g_bad; /* marker; must come back unchanged */
    r = U(WSAStartup)(ask, &d);
    KCHK(r == (LOBYTE(ask) ? 0 : WSAVERNOTSUPPORTED), "WSAStartup result");
    KCHK(d.wVersion == kRows[row].got, "wVersion");
    if (!r) {
        r = U(WSAStartup)(ask, &d); /* second reference */
        KCHK(r == 0, "second WSAStartup");
        for (int k = 0; k < 2; k++) {
            U(WSASetLastError)(0x1234);
            KCHK(U(WSACleanup)() == 0, "WSACleanup while referenced");
            KCHK(U(WSAGetLastError)() == 0, "WSACleanup leaves error 0");
        }
    }
    KCHK(d.lpVendorInfo == (char *)&g_bad, "lpVendorInfo untouched");
    KCHK(d.wHighVersion == 0x202, "wHighVersion");
    KCHK(!strcmp(d.szDescription, "WinSock 2.0"), "szDescription");
    KCHK(!strcmp(d.szSystemStatus, "Running"), "szSystemStatus");
    KCHK(d.iMaxSockets == (LOBYTE(ask) == 1 ? 32767 : 0), "iMaxSockets");
    KCHK(d.iMaxUdpDg == (LOBYTE(ask) == 1 ? 65467 : 0), "iMaxUdpDg");

    /* every reference is gone: one more cleanup is an error */
    U(WSASetLastError)(0x1234);
    KCHK(U(WSACleanup)() == SOCKET_ERROR, "WSACleanup with no reference");
    KCHK(U(WSAGetLastError)() == WSANOTINITIALISED, "WSANOTINITIALISED");

    /* a NULL WSADATA is rejected after the version check */
    r = U(WSAStartup)(ask, NULL);
    KCHK(r == (LOBYTE(ask) ? WSAEFAULT : WSAVERNOTSUPPORTED), "WSAStartup(NULL data)");
    return g_bad;
}

#define STARTUP_ROW(n) TEST(startup_version_row_##n) { REQUIRE(U(WSAStartup)); EXPECT_EQ(t_run_child("startup_row", #n, 20000), 0); }
STARTUP_ROW(0) STARTUP_ROW(1) STARTUP_ROW(2) STARTUP_ROW(3) STARTUP_ROW(4) STARTUP_ROW(5) STARTUP_ROW(6)
STARTUP_ROW(7) STARTUP_ROW(8) STARTUP_ROW(9) STARTUP_ROW(10) STARTUP_ROW(11) STARTUP_ROW(12)

/* ---- WSAProviderConfigChange + SIO_ADDRESS_LIST_CHANGE ---------------------------------------------- */
#ifndef SIO_ADDRESS_LIST_CHANGE
#define SIO_ADDRESS_LIST_CHANGE _WSAIO(IOC_WS2, 23)
#endif

/* A NULL-initialised notification handle request succeeds and produces a handle that can be bound to a
 * completion port together with an overlapped socket; the overlapped address-list-change ioctl then stays
 * pending (SOCKET_ERROR / WSA_IO_PENDING). */
TEST(startup_provider_config_change_and_addr_list_change)
{
    REQUIRE(U(WSAProviderConfigChange)); REQUIRE(U(WSASocketW)); REQUIRE(U(WSAIoctl)); REQUIRE(U(closesocket));
    if (l3_up()) { t_skip("WSAStartup failed"); return; }
    HANDLE change = 0;
    CHECK(U(WSAProviderConfigChange)(&change, NULL, NULL) != SOCKET_ERROR);
    HANDLE port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0);
    CHECK(port != NULL);
    SOCKET s = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    CHECK(s != INVALID_SOCKET);
    if (port && s != INVALID_SOCKET) {
        HANDLE p2 = CreateIoCompletionPort((HANDLE)s, port, 123, 0);
        CHECK(p2 == port);
        if (change) {
            p2 = CreateIoCompletionPort(change, port, 456, 0);
            CHECK(p2 == port);
        }
        static OVERLAPPED ov;
        memset(&ov, 0, sizeof ov);
        DWORD bytes = 0;
        U(WSASetLastError)(0);
        int r = U(WSAIoctl)(s, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &bytes, (LPWSAOVERLAPPED)&ov, NULL);
        EXPECT_EQ(r, SOCKET_ERROR);
        EXPECT_EQ(WSERR(), WSA_IO_PENDING);
        U(closesocket)(s);
        s = INVALID_SOCKET;
        /* closing cancels the pending request; drain its packet so the OVERLAPPED is idle before it goes away */
        DWORD n; ULONG_PTR key; LPOVERLAPPED pov;
        GetQueuedCompletionStatus(port, &n, &key, &pov, 3000);
    }
    if (s != INVALID_SOCKET) U(closesocket)(s);
    if (port) CloseHandle(port);
    if (change) CloseHandle(change);
    l3_down();
}
