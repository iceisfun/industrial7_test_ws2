/* Which exports need a started stack, and what they report when it is not there.
 *
 * Each row is one export called with well-formed arguments, in a fresh child process, in three phases:
 *   1. before any WSAStartup           -> expected error `pre`  (WSANOTINITIALISED for nearly everything,
 *                                         but a few functions validate their arguments first, and a few
 *                                         never need the stack at all)
 *   2. after WSAStartup(2.2)           -> expected error `post` (0 = only "not WSANOTINITIALISED")
 *   3. after the matching WSACleanup   -> the phase-1 answer again
 * A row function returns the last-error value observed after the call failed, or OKV when the call
 * succeeded (or, for rows that cannot fail that way, when the call behaved as specified). */
#include "sc.h"
#include <ws2spi.h>

#define OKV  0xFFFFFFFFu        /* the call did not fail */
#define ANY  0xFFFFFFFEu        /* any error except WSANOTINITIALISED */
#define NOPOST 0xFFFFFFFDu      /* the started phase is not run (the argument would be dereferenced as a handle) */

typedef DWORD (*row_fn)(void);
typedef struct { const char *name; row_fn fn; DWORD pre, post; } row_t;

static struct sockaddr_in g_sa;
static void init_sa(void)
{
    memset(&g_sa, 0, sizeof g_sa);
    g_sa.sin_family = AF_INET;
    g_sa.sin_addr.s_addr = 0x0100007fu;   /* 127.0.0.1 in network order */
}

/* Reset last error, evaluate, and report: failure sentinel -> error code, else OKV. */
#define FAILS(NAME, SENT, ...) \
    static DWORD r_##NAME(void) { init_sa(); U(WSASetLastError)(0); \
        return ((__VA_ARGS__) == (SENT)) ? (DWORD)U(WSAGetLastError)() : OKV; }
/* Functions that return the error code itself. */
#define RETERR(NAME, ...) \
    static DWORD r_##NAME(void) { init_sa(); U(WSASetLastError)(0); int e_ = (__VA_ARGS__); return e_ ? (DWORD)e_ : OKV; }

#define B SC_BOGUS_SOCKET
static char g_buf[16];
static int g_len;
static WSABUF g_wb = { 1, g_buf };
static DWORD g_n, g_fl;
static OVERLAPPED g_ov;
static WSANETWORKEVENTS g_ne;
static WSAPROTOCOL_INFOW g_pi;
static WSAPROTOCOL_INFOA g_pia;
static u_long g_u;
static fd_set g_fds;
static struct timeval g_tv0;
#define SA ((struct sockaddr *)&g_sa)

FAILS(bind,        SOCKET_ERROR, U(bind)(B, SA, sizeof g_sa))
FAILS(connect,     SOCKET_ERROR, U(connect)(B, SA, sizeof g_sa))
FAILS(listen,      SOCKET_ERROR, U(listen)(B, 1))
FAILS(getsockname, SOCKET_ERROR, (g_len = sizeof g_sa, U(getsockname)(B, SA, &g_len)))
FAILS(getpeername, SOCKET_ERROR, (g_len = sizeof g_sa, U(getpeername)(B, SA, &g_len)))
FAILS(shutdown,    SOCKET_ERROR, U(shutdown)(B, SD_BOTH))
FAILS(accept,      INVALID_SOCKET, U(accept)(B, NULL, NULL))
FAILS(WSAAccept,   INVALID_SOCKET, U(WSAAccept)(B, NULL, NULL, NULL, 0))
FAILS(recv,        SOCKET_ERROR, U(recv)(B, g_buf, 1, 0))
FAILS(send,        SOCKET_ERROR, U(send)(B, g_buf, 1, 0))
FAILS(recvfrom,    SOCKET_ERROR, (g_len = sizeof g_sa, U(recvfrom)(B, g_buf, 1, 0, SA, &g_len)))
FAILS(sendto,      SOCKET_ERROR, U(sendto)(B, g_buf, 1, 0, SA, sizeof g_sa))
FAILS(getsockopt,  SOCKET_ERROR, (g_len = 4, U(getsockopt)(B, SOL_SOCKET, SO_TYPE, (char *)&g_u, &g_len)))
FAILS(setsockopt,  SOCKET_ERROR, (g_u = 1, U(setsockopt)(B, SOL_SOCKET, SO_REUSEADDR, (char *)&g_u, 4)))
FAILS(ioctlsocket, SOCKET_ERROR, (g_u = 1, U(ioctlsocket)(B, FIONBIO, &g_u)))
FAILS(closesocket, SOCKET_ERROR, U(closesocket)(B))
FAILS(WSAIoctl,    SOCKET_ERROR, (g_u = 1, U(WSAIoctl)(B, FIONBIO, &g_u, 4, NULL, 0, &g_n, NULL, NULL)))
FAILS(WSARecv,     SOCKET_ERROR, (g_fl = 0, U(WSARecv)(B, &g_wb, 1, &g_n, &g_fl, NULL, NULL)))
FAILS(WSASend,     SOCKET_ERROR, U(WSASend)(B, &g_wb, 1, &g_n, 0, NULL, NULL))
FAILS(WSARecvFrom, SOCKET_ERROR, (g_fl = 0, g_len = sizeof g_sa, U(WSARecvFrom)(B, &g_wb, 1, &g_n, &g_fl, SA, &g_len, NULL, NULL)))
FAILS(WSASendTo,   SOCKET_ERROR, U(WSASendTo)(B, &g_wb, 1, &g_n, 0, SA, sizeof g_sa, NULL, NULL))
FAILS(WSAConnect,  SOCKET_ERROR, U(WSAConnect)(B, SA, sizeof g_sa, NULL, NULL, NULL, NULL))
FAILS(WSAEnumNetworkEvents, SOCKET_ERROR, U(WSAEnumNetworkEvents)(B, NULL, &g_ne))
FAILS(WSAGetOverlappedResult, FALSE, (memset(&g_ov, 0, sizeof g_ov), U(WSAGetOverlappedResult)(B, &g_ov, &g_n, FALSE, &g_fl)))
FAILS(WSADuplicateSocketW, SOCKET_ERROR, U(WSADuplicateSocketW)(B, GetCurrentProcessId(), &g_pi))
FAILS(WSADuplicateSocketA, SOCKET_ERROR, U(WSADuplicateSocketA)(B, GetCurrentProcessId(), &g_pia))
FAILS(WSASendDisconnect, SOCKET_ERROR, U(WSASendDisconnect)(B, NULL))
FAILS(WSARecvDisconnect, SOCKET_ERROR, U(WSARecvDisconnect)(B, NULL))
static int sel_bogus(void) { g_fds.fd_count = 1; g_fds.fd_array[0] = B; g_tv0.tv_sec = 0; g_tv0.tv_usec = 0; return U(select)(0, &g_fds, NULL, NULL, &g_tv0); }
FAILS(select,      SOCKET_ERROR, sel_bogus())
FAILS(WSAHtonl,    SOCKET_ERROR, U(WSAHtonl)(B, 1, (u_long *)&g_n))
FAILS(WSAHtons,    SOCKET_ERROR, U(WSAHtons)(B, 1, (u_short *)&g_n))
FAILS(WSANtohl,    SOCKET_ERROR, U(WSANtohl)(B, 1, (u_long *)&g_n))
FAILS(WSANtohs,    SOCKET_ERROR, U(WSANtohs)(B, 1, (u_short *)&g_n))
/* the output pointer is checked before the socket is looked up, so with NULL the answer is WSAEINVAL after startup */
FAILS(WSAHtonl_null, SOCKET_ERROR, U(WSAHtonl)(B, 1, NULL))
FAILS(WSANtohs_null, SOCKET_ERROR, U(WSANtohs)(B, 1, NULL))

static DWORD r_socket(void)
{
    U(WSASetLastError)(0);
    SOCKET s = U(socket)(AF_INET, SOCK_STREAM, 0);
    if (s != INVALID_SOCKET) { U(closesocket)(s); return OKV; }
    return (DWORD)U(WSAGetLastError)();
}
static DWORD r_WSASocketW(void)
{
    U(WSASetLastError)(0);
    SOCKET s = U(WSASocketW)(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, 0);
    if (s != INVALID_SOCKET) { U(closesocket)(s); return OKV; }
    return (DWORD)U(WSAGetLastError)();
}
static DWORD r_WSASocketA(void)
{
    U(WSASetLastError)(0);
    SOCKET s = U(WSASocketA)(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, 0);
    if (s != INVALID_SOCKET) { U(closesocket)(s); return OKV; }
    return (DWORD)U(WSAGetLastError)();
}
static char g_host[512];
FAILS(gethostname, SOCKET_ERROR, U(gethostname)(g_host, sizeof g_host))
FAILS(gethostbyname, NULL, U(gethostbyname)("localhost"))
static DWORD r_gethostbyaddr(void)
{
    static const char a[4] = { 127, 0, 0, 1 };
    U(WSASetLastError)(0);
    return U(gethostbyaddr)(a, 4, AF_INET) == NULL ? (DWORD)U(WSAGetLastError)() : OKV;
}
FAILS(getprotobyname, NULL, U(getprotobyname)("tcp"))
FAILS(getprotobynumber, NULL, U(getprotobynumber)(6))
FAILS(getservbyname, NULL, U(getservbyname)("http", "tcp"))
FAILS(getservbyport, NULL, U(getservbyport)(0x5000, "tcp"))
static DWORD r_getaddrinfo(void)
{
    ADDRINFOA *res = NULL, hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_flags = AI_NUMERICHOST;
    int e = U(getaddrinfo)("127.0.0.1", NULL, &hints, &res);
    if (e == 0 && res) U(freeaddrinfo)(res);
    return e ? (DWORD)e : OKV;
}
static DWORD r_GetAddrInfoW(void)
{
    ADDRINFOW *res = NULL, hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_flags = AI_NUMERICHOST;
    int e = U(GetAddrInfoW)(L"127.0.0.1", NULL, &hints, &res);
    if (e == 0 && res) U(FreeAddrInfoW)(res);
    return e ? (DWORD)e : OKV;
}
static DWORD r_getnameinfo(void)
{
    char host[64];
    init_sa();
    int e = U(getnameinfo)(SA, sizeof g_sa, host, sizeof host, NULL, 0, NI_NUMERICHOST);
    return e ? (DWORD)e : OKV;
}
static DWORD r_GetNameInfoW(void)
{
    WCHAR host[64];
    init_sa();
    int e = U(GetNameInfoW)(SA, sizeof g_sa, host, 64, NULL, 0, NI_NUMERICHOST);
    return e ? (DWORD)e : OKV;
}
FAILS(WSAEnumProtocolsW, SOCKET_ERROR, (g_n = 0, U(WSAEnumProtocolsW)(NULL, NULL, &g_n)))
FAILS(WSAEnumProtocolsA, SOCKET_ERROR, (g_n = 0, U(WSAEnumProtocolsA)(NULL, NULL, &g_n)))
FAILS(WSAEnumNameSpaceProvidersW, SOCKET_ERROR, (g_n = 0, U(WSAEnumNameSpaceProvidersW)(&g_n, NULL)))
FAILS(WSAEnumNameSpaceProvidersExW, SOCKET_ERROR, (g_n = 0, U(WSAEnumNameSpaceProvidersExW)(&g_n, NULL)))
FAILS(WSAAddressToStringW, SOCKET_ERROR, (g_n = 0, U(WSAAddressToStringW)(NULL, 0, NULL, NULL, &g_n)))
FAILS(WSAAddressToStringA, SOCKET_ERROR, (g_n = 0, U(WSAAddressToStringA)(NULL, 0, NULL, NULL, &g_n)))
FAILS(WSAStringToAddressW, SOCKET_ERROR, (g_len = sizeof g_sa, U(WSAStringToAddressW)((LPWSTR)L"127.0.0.1", AF_INET, NULL, SA, &g_len)))
FAILS(WSAStringToAddressA, SOCKET_ERROR, (g_len = sizeof g_sa, U(WSAStringToAddressA)((LPSTR)"127.0.0.1", AF_INET, NULL, SA, &g_len)))
FAILS(WSALookupServiceEnd, SOCKET_ERROR, U(WSALookupServiceEnd)((HANDLE)B))
FAILS(WSALookupServiceNextW, SOCKET_ERROR, (g_n = 0, U(WSALookupServiceNextW)((HANDLE)B, 0, &g_n, NULL)))
FAILS(WSACancelAsyncRequest, SOCKET_ERROR, U(WSACancelAsyncRequest)((HANDLE)0x1234))
FAILS(WSAInstallServiceClassW, SOCKET_ERROR, U(WSAInstallServiceClassW)(NULL))
FAILS(WSARemoveServiceClass, SOCKET_ERROR, U(WSARemoveServiceClass)(NULL))
/* argument validation runs BEFORE the stack check in these two */
FAILS(WSAGetServiceClassInfoW, SOCKET_ERROR, U(WSAGetServiceClassInfoW)(NULL, NULL, NULL, NULL))
FAILS(WSASetServiceW, SOCKET_ERROR, U(WSASetServiceW)(NULL, RNRSERVICE_DEREGISTER, 0))

FAILS(WSAEventSelect, SOCKET_ERROR, U(WSAEventSelect)(B, NULL, 0))
FAILS(WSAAsyncSelect, SOCKET_ERROR, U(WSAAsyncSelect)(B, NULL, 0, 0))
FAILS(WSAPoll, SOCKET_ERROR, U(WSAPoll)(NULL, 0, 0))
static WSAMSG g_msg;
FAILS(WSASendMsg, SOCKET_ERROR, (memset(&g_msg, 0, sizeof g_msg), U(WSASendMsg)(B, &g_msg, 0, &g_n, NULL, NULL)))

/* ---- functions that work with no stack at all ------------------------------------------------------------- */
static DWORD r_WSACreateEvent(void)
{
    WSAEVENT e = U(WSACreateEvent)();
    if (e == WSA_INVALID_EVENT) return GetLastError() ? GetLastError() : 1;
    int ok = U(WSACloseEvent)(e);
    return ok ? OKV : 1;
}
static DWORD r_event_cycle(void)
{
    WSAEVENT e = U(WSACreateEvent)();
    if (e == WSA_INVALID_EVENT) return 1;
    DWORD res = OKV;
    if (U(WSAWaitForMultipleEvents)(1, &e, FALSE, 0, FALSE) != WSA_WAIT_TIMEOUT) res = 2;
    else if (!U(WSASetEvent)(e)) res = 3;
    else if (U(WSAWaitForMultipleEvents)(1, &e, FALSE, 0, FALSE) != WSA_WAIT_EVENT_0) res = 4;
    else if (!U(WSAResetEvent)(e)) res = 5;
    else if (U(WSAWaitForMultipleEvents)(1, &e, FALSE, 0, FALSE) != WSA_WAIT_TIMEOUT) res = 6;
    U(WSACloseEvent)(e);
    return res;
}
static DWORD r_byteorder(void)
{
    return (U(htons)(0x1234) == 0x3412 && U(htonl)(0x11223344) == 0x44332211u && U(ntohs)(0x1234) == 0x3412 &&
            U(ntohl)(0x11223344) == 0x44332211u) ? OKV : 1;
}
static DWORD r_fdisset(void)
{
    fd_set s;
    FD_ZERO(&s); s.fd_count = 2; s.fd_array[0] = 5; s.fd_array[1] = 9;
    return (U(__WSAFDIsSet)(9, &s) && !U(__WSAFDIsSet)(7, &s)) ? OKV : 1;
}
static DWORD r_inet_addr(void)
{
    return (U(inet_addr)("127.0.0.1") == 0x0100007fu && U(inet_addr)("1.2.3.256") == INADDR_NONE) ? OKV : 1;
}
static DWORD r_inet_pton(void)
{
    struct in_addr a;
    a.s_addr = 0;
    return (U(inet_pton)(AF_INET, "10.1.2.3", &a) == 1 && a.s_addr == 0x0302010au) ? OKV : 1;
}
static DWORD r_inet_ntop(void)
{
    struct in_addr a;
    char b[32];
    a.s_addr = 0x0302010au;
    return (U(inet_ntop)(AF_INET, &a, b, sizeof b) && !strcmp(b, "10.1.2.3")) ? OKV : 1;
}
static DWORD r_lasterror_pair(void)
{
    U(WSASetLastError)(4321);
    return (U(WSAGetLastError)() == 4321 && GetLastError() == 4321) ? OKV : 1;
}
static DWORD r_isblocking(void)
{
    /* never an error: reports FALSE and leaves the thread's error alone */
    U(WSASetLastError)(0x1234);
    BOOL b = U(WSAIsBlocking)();
    return b == FALSE ? OKV : 1;   /* whether the slot is preserved is not asserted */
}
static DWORD r_wscenum_probe(void)
{
    int err = 0;
    DWORD len = 0;
    int r = U(WSCEnumProtocols)(NULL, NULL, &len, &err);
    return (r == SOCKET_ERROR && err == WSAENOBUFS && len > 0) ? OKV : 1;
}

#define ROW(n, pre, post) { #n, r_##n, pre, post }
static const row_t kRows[] = {
    /* socket-handle functions: a bogus socket after startup is WSAENOTSOCK */
    ROW(bind, 10093, 10038), ROW(connect, 10093, 10038), ROW(listen, 10093, 10038), ROW(getsockname, 10093, 10038),
    ROW(getpeername, 10093, 10038), ROW(shutdown, 10093, 10038), ROW(accept, 10093, 10038), ROW(WSAAccept, 10093, 10038),
    ROW(recv, 10093, 10038), ROW(send, 10093, 10038), ROW(recvfrom, 10093, 10038), ROW(sendto, 10093, 10038),
    ROW(getsockopt, 10093, 10038), ROW(setsockopt, 10093, 10038), ROW(ioctlsocket, 10093, 10038), ROW(closesocket, 10093, 10038),
    ROW(WSAIoctl, 10093, 10038), ROW(WSARecv, 10093, 10038), ROW(WSASend, 10093, 10038), ROW(WSARecvFrom, 10093, 10038),
    ROW(WSASendTo, 10093, 10038), ROW(WSAConnect, 10093, 10038), ROW(WSAEnumNetworkEvents, 10093, 10038),
    ROW(WSAGetOverlappedResult, 10093, 10038), ROW(WSADuplicateSocketW, 10093, 10038), ROW(WSADuplicateSocketA, 10093, 10038),
    ROW(WSASendDisconnect, 10093, 10038), ROW(WSARecvDisconnect, 10093, 10038), ROW(select, 10093, 10038),
    ROW(WSAHtonl, 10093, 10038), ROW(WSAHtons, 10093, 10038), ROW(WSANtohl, 10093, 10038), ROW(WSANtohs, 10093, 10038),
    ROW(WSAHtonl_null, 10093, 10014), ROW(WSANtohs_null, 10093, 10014),
    ROW(WSAEventSelect, 10093, ANY), ROW(WSAAsyncSelect, 10093, ANY), ROW(WSAPoll, 10093, ANY), ROW(WSASendMsg, 10093, ANY),
    /* creators and resolvers: they succeed once the stack is up */
    ROW(socket, 10093, OKV), ROW(WSASocketW, 10093, OKV), ROW(WSASocketA, 10093, OKV), ROW(gethostname, 10093, OKV),
    ROW(gethostbyname, 10093, ANY), ROW(gethostbyaddr, 10093, ANY), ROW(getprotobyname, 10093, ANY),
    ROW(getprotobynumber, 10093, ANY), ROW(getservbyname, 10093, ANY), ROW(getservbyport, 10093, ANY),
    ROW(getaddrinfo, 10093, OKV), ROW(GetAddrInfoW, 10093, OKV), ROW(getnameinfo, 10093, OKV), ROW(GetNameInfoW, 10093, OKV),
    ROW(WSAEnumProtocolsW, 10093, 10055), ROW(WSAEnumProtocolsA, 10093, 10055),
    ROW(WSAEnumNameSpaceProvidersW, 10093, ANY), ROW(WSAEnumNameSpaceProvidersExW, 10093, ANY),
    ROW(WSAAddressToStringW, 10093, 10022), ROW(WSAAddressToStringA, 10093, 10022),
    ROW(WSAStringToAddressW, 10093, OKV), ROW(WSAStringToAddressA, 10093, OKV),
    ROW(WSALookupServiceEnd, 10093, NOPOST), ROW(WSALookupServiceNextW, 10093, NOPOST), ROW(WSACancelAsyncRequest, 10093, ANY),
    ROW(WSAInstallServiceClassW, 10093, 10022), ROW(WSARemoveServiceClass, 10093, 10022),
    /* validated before the stack check: the same answer in every phase */
    ROW(WSAGetServiceClassInfoW, 10022, 10022), ROW(WSASetServiceW, 10014, 10014),
    /* never need the stack */
    ROW(WSACreateEvent, OKV, OKV), ROW(event_cycle, OKV, OKV), ROW(byteorder, OKV, OKV), ROW(fdisset, OKV, OKV),
    ROW(inet_addr, OKV, OKV), ROW(inet_pton, OKV, OKV), ROW(inet_ntop, OKV, OKV), ROW(lasterror_pair, OKV, OKV),
    ROW(isblocking, OKV, OKV), ROW(wscenum_probe, OKV, OKV),
};
#define NROWS ((int)ARRSZ(kRows))

/* argv[1] = row index */
CHILD(api_row)
{
    int i = argc > 1 ? atoi(argv[1]) : 0;
    if (i < 0 || i >= NROWS) return 99;
    const row_t *r = &kRows[i];
    DWORD v;
    STEP(90, U(WSAStartup) && U(WSACleanup) && U(WSAGetLastError) && U(WSASetLastError));

    v = r->fn();
    STEP(1, v == r->pre);
    if (r->pre != OKV) { SETWSAERR(0); STEP(2, U(WSACleanup)() == SOCKET_ERROR); STEP(3, WSAERR() == WSANOTINITIALISED); }

    if (r->post == NOPOST) return 0;
    STEP(4, sc_up() == 0);
    v = r->fn();
    if (r->post == ANY) { STEP(5, v != WSANOTINITIALISED); }
    else if (r->post == 10055 && v == OKV) { /* a zero-length probe may also be accepted; not an error here */ }
    else STEP(6, v == r->post);
    STEP(7, U(WSACleanup)() == 0);

    v = r->fn();
    STEP(8, v == r->pre);           /* the stack is gone again */
    return 0;
}

#define AR(n) TEST(startup_api_table_row_##n) { REQUIRE(U(WSAStartup)); \
    DWORD rc_ = t_run_child("api_row", #n, 30000); \
    CHECKF(rc_ == 0, "row %d (%s) failed at step %lu", n, n < NROWS ? kRows[n].name : "?", rc_); }
AR(0) AR(1) AR(2) AR(3) AR(4) AR(5) AR(6) AR(7) AR(8) AR(9) 
AR(10) AR(11) AR(12) AR(13) AR(14) AR(15) AR(16) AR(17) AR(18) AR(19) 
AR(20) AR(21) AR(22) AR(23) AR(24) AR(25) AR(26) AR(27) AR(28) AR(29) 
AR(30) AR(31) AR(32) AR(33) AR(34) AR(35) AR(36) AR(37) AR(38) AR(39) 
AR(40) AR(41) AR(42) AR(43) AR(44) AR(45) AR(46) AR(47) AR(48) AR(49) 
AR(50) AR(51) AR(52) AR(53) AR(54) AR(55) AR(56) AR(57) AR(58) AR(59) 
AR(60) AR(61) AR(62) AR(63) AR(64) AR(65) AR(66) AR(67) AR(68) AR(69) 
AR(70) AR(71) AR(72) AR(73) AR(74) AR(75) AR(76) AR(77)

TEST(startup_api_table_covers_every_row)
{
    /* the generated tests above are named by index; keep the table and the generated range in step */
    CHECKF(NROWS == 78, "table has %d rows but 78 row tests exist", NROWS);
}
