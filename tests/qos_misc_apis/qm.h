/* Shared helpers for the qos_misc_apis area: the leftover ws2_32 surface (event objects, joins, QoS,
 * provider advertisement, catalog writers, the handle-context helpers exported from the same DLL).
 * The DLL under test is never linked; every service is reached through U()/UN() pointers.
 *
 * Process-wide startup state is part of what several of these tests observe, so scenarios that need a
 * pristine process run in a child (exe --child <name>); a child returns 0 or the number of the first
 * failing step, and the parent reports it. */
#ifndef QM_H
#define QM_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2spi.h>
#include <stdlib.h>

/* The harness macro evaluates its arguments twice (once to compare, once to print), which repeats any call
 * with side effects; this area passes calls straight into it, so it gets a single-evaluation version. */
#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { unsigned long long ea_ = (unsigned long long)(ULONG_PTR)(a), eb_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(ea_ == eb_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", ea_, eb_); } while (0)

#define QM_N(a) ((int)(sizeof(a) / sizeof((a)[0])))
#define STEP(n, c) do { if (!(c)) return (n); } while (0)

/* Parent side: run child `name` with extra args, expect exit code 0. */
#define RUN_CHILD(name, args, ms) do { \
    DWORD rc_ = t_run_child((name), (args), (ms)); \
    t_check(rc_ == 0, __FILE__, __LINE__, "child " name " " args, "exit/step %lu", rc_); } while (0)

#define WSAERR()     ((int)U(WSAGetLastError)())
#define SETWSAERR(e) U(WSASetLastError)((e))

/* A socket value that is neither a live socket nor a live handle of this process. */
#define QM_BOGUS_SOCKET ((SOCKET)0x6FFFC)

/* WSAStartup(2.2) in the calling process; returns 0 on success. Never torn down by the helpers. */
static inline int qm_up(void) { WSADATA d; return U(WSAStartup)(MAKEWORD(2, 2), &d); }
#define QM_NEED_WSA() do { if (qm_up() != 0) { t_skip("WSAStartup failed"); return; } } while (0)

/* True when the process token is an elevated administrator token (or UAC is off for an admin). */
static inline int qm_elevated(void)
{
    HANDLE tok = NULL; TOKEN_ELEVATION el; DWORD n = 0; int r = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &n)) r = el.TokenIsElevated != 0;
    CloseHandle(tok);
    return r;
}

/* A fresh TCP / UDP socket created through the DLL under test (INVALID_SOCKET on failure). */
static inline SOCKET qm_sock(int type)
{
    return U(socket)(AF_INET, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP);
}
static inline void qm_close(SOCKET s) { if (s != INVALID_SOCKET) U(closesocket)(s); }

/* Loopback address with an ephemeral port. */
static inline void qm_lo4(struct sockaddr_in *a)
{
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = U(inet_addr)("127.0.0.1");
}

/* Throwaway ids no catalog contains. */
static const GUID qm_guid_a = { 0x7c2e9a10, 0x41d3, 0x4b7e, { 0x9a, 0x01, 0xd0, 0x5e, 0x77, 0x31, 0xaa, 0x01 } };
static const GUID qm_guid_b = { 0x7c2e9a10, 0x41d3, 0x4b7e, { 0x9a, 0x01, 0xd0, 0x5e, 0x77, 0x31, 0xaa, 0x02 } };
static inline int qm_guid_eq(const GUID *a, const GUID *b) { return memcmp(a, b, sizeof(GUID)) == 0; }
#endif
