/* Shared helpers for the startup_cleanup area.
 *
 * Process-wide startup state is the thing under test, so almost every scenario runs in a child process
 * (exe --child <name> args). A child returns 0 on success, otherwise the number of the first failing
 * step; the parent reports it. Nothing here links the DLL under test. */
#ifndef SC_H
#define SC_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>

#define ARRSZ(a) (sizeof(a) / sizeof((a)[0]))
#define STEP(n, c) do { if (!(c)) return (n); } while (0)

#define WSAERR()      ((int)U(WSAGetLastError)())
#define SETWSAERR(e)  U(WSASetLastError)((e))

/* A socket handle value that is neither a live socket nor a live handle of this test process. */
#define SC_BOGUS_SOCKET ((SOCKET)0x6FFFC)

/* Parent side: run child `name` with extra args, expect exit code 0. */
#define RUN_CHILD(name, args, ms) do { \
    DWORD rc_ = t_run_child((name), (args), (ms)); \
    t_check(rc_ == 0, __FILE__, __LINE__, "child " name " " args, "exit/step %lu", rc_); } while (0)

/* Unverified or SKU-dependent observation: logged, never fails the step. */
#define SOFT(c, what) do { if (!(c)) t_note("differs from expectation: " what); } while (0)

/* Convenience: WSAStartup(2.2) in the child. */
static inline int sc_up(void) { WSADATA d; return U(WSAStartup)(MAKEWORD(2, 2), &d); }
#endif
