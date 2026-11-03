/* The proxy-service pair of mswsock.dll (StartWsdpService / StopWsdpService), kept apart from the stateless
 * areas because the pair registers and releases a per-process provider-change watch and an extra stack reference.
 * Nothing persistent on the machine is written, and no catalog entry is installed or removed; the work is
 * limited to the calling process. Skipped unless the process runs elevated.
 *
 * Measures: the stop call is safe with nothing started, repeatable and leaves the stack usable; a start call
 * with no matching proxy provider installed completes without crashing and leaves the stack usable, and a stop
 * call afterwards releases whatever the start took; sockets keep working across the sequence. The return value of the
 * start call is recorded as an observation only (its meaning depends on whether a proxy provider is present). */
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

#define N(a) (sizeof(a) / sizeof((a)[0]))

static int elevated(void)
{
    HANDLE tok; TOKEN_ELEVATION te; DWORD n = 0; int r = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &te, sizeof te, &n)) r = te.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}
static int stack_up(void)
{
    static int st;
    if (!st) {
        WSADATA d; typedef int (WSAAPI *su_fn)(WORD, LPWSADATA);
        su_fn f = (su_fn)t_proc_in("ws2_32.dll", "WSAStartup");
        st = (f && f(0x202, &d) == 0) ? 1 : -1;
    }
    return st > 0;
}
/* A loopback datagram round trip proves the stack is functional. */
static int stack_works(void)
{
    typedef SOCKET (WSAAPI *so_fn)(int, int, int); typedef int (WSAAPI *cl_fn)(SOCKET);
    typedef int (WSAAPI *bind_fn)(SOCKET, const struct sockaddr *, int);
    typedef int (WSAAPI *gsn_fn)(SOCKET, struct sockaddr *, int *);
    typedef int (WSAAPI *snd_fn)(SOCKET, const char *, int, int, const struct sockaddr *, int);
    typedef int (WSAAPI *rcv_fn)(SOCKET, char *, int, int);
    typedef int (WSAAPI *sopt_fn)(SOCKET, int, int, const char *, int);
    so_fn so = (so_fn)t_proc_in("ws2_32.dll", "socket"); cl_fn cl = (cl_fn)t_proc_in("ws2_32.dll", "closesocket");
    bind_fn bd = (bind_fn)t_proc_in("ws2_32.dll", "bind"); gsn_fn gsn = (gsn_fn)t_proc_in("ws2_32.dll", "getsockname");
    snd_fn sn = (snd_fn)t_proc_in("ws2_32.dll", "sendto"); rcv_fn rc = (rcv_fn)t_proc_in("ws2_32.dll", "recv");
    sopt_fn so_opt = (sopt_fn)t_proc_in("ws2_32.dll", "setsockopt");
    struct sockaddr_in a; int l = sizeof a, ok = 0; SOCKET s; char b[4] = { 0 }; DWORD tmo = 3000;
    if (!so || !cl || !bd || !gsn || !sn || !rc || !so_opt) return 0;
    s = so(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) return 0;
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = 0x0100007Fu;
    so_opt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, sizeof tmo);
    if (bd(s, (struct sockaddr *)&a, sizeof a) == 0 && gsn(s, (struct sockaddr *)&a, &l) == 0 &&
        sn(s, "ping", 4, 0, (struct sockaddr *)&a, sizeof a) == 4 && rc(s, b, 4, 0) == 4 && !memcmp(b, "ping", 4)) ok = 1;
    cl(s);
    return ok;
}

typedef DWORD (WINAPI *start_fn)(void);
typedef void (WINAPI *stop_fn)(void);

TEST(gap4dx_stop_with_nothing_started_is_harmless)
{
    stop_fn stop = (stop_fn)t_proc_in("mswsock.dll", "StopWsdpService");
    REQUIRE(stop);
    if (!elevated()) { t_skip("not elevated"); return; }
    if (!stack_up()) { t_skip("stack did not start"); return; }
    stop();
    CHECK(stack_works());
}
TEST(gap4dx_stop_is_repeatable)
{
    stop_fn stop = (stop_fn)t_proc_in("mswsock.dll", "StopWsdpService");
    int i;
    REQUIRE(stop);
    if (!elevated()) { t_skip("not elevated"); return; }
    if (!stack_up()) { t_skip("stack did not start"); return; }
    for (i = 0; i < 4; i++) stop();
    CHECK(stack_works());
}
TEST(gap4dx_start_then_stop_leaves_the_stack_usable)
{
    start_fn start = (start_fn)t_proc_in("mswsock.dll", "StartWsdpService");
    stop_fn stop = (stop_fn)t_proc_in("mswsock.dll", "StopWsdpService");
    DWORD rc;
    REQUIRE(start); REQUIRE(stop);
    if (!elevated()) { t_skip("not elevated"); return; }
    if (!stack_up()) { t_skip("stack did not start"); return; }
    rc = start();
    t_note("start returned %s", rc == 0 ? "zero" : "non-zero");
    CHECK(stack_works());
    stop();
    CHECK(stack_works());
}
TEST(gap4dx_start_stop_cycles)
{
    start_fn start = (start_fn)t_proc_in("mswsock.dll", "StartWsdpService");
    stop_fn stop = (stop_fn)t_proc_in("mswsock.dll", "StopWsdpService");
    int i;
    REQUIRE(start); REQUIRE(stop);
    if (!elevated()) { t_skip("not elevated"); return; }
    if (!stack_up()) { t_skip("stack did not start"); return; }
    for (i = 0; i < 3; i++) { start(); stop(); }
    CHECK(stack_works());
}
TEST(gap4dx_start_twice_then_stop)
{
    start_fn start = (start_fn)t_proc_in("mswsock.dll", "StartWsdpService");
    stop_fn stop = (stop_fn)t_proc_in("mswsock.dll", "StopWsdpService");
    REQUIRE(start); REQUIRE(stop);
    if (!elevated()) { t_skip("not elevated"); return; }
    if (!stack_up()) { t_skip("stack did not start"); return; }
    start(); start();
    stop();
    CHECK(stack_works());
}
