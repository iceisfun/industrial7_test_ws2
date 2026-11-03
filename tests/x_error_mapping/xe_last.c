/* x_error_mapping / the Winsock error slot: WSAGetLastError and WSASetLastError share storage with the thread's
 * Win32 last error, a failing Win32 call is visible through WSAGetLastError, successful Winsock calls leave the slot
 * alone (or not: one row per call records what happens), the slot is per thread, and calls made before WSAStartup
 * fail with the not-initialised error. */
#include "xe.h"

TEST(xelast_wsaget_equals_getlasterror) {
    int e; XE_UP();
    SetLastError(1234); e = WSAGetLastError(); CHECK(e == 1234);
    SetLastError(0); CHECK(WSAGetLastError() == 0);
    SetLastError(0xdeadbeef); CHECK((DWORD)WSAGetLastError() == 0xdeadbeef);
}
TEST(xelast_wsaset_visible_to_getlasterror) {
    XE_UP();
    WSASetLastError(10035); CHECK(GetLastError() == 10035);
    WSASetLastError(0); CHECK(GetLastError() == 0);
    WSASetLastError(-1); CHECK(GetLastError() == 0xffffffff);
    WSASetLastError(123456789); CHECK(GetLastError() == 123456789);
}
TEST(xelast_get_does_not_clear) {
    XE_UP();
    WSASetLastError(10061);
    CHECK(WSAGetLastError() == 10061); CHECK(WSAGetLastError() == 10061); CHECK(GetLastError() == 10061);
}
TEST(xelast_set_zero_clears_win32_error) {
    XE_UP();
    SetLastError(ERROR_ACCESS_DENIED); WSASetLastError(0); CHECK(GetLastError() == 0 && WSAGetLastError() == 0);
}
TEST(xelast_win32_failure_visible_through_wsa) {
    XE_UP();
    SetLastError(0); CHECK(!CloseHandle((HANDLE)(ULONG_PTR)0x7fff0)); CHECK(WSAGetLastError() == ERROR_INVALID_HANDLE);
    SetLastError(0); CHECK(WaitForSingleObject((HANDLE)(ULONG_PTR)0x7fff0, 0) == WAIT_FAILED); CHECK(WSAGetLastError() == ERROR_INVALID_HANDLE);
}
TEST(xelast_wsa_failure_visible_through_getlasterror) {
    XE_UP();
    SetLastError(0); CHECK(closesocket(INVALID_SOCKET) == SOCKET_ERROR);
    CHECK(GetLastError() == WSAENOTSOCK); CHECK(WSAGetLastError() == WSAENOTSOCK);
}
TEST(xelast_failure_replaces_previous_value) {
    XE_UP();
    WSASetLastError(10061); CHECK(closesocket(INVALID_SOCKET) == SOCKET_ERROR); CHECK(WSAGetLastError() == WSAENOTSOCK);
    CHECK(closesocket(INVALID_SOCKET) == SOCKET_ERROR); CHECK(WSAGetLastError() == WSAENOTSOCK);
}
TEST(xelast_successful_closesocket_clears_slot) {
    SOCKET s; int r; XE_UP();
    s = xe_sock(SOCK_STREAM); WSASetLastError(XE_BAD);
    CHECK(closesocket(s) == 0); r = WSAGetLastError(); CHECK(r == 0);
}

/* ---- successful calls versus the slot: report what each leaves behind ---- */
static int after_ok(int which) {
    SOCKET s = INVALID_SOCKET, c = INVALID_SOCKET, t = INVALID_SOCKET; struct sockaddr_in a, b; int n = sizeof a, v = 0, r = XE_BAD; u_long u = 0; char buf[8]; WSADATA d; WSAEVENT ev; fd_set f; DWORD dw;
    switch (which) {
    case 0: WSASetLastError(XE_BAD); s = xe_sock(SOCK_STREAM); r = WSAGetLastError(); xe_close(s); break;
    case 1: s = xe_sock(SOCK_STREAM); a = xe_lo(0); WSASetLastError(XE_BAD); bind(s, (struct sockaddr *)&a, sizeof a); r = WSAGetLastError(); xe_close(s); break;
    case 2: s = xe_sock(SOCK_STREAM); xe_bind_lo(s, NULL); WSASetLastError(XE_BAD); listen(s, 2); r = WSAGetLastError(); xe_close(s); break;
    case 3: s = xe_sock(SOCK_STREAM); xe_bind_lo(s, NULL); WSASetLastError(XE_BAD); getsockname(s, (struct sockaddr *)&b, &n); r = WSAGetLastError(); xe_close(s); break;
    case 4: s = xe_sock(SOCK_STREAM); WSASetLastError(XE_BAD); closesocket(s); r = WSAGetLastError(); break;
    case 5: xe_pair(&c, &t); WSASetLastError(XE_BAD); send(c, "x", 1, 0); r = WSAGetLastError(); xe_close(c); xe_close(t); break;
    case 6: xe_pair(&c, &t); send(t, "x", 1, 0); xe_wait_readable(c, 1000); WSASetLastError(XE_BAD); recv(c, buf, 8, 0); r = WSAGetLastError(); xe_close(c); xe_close(t); break;
    case 7: s = xe_sock(SOCK_STREAM); WSASetLastError(XE_BAD); ioctlsocket(s, FIONBIO, &u); r = WSAGetLastError(); xe_close(s); break;
    case 8: s = xe_sock(SOCK_STREAM); WSASetLastError(XE_BAD); setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&v, sizeof v); r = WSAGetLastError(); xe_close(s); break;
    case 9: s = xe_sock(SOCK_STREAM); n = sizeof v; WSASetLastError(XE_BAD); getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&v, &n); r = WSAGetLastError(); xe_close(s); break;
    case 10: { char hn[256]; WSASetLastError(XE_BAD); gethostname(hn, sizeof hn); } r = WSAGetLastError(); break;
    case 11: WSASetLastError(XE_BAD); ev = WSACreateEvent(); r = WSAGetLastError(); WSACloseEvent(ev); break;
    case 12: ev = WSACreateEvent(); WSASetLastError(XE_BAD); WSASetEvent(ev); r = WSAGetLastError(); WSACloseEvent(ev); break;
    case 13: ev = WSACreateEvent(); WSASetLastError(XE_BAD); WSACloseEvent(ev); r = WSAGetLastError(); break;
    case 14: s = xe_sock(SOCK_STREAM); FD_ZERO(&f); FD_SET(s, &f); WSASetLastError(XE_BAD); select(0, NULL, &f, NULL, &(struct timeval){0, 0}); r = WSAGetLastError(); xe_close(s); break;
    case 15: WSASetLastError(XE_BAD); WSAStartup(MAKEWORD(2, 2), &d); r = WSAGetLastError(); WSACleanup(); break;
    case 16: WSAStartup(MAKEWORD(2, 2), &d); WSASetLastError(XE_BAD); WSACleanup(); r = WSAGetLastError(); break;
    case 17: xe_pair(&c, &t); WSASetLastError(XE_BAD); shutdown(c, SD_SEND); r = WSAGetLastError(); xe_close(c); xe_close(t); break;
    case 18: WSASetLastError(XE_BAD); inet_addr("127.0.0.1"); r = WSAGetLastError(); break;
    case 19: WSASetLastError(XE_BAD); r = (int)U(htons)(1) ? WSAGetLastError() : 0; break;
    case 20: WSASetLastError(XE_BAD); { ADDRINFOA *res = NULL; getaddrinfo("127.0.0.1", "80", NULL, &res); if (res) freeaddrinfo(res); } r = WSAGetLastError(); break;
    case 21: WSASetLastError(XE_BAD); gethostbyname("localhost"); r = WSAGetLastError(); break;
    case 22: s = xe_sock(SOCK_STREAM); ev = WSACreateEvent(); WSASetLastError(XE_BAD); WSAEventSelect(s, ev, FD_READ); r = WSAGetLastError(); WSAEventSelect(s, NULL, 0); WSACloseEvent(ev); xe_close(s); break;
    case 23: WSASetLastError(XE_BAD); r = (WSAWaitForMultipleEvents(0, NULL, 0, 0, 0), WSAGetLastError()); break;
    case 24: { struct sockaddr_in la; s = xe_listener(&la); c = xe_sock(SOCK_STREAM); connect(c, (struct sockaddr *)&la, sizeof la); xe_wait_readable(s, 1000); WSASetLastError(XE_BAD); t = accept(s, NULL, NULL); r = WSAGetLastError(); xe_close(t); xe_close(c); xe_close(s); } break;
    case 25: { struct sockaddr_in la; s = xe_listener(&la); c = xe_sock(SOCK_STREAM); WSASetLastError(XE_BAD); connect(c, (struct sockaddr *)&la, sizeof la); r = WSAGetLastError(); xe_close(c); xe_close(s); } break;
    }
    (void)dw;
    return r;
}
#define ALAST(n, idx, W) TEST(xelast_after_ok_##n) { int r_; XE_UP(); r_ = after_ok(idx); if ((W) == XE_UNK) { t_note("ROW last %s %d", #n, r_); return; } CHECKF(r_ == (W), "got %d want %d", r_, (int)(W)); }
ALAST(socket, 0, 0) ALAST(bind, 1, 0) ALAST(listen, 2, 0) ALAST(getsockname, 3, 0) ALAST(closesocket, 4, 0) ALAST(send, 5, 0) ALAST(recv, 6, 0)
ALAST(ioctlsocket, 7, 0) ALAST(setsockopt, 8, 0) ALAST(getsockopt, 9, 0) ALAST(gethostname, 10, 0) ALAST(wsacreateevent, 11, 0) ALAST(wsasetevent, 12, 57005)
ALAST(wsacloseevent, 13, 57005) ALAST(select, 14, 0) ALAST(wsastartup, 15, 57005) ALAST(wsacleanup, 16, 0) ALAST(shutdown, 17, 0) ALAST(inet_addr, 18, 57005)
ALAST(htons, 19, 57005) ALAST(getaddrinfo, 20, 0) ALAST(gethostbyname, 21, 0) ALAST(wsaeventselect, 22, 0) ALAST(wsawait_failed, 23, 87) ALAST(accept, 24, 0) ALAST(connect, 25, 0)

/* ---- per thread ---- */
static DWORD WINAPI th_read_initial(LPVOID p) { *(int *)p = WSAGetLastError(); WSASetLastError(10054); return (DWORD)WSAGetLastError(); }
TEST(xelast_new_thread_does_not_inherit_slot) {
    int seen = -9; HANDLE h; XE_UP();
    WSASetLastError(10061); h = CreateThread(NULL, 0, th_read_initial, &seen, 0, NULL);
    WaitForSingleObject(h, 5000); CloseHandle(h);
    CHECK(seen != 10061); t_note("initial slot of a fresh thread is not inherited"); CHECK(WSAGetLastError() == 10061);
}
static DWORD WINAPI th_set(LPVOID p) { WSASetLastError((int)(ULONG_PTR)p); Sleep(10); return (DWORD)WSAGetLastError(); }
TEST(xelast_threads_do_not_share_slot) {
    HANDLE h[3]; DWORD rc; int i; XE_UP();
    WSASetLastError(10022);
    for (i = 0; i < 3; i++) h[i] = CreateThread(NULL, 0, th_set, (LPVOID)(ULONG_PTR)(10100 + i), 0, NULL);
    for (i = 0; i < 3; i++) { WaitForSingleObject(h[i], 5000); GetExitCodeThread(h[i], &rc); CHECK(rc == (DWORD)(10100 + i)); CloseHandle(h[i]); }
    CHECK(WSAGetLastError() == 10022);
}
static DWORD WINAPI th_fail(LPVOID p) { closesocket(INVALID_SOCKET); return (DWORD)WSAGetLastError(); }
TEST(xelast_failure_on_other_thread_is_local) {
    HANDLE h; DWORD rc = 0; XE_UP();
    WSASetLastError(0); h = CreateThread(NULL, 0, th_fail, NULL, 0, NULL);
    WaitForSingleObject(h, 5000); GetExitCodeThread(h, &rc); CloseHandle(h);
    CHECK(rc == WSAENOTSOCK); CHECK(WSAGetLastError() == 0);
}
static DWORD WINAPI th_getaddr(LPVOID p) { ADDRINFOA h, *res = NULL; memset(&h, 0, sizeof h); h.ai_family = 0x7ff0; *(int *)p = getaddrinfo("127.0.0.1", "80", &h, &res); return (DWORD)WSAGetLastError(); }
TEST(xelast_getaddrinfo_error_is_returned_and_left_in_slot) {
    HANDLE h; DWORD rc = 0; int ret = 0; XE_UP();
    h = CreateThread(NULL, 0, th_getaddr, &ret, 0, NULL); WaitForSingleObject(h, 5000); GetExitCodeThread(h, &rc); CloseHandle(h);
    CHECK(ret == EAI_FAMILY); CHECK(rc == (DWORD)EAI_FAMILY);
}

/* ---- before WSAStartup (each case in a fresh process so no earlier startup counts) ---- */
static int pre_case(int idx) {
    WSADATA d; struct sockaddr_in a; int n = sizeof a; char buf[8]; fd_set f; SOCKET s;
    switch (idx) {
    case 0: s = socket(AF_INET, SOCK_STREAM, 0); return s == INVALID_SOCKET ? WSAGetLastError() : -1;
    case 1: return WSACleanup() == SOCKET_ERROR ? WSAGetLastError() : -1;
    case 2: return closesocket(INVALID_SOCKET) == SOCKET_ERROR ? WSAGetLastError() : -1;
    case 3: return gethostname(buf, 8) == SOCKET_ERROR ? WSAGetLastError() : -1;
    case 4: return gethostbyname("localhost") == NULL ? WSAGetLastError() : -1;
    case 5: { ADDRINFOA *res = NULL; int r = getaddrinfo("127.0.0.1", "80", NULL, &res); if (res) freeaddrinfo(res); return r ? r : -1; }
    case 6: FD_ZERO(&f); return select(0, &f, NULL, NULL, &(struct timeval){0, 0}) == SOCKET_ERROR ? WSAGetLastError() : -1;
    case 7: return WSACreateEvent() == NULL ? WSAGetLastError() : -1;
    case 8: WSASetLastError(1234); return WSAGetLastError();
    case 9: return WSAStartup(0, &d);
    case 10: return WSAStartup(MAKEWORD(3, 0), &d);
    case 11: return WSAStartup(MAKEWORD(2, 2), &d) == 0 ? (WSACleanup(), -1) : -2;
    case 12: return WSAStartup(MAKEWORD(2, 2), &d) == 0 && WSACleanup() == 0 ? (WSACleanup() == SOCKET_ERROR ? WSAGetLastError() : -1) : -2;
    case 13: return WSAStartup(MAKEWORD(2, 2), &d) == 0 ? (WSACleanup(), socket(AF_INET, SOCK_STREAM, 0) == INVALID_SOCKET ? WSAGetLastError() : -1) : -2;
    case 14: return recv(INVALID_SOCKET, buf, 1, 0) == SOCKET_ERROR ? WSAGetLastError() : -1;
    case 15: return WSAIoctl(INVALID_SOCKET, 0, NULL, 0, NULL, 0, (DWORD *)&n, NULL, NULL) == SOCKET_ERROR ? WSAGetLastError() : -1;
    case 16: return getsockname(INVALID_SOCKET, (struct sockaddr *)&a, &n) == SOCKET_ERROR ? WSAGetLastError() : -1;
    case 17: return WSACancelBlockingCall() == SOCKET_ERROR ? WSAGetLastError() : -1;
    case 18: return WSAIsBlocking() ? 1 : 0;
    case 19: return getservbyname("http", "tcp") == NULL ? WSAGetLastError() : -1;
    case 20: return WSAEnumProtocolsW(NULL, NULL, &(DWORD){0}) == SOCKET_ERROR ? WSAGetLastError() : -1;
    case 21: return WSAStartup(MAKEWORD(1, 1), &d) == 0 ? (WSACleanup(), d.wVersion == MAKEWORD(1, 1) ? -1 : -2) : -3;
    case 22: return WSAStartup(MAKEWORD(2, 3), &d) == 0 ? (WSACleanup(), d.wVersion) : -3;
    case 23: return WSAStartup(MAKEWORD(1, 0), &d) == 0 ? (WSACleanup(), d.wVersion) : -3;
    case 24: return WSAStartup(MAKEWORD(0, 3), &d);
    case 25: return WSAStartup(MAKEWORD(1, 2), &d);
    case 26: return WSAStartup(MAKEWORD(2, 2), &d) == 0 && WSAStartup(MAKEWORD(2, 2), &d) == 0 && WSACleanup() == 0 ? (socket(AF_INET, SOCK_STREAM, 0) != INVALID_SOCKET ? -1 : WSAGetLastError()) : -2;
    case 27: if (WSAStartup(MAKEWORD(2, 2), &d) != 0) return -2; s = socket(AF_INET, SOCK_STREAM, 0); WSACleanup(); return closesocket(s) == SOCKET_ERROR ? WSAGetLastError() : -1;
    case 28: if (WSAStartup(MAKEWORD(1, 1), &d) != 0) return -2; { int r = d.wHighVersion; WSACleanup(); return r; }
    case 29: if (WSAStartup(MAKEWORD(2, 2), &d) != 0) return -2; { int r = d.iMaxSockets * 100000 + d.iMaxUdpDg; WSACleanup(); return r; }
    case 30: if (WSAStartup(MAKEWORD(2, 2), &d) != 0) return -2; { int r = d.szDescription[0] != 0 && d.szSystemStatus[0] != 0 ? -1 : -3; WSACleanup(); return r; }
    case 31: if (WSAStartup(MAKEWORD(2, 2), &d) != 0) return -2; { int r = WSAIsBlocking() ? 1 : 0; WSACleanup(); return r; }
    case 32: if (WSAStartup(MAKEWORD(2, 2), &d) != 0) return -2; s = socket(AF_INET, SOCK_STREAM, 0); { int r = s != INVALID_SOCKET ? -1 : WSAGetLastError(); closesocket(s); WSACleanup(); return r; }
    case 33: if (WSAStartup(MAKEWORD(2, 2), &d) != 0) return -2; { int r1 = WSACleanup(); int r2 = WSACleanup(); return r1 == 0 && r2 == SOCKET_ERROR ? WSAGetLastError() : -3; }
    case 34: return WSAStartup(MAKEWORD(2, 2), &d) == 0 ? (int)d.wVersion : -2;
    }
    return -100;
}
CHILD(xe_pre) { return pre_case(argc > 1 ? atoi(argv[1]) : 0); }
static int run_pre(int idx) { char a[16]; sprintf(a, "%d", idx); return (int)t_run_child("xe_pre", a, 15000); }
#define PRE(n, idx, WANT) TEST(xepre_##n) { int r; REQUIRE(t_proc("WSAStartup")); r = run_pre(idx); \
    if ((WANT) == XE_UNK) { t_note("ROW pre %s %d", #n, r); return; } CHECKF(r == (WANT), "got %d want %d", r, (int)(WANT)); }
PRE(socket, 0, 10093) PRE(wsacleanup, 1, 10093) PRE(closesocket_invalid, 2, 10093) PRE(gethostname, 3, 10093) PRE(gethostbyname, 4, 10093)
PRE(getaddrinfo, 5, 10093) PRE(select, 6, 10093) PRE(wsacreateevent, 7, -1) PRE(set_get_lasterror, 8, 1234)
PRE(wsastartup_version_zero, 9, 10092) PRE(wsastartup_version_3_0, 10, 0) PRE(startup_cleanup_ok, 11, -1)
PRE(second_cleanup, 12, 10093) PRE(socket_after_cleanup, 13, 10093) PRE(recv_invalid, 14, 10093) PRE(wsaioctl_invalid, 15, 10093)
PRE(getsockname_invalid, 16, 10093) PRE(wsacancelblockingcall, 17, 10093) PRE(wsaisblocking, 18, 0) PRE(getservbyname, 19, 10093)
PRE(wsaenumprotocols, 20, 10093) PRE(wsastartup_1_1_version, 21, -1) PRE(wsastartup_2_3_version, 22, 514)
PRE(second_startup_keeps_sockets_usable, 26, -1) PRE(socket_closed_after_final_cleanup, 27, 10093) PRE(high_version_for_1_1_request, 28, 514)
PRE(startup_data_limits_fields, 29, 0) PRE(startup_description_fields_filled, 30, -1) PRE(isblocking_after_startup, 31, 0)
PRE(socket_after_startup_ok, 32, -1) PRE(cleanup_underflow_error, 33, 10093) PRE(startup_2_2_version, 34, 514)
PRE(wsastartup_1_0_version, 23, 1) PRE(wsastartup_0_3, 24, 10092) PRE(wsastartup_1_2, 25, 0)
