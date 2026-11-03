/* x_child_process_inherit / extra: a child that duplicates an inherited socket back to its parent, an abortive close
 * made by a child while the parent still holds a handle, and a second close of an inherited handle in the child. */
#include "xc.h"

/* The child duplicates its inherited socket to the process whose id is argv[3] and sends the blob through the pipe in argv[2]. */
CHILD(dup_back)
{
    SOCKET s = xc_arg_sock(argv, 1); HANDLE pipe = (HANDLE)(ULONG_PTR)_strtoui64(argv[2], NULL, 10); WSAPROTOCOL_INFOW pi; DWORD n = 0;
    xc_child_up();
    memset(&pi, 0, sizeof pi);
    if (U(WSADuplicateSocketW)(s, (DWORD)xc_arg_int(argv, 3), &pi)) return (int)(1 | (xc_e8(xc_werr()) << 8));
    if (!WriteFile(pipe, &pi, sizeof pi, &n, NULL) || n != sizeof pi) return 2;
    Sleep(300);                                            /* keep the original handle alive while the parent reads */
    return 0;
}
TEST(extra_child_duplicates_inherited_socket_back_to_parent)
{
    SOCKET c, s, d; HANDLE rd, wr, h[2], p; SECURITY_ATTRIBUTES sa; char a[128]; WSAPROTOCOL_INFOW pi; DWORD n = 0; struct sockaddr_in cn;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    sa.nLength = sizeof sa; sa.lpSecurityDescriptor = NULL; sa.bInheritHandle = TRUE;
    if (!CreatePipe(&rd, &wr, &sa, 4096)) { t_skip("pipe"); return; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    h[0] = H(c); h[1] = wr;
    p = xc_spawn("dup_back", XARGS(a, "%llu %llu %lu", xc_u(c), (unsigned long long)(ULONG_PTR)wr, GetCurrentProcessId()), h, 2, NULL);
    CloseHandle(wr);
    CHECK(p != NULL);
    memset(&pi, 0, sizeof pi);
    CHECK(ReadFile(rd, &pi, sizeof pi, &n, NULL) && n == sizeof pi);
    d = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi, 0, OVLD);
    CHECK(d != INVALID_SOCKET);
    XEQ(xc_wait(p, XC_CHILD_TIMEOUT), 0);
    if (d != INVALID_SOCKET) {
        int cl = sizeof cn;
        XEQ(xc_type_of(d), SOCK_STREAM);
        XEQ(xc_name_port(d, 0), xc_name_port(c, 0));
        XEQ(xc_name_port(d, 1), xc_name_port(c, 1));
        XEQ(xc_send(d, "back", 4), 4);
        CHECK(xc_expect(s, "back"));
        (void)cn; (void)cl;
        xc_close(d);
    }
    CloseHandle(rd); xc_close(c); xc_close(s);
}

CHILD(linger_close)
{
    SOCKET s = xc_arg_sock(argv, 1); struct linger l = { 1, 0 };
    xc_child_up();
    if (U(setsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof l)) return 1;
    return U(closesocket)(s) == 0 ? 0 : 2;
}
TEST(extra_child_abortive_linger_close_resets_peer_though_parent_holds)
{
    SOCKET c, s; char a[64], b; HANDLE h[1]; int r;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    h[0] = H(c);
    XEQ(xc_run("linger_close", XARGS(a, "%llu", xc_u(c)), h, 1), 0);
    CHECK(xc_readable(s, XC_WAIT));
    xc_setwerr(0);
    XEQ(U(recv)(s, &b, 1, 0), SOCKET_ERROR);               /* the child's abortive close reset the shared connection */
    XEQ(xc_werr(), WSAECONNRESET);
    xc_setwerr(0);
    r = xc_send(c, "p", 1);
    t_note("parent send after the child's abortive close: %s", r == 1 ? "accepted" : xc_werr() == WSAECONNRESET ? "WSAECONNRESET" : xc_werr() == WSAECONNABORTED ? "WSAECONNABORTED" : "other error");
    xc_close(c); xc_close(s);
}

CHILD(close_twice)
{
    SOCKET s = xc_arg_sock(argv, 1); unsigned fails = 0;
    xc_child_up();
    STEP(0, U(closesocket)(s) == 0);
    xc_setwerr(0);
    STEP(1, U(closesocket)(s) == SOCKET_ERROR);
    STEP(2, xc_werr() == WSAENOTSOCK);
    xc_setwerr(0);
    STEP(3, U(send)(s, "x", 1, 0) == SOCKET_ERROR);
    STEP(4, xc_werr() == WSAENOTSOCK);
    return (int)fails;
}
TEST(extra_child_second_close_of_inherited_handle_is_notsock)
{
    SOCKET c, s; char a[64]; HANDLE h[1];
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    h[0] = H(c);
    XEQ(xc_run("close_twice", XARGS(a, "%llu", xc_u(c)), h, 1), 0);
    XEQ(xc_send(c, "p", 1), 1);                            /* the parent's handle is unaffected */
    xc_close(c); xc_close(s);
}
