/* State of an AF_UNIX stream socket after a connect() that failed: exact error codes per kind of target, what
 * SO_ERROR reports (nothing: the failure was synchronous), what the socket looks like afterwards (implicitly
 * named, not connected, still usable as a listener) and how select/WSAPoll describe it. */
#include "xud.h"

/* ---- the error per target kind ---- */
static void fail_to(const char *path, int want, int nonblocking)
{
    SOCKADDR_UN a;
    SOCKET s;
    int so = -1, l = sizeof so;
    UP();
    s = x_sock();
    if (s == INVALID_SOCKET) return;
    if (nonblocking) x_blocking(s, FALSE);
    x_addr(&a, path);
    XEQ(x_connect(s, &a), -1);
    XEQ(x_err(), want);
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_ERROR, (char *)&so, &l), 0);
    XEQ(so, 0);                                   /* synchronous failure leaves no pending socket error */
    so = -1; l = sizeof so;
    U(getsockopt)(s, SOL_SOCKET, SO_ERROR, (char *)&so, &l);
    XEQ(so, 0);
    U(closesocket)(s);
}
TEST(xud_cf_missing_file_blocking) { fail_to(x_path("cf_missing.sock"), WSAECONNREFUSED, 0); }
TEST(xud_cf_missing_file_nonblocking) { fail_to(x_path("cf_missing.sock"), WSAECONNREFUSED, 1); }
TEST(xud_cf_missing_dir_blocking) { fail_to(x_path("cf_nodir\\x.sock"), WSAENETDOWN, 0); }
TEST(xud_cf_missing_dir_nonblocking) { fail_to(x_path("cf_nodir\\x.sock"), WSAENETDOWN, 1); }

TEST(xud_cf_regular_file_target)
{
    HANDLE h;
    const char *p = x_path("cf_reg.txt");
    h = CreateFileA(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { t_skip("cannot create file"); return; }
    CloseHandle(h);
    fail_to(p, WSAECONNREFUSED, 0);
    fail_to(p, WSAECONNREFUSED, 1);
    DeleteFileA(p);
}
TEST(xud_cf_directory_target)
{
    const char *p = x_path("cf_dir");
    CreateDirectoryA(p, NULL);
    fail_to(p, WSAEINVAL, 0);
    fail_to(p, WSAEINVAL, 1);
    RemoveDirectoryA(p);
}
TEST(xud_cf_file_as_directory_component)
{
    HANDLE h;
    char q[MAX_PATH];
    const char *p = x_path("cf_regdir.txt");
    h = CreateFileA(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { t_skip("cannot create file"); return; }
    CloseHandle(h);
    snprintf(q, sizeof q, "%s\\x.sock", p);
    fail_to(q, WSAENETDOWN, 0);
    DeleteFileA(p);
}
TEST(xud_cf_bound_but_not_listening_target)
{
    SOCKADDR_UN a;
    SOCKET b;
    UP();
    b = x_sock();
    if (b == INVALID_SOCKET) return;
    x_addr(&a, x_path("cf_bound.sock"));
    XEQ(x_bind(b, &a), 0);
    fail_to(a.sun_path, WSAECONNREFUSED, 0);
    fail_to(a.sun_path, WSAECONNREFUSED, 1);
    U(closesocket)(b);
    DeleteFileA(a.sun_path);
}
TEST(xud_cf_closed_listener_leaves_refusing_file)
{
    SOCKADDR_UN a;
    SOCKET l;
    UP();
    l = x_sock();
    if (l == INVALID_SOCKET) return;
    x_addr(&a, x_path("cf_closed.sock"));
    XEQ(x_bind(l, &a), 0);
    XEQ(U(listen)(l, 1), 0);
    U(closesocket)(l);
    CHECK(x_exists(a.sun_path));
    fail_to(a.sun_path, WSAECONNREFUSED, 0);
    DeleteFileA(a.sun_path);
}

/* ---- the socket afterwards ---- */
static SOCKET failed_socket(int nonblocking)
{
    SOCKADDR_UN a;
    SOCKET s = x_sock();
    if (s == INVALID_SOCKET) return s;
    if (nonblocking) x_blocking(s, FALSE);
    x_addr(&a, x_path("cf_after.sock"));
    if (x_connect(s, &a) == 0) { U(closesocket)(s); return INVALID_SOCKET; }
    return s;
}
TEST(xud_cf_after_recv_and_send_are_notconn)
{
    char b = 0;
    SOCKET s;
    UP();
    s = failed_socket(0);
    if (s == INVALID_SOCKET) { t_skip("connect unexpectedly succeeded"); return; }
    XEQ(U(recv)(s, &b, 1, 0), -1);
    XEQ(x_err(), WSAENOTCONN);
    XEQ(U(send)(s, &b, 1, 0), -1);
    XEQ(x_err(), WSAENOTCONN);
    U(closesocket)(s);
}
TEST(xud_cf_after_getpeername_is_notconn)
{
    SOCKADDR_UN g;
    int gl = (int)sizeof g;
    SOCKET s;
    UP();
    s = failed_socket(0);
    if (s == INVALID_SOCKET) { t_skip("connect unexpectedly succeeded"); return; }
    XEQ(U(getpeername)(s, (struct sockaddr *)&g, &gl), -1);
    XEQ(x_err(), WSAENOTCONN);
    U(closesocket)(s);
}
TEST(xud_cf_after_socket_has_implicit_unnamed_name)
{
    SOCKADDR_UN g;
    int gl = (int)sizeof g;
    SOCKET s;
    UP();
    s = failed_socket(0);
    if (s == INVALID_SOCKET) { t_skip("connect unexpectedly succeeded"); return; }
    memset(&g, 0x55, sizeof g);
    XEQ(U(getsockname)(s, (struct sockaddr *)&g, &gl), 0);   /* the failed connect bound it implicitly */
    XEQ(gl, 110);
    XEQ(g.sun_family, AF_UNIX);
    XEQ(g.sun_path[0], 0);
    U(closesocket)(s);
}
TEST(xud_cf_after_bind_is_inval_because_implicitly_bound)
{
    SOCKADDR_UN a;
    SOCKET s;
    UP();
    s = failed_socket(0);
    if (s == INVALID_SOCKET) { t_skip("connect unexpectedly succeeded"); return; }
    x_addr(&a, x_path("cf_rebind.sock"));
    XEQ(x_bind(s, &a), -1);
    XEQ(x_err(), WSAEINVAL);
    CHECK(!x_exists(a.sun_path));
    U(closesocket)(s);
}
TEST(xud_cf_after_listen_succeeds)
{
    SOCKET s;
    int ac = 0, l = sizeof ac;
    UP();
    s = failed_socket(0);
    if (s == INVALID_SOCKET) { t_skip("connect unexpectedly succeeded"); return; }
    XEQ(U(listen)(s, 1), 0);
    XEQ(U(getsockopt)(s, SOL_SOCKET, SO_ACCEPTCONN, (char *)&ac, &l), 0);
    XEQ(ac, 1);
    U(closesocket)(s);
}
TEST(xud_cf_after_second_connect_to_live_listener_works)
{
    SOCKADDR_UN la;
    SOCKET lis, s, srv;
    UP();
    lis = x_sock();
    if (lis == INVALID_SOCKET) return;
    x_addr(&la, x_path("cf_live.sock"));
    if (x_bind(lis, &la) || U(listen)(lis, 2)) { t_skip("cannot listen"); U(closesocket)(lis); return; }
    s = failed_socket(0);
    if (s == INVALID_SOCKET) { t_skip("connect unexpectedly succeeded"); U(closesocket)(lis); DeleteFileA(la.sun_path); return; }
    x_blocking(s, FALSE);
    XEQ(x_connect(s, &la), -1);
    XEQ(x_err(), WSAEWOULDBLOCK);
    srv = x_accept_wait(lis);
    CHECK(srv != INVALID_SOCKET);
    if (srv != INVALID_SOCKET) U(closesocket)(srv);
    U(closesocket)(s);
    U(closesocket)(lis);
    DeleteFileA(la.sun_path);
}
TEST(xud_cf_after_select_reports_exception_not_writable)
{
    fd_set w, x;
    struct timeval tv = { 0, 200000 };
    SOCKET s;
    int n;
    UP();
    s = failed_socket(1);
    if (s == INVALID_SOCKET) { t_skip("connect unexpectedly succeeded"); return; }
    FD_ZERO(&w); FD_ZERO(&x);
    FD_SET(s, &w); FD_SET(s, &x);
    n = U(select)(0, NULL, &w, &x, &tv);
    XEQ(n, 1);
    CHECK(!x_isset(s, &w));
    CHECK(x_isset(s, &x));
    U(closesocket)(s);
}
TEST(xud_cf_after_poll_reports_err_hup_wrnorm)
{
    WSAPOLLFD p;
    SOCKET s;
    UP();
    s = failed_socket(1);
    if (s == INVALID_SOCKET) { t_skip("connect unexpectedly succeeded"); return; }
    p.fd = s; p.events = POLLRDNORM | POLLWRNORM; p.revents = 0;
    XEQ(U(WSAPoll)(&p, 1, 200), 1);
    XEQ((unsigned short)p.revents, POLLERR | POLLHUP | POLLWRNORM);
    U(closesocket)(s);
}
