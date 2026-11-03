/* Relative AF_UNIX names resolve against the working directory of the process at the time of the call, not at
 * the time the socket was created or bound. getsockname returns the relative spelling unchanged; the file
 * lives where the directory was when bind ran. Each test works in two scratch subdirectories. */
#include "xud.h"

static char d1[MAX_PATH], d2[MAX_PATH];
static int setup(void)
{
    snprintf(d1, sizeof d1, "%scwd1", t_tmpdir());
    snprintf(d2, sizeof d2, "%scwd2", t_tmpdir());
    CreateDirectoryA(d1, NULL);
    CreateDirectoryA(d2, NULL);
    x_cd_scratch();
    return 1;
}
static void teardown(void)
{
    x_cd_restore();
    x_rmtree_flat(d1);
    x_rmtree_flat(d2);
}
static void in_dir(const char *d) { SetCurrentDirectoryA(d); }

TEST(xud_cwd_bind_relative_creates_file_in_current_directory)
{
    SOCKADDR_UN a;
    char f1[MAX_PATH], f2[MAX_PATH];
    SOCK_OR_RETURN(s);
    setup();
    in_dir(d1);
    x_addr(&a, "rel.sock");
    XEQ(x_bind(s, &a), 0);
    snprintf(f1, sizeof f1, "%s\\rel.sock", d1);
    snprintf(f2, sizeof f2, "%s\\rel.sock", d2);
    CHECK(x_exists(f1));
    CHECK(!x_exists(f2));
    U(closesocket)(s);
    teardown();
}
TEST(xud_cwd_getsockname_returns_relative_spelling)
{
    SOCKADDR_UN a, g;
    int gl = (int)sizeof g;
    SOCK_OR_RETURN(s);
    setup();
    in_dir(d1);
    x_addr(&a, "rel.sock");
    XEQ(x_bind(s, &a), 0);
    in_dir(d2);                                   /* moving away does not change the reported name */
    memset(&g, 0x55, sizeof g);
    XEQ(U(getsockname)(s, (struct sockaddr *)&g, &gl), 0);
    XEQ(gl, X_ADDR_BASE + 8 + 1);
    EXPECT_STR(g.sun_path, "rel.sock");
    U(closesocket)(s);
    teardown();
}
TEST(xud_cwd_connect_from_other_directory_is_refused)
{
    SOCKADDR_UN a;
    SOCKET lis;
    int e;
    setup();
    in_dir(d1);
    lis = x_sock();
    if (lis == INVALID_SOCKET) { teardown(); return; }
    x_addr(&a, "rel.sock");
    XEQ(x_bind(lis, &a), 0);
    XEQ(U(listen)(lis, 2), 0);
    in_dir(d2);
    CHECK(!x_try_connect(lis, "rel.sock", &e));
    XEQ(e, WSAECONNREFUSED);
    U(closesocket)(lis);
    teardown();
}
TEST(xud_cwd_connect_from_same_directory_reaches_listener)
{
    SOCKADDR_UN a;
    SOCKET lis;
    int e;
    setup();
    in_dir(d1);
    lis = x_sock();
    if (lis == INVALID_SOCKET) { teardown(); return; }
    x_addr(&a, "rel.sock");
    XEQ(x_bind(lis, &a), 0);
    XEQ(U(listen)(lis, 2), 0);
    CHECK(x_try_connect(lis, "rel.sock", &e));
    XEQ(e, WSAEWOULDBLOCK);
    U(closesocket)(lis);
    teardown();
}
TEST(xud_cwd_listen_after_directory_change_still_listens_on_original_file)
{
    SOCKADDR_UN a;
    SOCKET lis;
    char abs_[MAX_PATH];
    int e;
    setup();
    in_dir(d1);
    lis = x_sock();
    if (lis == INVALID_SOCKET) { teardown(); return; }
    x_addr(&a, "rel.sock");
    XEQ(x_bind(lis, &a), 0);
    in_dir(d2);                                   /* listen() comes after the working directory moved */
    XEQ(U(listen)(lis, 2), 0);
    snprintf(abs_, sizeof abs_, "%s\\rel.sock", d1);
    CHECK(x_try_connect(lis, abs_, &e));          /* reached through the absolute name of the original file */
    CHECK(!x_exists("rel.sock"));
    U(closesocket)(lis);
    teardown();
}
TEST(xud_cwd_accept_after_directory_change)
{
    SOCKADDR_UN a;
    SOCKET lis, c, srv;
    setup();
    in_dir(d1);
    lis = x_sock();
    if (lis == INVALID_SOCKET) { teardown(); return; }
    x_addr(&a, "rel.sock");
    XEQ(x_bind(lis, &a), 0);
    XEQ(U(listen)(lis, 2), 0);
    c = x_sock();
    x_blocking(c, FALSE);
    XEQ(x_connect(c, &a), -1);
    XEQ(x_err(), WSAEWOULDBLOCK);
    in_dir(d2);
    srv = x_accept_wait(lis);
    CHECK(srv != INVALID_SOCKET);
    if (srv != INVALID_SOCKET) U(closesocket)(srv);
    U(closesocket)(c);
    U(closesocket)(lis);
    teardown();
}
TEST(xud_cwd_dotdot_from_sibling_reaches_listener)
{
    SOCKADDR_UN a;
    SOCKET lis;
    int e;
    setup();
    in_dir(d1);
    lis = x_sock();
    if (lis == INVALID_SOCKET) { teardown(); return; }
    x_addr(&a, "rel.sock");
    XEQ(x_bind(lis, &a), 0);
    XEQ(U(listen)(lis, 2), 0);
    in_dir(d2);
    CHECK(x_try_connect(lis, "..\\cwd1\\rel.sock", &e));
    XEQ(e, WSAEWOULDBLOCK);
    CHECK(x_try_connect(lis, "../cwd1/rel.sock", &e));
    U(closesocket)(lis);
    teardown();
}
TEST(xud_cwd_same_relative_name_in_two_directories_is_two_sockets)
{
    SOCKADDR_UN a;
    SOCKET l1, l2;
    int e;
    setup();
    l1 = x_sock(); l2 = x_sock();
    if (l1 == INVALID_SOCKET || l2 == INVALID_SOCKET) { teardown(); return; }
    x_addr(&a, "twin.sock");
    in_dir(d1);
    XEQ(x_bind(l1, &a), 0);
    XEQ(U(listen)(l1, 2), 0);
    in_dir(d2);
    XEQ(x_bind(l2, &a), 0);                       /* same spelling, different directory: no collision */
    XEQ(U(listen)(l2, 2), 0);
    CHECK(x_try_connect(l2, "twin.sock", &e));
    CHECK(!x_readable(l1, 200));
    in_dir(d1);
    CHECK(x_try_connect(l1, "twin.sock", &e));
    CHECK(!x_readable(l2, 200));
    U(closesocket)(l1); U(closesocket)(l2);
    teardown();
}
TEST(xud_cwd_same_relative_name_second_bind_same_directory_is_addrinuse)
{
    SOCKADDR_UN a;
    SOCKET s1, s2;
    setup();
    s1 = x_sock(); s2 = x_sock();
    if (s1 == INVALID_SOCKET || s2 == INVALID_SOCKET) { teardown(); return; }
    in_dir(d1);
    x_addr(&a, "dup.sock");
    XEQ(x_bind(s1, &a), 0);
    XEQ(x_bind(s2, &a), -1);
    XEQ(x_err(), WSAEADDRINUSE);
    U(closesocket)(s1); U(closesocket)(s2);
    teardown();
}
TEST(xud_cwd_connected_pair_survives_directory_removal_of_nothing)
{
    /* an established connection does not depend on the working directory at all */
    SOCKADDR_UN a;
    SOCKET lis, c, srv;
    char b[4];
    setup();
    in_dir(d1);
    lis = x_sock(); c = x_sock();
    if (lis == INVALID_SOCKET || c == INVALID_SOCKET) { teardown(); return; }
    x_addr(&a, "est.sock");
    XEQ(x_bind(lis, &a), 0);
    XEQ(U(listen)(lis, 2), 0);
    x_blocking(c, FALSE);
    x_connect(c, &a);
    srv = x_accept_wait(lis);
    x_blocking(c, TRUE);
    CHECK(srv != INVALID_SOCKET);
    if (srv != INVALID_SOCKET) {
        in_dir(d2);
        XEQ(U(send)(c, "q", 1, 0), 1);
        XEQ(x_recv_n(srv, b, 1), 1);
        XEQ(U(send)(srv, "r", 1, 0), 1);
        XEQ(x_recv_n(c, b, 1), 1);
        U(closesocket)(srv);
    }
    U(closesocket)(c); U(closesocket)(lis);
    teardown();
}
TEST(xud_cwd_client_getpeername_reports_relative_spelling)
{
    SOCKADDR_UN a, g;
    SOCKET lis, c, srv;
    int gl = (int)sizeof g;
    setup();
    in_dir(d1);
    lis = x_sock(); c = x_sock();
    if (lis == INVALID_SOCKET || c == INVALID_SOCKET) { teardown(); return; }
    x_addr(&a, "peer.sock");
    XEQ(x_bind(lis, &a), 0);
    XEQ(U(listen)(lis, 2), 0);
    x_blocking(c, FALSE);
    x_connect(c, &a);
    srv = x_accept_wait(lis);
    CHECK(srv != INVALID_SOCKET);
    memset(&g, 0x55, sizeof g);
    XEQ(U(getpeername)(c, (struct sockaddr *)&g, &gl), 0);
    XEQ(gl, 110);
    EXPECT_STR(g.sun_path, "peer.sock");
    if (srv != INVALID_SOCKET) U(closesocket)(srv);
    U(closesocket)(c); U(closesocket)(lis);
    teardown();
}
