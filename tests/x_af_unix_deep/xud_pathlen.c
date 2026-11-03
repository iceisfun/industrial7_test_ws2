/* AF_UNIX name length at the capacity boundary: absolute names built to an exact number of characters (the
 * sun_path field holds 108 bytes). Every length from comfortably short up to the full field binds, creates a
 * file with exactly that name, is reported by getsockname with the documented length rule (name + terminator,
 * capped at the structure size), and can be reached by connect with either a full-size or an exact length. */
#include "xud.h"

static void at_length(size_t total)
{
    const char *p;
    SOCKADDR_UN a, g;
    SOCKET lis, c;
    int gl = (int)sizeof g, want;
    UP();
    p = x_path_len(total, ".s");
    if (!p) { t_skip("scratch directory longer than %u characters", (unsigned)total); return; }
    lis = x_sock();
    if (lis == INVALID_SOCKET) return;
    x_addr(&a, p);
    XEQ(x_bind(lis, &a), 0);
    CHECK(x_exists(p));
    memset(&g, 0x55, sizeof g);
    XEQ(U(getsockname)(lis, (struct sockaddr *)&g, &gl), 0);
    want = (total < 108) ? (int)total + 3 : 110;
    XEQ(gl, want);
    XEQ(g.sun_family, AF_UNIX);
    CHECK(!strncmp(g.sun_path, p, total));
    XEQ(U(listen)(lis, 2), 0);
    {
        int e;
        CHECK(x_try_connect(lis, p, &e));
        XEQ(e, WSAEWOULDBLOCK);
    }
    /* exact length without a terminator reaches the same file */
    c = x_sock();
    x_blocking(c, FALSE);
    {
        int r = U(connect)(c, (struct sockaddr *)&a, X_ADDR_BASE + (int)total);
        XEQ(r, -1);
        XEQ(x_err(), WSAEWOULDBLOCK);
        CHECK(x_readable(lis, 3000));
    }
    U(closesocket)(c);
    U(closesocket)(lis);
    DeleteFileA(p);
    CHECK(!x_exists(p));
}
TEST(xud_pathlen_60) { at_length(60); }
TEST(xud_pathlen_80) { at_length(80); }
TEST(xud_pathlen_96) { at_length(96); }
TEST(xud_pathlen_100) { at_length(100); }
TEST(xud_pathlen_104) { at_length(104); }
TEST(xud_pathlen_105) { at_length(105); }
TEST(xud_pathlen_106) { at_length(106); }
TEST(xud_pathlen_107_last_with_terminator) { at_length(107); }
TEST(xud_pathlen_108_fills_field) { at_length(108); }

/* Exact-length bind (no terminator) reports the name length plus one, except when the field is full. */
static void exact_len_bind(size_t total)
{
    const char *p;
    SOCKADDR_UN a, g;
    SOCKET s;
    int gl = (int)sizeof g;
    UP();
    p = x_path_len(total, ".e");
    if (!p) { t_skip("scratch directory too long"); return; }
    s = x_sock();
    if (s == INVALID_SOCKET) return;
    x_addr(&a, p);
    XEQ(x_bind_len(s, &a, X_ADDR_BASE + (int)total), 0);
    CHECK(x_exists(p));
    memset(&g, 0x55, sizeof g);
    XEQ(U(getsockname)(s, (struct sockaddr *)&g, &gl), 0);
    XEQ(gl, (total < 108) ? (int)total + 3 : 110);
    U(closesocket)(s);
    DeleteFileA(p);
}
TEST(xud_pathlen_exact_bind_70) { exact_len_bind(70); }
TEST(xud_pathlen_exact_bind_107) { exact_len_bind(107); }
TEST(xud_pathlen_exact_bind_108) { exact_len_bind(108); }

/* A 108-character field has no terminator; the name returned is all 108 characters. */
TEST(xud_pathlen_full_field_getsockname_has_no_terminator)
{
    const char *p;
    SOCKADDR_UN a, g;
    SOCKET s;
    int gl = (int)sizeof g;
    UP();
    p = x_path_len(108, ".f");
    if (!p) { t_skip("scratch directory too long"); return; }
    s = x_sock();
    if (s == INVALID_SOCKET) return;
    x_addr(&a, p);
    XEQ(x_bind(s, &a), 0);
    memset(&g, 0x55, sizeof g);
    XEQ(U(getsockname)(s, (struct sockaddr *)&g, &gl), 0);
    XEQ(gl, 110);
    CHECK(!memcmp(g.sun_path, p, 108));
    U(closesocket)(s);
    DeleteFileA(p);
}

/* The same long name collides on a second bind. */
TEST(xud_pathlen_107_second_bind_is_addrinuse)
{
    const char *p;
    SOCKADDR_UN a;
    SOCKET s1, s2;
    UP();
    p = x_path_len(107, ".d");
    if (!p) { t_skip("scratch directory too long"); return; }
    s1 = x_sock(); s2 = x_sock();
    if (s1 == INVALID_SOCKET || s2 == INVALID_SOCKET) return;
    x_addr(&a, p);
    XEQ(x_bind(s1, &a), 0);
    XEQ(x_bind(s2, &a), -1);
    XEQ(x_err(), WSAEADDRINUSE);
    U(closesocket)(s2);
    U(closesocket)(s1);
    DeleteFileA(p);
}

/* A bound long name with the directory part missing fails like any missing directory. */
TEST(xud_pathlen_107_in_missing_directory)
{
    char p[MAX_PATH];
    SOCKADDR_UN a;
    SOCKET s;
    size_t dir;
    UP();
    snprintf(p, sizeof p, "%smissing_dir_x\\", t_tmpdir());
    dir = strlen(p);
    if (dir + 5 > 107) { t_skip("scratch directory too long"); return; }
    memset(p + dir, 'm', 107 - dir);
    p[107] = 0;
    s = x_sock();
    if (s == INVALID_SOCKET) return;
    x_addr(&a, p);
    XEQ(x_bind(s, &a), -1);
    XEQ(x_err(), WSAENETDOWN);
    U(closesocket)(s);
}
