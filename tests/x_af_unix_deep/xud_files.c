/* The file-system footprint of AF_UNIX sockets: binding creates a reparse-point file, nothing but an explicit
 * delete removes it (close, shutdown, abortive close, failed operations all leave it), unnamed sockets and
 * failed calls leave no trace, and a stale file blocks the name until it is removed. */
#include "xud.h"

#ifndef IO_REPARSE_TAG_AF_UNIX
#define IO_REPARSE_TAG_AF_UNIX 0x80000023
#endif

static DWORD attrs(const char *p) { return GetFileAttributesA(p); }
static int count_entries(const char *dir)
{
    char pat[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    int n = 0;
    snprintf(pat, sizeof pat, "%s*", dir);
    h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    do { if (strcmp(fd.cFileName, ".") && strcmp(fd.cFileName, "..")) n++; } while (FindNextFileA(h, &fd));
    FindClose(h);
    return n;
}

TEST(xud_file_bind_creates_reparse_file_not_directory)
{
    SOCKADDR_UN a;
    DWORD at;
    SOCK_OR_RETURN(s);
    x_addr(&a, x_path("fl1.sock"));
    XEQ(x_bind(s, &a), 0);
    at = attrs(a.sun_path);
    CHECK(at != INVALID_FILE_ATTRIBUTES);
    CHECK(at & FILE_ATTRIBUTE_REPARSE_POINT);
    CHECK(!(at & FILE_ATTRIBUTE_DIRECTORY));
    U(closesocket)(s);
    DeleteFileA(a.sun_path);
}
TEST(xud_file_find_data_reports_af_unix_tag)
{
    SOCKADDR_UN a;
    WIN32_FIND_DATAA fd;
    HANDLE h;
    SOCK_OR_RETURN(s);
    x_addr(&a, x_path("fl2.sock"));
    XEQ(x_bind(s, &a), 0);
    h = FindFirstFileA(a.sun_path, &fd);
    CHECK(h != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) {
        XEQ(fd.dwReserved0, IO_REPARSE_TAG_AF_UNIX);
        FindClose(h);
    }
    U(closesocket)(s);
    DeleteFileA(a.sun_path);
}
TEST(xud_file_remains_after_plain_close)
{
    SOCKADDR_UN a;
    SOCK_OR_RETURN(s);
    x_addr(&a, x_path("fl3.sock"));
    XEQ(x_bind(s, &a), 0);
    XEQ(U(closesocket)(s), 0);
    CHECK(x_exists(a.sun_path));
    XEQ(DeleteFileA(a.sun_path), TRUE);
    CHECK(!x_exists(a.sun_path));
}
TEST(xud_file_remains_after_listener_close)
{
    SOCKADDR_UN a;
    SOCK_OR_RETURN(s);
    x_addr(&a, x_path("fl4.sock"));
    XEQ(x_bind(s, &a), 0);
    XEQ(U(listen)(s, 3), 0);
    XEQ(U(closesocket)(s), 0);
    CHECK(x_exists(a.sun_path));
    DeleteFileA(a.sun_path);
}
TEST(xud_file_remains_after_connection_traffic_and_close_of_all_ends)
{
    TRIO(t, "fl5.sock");
    XEQ(U(send)(t.cli, "a", 1, 0), 1);
    U(closesocket)(t.srv); t.srv = INVALID_SOCKET;
    U(closesocket)(t.cli); t.cli = INVALID_SOCKET;
    U(closesocket)(t.lis); t.lis = INVALID_SOCKET;
    CHECK(x_exists(t.path));
    x_trio_close(&t);
    CHECK(!x_exists(t.path));
}
TEST(xud_file_remains_after_abortive_close)
{
    SOCKADDR_UN a;
    LINGER lg = { 1, 0 };
    SOCK_OR_RETURN(s);
    x_addr(&a, x_path("fl6.sock"));
    XEQ(x_bind(s, &a), 0);
    XEQ(U(setsockopt)(s, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof lg), 0);
    XEQ(U(closesocket)(s), 0);
    CHECK(x_exists(a.sun_path));
    DeleteFileA(a.sun_path);
}
TEST(xud_file_remains_after_shutdown_of_bound_socket)
{
    SOCKADDR_UN a;
    SOCK_OR_RETURN(s);
    x_addr(&a, x_path("fl7.sock"));
    XEQ(x_bind(s, &a), 0);
    U(shutdown)(s, SD_BOTH);
    U(closesocket)(s);
    CHECK(x_exists(a.sun_path));
    DeleteFileA(a.sun_path);
}
TEST(xud_file_unnamed_bind_creates_nothing)
{
    SOCKADDR_UN a;
    int before, after;
    SOCK_OR_RETURN(s);
    before = count_entries(t_tmpdir());
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    XEQ(x_bind_len(s, &a, X_ADDR_BASE), 0);
    after = count_entries(t_tmpdir());
    XEQ(after, before);
    U(closesocket)(s);
    XEQ(count_entries(t_tmpdir()), before);
}
TEST(xud_file_unnamed_connected_pair_creates_nothing_beyond_listener_file)
{
    int before, after;
    before = count_entries(t_tmpdir());
    {
        TRIO(t, "fl9.sock");
        after = count_entries(t_tmpdir());
        XEQ(after, before + 1);                          /* exactly the listener's file; the client left no file */
        x_trio_close(&t);
    }
    XEQ(count_entries(t_tmpdir()), before);
}
TEST(xud_file_failed_connect_creates_nothing)
{
    SOCKADDR_UN a;
    int before;
    SOCK_OR_RETURN(s);
    before = count_entries(t_tmpdir());
    x_addr(&a, x_path("fl10_missing.sock"));
    XEQ(x_connect(s, &a), -1);
    XEQ(count_entries(t_tmpdir()), before);
    CHECK(!x_exists(a.sun_path));
    U(closesocket)(s);
}
TEST(xud_file_failed_bind_leaves_existing_file_alone)
{
    SOCKADDR_UN a;
    SOCKET s2;
    WIN32_FILE_ATTRIBUTE_DATA d1, d2;
    SOCK_OR_RETURN(s);
    x_addr(&a, x_path("fl11.sock"));
    XEQ(x_bind(s, &a), 0);
    XEQ(U(listen)(s, 2), 0);
    CHECK(GetFileAttributesExA(a.sun_path, GetFileExInfoStandard, &d1));
    s2 = x_sock();
    XEQ(x_bind(s2, &a), -1);
    XEQ(x_err(), WSAEADDRINUSE);
    CHECK(GetFileAttributesExA(a.sun_path, GetFileExInfoStandard, &d2));
    XEQ(d1.ftCreationTime.dwLowDateTime, d2.ftCreationTime.dwLowDateTime);
    XEQ(d1.ftCreationTime.dwHighDateTime, d2.ftCreationTime.dwHighDateTime);
    {   /* and the original is still the live one */
        int e;
        CHECK(x_try_connect(s, a.sun_path, &e));
    }
    U(closesocket)(s2);
    U(closesocket)(s);
    DeleteFileA(a.sun_path);
}
TEST(xud_file_stale_file_blocks_name_until_deleted)
{
    SOCKADDR_UN a;
    SOCKET s2;
    SOCK_OR_RETURN(s);
    x_addr(&a, x_path("fl12.sock"));
    XEQ(x_bind(s, &a), 0);
    U(closesocket)(s);
    s2 = x_sock();
    XEQ(x_bind(s2, &a), -1);
    XEQ(x_err(), WSAEADDRINUSE);
    DeleteFileA(a.sun_path);
    XEQ(x_bind(s2, &a), 0);                       /* the failed socket is still bindable once the name is free */
    U(closesocket)(s2);
    DeleteFileA(a.sun_path);
}
TEST(xud_file_many_sockets_make_many_files)
{
    enum { N = 24 };
    SOCKET s[N];
    SOCKADDR_UN a;
    int i, before = count_entries(t_tmpdir());
    char leaf[32];
    for (i = 0; i < N; i++) {
        s[i] = x_sock();
        if (s[i] == INVALID_SOCKET) { while (i--) U(closesocket)(s[i]); return; }
        snprintf(leaf, sizeof leaf, "fl13_%02d.sock", i);
        x_addr(&a, x_path(leaf));
        XEQ(x_bind(s[i], &a), 0);
    }
    XEQ(count_entries(t_tmpdir()), before + N);
    for (i = 0; i < N; i++) U(closesocket)(s[i]);
    XEQ(count_entries(t_tmpdir()), before + N);   /* closing removes none of them */
    for (i = 0; i < N; i++) {
        snprintf(leaf, sizeof leaf, "fl13_%02d.sock", i);
        CHECK(DeleteFileA(x_path(leaf)));
    }
    XEQ(count_entries(t_tmpdir()), before);
}
TEST(xud_file_delete_while_bound_does_not_close_socket)
{
    SOCKADDR_UN a, g;
    int gl = (int)sizeof g;
    SOCK_OR_RETURN(s);
    x_addr(&a, x_path("fl14.sock"));
    XEQ(x_bind(s, &a), 0);
    XEQ(DeleteFileA(a.sun_path), TRUE);
    XEQ(U(getsockname)(s, (struct sockaddr *)&g, &gl), 0);   /* the bound name is a property of the socket */
    EXPECT_STR(g.sun_path, a.sun_path);
    XEQ(U(listen)(s, 1), 0);
    U(closesocket)(s);
}
TEST(xud_file_last_error_from_file_apis_on_socket_file)
{
    SOCKADDR_UN a;
    HANDLE h;
    SOCK_OR_RETURN(s);
    x_addr(&a, x_path("fl15.sock"));
    XEQ(x_bind(s, &a), 0);
    h = CreateFileA(a.sun_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(h == INVALID_HANDLE_VALUE);             /* following the reparse point fails: no one backs it */
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    else XEQ(GetLastError(), ERROR_CANT_ACCESS_FILE);
    h = CreateFileA(a.sun_path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    CHECK(h != INVALID_HANDLE_VALUE);             /* the reparse point itself can be opened */
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    U(closesocket)(s);
    DeleteFileA(a.sun_path);
}
