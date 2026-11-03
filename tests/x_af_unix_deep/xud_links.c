/* AF_UNIX socket files seen through file-system aliases: hard links, directory junctions, symbolic links and
 * plain copies, plus replacement of the socket file while the listener is alive. A socket file is a reparse
 * point; only aliases that resolve to the very same file object reach the listener. */
#include "xud.h"

struct lk { struct x_trio t; char dir[MAX_PATH]; };

static int run_cmd(const char *cmdline)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char buf[2 * MAX_PATH];
    DWORD code = 1;
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    snprintf(buf, sizeof buf, "%s", cmdline);
    if (!CreateProcessA(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return -1;
    if (WaitForSingleObject(pi.hProcess, 10000) != WAIT_OBJECT_0) TerminateProcess(pi.hProcess, 1);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return (int)code;
}

TEST(xud_link_hardlink_reaches_listener)
{
    char hl[MAX_PATH];
    int e;
    TRIO(t, "hl_orig.sock");
    snprintf(hl, sizeof hl, "%shl_alias.sock", t_tmpdir());
    if (!CreateHardLinkA(hl, t.path, NULL)) { t_skip("hard links unavailable (error %lu)", GetLastError()); x_trio_close(&t); return; }
    CHECK(x_try_connect(t.lis, hl, &e));
    XEQ(e, WSAEWOULDBLOCK);
    DeleteFileA(hl);
    x_trio_close(&t);
}
TEST(xud_link_hardlink_name_is_addrinuse_for_bind)
{
    char hl[MAX_PATH];
    SOCKADDR_UN a;
    SOCKET b;
    TRIO(t, "hl2_orig.sock");
    snprintf(hl, sizeof hl, "%shl2_alias.sock", t_tmpdir());
    if (!CreateHardLinkA(hl, t.path, NULL)) { t_skip("hard links unavailable"); x_trio_close(&t); return; }
    b = x_sock();
    x_addr(&a, hl);
    XEQ(x_bind(b, &a), -1);
    XEQ(x_err(), WSAEADDRINUSE);
    U(closesocket)(b);
    DeleteFileA(hl);
    x_trio_close(&t);
}
TEST(xud_link_hardlink_survives_original_delete)
{
    char hl[MAX_PATH];
    int e;
    TRIO(t, "hl3_orig.sock");
    snprintf(hl, sizeof hl, "%shl3_alias.sock", t_tmpdir());
    if (!CreateHardLinkA(hl, t.path, NULL)) { t_skip("hard links unavailable"); x_trio_close(&t); return; }
    DeleteFileA(t.path);
    CHECK(!x_exists(t.path));
    CHECK(x_try_connect(t.lis, hl, &e));      /* the surviving name still leads to the listener */
    DeleteFileA(hl);
    x_trio_close(&t);
}

TEST(xud_link_junction_directory_reaches_listener)
{
    char jd[MAX_PATH], via[MAX_PATH], cmd[3 * MAX_PATH];
    int e;
    TRIO(t, "jn.sock");
    snprintf(jd, sizeof jd, "%sjunc", t_tmpdir());
    snprintf(cmd, sizeof cmd, "cmd.exe /c mklink /J \"%s\" \"%s\" >nul 2>&1", jd, t_tmpdir());
    if (run_cmd(cmd) != 0) { t_skip("cannot create a junction"); x_trio_close(&t); return; }
    snprintf(via, sizeof via, "%s\\jn.sock", jd);
    CHECK(x_try_connect(t.lis, via, &e));
    XEQ(e, WSAEWOULDBLOCK);
    {   /* binding through the junction collides with the listener's file */
        SOCKADDR_UN a;
        SOCKET b = x_sock();
        x_addr(&a, via);
        XEQ(x_bind(b, &a), -1);
        XEQ(x_err(), WSAEADDRINUSE);
        U(closesocket)(b);
    }
    RemoveDirectoryA(jd);
    x_trio_close(&t);
}

TEST(xud_link_symlink_to_socket_is_not_followed)
{
    char sl[MAX_PATH];
    int e;
    TRIO(t, "sy.sock");
    snprintf(sl, sizeof sl, "%ssy_alias.sock", t_tmpdir());
    if (!CreateSymbolicLinkA(sl, t.path, 0)) {
        t_skip("symbolic links need a privilege this token lacks (error %lu)", GetLastError());
        x_trio_close(&t);
        return;
    }
    CHECK(!x_try_connect(t.lis, sl, &e));
    XEQ(e, WSAECONNREFUSED);
    {   /* the link name exists as a file, so binding to it is an address-in-use error */
        SOCKADDR_UN a;
        SOCKET b = x_sock();
        x_addr(&a, sl);
        XEQ(x_bind(b, &a), -1);
        XEQ(x_err(), WSAEADDRINUSE);
        U(closesocket)(b);
    }
    DeleteFileA(sl);
    x_trio_close(&t);
}

TEST(xud_link_copy_of_socket_file_is_not_a_socket)
{
    char cp[MAX_PATH];
    int e;
    TRIO(t, "cp.sock");
    snprintf(cp, sizeof cp, "%scp_copy.sock", t_tmpdir());
    if (!CopyFileA(t.path, cp, FALSE)) { t_skip("copy refused (error %lu)", GetLastError()); x_trio_close(&t); return; }
    CHECK(!x_try_connect(t.lis, cp, &e));
    XEQ(e, WSAECONNREFUSED);
    DeleteFileA(cp);
    x_trio_close(&t);
}

/* ---- replacing the file under a live listener ---- */
TEST(xud_link_unlinked_listener_unreachable)
{
    int e;
    TRIO(t, "ul.sock");
    DeleteFileA(t.path);
    CHECK(!x_try_connect(t.lis, t.path, &e));
    XEQ(e, WSAECONNREFUSED);
    x_trio_close(&t);
}
TEST(xud_link_regular_file_in_place_of_socket_is_refused)
{
    int e;
    HANDLE h;
    TRIO(t, "rf.sock");
    DeleteFileA(t.path);
    h = CreateFileA(t.path, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { t_skip("cannot create replacement file"); x_trio_close(&t); return; }
    CloseHandle(h);
    CHECK(!x_try_connect(t.lis, t.path, &e));
    XEQ(e, WSAECONNREFUSED);
    {
        SOCKADDR_UN a;
        SOCKET b = x_sock();
        x_addr(&a, t.path);
        XEQ(x_bind(b, &a), -1);
        XEQ(x_err(), WSAEADDRINUSE);
        U(closesocket)(b);
    }
    DeleteFileA(t.path);
    x_trio_close(&t);
}
TEST(xud_link_new_listener_takes_over_the_name)
{
    SOCKET l2;
    SOCKADDR_UN a;
    int e;
    TRIO(t, "ov.sock");
    DeleteFileA(t.path);
    l2 = x_sock();
    x_addr(&a, t.path);
    XEQ(x_bind(l2, &a), 0);
    XEQ(U(listen)(l2, 2), 0);
    CHECK(x_try_connect(l2, t.path, &e));          /* the new listener answers */
    CHECK(!x_readable(t.lis, 200));                /* the old one saw nothing */
    U(closesocket)(t.lis);                         /* closing the old listener does not disturb the name */
    t.lis = INVALID_SOCKET;
    CHECK(x_try_connect(l2, t.path, &e));
    U(closesocket)(l2);
    x_trio_close(&t);
}
