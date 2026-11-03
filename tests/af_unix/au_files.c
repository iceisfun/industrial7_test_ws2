/* AF_UNIX stream sockets: the socket file and process boundaries. How the file looks to directory
 * enumeration and file operations, what outlives the socket, cleanup, and sockets used across processes
 * (inherited listener, duplicated socket, a listener in a child process, files left behind by a child). */
#include "au.h"

#ifndef IO_REPARSE_TAG_AF_UNIX
#define IO_REPARSE_TAG_AF_UNIX 0x80000023
#endif

static int exists_a(const char *p) { return GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES; }

TEST(afu_file_directory_enumeration_shows_reparse_tag)
{
    WIN32_FIND_DATAA fd;
    HANDLE h;
    SOCKADDR_UN a;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "enum_me.sock", &a), 0);
    h = FindFirstFileA(a.sun_path, &fd);
    CHECK(h != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) {
        CHECK(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
        AU_EQ(fd.dwReserved0, IO_REPARSE_TAG_AF_UNIX);
        CHECK(!strcmp(fd.cFileName, "enum_me.sock"));
        FindClose(h);
    }
    U(closesocket)(s);
    au_unlink_leaf("enum_me.sock");
}

TEST(afu_file_size_is_zero)
{
    WIN32_FILE_ATTRIBUTE_DATA d;
    SOCKADDR_UN a;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "size0.sock", &a), 0);
    CHECK(GetFileAttributesExA(a.sun_path, GetFileExInfoStandard, &d));
    AU_EQ(d.nFileSizeLow, 0);
    AU_EQ(d.nFileSizeHigh, 0);
    U(closesocket)(s);
    au_unlink_leaf("size0.sock");
}

TEST(afu_file_create_new_over_socket_file_is_cant_access)
{
    SOCKADDR_UN a;
    HANDLE h;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "create_over.sock", &a), 0);
    h = CreateFileA(a.sun_path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(h == INVALID_HANDLE_VALUE);
    AU_EQ(GetLastError(), ERROR_CANT_ACCESS_FILE);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    U(closesocket)(s);
    au_unlink_leaf("create_over.sock");
}

TEST(afu_file_delete_twice)
{
    SOCKADDR_UN a;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "del2.sock", &a), 0);
    U(closesocket)(s);
    CHECK(DeleteFileA(a.sun_path));
    SetLastError(0);
    CHECK(!DeleteFileA(a.sun_path));
    AU_EQ(GetLastError(), ERROR_FILE_NOT_FOUND);
}

TEST(afu_file_delete_while_bound_open)
{
    SOCKADDR_UN a;
    BOOL ok;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "del_open.sock", &a), 0);
    ok = DeleteFileA(a.sun_path);
    CHECK(ok);
    U(closesocket)(s);
    au_unlink_leaf("del_open.sock");
}

TEST(afu_file_rename_bound_file)
{
    SOCKADDR_UN a;
    char to[MAX_PATH];
    BOOL ok;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "ren_from.sock", &a), 0);
    snprintf(to, sizeof(to), "%s", au_path("ren_to.sock"));
    ok = MoveFileA(a.sun_path, to);
    CHECK(ok);
    if (ok) CHECK(exists_a(to) && !exists_a(a.sun_path));
    U(closesocket)(s);
    DeleteFileA(a.sun_path); DeleteFileA(to);
}

TEST(afu_file_renamed_listener_reachable_by_new_name)
{
    SOCKADDR_UN to_a;
    SOCKET c, s;
    int r;
    TRIO(t, "ren2_from.sock");
    au_addr_leaf(&to_a, "ren2_to.sock");
    if (!MoveFileA(t.path, to_a.sun_path)) { AU_OBS("rename listening socket file", "err %lu", GetLastError()); au_trio_close(&t); return; }
    c = au_sock();
    au_blocking(c, FALSE);
    au_seterr(0);
    r = U(connect)(c, (struct sockaddr *)&to_a, sizeof(to_a));
    AU_OBS("connect through renamed file", "ret %d err %d", r, r ? au_err() : 0);
    s = au_accept_bounded(t.lis);
    AU_OBS("listener sees the connection", "%s", s == INVALID_SOCKET ? "no" : "yes");
    if (s != INVALID_SOCKET) U(closesocket)(s);
    U(closesocket)(c);
    DeleteFileA(to_a.sun_path);
    au_trio_close(&t);
}

TEST(afu_file_copy_outcome)
{
    SOCKADDR_UN a;
    char dst[MAX_PATH];
    BOOL ok;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "copy_src.sock", &a), 0);
    snprintf(dst, sizeof(dst), "%s", au_path("copy_dst.bin"));
    SetLastError(0);
    ok = CopyFileA(a.sun_path, dst, FALSE);
    AU_OBS("CopyFile of socket file", "ok %d err %lu", ok, ok ? 0 : GetLastError());
    U(closesocket)(s);
    DeleteFileA(dst);
    au_unlink_leaf("copy_src.sock");
}

TEST(afu_file_open_with_reparse_flag_gives_handle)
{
    SOCKADDR_UN a;
    HANDLE h;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "rp_open.sock", &a), 0);
    h = CreateFileA(a.sun_path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                    OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    CHECK(h != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) {
        BY_HANDLE_FILE_INFORMATION bi;
        CHECK(GetFileInformationByHandle(h, &bi));
        CHECK(bi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
        CloseHandle(h);
    }
    U(closesocket)(s);
    au_unlink_leaf("rp_open.sock");
}

TEST(afu_file_remove_directory_blocked_by_socket_file)
{
    char dir[MAX_PATH];
    SOCKADDR_UN a;
    char p[MAX_PATH];
    UP();
    SOCK_OR_RETURN(s);
    snprintf(dir, sizeof(dir), "%srmdir_t", au_path(""));
    CreateDirectoryA(dir, NULL);
    snprintf(p, sizeof(p), "%s\\in.sock", dir);
    au_addr(&a, p);
    AU_EQ(au_bind_to(s, &a), 0);
    U(closesocket)(s);
    SetLastError(0);
    CHECK(!RemoveDirectoryA(dir));
    AU_EQ(GetLastError(), ERROR_DIR_NOT_EMPTY);
    DeleteFileA(p);
    CHECK(RemoveDirectoryA(dir));
}

TEST(afu_file_bind_in_read_only_directory_fails)
{
    char dir[MAX_PATH], p[MAX_PATH];
    SOCKADDR_UN a;
    int r, e;
    UP();
    SOCK_OR_RETURN(s);
    snprintf(dir, sizeof(dir), "%sro_dir", au_path(""));
    CreateDirectoryA(dir, NULL);
    snprintf(p, sizeof(p), "%s\\x.sock", dir);
    au_addr(&a, p);
    /* Directory attributes do not restrict creation on NTFS; record what happens. */
    SetFileAttributesA(dir, FILE_ATTRIBUTE_READONLY);
    r = au_bind_to(s, &a);
    e = r ? au_err() : 0;
    AU_EQ(r, 0);
    U(closesocket)(s);
    DeleteFileA(p);
    SetFileAttributesA(dir, FILE_ATTRIBUTE_NORMAL);
    RemoveDirectoryA(dir);
}

TEST(afu_file_final_path_of_reparse_handle)
{
    SOCKADDR_UN a;
    HANDLE h;
    char fp[MAX_PATH * 2];
    DWORD n;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "final.sock", &a), 0);
    h = CreateFileA(a.sun_path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                    OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        n = GetFinalPathNameByHandleA(h, fp, sizeof(fp), FILE_NAME_NORMALIZED);
        CHECK(n > 0 && n < sizeof(fp));
        CHECK(strstr(fp, "final.sock") != NULL);
        CloseHandle(h);
    }
    U(closesocket)(s);
    au_unlink_leaf("final.sock");
}

TEST(afu_file_many_files_cleanup)
{
    int i, left = 0;
    UP();
    for (i = 0; i < 24; i++) {
        char leaf[32];
        SOCKET s = au_sock();
        if (s == INVALID_SOCKET) return;
        snprintf(leaf, sizeof(leaf), "bulk_%d.sock", i);
        AU_EQ(au_bind_leaf(s, leaf, NULL), 0);
        U(closesocket)(s);
    }
    for (i = 0; i < 24; i++) {
        char leaf[32];
        snprintf(leaf, sizeof(leaf), "bulk_%d.sock", i);
        CHECK(DeleteFileA(au_path(leaf)));
        if (exists_a(au_path(leaf))) left++;
    }
    AU_EQ(left, 0);
}

/* ---- processes --------------------------------------------------------------------------------- */
CHILD(afu_bind_and_exit)
{
    /* Binds and listens on the path given, then exits without removing the file. */
    SOCKADDR_UN a;
    WSADATA d;
    SOCKET s;
    int code = 10;
    if (argc < 2) return 2;
    if (U(WSAStartup)(MAKEWORD(2, 2), &d)) return 3;
    s = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) return 4;
    au_addr(&a, argv[1]);
    if (au_bind_to(s, &a) == 0 && U(listen)(s, 1) == 0) code = 0;
    /* exit with the socket still open */
    return code;
}

TEST(afu_proc_file_left_behind_after_exit)
{
    SOCKADDR_UN a;
    char args[MAX_PATH + 4];
    DWORD rc;
    UP();
    SOCK_OR_RETURN(probe);
    U(closesocket)(probe);
    au_addr_leaf(&a, "left_behind.sock");
    snprintf(args, sizeof(args), "\"%s\"", a.sun_path);
    rc = t_run_child("afu_bind_and_exit", args, 20000);
    AU_EQ(rc, 0);
    CHECK(exists_a(a.sun_path));
    DeleteFileA(a.sun_path);
}

TEST(afu_proc_connect_to_dead_listener_fails)
{
    SOCKADDR_UN a;
    SOCKET c;
    char args[MAX_PATH + 4];
    DWORD rc;
    UP();
    c = au_sock();
    if (c == INVALID_SOCKET) return;
    au_addr_leaf(&a, "dead_listener.sock");
    snprintf(args, sizeof(args), "\"%s\"", a.sun_path);
    rc = t_run_child("afu_bind_and_exit", args, 20000);
    AU_EQ(rc, 0);
    au_seterr(0);
    AU_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAECONNREFUSED);
    U(closesocket)(c);
    DeleteFileA(a.sun_path);
}

TEST(afu_proc_rebind_after_child_left_file_is_addrinuse)
{
    SOCKADDR_UN a;
    char args[MAX_PATH + 4];
    DWORD rc;
    UP();
    SOCK_OR_RETURN(s);
    au_addr_leaf(&a, "left_inuse.sock");
    snprintf(args, sizeof(args), "\"%s\"", a.sun_path);
    rc = t_run_child("afu_bind_and_exit", args, 20000);
    AU_EQ(rc, 0);
    au_seterr(0);
    AU_EQ(au_bind_to(s, &a), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEADDRINUSE);
    U(closesocket)(s);
    DeleteFileA(a.sun_path);
}

/* A listener in a child that accepts one connection, echoes up to 16 bytes and exits. */
CHILD(afu_echo_server)
{
    SOCKADDR_UN a;
    WSADATA d;
    SOCKET s, c;
    HANDLE ev;
    char b[16];
    int n;
    if (argc < 3) return 2;
    if (U(WSAStartup)(MAKEWORD(2, 2), &d)) return 3;
    s = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) return 4;
    au_addr(&a, argv[1]);
    if (au_bind_to(s, &a) || U(listen)(s, 1)) return 5;
    ev = OpenEventA(EVENT_MODIFY_STATE, FALSE, argv[2]);
    if (!ev) return 6;
    SetEvent(ev);
    if (!au_readable(s, 8000)) return 7;
    c = U(accept)(s, NULL, NULL);
    if (c == INVALID_SOCKET) return 8;
    au_rcvtimeo(c, 8000);
    n = U(recv)(c, b, sizeof(b), 0);
    if (n <= 0) return 9;
    U(send)(c, b, n, 0);
    U(shutdown)(c, SD_SEND);
    U(closesocket)(c);
    U(closesocket)(s);
    DeleteFileA(argv[1]);
    return 0;
}

TEST(afu_proc_child_server_echo)
{
    SOCKADDR_UN a;
    char args[MAX_PATH + 64], evname[64], b[16] = {0};
    HANDLE ev, ch;
    PROCESS_INFORMATION pi;
    SOCKET c;
    DWORD rc = 1;
    UP();
    c = au_sock();
    if (c == INVALID_SOCKET) return;
    au_addr_leaf(&a, "child_srv.sock");
    snprintf(evname, sizeof(evname), "ws2t_afu_%lu", GetCurrentProcessId());
    ev = CreateEventA(NULL, TRUE, FALSE, evname);
    snprintf(args, sizeof(args), "\"%s\" %s", a.sun_path, evname);
    ch = t_spawn_child("afu_echo_server", args, 0, NULL, NULL, NULL, FALSE, NULL, &pi);
    if (!ch) { t_skip("spawn"); U(closesocket)(c); CloseHandle(ev); return; }
    if (WaitForSingleObject(ev, 10000) == WAIT_OBJECT_0) {
        AU_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), 0);
        au_rcvtimeo(c, 5000);
        AU_EQ(U(send)(c, "ping-pong", 9, 0), 9);
        AU_EQ(au_recv_n(c, b, 9), 9);
        CHECK(!memcmp(b, "ping-pong", 9));
        AU_EQ(U(recv)(c, b, 4, 0), 0);
    } else CHECK(0);
    if (WaitForSingleObject(ch, 10000) != WAIT_OBJECT_0) TerminateProcess(ch, 1);
    GetExitCodeProcess(ch, &rc);
    AU_EQ(rc, 0);
    CloseHandle(pi.hThread); CloseHandle(ch); CloseHandle(ev);
    U(closesocket)(c);
    DeleteFileA(a.sun_path);
}

/* Child that accepts on an inherited listener handle (value passed on the command line). */
CHILD(afu_inherited_accept)
{
    WSADATA d;
    SOCKET lis, c;
    unsigned long long hv;
    if (argc < 2) return 2;
    hv = _strtoui64(argv[1], NULL, 10);
    lis = (SOCKET)(ULONG_PTR)hv;
    if (U(WSAStartup)(MAKEWORD(2, 2), &d)) return 3;
    if (!au_readable(lis, 8000)) return 4;
    c = U(accept)(lis, NULL, NULL);
    if (c == INVALID_SOCKET) return 5;
    if (U(send)(c, "kid", 3, 0) != 3) return 6;
    U(shutdown)(c, SD_SEND);
    U(closesocket)(c);
    return 0;
}

TEST(afu_proc_inherited_listener_accepts_in_child)
{
    SOCKADDR_UN a;
    SOCKET c;
    char args[64], b[8] = {0};
    PROCESS_INFORMATION pi;
    HANDLE ch;
    DWORD rc = 1;
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "inherit.sock", &a), 0);
    AU_EQ(U(listen)(lis, 2), 0);
    snprintf(args, sizeof(args), "%llu", (unsigned long long)(ULONG_PTR)lis);
    ch = t_spawn_child("afu_inherited_accept", args, 0, NULL, NULL, NULL, TRUE, NULL, &pi);
    if (!ch) { t_skip("spawn"); U(closesocket)(lis); au_unlink_leaf("inherit.sock"); return; }
    c = au_sock();
    AU_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), 0);
    au_rcvtimeo(c, 8000);
    AU_EQ(au_recv_n(c, b, 3), 3);
    CHECK(!memcmp(b, "kid", 3));
    if (WaitForSingleObject(ch, 10000) != WAIT_OBJECT_0) TerminateProcess(ch, 1);
    GetExitCodeProcess(ch, &rc);
    AU_EQ(rc, 0);
    CloseHandle(pi.hThread); CloseHandle(ch);
    U(closesocket)(c); U(closesocket)(lis);
    au_unlink_leaf("inherit.sock");
}

TEST(afu_proc_no_inherit_flag_blocks_child_use)
{
    SOCKADDR_UN a;
    char args[64];
    PROCESS_INFORMATION pi;
    HANDLE ch;
    DWORD rc = 1;
    UP();
    SOCK_OR_RETURN(lis0);
    U(closesocket)(lis0);
    SOCKET lis = au_sock_flags(WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    AU_EQ(au_bind_leaf(lis, "noinherit.sock", &a), 0);
    AU_EQ(U(listen)(lis, 2), 0);
    snprintf(args, sizeof(args), "%llu", (unsigned long long)(ULONG_PTR)lis);
    ch = t_spawn_child("afu_inherited_accept", args, 0, NULL, NULL, NULL, TRUE, NULL, &pi);
    if (!ch) { t_skip("spawn"); U(closesocket)(lis); au_unlink_leaf("noinherit.sock"); return; }
    if (WaitForSingleObject(ch, 15000) != WAIT_OBJECT_0) TerminateProcess(ch, 1);
    GetExitCodeProcess(ch, &rc);
    /* The child could not use the handle: it never reached the successful exit. */
    CHECK(rc != 0);
    CloseHandle(pi.hThread); CloseHandle(ch);
    U(closesocket)(lis);
    au_unlink_leaf("noinherit.sock");
}
