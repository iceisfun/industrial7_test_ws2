/* AF_UNIX sockets as kernel handles: DuplicateHandle inside a process and into a child, handle inheritance into
 * a child process, WSADuplicateSocket hand-over, and who keeps the connection alive. The peer only sees end of
 * stream once every duplicate of a socket has been closed. */
#include "xud.h"

/* ---- same process: duplicate handle ---- */
static HANDLE dup_self(SOCKET s)
{
    HANDLE d = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &d, 0, FALSE, DUPLICATE_SAME_ACCESS)) return NULL;
    return d;
}
TEST(xud_dup_handle_carries_data)
{
    HANDLE d;
    char b[8] = { 0 };
    TRIO(t, "dh1.sock");
    d = dup_self(t.cli);
    CHECK(d != NULL);
    if (d) {
        XEQ(U(send)((SOCKET)d, "dup", 3, 0), 3);
        XEQ(x_recv_n(t.srv, b, 3), 3);
        CHECK(!memcmp(b, "dup", 3));
        XEQ(U(closesocket)((SOCKET)d), 0);
    }
    x_trio_close(&t);
}
TEST(xud_dup_handle_is_a_different_value)
{
    HANDLE d;
    TRIO(t, "dh2.sock");
    d = dup_self(t.cli);
    CHECK(d != NULL);
    if (d) {
        XNE(d, t.cli);
        U(closesocket)((SOCKET)d);
    }
    x_trio_close(&t);
}
TEST(xud_dup_handle_timeouts_are_per_handle)
{
    HANDLE d;
    DWORD ms = 1234, got = 0;
    int l = sizeof got;
    TRIO(t, "dh3.sock");
    d = dup_self(t.cli);
    CHECK(d != NULL);
    if (d) {
        XEQ(U(setsockopt)((SOCKET)d, SOL_SOCKET, SO_RCVTIMEO, (char *)&ms, sizeof ms), 0);
        XEQ(U(getsockopt)(t.cli, SOL_SOCKET, SO_RCVTIMEO, (char *)&got, &l), 0);
        XEQ(got, 3000);                    /* the original keeps the value the fixture gave it: timeouts live in per-handle state */
        l = sizeof got;
        XEQ(U(getsockopt)((SOCKET)d, SOL_SOCKET, SO_RCVTIMEO, (char *)&got, &l), 0);
        XEQ(got, 1234);
        U(closesocket)((SOCKET)d);
    }
    x_trio_close(&t);
}
TEST(xud_dup_handle_original_close_keeps_connection)
{
    HANDLE d;
    char b[4];
    TRIO(t, "dh4.sock");
    d = dup_self(t.cli);
    CHECK(d != NULL);
    if (d) {
        XEQ(U(closesocket)(t.cli), 0);
        t.cli = INVALID_SOCKET;
        CHECK(!x_readable(t.srv, 300));                       /* no end of stream yet */
        XEQ(U(send)((SOCKET)d, "x", 1, 0), 1);
        XEQ(x_recv_n(t.srv, b, 1), 1);
        XEQ(U(closesocket)((SOCKET)d), 0);
        CHECK(x_readable(t.srv, 3000));                       /* now it is gone */
        XEQ(U(recv)(t.srv, b, 1, 0), 0);
    }
    x_trio_close(&t);
}
TEST(xud_dup_handle_duplicate_close_keeps_connection)
{
    HANDLE d;
    char b[4];
    TRIO(t, "dh5.sock");
    d = dup_self(t.cli);
    CHECK(d != NULL);
    if (d) {
        XEQ(U(closesocket)((SOCKET)d), 0);
        CHECK(!x_readable(t.srv, 300));
        XEQ(U(send)(t.cli, "y", 1, 0), 1);
        XEQ(x_recv_n(t.srv, b, 1), 1);
    }
    x_trio_close(&t);
}
TEST(xud_dup_handle_wsa_duplicate_into_same_process)
{
    WSAPROTOCOL_INFOW pi;
    SOCKET d;
    char b[4] = { 0 };
    TRIO(t, "dh6.sock");
    memset(&pi, 0, sizeof pi);
    if (U(WSADuplicateSocketW)(t.cli, GetCurrentProcessId(), &pi)) {
        OBS("WSADuplicateSocketW to self: error %d", x_err());
        x_trio_close(&t);
        return;
    }
    d = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi, 0, WSA_FLAG_OVERLAPPED);
    CHECK(d != INVALID_SOCKET);
    if (d != INVALID_SOCKET) {
        XEQ(U(send)(d, "w", 1, 0), 1);
        XEQ(x_recv_n(t.srv, b, 1), 1);
        U(closesocket)(d);
    }
    x_trio_close(&t);
}
TEST(xud_dup_handle_wsa_duplicate_info_fields)
{
    WSAPROTOCOL_INFOW pi;
    TRIO(t, "dh7.sock");
    memset(&pi, 0, sizeof pi);
    XEQ(U(WSADuplicateSocketW)(t.cli, GetCurrentProcessId(), &pi), 0);
    XEQ(pi.iAddressFamily, AF_UNIX);
    XEQ(pi.iSocketType, SOCK_STREAM);
    XEQ(pi.iProtocol, 0);
    x_trio_close(&t);
}

/* ---- inheritance into a child ---- */
CHILD(xud_dup_child_echo)
{
    SOCKET s;
    WSADATA d;
    char b[64];
    int n;
    if (argc < 2) return 90;
    if (U(WSAStartup)(MAKEWORD(2, 2), &d)) return 91;
    s = (SOCKET)(ULONG_PTR)strtoull(argv[1], NULL, 10);
    {
        DWORD to = 5000;
        U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof to);
    }
    n = U(recv)(s, b, sizeof b, 0);
    if (n <= 0) return 100 + (n < 0);
    if (U(send)(s, b, n, 0) != n) return 102;
    if (argc > 2 && argv[2][0] == 'c') U(closesocket)(s);
    return 0;
}
static DWORD run_inherit(SOCKET child_sock, const char *mode, PROCESS_INFORMATION *pi, HANDLE *h)
{
    char args[64];
    snprintf(args, sizeof args, "%llu %s", (unsigned long long)child_sock, mode);
    *h = t_spawn_child("xud_dup_child_echo", args, 0, NULL, NULL, NULL, TRUE, NULL, pi);
    return *h ? 0 : 1;
}
TEST(xud_dup_inherit_flag_set_child_echoes)
{
    PROCESS_INFORMATION pi;
    HANDLE h;
    char b[8] = { 0 };
    DWORD code = 0xffff;
    TRIO(t, "in1.sock");
    SetHandleInformation((HANDLE)t.srv, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    if (run_inherit(t.srv, "", &pi, &h)) { t_skip("cannot start child"); x_trio_close(&t); return; }
    XEQ(U(send)(t.cli, "ping", 4, 0), 4);
    XEQ(x_recv_n(t.cli, b, 4), 4);
    CHECK(!memcmp(b, "ping", 4));
    if (WaitForSingleObject(h, 8000) != WAIT_OBJECT_0) { TerminateProcess(h, 1); code = 0xdead; } else GetExitCodeProcess(h, &code);
    XEQ(code, 0);
    CloseHandle(pi.hThread); CloseHandle(h);
    x_trio_close(&t);
}
TEST(xud_dup_inherit_child_exit_does_not_close_parent_copy)
{
    PROCESS_INFORMATION pi;
    HANDLE h;
    char b[8] = { 0 };
    TRIO(t, "in2.sock");
    SetHandleInformation((HANDLE)t.srv, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    if (run_inherit(t.srv, "c", &pi, &h)) { t_skip("cannot start child"); x_trio_close(&t); return; }
    XEQ(U(send)(t.cli, "one", 3, 0), 3);
    XEQ(x_recv_n(t.cli, b, 3), 3);
    WaitForSingleObject(h, 8000);
    CHECK(!x_readable(t.cli, 300));                    /* the parent still holds the server end */
    XEQ(U(send)(t.cli, "two", 3, 0), 3);
    XEQ(x_recv_n(t.srv, b, 3), 3);
    CHECK(!memcmp(b, "two", 3));
    CloseHandle(pi.hThread); CloseHandle(h);
    x_trio_close(&t);
}
TEST(xud_dup_inherit_parent_close_child_keeps_connection)
{
    PROCESS_INFORMATION pi;
    HANDLE h;
    char b[8] = { 0 };
    DWORD code = 0xffff;
    SOCKET srv;
    TRIO(t, "in3.sock");
    srv = t.srv;
    SetHandleInformation((HANDLE)srv, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    if (run_inherit(srv, "", &pi, &h)) { t_skip("cannot start child"); x_trio_close(&t); return; }
    Sleep(300);                                         /* the child is up and blocked in recv */
    XEQ(U(closesocket)(srv), 0);                        /* parent gives up its copy */
    t.srv = INVALID_SOCKET;
    CHECK(!x_readable(t.cli, 300));                     /* connection lives in the child */
    XEQ(U(send)(t.cli, "late", 4, 0), 4);
    XEQ(x_recv_n(t.cli, b, 4), 4);
    CHECK(!memcmp(b, "late", 4));
    if (WaitForSingleObject(h, 8000) != WAIT_OBJECT_0) { TerminateProcess(h, 1); code = 0xdead; } else GetExitCodeProcess(h, &code);
    XEQ(code, 0);
    CloseHandle(pi.hThread); CloseHandle(h);
    x_trio_close(&t);
}
TEST(xud_dup_inherit_flag_clear_child_cannot_use)
{
    PROCESS_INFORMATION pi;
    HANDLE h;
    DWORD code = 0xffff;
    TRIO(t, "in4.sock");
    SetHandleInformation((HANDLE)t.srv, HANDLE_FLAG_INHERIT, 0);
    if (run_inherit(t.srv, "", &pi, &h)) { t_skip("cannot start child"); x_trio_close(&t); return; }
    /* the child's attempt to use the numeric handle value fails; it exits with the recv failure code */
    XEQ(U(send)(t.cli, "zzzz", 4, 0), 4);
    if (WaitForSingleObject(h, 8000) != WAIT_OBJECT_0) { TerminateProcess(h, 1); code = 0xdead; } else GetExitCodeProcess(h, &code);
    XEQ(code, 101);
    CloseHandle(pi.hThread); CloseHandle(h);
    x_trio_close(&t);
}

/* ---- DuplicateHandle into the child, and WSADuplicateSocket ---- */
TEST(xud_dup_into_child_process_by_duplicatehandle)
{
    PROCESS_INFORMATION pi;
    HANDLE h, dup = NULL;
    char b[8] = { 0 }, args[64];
    DWORD code = 0xffff;
    TRIO(t, "in5.sock");
    h = t_spawn_child("xud_dup_child_echo", "0", CREATE_SUSPENDED, NULL, NULL, NULL, FALSE, NULL, &pi);
    if (!h) { t_skip("cannot start child"); x_trio_close(&t); return; }
    if (!DuplicateHandle(GetCurrentProcess(), (HANDLE)t.srv, h, &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        OBS("DuplicateHandle into child failed: %lu", GetLastError());
        TerminateProcess(h, 0); CloseHandle(pi.hThread); CloseHandle(h);
        x_trio_close(&t);
        return;
    }
    TerminateProcess(h, 0);                             /* this child was only a handle target */
    CloseHandle(pi.hThread); CloseHandle(h);
    (void)args; (void)b; (void)code;
    x_trio_close(&t);
}

CHILD(xud_dup_child_import)
{
    WSAPROTOCOL_INFOW pi;
    SOCKET s;
    WSADATA d;
    char b[16];
    int n, i;
    HANDLE f = INVALID_HANDLE_VALUE;
    DWORD got = 0;
    if (argc < 2) return 90;
    if (U(WSAStartup)(MAKEWORD(2, 2), &d)) return 91;
    for (i = 0; i < 100 && f == INVALID_HANDLE_VALUE; i++) {   /* the parent writes the file after we start */
        f = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (f == INVALID_HANDLE_VALUE) Sleep(50);
    }
    if (f == INVALID_HANDLE_VALUE) return 92;
    for (i = 0; i < 100; i++) {
        SetFilePointer(f, 0, NULL, FILE_BEGIN);
        if (ReadFile(f, &pi, sizeof pi, &got, NULL) && got == sizeof pi) break;
        Sleep(50);
    }
    CloseHandle(f);
    if (got != sizeof pi) return 93;
    s = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi, 0, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) return 94;
    {
        DWORD to = 5000;
        U(setsockopt)(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof to);
    }
    n = U(recv)(s, b, sizeof b, 0);
    if (n <= 0) return 95;
    if (U(send)(s, b, n, 0) != n) return 96;
    U(closesocket)(s);
    return 0;
}
TEST(xud_dup_wsaduplicatesocket_into_child)
{
    PROCESS_INFORMATION pi;
    HANDLE h, f;
    WSAPROTOCOL_INFOW info;
    char b[8] = { 0 };
    DWORD code = 0xffff, wr = 0;
    char fp[MAX_PATH];
    TRIO(t, "in6.sock");
    snprintf(fp, sizeof fp, "%swsadup.bin", t_tmpdir());
    h = t_spawn_child("xud_dup_child_import", fp, 0, NULL, NULL, NULL, FALSE, NULL, &pi);
    if (!h) { t_skip("cannot start child"); x_trio_close(&t); return; }
    memset(&info, 0, sizeof info);
    XEQ(U(WSADuplicateSocketW)(t.srv, pi.dwProcessId, &info), 0);
    f = CreateFileA(fp, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    CHECK(f != INVALID_HANDLE_VALUE);
    if (f != INVALID_HANDLE_VALUE) { WriteFile(f, &info, sizeof info, &wr, NULL); CloseHandle(f); }
    XEQ(U(send)(t.cli, "hand", 4, 0), 4);
    XEQ(x_recv_n(t.cli, b, 4), 4);
    CHECK(!memcmp(b, "hand", 4));
    if (WaitForSingleObject(h, 8000) != WAIT_OBJECT_0) { TerminateProcess(h, 1); code = 0xdead; } else GetExitCodeProcess(h, &code);
    XEQ(code, 0);
    CloseHandle(pi.hThread); CloseHandle(h);
    DeleteFileA(fp);
    CHECK(!x_readable(t.cli, 300));              /* parent's own handle keeps the connection after the child left */
    x_trio_close(&t);
}
TEST(xud_dup_wsaduplicatesocket_null_info_is_fault)
{
    TRIO(t, "in7.sock");
    XEQ(U(WSADuplicateSocketW)(t.cli, GetCurrentProcessId(), NULL), -1);
    XEQ(x_err(), WSAEFAULT);
    x_trio_close(&t);
}
TEST(xud_dup_wsaduplicatesocket_invalid_process_is_inval)
{
    WSAPROTOCOL_INFOW info;
    TRIO(t, "in8.sock");
    memset(&info, 0, sizeof info);
    XEQ(U(WSADuplicateSocketW)(t.cli, 0xfffffff0u, &info), -1);
    XEQ(x_err(), WSAEINVAL);
    x_trio_close(&t);
}
TEST(xud_dup_wsaduplicatesocket_closed_socket_is_notsock)
{
    WSAPROTOCOL_INFOW info;
    TRIO(t, "in9.sock");
    memset(&info, 0, sizeof info);
    U(closesocket)(t.cli);
    XEQ(U(WSADuplicateSocketW)(t.cli, GetCurrentProcessId(), &info), -1);
    XEQ(x_err(), WSAENOTSOCK);
    t.cli = INVALID_SOCKET;
    x_trio_close(&t);
}
