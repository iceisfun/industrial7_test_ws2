/* Peer identity and credential-style queries on AF_UNIX: the vendor ioctl that returns the peer process id
 * (on connected sockets only, with a strict output-buffer protocol), and the family of credential-ish socket
 * options other systems offer, which this stack does not have (exact error). Includes a real second process. */
#include "xud.h"

static int peer_pid(SOCKET s, DWORD *pid, DWORD *ret, void *out, DWORD outlen, DWORD *bytes_ptr_null_flag)
{
    DWORD dummy = 0;
    (void)bytes_ptr_null_flag;
    *pid = 0xdeadbeef;
    *ret = 0xfeedf00d;
    (void)dummy;
    return U(WSAIoctl)(s, SIO_AF_UNIX_GETPEERPID, NULL, 0, out, outlen, ret, NULL, NULL);
}

TEST(xud_peer_ioctl_code_value)
{
    XEQ(SIO_AF_UNIX_GETPEERPID, 0x58000100);
}
TEST(xud_peer_pid_client_sees_own_process)
{
    DWORD pid = 0, ret = 0;
    TRIO(t, "pp1.sock");
    XEQ(peer_pid(t.cli, &pid, &ret, &pid, sizeof pid, NULL), 0);
    XEQ(pid, GetCurrentProcessId());          /* both ends live in this process */
    x_trio_close(&t);
}
TEST(xud_peer_pid_accepted_sees_own_process)
{
    DWORD pid = 0, ret = 0;
    TRIO(t, "pp2.sock");
    XEQ(peer_pid(t.srv, &pid, &ret, &pid, sizeof pid, NULL), 0);
    XEQ(pid, GetCurrentProcessId());
    x_trio_close(&t);
}
TEST(xud_peer_pid_listener_is_opnotsupp)
{
    DWORD pid = 0x1234, ret = 0;
    TRIO(t, "pp3.sock");
    XEQ(peer_pid(t.lis, &pid, &ret, &pid, sizeof pid, NULL), -1);
    XEQ(x_err(), WSAEOPNOTSUPP);
    XEQ(pid, 0xdeadbeef + 0);                 /* helper sets a poison value; the call must not write it */
    x_trio_close(&t);
}
TEST(xud_peer_pid_unconnected_is_opnotsupp)
{
    DWORD pid = 0, ret = 0;
    SOCK_OR_RETURN(s);
    XEQ(peer_pid(s, &pid, &ret, &pid, sizeof pid, NULL), -1);
    XEQ(x_err(), WSAEOPNOTSUPP);
    U(closesocket)(s);
}
TEST(xud_peer_pid_bound_unconnected_is_opnotsupp)
{
    DWORD pid = 0, ret = 0;
    SOCKADDR_UN a;
    SOCK_OR_RETURN(s);
    x_addr(&a, x_path("pp4.sock"));
    XEQ(x_bind(s, &a), 0);
    XEQ(peer_pid(s, &pid, &ret, &pid, sizeof pid, NULL), -1);
    XEQ(x_err(), WSAEOPNOTSUPP);
    U(closesocket)(s);
    DeleteFileA(a.sun_path);
}
TEST(xud_peer_pid_output_two_bytes_is_inval)
{
    char buf[16];
    DWORD pid, ret;
    TRIO(t, "pp5.sock");
    memset(buf, 0x5a, sizeof buf);
    XEQ(peer_pid(t.cli, &pid, &ret, buf, 2, NULL), -1);
    XEQ(x_err(), WSAEINVAL);
    XEQ((unsigned char)buf[0], 0x5a);
    x_trio_close(&t);
}
TEST(xud_peer_pid_output_three_bytes_is_inval)
{
    char buf[16];
    DWORD pid, ret;
    TRIO(t, "pp6.sock");
    XEQ(peer_pid(t.cli, &pid, &ret, buf, 3, NULL), -1);
    XEQ(x_err(), WSAEINVAL);
    x_trio_close(&t);
}
TEST(xud_peer_pid_no_output_buffer_is_inval)
{
    DWORD pid, ret;
    TRIO(t, "pp7.sock");
    XEQ(peer_pid(t.cli, &pid, &ret, NULL, 0, NULL), -1);
    XEQ(x_err(), WSAEINVAL);
    x_trio_close(&t);
}
TEST(xud_peer_pid_output_larger_than_four_only_writes_four)
{
    unsigned char buf[16];
    DWORD pid, ret;
    TRIO(t, "pp8.sock");
    memset(buf, 0x5a, sizeof buf);
    XEQ(peer_pid(t.cli, &pid, &ret, buf, 16, NULL), 0);
    XEQ(*(DWORD *)buf, GetCurrentProcessId());
    XEQ(buf[4], 0x5a);
    XEQ(buf[15], 0x5a);
    x_trio_close(&t);
}
TEST(xud_peer_pid_input_buffer_is_ignored)
{
    DWORD pid = 0, ret = 0;
    char in[4] = { 1, 2, 3, 4 };
    TRIO(t, "pp9.sock");
    XEQ(U(WSAIoctl)(t.cli, SIO_AF_UNIX_GETPEERPID, in, sizeof in, &pid, sizeof pid, &ret, NULL, NULL), 0);
    XEQ(pid, GetCurrentProcessId());
    x_trio_close(&t);
}
TEST(xud_peer_pid_null_bytes_returned_is_fault)
{
    DWORD pid = 0;
    TRIO(t, "pp10.sock");
    XEQ(U(WSAIoctl)(t.cli, SIO_AF_UNIX_GETPEERPID, NULL, 0, &pid, sizeof pid, NULL, NULL, NULL), -1);
    XEQ(x_err(), WSAEFAULT);
    x_trio_close(&t);
}
TEST(xud_peer_pid_after_close_is_notsock)
{
    DWORD pid, ret;
    TRIO(t, "pp11.sock");
    U(closesocket)(t.cli);
    XEQ(peer_pid(t.cli, &pid, &ret, &pid, sizeof pid, NULL), -1);
    XEQ(x_err(), WSAENOTSOCK);
    t.cli = INVALID_SOCKET;
    x_trio_close(&t);
}
TEST(xud_peer_pid_still_answers_after_peer_closed)
{
    DWORD pid = 0, ret = 0;
    TRIO(t, "pp12.sock");
    U(closesocket)(t.srv);
    t.srv = INVALID_SOCKET;
    {
        XEQ(peer_pid(t.cli, &pid, &ret, &pid, sizeof pid, NULL), 0);
        XEQ(pid, GetCurrentProcessId());
    }
    x_trio_close(&t);
}
TEST(xud_peer_pid_not_available_on_tcp_socket)
{
    DWORD pid = 0, ret = 0;
    SOCKET s;
    UP();
    s = U(WSASocketW)(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) { t_skip("no TCP socket"); return; }
    XEQ(peer_pid(s, &pid, &ret, &pid, sizeof pid, NULL), -1);
    CHECK(x_err() != 0);
    U(closesocket)(s);
}

/* ---- a second process: the accepted socket reports the child's id, the child's socket reports ours ---- */
CHILD(xud_peer_child)
{
    SOCKET s;
    SOCKADDR_UN a;
    WSADATA d;
    DWORD pid = 0, ret = 0;
    char b;
    int rc = 0;
    if (argc < 2) return 90;
    if (U(WSAStartup)(MAKEWORD(2, 2), &d)) return 91;
    s = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) return 92;
    x_addr(&a, argv[1]);
    if (U(connect)(s, (struct sockaddr *)&a, sizeof a)) return 93;
    if (U(send)(s, "k", 1, 0) != 1) return 94;
    if (U(recv)(s, &b, 1, 0) != 1) return 95;
    if (U(WSAIoctl)(s, SIO_AF_UNIX_GETPEERPID, NULL, 0, &pid, sizeof pid, &ret, NULL, NULL)) return 96;
    /* the parent's id is the pid it sent back as payload after the ack: read 4 bytes */
    {
        DWORD parent = 0;
        if (U(recv)(s, (char *)&parent, 4, 0) != 4) return 97;
        rc = (pid == parent) ? 0 : 98;
    }
    U(closesocket)(s);
    return rc;
}
TEST(xud_peer_pid_two_processes)
{
    SOCKET lis, srv;
    SOCKADDR_UN a;
    PROCESS_INFORMATION pi;
    HANDLE h;
    DWORD pid = 0, ret = 0, code = 0xffff;
    char b = 0, arg[MAX_PATH];
    UP();
    lis = x_sock();
    if (lis == INVALID_SOCKET) return;
    x_addr(&a, x_path("pp_two.sock"));
    if (x_bind(lis, &a) || U(listen)(lis, 2)) { t_skip("cannot listen"); U(closesocket)(lis); return; }
    snprintf(arg, sizeof arg, "%s", a.sun_path);
    h = t_spawn_child("xud_peer_child", arg, 0, NULL, NULL, NULL, FALSE, NULL, &pi);
    if (!h) { t_skip("cannot start child"); U(closesocket)(lis); DeleteFileA(a.sun_path); return; }
    srv = x_accept_wait(lis);
    CHECK(srv != INVALID_SOCKET);
    if (srv != INVALID_SOCKET) {
        x_rcvtimeo(srv, 5000);
        XEQ(U(recv)(srv, &b, 1, 0), 1);
        XEQ(peer_pid(srv, &pid, &ret, &pid, sizeof pid, NULL), 0);
        XEQ(pid, pi.dwProcessId);                 /* the accepted socket names the child */
        CHECK(pid != GetCurrentProcessId());
        XEQ(U(send)(srv, "a", 1, 0), 1);
        {
            DWORD me = GetCurrentProcessId();
            XEQ(U(send)(srv, (char *)&me, 4, 0), 4);
        }
        U(closesocket)(srv);
    }
    if (WaitForSingleObject(h, 8000) != WAIT_OBJECT_0) { TerminateProcess(h, 1); code = 0xdead; }
    else GetExitCodeProcess(h, &code);
    XEQ(code, 0);                                 /* the child's own query returned our id */
    CloseHandle(pi.hThread);
    CloseHandle(h);
    U(closesocket)(lis);
    DeleteFileA(a.sun_path);
}

/* ---- credential-like socket options: not present ---- */
static void opt_row(int level, int opt, int want_ok)
{
    char v[64];
    int l = sizeof v, r, e;
    TRIO(t, "po.sock");
    memset(v, 0xab, sizeof v);
    r = U(getsockopt)(t.cli, level, opt, v, &l);
    e = r ? x_err() : 0;
    if (want_ok) {
        XEQ(r, 0);
    } else {
        XEQ(r, -1);
        XEQ(e, WSAENOPROTOOPT);
    }
    x_trio_close(&t);
}
/* Linux-style names and values: SO_PEERCRED 17, SO_PEERSEC 31, SO_PASSCRED 16, SO_PEERNAME 28, SO_PEERGROUPS 59 */
TEST(xud_peer_opt_so_peercred_17) { opt_row(SOL_SOCKET, 17, 0); }
TEST(xud_peer_opt_so_passcred_16) { opt_row(SOL_SOCKET, 16, 0); }
TEST(xud_peer_opt_so_peersec_31) { opt_row(SOL_SOCKET, 31, 0); }
TEST(xud_peer_opt_so_peername_28) { opt_row(SOL_SOCKET, 28, 0); }
TEST(xud_peer_opt_so_peergroups_59) { opt_row(SOL_SOCKET, 59, 0); }
TEST(xud_peer_opt_zero) { opt_row(SOL_SOCKET, 0, 0); }

static void sweep_solsocket_low(void)
{
    int opt;
    TRIO(t, "po2.sock");
    for (opt = 0; opt <= 0x30; opt++) {
        char v[64];
        int l = sizeof v;
        int r = U(getsockopt)(t.cli, SOL_SOCKET, opt, v, &l);
        int e = r ? x_err() : 0;
        int ok = (opt == SO_DEBUG || opt == SO_ACCEPTCONN || opt == SO_REUSEADDR);
        t_check(ok ? r == 0 : (r == -1 && e == WSAENOPROTOOPT), __FILE__, __LINE__, "sol_socket low option", "opt %d r=%d e=%d", opt, r, e);
    }
    x_trio_close(&t);
}
TEST(xud_peer_opt_solsocket_low_sweep) { sweep_solsocket_low(); }

static void sweep_level(int level)
{
    int opt;
    TRIO(t, "po3.sock");
    for (opt = 0; opt <= 0x30; opt++) {
        char v[64];
        int l = sizeof v;
        int r = U(getsockopt)(t.cli, level, opt, v, &l);
        int e = r ? x_err() : 0;
        t_check(r == -1 && e == WSAENOPROTOOPT, __FILE__, __LINE__, "foreign level option", "level %d opt %d r=%d e=%d", level, opt, r, e);
    }
    x_trio_close(&t);
}
TEST(xud_peer_opt_level_ip_sweep) { sweep_level(IPPROTO_IP); }
TEST(xud_peer_opt_level_tcp_sweep) { sweep_level(IPPROTO_TCP); }
TEST(xud_peer_opt_level_udp_sweep) { sweep_level(IPPROTO_UDP); }
TEST(xud_peer_opt_level_ipv6_sweep) { sweep_level(IPPROTO_IPV6); }
TEST(xud_peer_opt_level_255_sweep) { sweep_level(255); }
TEST(xud_peer_opt_level_fffe_sweep) { sweep_level(0xfffe); }
