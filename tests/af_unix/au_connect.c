/* AF_UNIX stream sockets: listen, accept and connect. State machine errors (the socket state is checked
 * before the address), backlog handling, the address returned by accept, several queued connections,
 * and the failures of connecting to something that is not a listening socket file. */
#include "au.h"

static int exists_a(const char *p) { return GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES; }

/* ---- listen ---------------------------------------------------------------------------------- */
TEST(afu_listen_after_bind_ok)
{
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "lis1.sock", NULL), 0);
    AU_EQ(U(listen)(s, 1), 0);
    U(closesocket)(s);
    au_unlink_leaf("lis1.sock");
}

TEST(afu_listen_backlog_somaxconn)
{
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "lis_max.sock", NULL), 0);
    AU_EQ(U(listen)(s, SOMAXCONN), 0);
    U(closesocket)(s);
    au_unlink_leaf("lis_max.sock");
}

static void listen_backlog(int bl, const char *leaf)
{
    int r;
    SOCKET s;
    if (!au_up()) return;
    s = au_sock();
    if (s == INVALID_SOCKET) return;
    AU_EQ(au_bind_leaf(s, leaf, NULL), 0);
    r = U(listen)(s, bl);
    AU_EQ(r, 0);
    U(closesocket)(s);
    au_unlink_leaf(leaf);
}
TEST(afu_listen_backlog_zero) { listen_backlog(0, "lis_b0.sock"); }
TEST(afu_listen_backlog_negative) { listen_backlog(-1, "lis_bn.sock"); }
TEST(afu_listen_backlog_large) { listen_backlog(0x7fffffff, "lis_bl.sock"); }
TEST(afu_listen_backlog_hint) { listen_backlog((-200), "lis_bh.sock"); }

TEST(afu_listen_twice_ok)
{
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "lis_twice.sock", NULL), 0);
    AU_EQ(U(listen)(s, 1), 0);
    au_seterr(0);
    int r = U(listen)(s, 2);
    AU_EQ(r, 0);
    U(closesocket)(s);
    au_unlink_leaf("lis_twice.sock");
}

TEST(afu_listen_unbound_socket_is_inval)
{
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    AU_EQ(U(listen)(s, 1), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEINVAL);
    U(closesocket)(s);
}

TEST(afu_listen_on_connected_is_isconn)
{
    TRIO(t, "lis_conn.sock");
    au_seterr(0);
    AU_EQ(U(listen)(t.cli, 1), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEISCONN);
    au_seterr(0);
    AU_EQ(U(listen)(t.srv, 1), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEISCONN);
    au_trio_close(&t);
}

/* ---- accept ---------------------------------------------------------------------------------- */
TEST(afu_accept_unbound_is_inval)
{
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    AU_EQ(U(accept)(s, NULL, NULL), INVALID_SOCKET);
    AU_EQ(au_err(), WSAEINVAL);
    U(closesocket)(s);
}

TEST(afu_accept_bound_not_listening_is_inval)
{
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "acc_nolis.sock", NULL), 0);
    au_seterr(0);
    AU_EQ(U(accept)(s, NULL, NULL), INVALID_SOCKET);
    AU_EQ(au_err(), WSAEINVAL);
    U(closesocket)(s);
    au_unlink_leaf("acc_nolis.sock");
}

TEST(afu_accept_on_connected_is_inval)
{
    TRIO(t, "acc_conn.sock");
    au_seterr(0);
    AU_EQ(U(accept)(t.cli, NULL, NULL), INVALID_SOCKET);
    AU_EQ(au_err(), WSAEINVAL);
    au_seterr(0);
    AU_EQ(U(accept)(t.srv, NULL, NULL), INVALID_SOCKET);
    AU_EQ(au_err(), WSAEINVAL);
    au_trio_close(&t);
}

TEST(afu_accept_nonblocking_empty_is_wouldblock)
{
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "acc_empty.sock", NULL), 0);
    AU_EQ(U(listen)(s, 1), 0);
    AU_EQ(au_blocking(s, FALSE), 0);
    au_seterr(0);
    AU_EQ(U(accept)(s, NULL, NULL), INVALID_SOCKET);
    AU_EQ(au_err(), WSAEWOULDBLOCK);
    U(closesocket)(s);
    au_unlink_leaf("acc_empty.sock");
}

TEST(afu_accept_returns_distinct_connected_socket)
{
    int v = 0, l = sizeof(v);
    TRIO(t, "acc_dist.sock");
    CHECK(t.srv != t.lis);
    CHECK(t.srv != t.cli);
    AU_EQ(U(getsockopt)(t.srv, SOL_SOCKET, SO_TYPE, (char *)&v, &l), 0);
    AU_EQ(v, SOCK_STREAM);
    v = 7; l = sizeof(v);
    AU_EQ(U(getsockopt)(t.srv, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &l), 0);
    AU_EQ(v, 0);
    au_trio_close(&t);
}

TEST(afu_accept_address_is_unnamed_peer)
{
    /* The connecting client never bound a name, so the peer address is family plus an empty path. */
    SOCKADDR_UN a, lis_a;
    SOCKET c, s;
    int l;
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "acc_addr.sock", &lis_a), 0);
    AU_EQ(U(listen)(lis, 2), 0);
    c = au_sock();
    au_blocking(c, FALSE);
    U(connect)(c, (struct sockaddr *)&lis_a, sizeof(lis_a));
    AU_EQ(au_readable(lis, 3000), 1);
    memset(&a, 0x55, sizeof(a)); l = sizeof(a);
    s = U(accept)(lis, (struct sockaddr *)&a, &l);
    CHECK(s != INVALID_SOCKET);
    AU_EQ(a.sun_family, AF_UNIX);
    CHECK(l >= 2 && l <= (int)sizeof(a));
    AU_EQ(l, (int)sizeof(SOCKADDR_UN));
    CHECK(a.sun_path[0] == 0);
    if (s != INVALID_SOCKET) U(closesocket)(s);
    U(closesocket)(c); U(closesocket)(lis);
    au_unlink_leaf("acc_addr.sock");
}

TEST(afu_accept_named_client_reports_client_path)
{
    SOCKADDR_UN a, lis_a, cli_a;
    SOCKET c, s;
    int l;
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "acc_nm_srv.sock", &lis_a), 0);
    AU_EQ(U(listen)(lis, 2), 0);
    c = au_sock();
    AU_EQ(au_bind_leaf(c, "acc_nm_cli.sock", &cli_a), 0);
    au_blocking(c, FALSE);
    U(connect)(c, (struct sockaddr *)&lis_a, sizeof(lis_a));
    AU_EQ(au_readable(lis, 3000), 1);
    memset(&a, 0, sizeof(a)); l = sizeof(a);
    s = U(accept)(lis, (struct sockaddr *)&a, &l);
    CHECK(s != INVALID_SOCKET);
    AU_EQ(a.sun_family, AF_UNIX);
    CHECK(!strcmp(a.sun_path, cli_a.sun_path));
    if (s != INVALID_SOCKET) U(closesocket)(s);
    U(closesocket)(c); U(closesocket)(lis);
    au_unlink_leaf("acc_nm_srv.sock"); au_unlink_leaf("acc_nm_cli.sock");
}

TEST(afu_accept_addrlen_one_is_fault)
{
    SOCKADDR_UN a;
    SOCKET c, s;
    int l = 1;
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "acc_small.sock", &a), 0);
    AU_EQ(U(listen)(lis, 2), 0);
    c = au_sock();
    au_blocking(c, FALSE);
    U(connect)(c, (struct sockaddr *)&a, sizeof(a));
    AU_EQ(au_readable(lis, 3000), 1);
    au_seterr(0);
    s = U(accept)(lis, (struct sockaddr *)&a, &l);
    AU_EQ(s, INVALID_SOCKET);
    AU_EQ(au_err(), WSAEFAULT);
    if (s != INVALID_SOCKET) U(closesocket)(s);
    U(closesocket)(c); U(closesocket)(lis);
    au_unlink_leaf("acc_small.sock");
}

TEST(afu_accept_two_queued_connections_in_order)
{
    SOCKADDR_UN a;
    SOCKET c[2], s[2];
    char b;
    int i;
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "acc_two.sock", &a), 0);
    AU_EQ(U(listen)(lis, 4), 0);
    for (i = 0; i < 2; i++) {
        c[i] = au_sock();
        au_blocking(c[i], FALSE);
        U(connect)(c[i], (struct sockaddr *)&a, sizeof(a));
        AU_EQ(au_readable(lis, 3000), 1);
        s[i] = INVALID_SOCKET;
    }
    s[0] = U(accept)(lis, NULL, NULL);
    s[1] = U(accept)(lis, NULL, NULL);
    CHECK(s[0] != INVALID_SOCKET && s[1] != INVALID_SOCKET);
    for (i = 0; i < 2; i++) {
        au_blocking(c[i], TRUE);
        if (s[i] != INVALID_SOCKET) au_rcvtimeo(s[i], 3000);
    }
    if (s[0] != INVALID_SOCKET && s[1] != INVALID_SOCKET) {
        /* Accept order is connect order: the first accepted socket talks to the first client. */
        AU_EQ(U(send)(c[0], "A", 1, 0), 1);
        AU_EQ(U(send)(c[1], "B", 1, 0), 1);
        b = 0; AU_EQ(U(recv)(s[0], &b, 1, 0), 1); AU_EQ(b, 'A');
        b = 0; AU_EQ(U(recv)(s[1], &b, 1, 0), 1); AU_EQ(b, 'B');
    }
    for (i = 0; i < 2; i++) { if (s[i] != INVALID_SOCKET) U(closesocket)(s[i]); U(closesocket)(c[i]); }
    U(closesocket)(lis);
    au_unlink_leaf("acc_two.sock");
}

TEST(afu_accept_loop_many_clients)
{
    SOCKADDR_UN a;
    int i, ok = 0;
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "acc_loop.sock", &a), 0);
    AU_EQ(U(listen)(lis, 4), 0);
    for (i = 0; i < 12; i++) {
        SOCKET c = au_sock(), s;
        char b = (char)('a' + i), g = 0;
        s = au_connect_accept(lis, c, &a);
        if (s != INVALID_SOCKET) {
            au_rcvtimeo(s, 3000);
            if (U(send)(c, &b, 1, 0) == 1 && U(recv)(s, &g, 1, 0) == 1 && g == b) ok++;
            U(closesocket)(s);
        }
        U(closesocket)(c);
    }
    AU_EQ(ok, 12);
    U(closesocket)(lis);
    au_unlink_leaf("acc_loop.sock");
}

TEST(afu_accept_pending_connection_survives_client_data)
{
    /* Data sent before accept is queued on the connection and delivered after accept. */
    SOCKADDR_UN a;
    SOCKET c, s;
    char b[8] = {0};
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "acc_pre.sock", &a), 0);
    AU_EQ(U(listen)(lis, 2), 0);
    c = au_sock();
    au_blocking(c, FALSE);
    U(connect)(c, (struct sockaddr *)&a, sizeof(a));
    AU_EQ(au_readable(lis, 3000), 1);
    au_blocking(c, TRUE);
    AU_EQ(U(send)(c, "early", 5, 0), 5);
    s = U(accept)(lis, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        au_rcvtimeo(s, 3000);
        AU_EQ(au_recv_n(s, b, 5), 5);
        CHECK(!memcmp(b, "early", 5));
        U(closesocket)(s);
    }
    U(closesocket)(c); U(closesocket)(lis);
    au_unlink_leaf("acc_pre.sock");
}

TEST(afu_accept_closed_client_before_accept)
{
    /* A client that connected and closed before accept is still accepted and shows end of stream. */
    SOCKADDR_UN a;
    SOCKET c, s;
    char b[4];
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "acc_closed.sock", &a), 0);
    AU_EQ(U(listen)(lis, 2), 0);
    c = au_sock();
    au_blocking(c, FALSE);
    U(connect)(c, (struct sockaddr *)&a, sizeof(a));
    AU_EQ(au_readable(lis, 3000), 1);
    U(closesocket)(c);
    s = U(accept)(lis, NULL, NULL);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        au_rcvtimeo(s, 3000);
        AU_EQ(U(recv)(s, b, sizeof(b), 0), 0);
        U(closesocket)(s);
    }
    U(closesocket)(lis);
    au_unlink_leaf("acc_closed.sock");
}

/* ---- connect: socket state first ---------------------------------------------------------------- */
TEST(afu_connect_twice_is_isconn)
{
    SOCKADDR_UN a;
    TRIO(t, "con_twice.sock");
    a = t.addr;
    au_seterr(0);
    AU_EQ(U(connect)(t.cli, (struct sockaddr *)&a, sizeof(a)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEISCONN);
    au_trio_close(&t);
}

TEST(afu_connect_accepted_socket_is_isconn)
{
    SOCKADDR_UN a;
    TRIO(t, "con_acc.sock");
    a = t.addr;
    au_seterr(0);
    AU_EQ(U(connect)(t.srv, (struct sockaddr *)&a, sizeof(a)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEISCONN);
    au_trio_close(&t);
}

TEST(afu_connect_on_listener_is_opnotsupp)
{
    SOCKADDR_UN a;
    TRIO(t, "con_lis.sock");
    a = t.addr;
    au_seterr(0);
    AU_EQ(U(connect)(t.lis, (struct sockaddr *)&a, sizeof(a)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEOPNOTSUPP);
    au_trio_close(&t);
}

TEST(afu_connect_family_checked_before_listener_state)
{
    /* A listening socket given an address of the wrong family reports the family error; an already
     * connected socket reports its state even when the length is too short. */
    SOCKADDR_UN a;
    TRIO(t, "con_order.sock");
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_INET;
    au_seterr(0);
    AU_EQ(U(connect)(t.lis, (struct sockaddr *)&a, sizeof(a)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEAFNOSUPPORT);
    au_seterr(0);
    AU_EQ(U(connect)(t.cli, (struct sockaddr *)&a, 1), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEISCONN);
    au_trio_close(&t);
}

/* ---- connect: address validation --------------------------------------------------------------- */
TEST(afu_connect_len_zero_is_fault)
{
    SOCKADDR_UN a;
    TRIO(t, "con_len0.sock");
    SOCKET c = au_sock();
    a = t.addr;
    au_seterr(0);
    AU_EQ(U(connect)(c, (struct sockaddr *)&a, 0), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    U(closesocket)(c);
    au_trio_close(&t);
}

TEST(afu_connect_len_one_is_fault)
{
    SOCKADDR_UN a;
    TRIO(t, "con_len1.sock");
    SOCKET c = au_sock();
    a = t.addr;
    au_seterr(0);
    AU_EQ(U(connect)(c, (struct sockaddr *)&a, 1), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    U(closesocket)(c);
    au_trio_close(&t);
}

static void connect_family(unsigned short fam)
{
    SOCKADDR_UN a;
    SOCKET c;
    int r;
    if (!au_up()) return;
    c = au_sock();
    if (c == INVALID_SOCKET) return;
    au_addr_leaf(&a, "con_fam.sock");
    a.sun_family = fam;
    au_seterr(0);
    r = U(connect)(c, (struct sockaddr *)&a, sizeof(a));
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(au_err(), WSAEAFNOSUPPORT);
    U(closesocket)(c);
}
TEST(afu_connect_family_unspec) { connect_family(AF_UNSPEC); }
TEST(afu_connect_family_inet) { connect_family(AF_INET); }
TEST(afu_connect_family_inet6) { connect_family(AF_INET6); }
TEST(afu_connect_family_ffff) { connect_family(0xffff); }

TEST(afu_connect_inet_address_on_unix_socket)
{
    struct sockaddr_in in;
    SOCKET c;
    UP();
    c = au_sock();
    if (c == INVALID_SOCKET) return;
    memset(&in, 0, sizeof(in));
    in.sin_family = AF_INET;
    in.sin_addr.s_addr = 0x0100007f;
    in.sin_port = 0x5000;
    au_seterr(0);
    AU_EQ(U(connect)(c, (struct sockaddr *)&in, sizeof(in)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEAFNOSUPPORT);
    U(closesocket)(c);
}

TEST(afu_connect_len_larger_than_struct_is_clamped)
{
    union { SOCKADDR_UN u; char raw[200]; } b;
    SOCKET c, s;
    TRIO(t, "con_big.sock");
    memset(&b, 0, sizeof(b));
    b.u = t.addr;
    c = au_sock();
    au_blocking(c, FALSE);
    int r = U(connect)(c, (struct sockaddr *)&b, (int)sizeof(b));
    CHECKF(r == 0 || au_err() == WSAEWOULDBLOCK, "ret %d err %d", r, au_err());
    s = au_accept_bounded(t.lis);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) U(closesocket)(s);
    U(closesocket)(c);
    au_trio_close(&t);
}

TEST(afu_connect_family_only_address)
{
    /* A bare family names no file: nothing to connect to. */
    SOCKADDR_UN a;
    SOCKET c;
    int r;
    UP();
    c = au_sock();
    if (c == INVALID_SOCKET) return;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    au_seterr(0);
    r = U(connect)(c, (struct sockaddr *)&a, 2);
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(au_err(), WSAEINVAL);
    U(closesocket)(c);
}

TEST(afu_connect_empty_path_full_length)
{
    SOCKADDR_UN a;
    SOCKET c;
    int r;
    UP();
    c = au_sock();
    if (c == INVALID_SOCKET) return;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    au_seterr(0);
    r = U(connect)(c, (struct sockaddr *)&a, sizeof(a));
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(au_err(), WSAEINVAL);
    U(closesocket)(c);
}

/* ---- connect: what is at the path ---------------------------------------------------------------- */
TEST(afu_connect_nonexistent_path_fails)
{
    SOCKADDR_UN a;
    SOCKET c;
    UP();
    c = au_sock();
    if (c == INVALID_SOCKET) return;
    au_addr_leaf(&a, "no_such.sock");
    au_seterr(0);
    AU_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAECONNREFUSED);
    U(closesocket)(c);
}

TEST(afu_connect_missing_directory_fails)
{
    SOCKADDR_UN a;
    char p[MAX_PATH];
    SOCKET c;
    UP();
    c = au_sock();
    if (c == INVALID_SOCKET) return;
    snprintf(p, sizeof(p), "%sno_dir_here\\x.sock", au_path(""));
    au_addr(&a, p);
    au_seterr(0);
    AU_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENETDOWN);
    U(closesocket)(c);
}

TEST(afu_connect_to_regular_file_fails)
{
    SOCKADDR_UN a;
    SOCKET c;
    HANDLE h;
    UP();
    c = au_sock();
    if (c == INVALID_SOCKET) return;
    au_addr_leaf(&a, "reg_file.sock");
    h = CreateFileA(a.sun_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { t_skip("scratch file"); U(closesocket)(c); return; }
    CloseHandle(h);
    au_seterr(0);
    AU_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAECONNREFUSED);
    U(closesocket)(c);
    DeleteFileA(a.sun_path);
}

TEST(afu_connect_to_directory_fails)
{
    SOCKADDR_UN a;
    SOCKET c;
    UP();
    c = au_sock();
    if (c == INVALID_SOCKET) return;
    au_addr_leaf(&a, "dir_target");
    CreateDirectoryA(a.sun_path, NULL);
    au_seterr(0);
    AU_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEINVAL);
    U(closesocket)(c);
    RemoveDirectoryA(a.sun_path);
}

TEST(afu_connect_bound_not_listening_fails)
{
    SOCKADDR_UN a;
    SOCKET c;
    UP();
    SOCK_OR_RETURN(b);
    AU_EQ(au_bind_leaf(b, "bound_only.sock", &a), 0);
    c = au_sock();
    au_seterr(0);
    AU_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAECONNREFUSED);
    U(closesocket)(c); U(closesocket)(b);
    au_unlink_leaf("bound_only.sock");
}

TEST(afu_connect_after_listener_closed_fails)
{
    /* The socket file stays but nobody listens behind it any more. */
    SOCKADDR_UN a;
    SOCKET c;
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "stale.sock", &a), 0);
    AU_EQ(U(listen)(lis, 1), 0);
    U(closesocket)(lis);
    CHECK(exists_a(a.sun_path));
    c = au_sock();
    au_seterr(0);
    AU_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAECONNREFUSED);
    U(closesocket)(c);
    au_unlink_leaf("stale.sock");
}

TEST(afu_connect_after_file_deleted_fails)
{
    SOCKADDR_UN a;
    SOCKET c;
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "deleted.sock", &a), 0);
    AU_EQ(U(listen)(lis, 1), 0);
    if (!DeleteFileA(a.sun_path)) { AU_OBS("delete listening file", "error %lu", GetLastError()); U(closesocket)(lis); return; }
    c = au_sock();
    au_seterr(0);
    AU_EQ(U(connect)(c, (struct sockaddr *)&a, sizeof(a)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAECONNREFUSED);
    U(closesocket)(c); U(closesocket)(lis);
}

TEST(afu_connect_path_spellings_reach_listener)
{
    /* The same listener is reached through forward slashes, a dot component and the extended prefix. */
    char spell[3][MAX_PATH];
    int i;
    TRIO(t, "spell.sock");
    snprintf(spell[0], MAX_PATH, "%s", t.path);
    { char *c; for (c = spell[0]; *c; c++) if (*c == '\\') *c = '/'; }
    snprintf(spell[1], MAX_PATH, "%s.\\spell.sock", au_path(""));
    snprintf(spell[2], MAX_PATH, "\\\\?\\%s", t.path);
    for (i = 0; i < 3; i++) {
        SOCKADDR_UN a;
        SOCKET c = au_sock(), s;
        au_addr(&a, spell[i]);
        s = au_connect_accept(t.lis, c, &a);
        CHECKF(s != INVALID_SOCKET, "spelling %d", i);
        if (s != INVALID_SOCKET) U(closesocket)(s);
        U(closesocket)(c);
    }
    au_trio_close(&t);
}

TEST(afu_connect_relative_path_uses_cwd)
{
    char saved[MAX_PATH];
    SOCKADDR_UN a;
    SOCKET c, s;
    TRIO(t, "rel_target.sock");
    GetCurrentDirectoryA(sizeof(saved), saved);
    SetCurrentDirectoryA(au_path(""));
    au_addr(&a, "rel_target.sock");
    c = au_sock();
    s = au_connect_accept(t.lis, c, &a);
    SetCurrentDirectoryA(saved);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) U(closesocket)(s);
    U(closesocket)(c);
    au_trio_close(&t);
}

TEST(afu_connect_multiple_clients_one_listener)
{
    SOCKET c[3], s[3];
    int i;
    TRIO(t, "multi.sock");
    for (i = 0; i < 3; i++) {
        c[i] = au_sock();
        s[i] = au_connect_accept(t.lis, c[i], &t.addr);
        CHECK(s[i] != INVALID_SOCKET);
    }
    for (i = 0; i < 3; i++) { if (s[i] != INVALID_SOCKET) U(closesocket)(s[i]); U(closesocket)(c[i]); }
    au_trio_close(&t);
}

TEST(afu_connect_client_reusable_after_failed_connect)
{
    SOCKADDR_UN bad;
    SOCKET s;
    TRIO(t, "reuse_cli.sock");
    SOCKET c = au_sock();
    au_addr_leaf(&bad, "reuse_missing.sock");
    AU_EQ(U(connect)(c, (struct sockaddr *)&bad, sizeof(bad)), SOCKET_ERROR);
    s = au_connect_accept(t.lis, c, &t.addr);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) U(closesocket)(s);
    U(closesocket)(c);
    au_trio_close(&t);
}

/* ---- blocking connect with a free backlog slot --------------------------------------------------- */
struct conn_arg { SOCKET c; SOCKADDR_UN a; int ret, err; };
static DWORD WINAPI conn_thread(LPVOID p)
{
    struct conn_arg *ca = (struct conn_arg *)p;
    ca->ret = U(connect)(ca->c, (struct sockaddr *)&ca->a, sizeof(ca->a));
    ca->err = ca->ret ? au_err() : 0;
    return 0;
}
TEST(afu_connect_blocking_completes_with_free_backlog)
{
    struct conn_arg ca;
    HANDLE th;
    DWORD w;
    SOCKET s;
    TRIO(t, "blk.sock");
    memset(&ca, 0, sizeof(ca));
    ca.c = au_sock();
    ca.a = t.addr;
    ca.ret = -2;
    th = CreateThread(NULL, 0, conn_thread, &ca, 0, NULL);
    if (!th) { t_skip("thread"); U(closesocket)(ca.c); au_trio_close(&t); return; }
    w = WaitForSingleObject(th, 3000);
    CHECK(w == WAIT_OBJECT_0);
    s = au_accept_bounded(t.lis);
    if (w != WAIT_OBJECT_0) w = WaitForSingleObject(th, 3000);
    CHECK(w == WAIT_OBJECT_0);
    CloseHandle(th);
    AU_EQ(ca.ret, 0);
    if (s != INVALID_SOCKET) U(closesocket)(s);
    U(closesocket)(ca.c);
    au_trio_close(&t);
}
