/* AF_UNIX stream sockets: bind. Address length and family rules enforced before any file is touched,
 * the path field limits (107 characters plus terminator, 108 unterminated, empty), path spellings that
 * the name-to-file conversion accepts, collisions with existing names, state errors, and name reuse
 * after the socket file is removed. Socket files live in the per-process scratch directory. */
#include "au.h"

static int exists_a(const char *p) { return GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES; }

/* ---- address length and shape -------------------------------------------------------------------- */
TEST(afu_bind_len1_is_fault)
{
    SOCKADDR_UN a;
    UP();
    SOCK_OR_RETURN(s);
    au_addr_leaf(&a, "bind_len1.sock");
    au_seterr(0);
    AU_EQ(U(bind)(s, (struct sockaddr *)&a, 1), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    CHECK(!exists_a(a.sun_path));
    U(closesocket)(s);
}

TEST(afu_bind_negative_len_is_fault)
{
    SOCKADDR_UN a;
    UP();
    SOCK_OR_RETURN(s);
    au_addr_leaf(&a, "bind_neg.sock");
    au_seterr(0);
    AU_EQ(U(bind)(s, (struct sockaddr *)&a, -1), SOCKET_ERROR);
    CHECKF(au_err() == WSAEFAULT || au_err() == WSAEINVAL, "err %d", au_err());
    CHECK(!exists_a(a.sun_path));
    U(closesocket)(s);
}

TEST(afu_bind_null_name_is_fault)
{
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    AU_EQ(U(bind)(s, NULL, (int)sizeof(SOCKADDR_UN)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    U(closesocket)(s);
}

/* The family is validated by the helper: anything but AF_UNIX is refused with the family error. */
static void bind_family(unsigned short fam)
{
    SOCKADDR_UN a;
    SOCKET s;
    if (!au_up()) return;
    s = au_sock();
    if (s == INVALID_SOCKET) return;
    au_addr_leaf(&a, "bind_fam.sock");
    a.sun_family = fam;
    au_seterr(0);
    AU_EQ(au_bind_to(s, &a), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEAFNOSUPPORT);
    CHECK(!exists_a(a.sun_path));
    U(closesocket)(s);
}
TEST(afu_bind_family_unspec) { bind_family(AF_UNSPEC); }
TEST(afu_bind_family_inet) { bind_family(AF_INET); }
TEST(afu_bind_family_inet6) { bind_family(AF_INET6); }
TEST(afu_bind_family_ipx) { bind_family(AF_IPX); }
TEST(afu_bind_family_netbios) { bind_family(AF_NETBIOS); }
TEST(afu_bind_family_2_unix_plus_one) { bind_family(AF_UNIX + 1); }
TEST(afu_bind_family_high_bit) { bind_family(0x8001); }
TEST(afu_bind_family_ffff) { bind_family(0xffff); }

TEST(afu_bind_family_inet_sockaddr_in)
{
    struct sockaddr_in in;
    UP();
    SOCK_OR_RETURN(s);
    memset(&in, 0, sizeof(in));
    in.sin_family = AF_INET;
    in.sin_addr.s_addr = 0x0100007f;
    au_seterr(0);
    AU_EQ(U(bind)(s, (struct sockaddr *)&in, sizeof(in)), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEAFNOSUPPORT);
    U(closesocket)(s);
}

TEST(afu_bind_unix_address_on_tcp_socket_refused)
{
    SOCKADDR_UN a;
    SOCKET t;
    UP();
    { SOCKET p = au_sock(); if (p == INVALID_SOCKET) return; U(closesocket)(p); }
    t = U(socket)(AF_INET, SOCK_STREAM, 0);
    if (t == INVALID_SOCKET) { t_skip("no tcp"); return; }
    au_addr_leaf(&a, "bind_on_tcp.sock");
    au_seterr(0);
    AU_EQ(au_bind_to(t, &a), SOCKET_ERROR);
    CHECKF(au_err() == WSAEAFNOSUPPORT || au_err() == WSAEFAULT || au_err() == WSAEINVAL, "err %d", au_err());
    CHECK(!exists_a(a.sun_path));
    U(closesocket)(t);
}

TEST(afu_bind_len_larger_than_struct_is_clamped)
{
    /* A name length above the maximum address size is cut down to it: a 200 byte buffer starting with a
     * valid SOCKADDR_UN binds. */
    union { SOCKADDR_UN u; char raw[200]; } b;
    SOCKADDR_UN got;
    int l = sizeof(got);
    UP();
    SOCK_OR_RETURN(s);
    memset(&b, 0, sizeof(b));
    au_addr_leaf(&b.u, "bind_big.sock");
    AU_EQ(U(bind)(s, (struct sockaddr *)&b, (int)sizeof(b)), 0);
    CHECK(exists_a(b.u.sun_path));
    AU_EQ(U(getsockname)(s, (struct sockaddr *)&got, &l), 0);
    CHECK(!strcmp(got.sun_path, b.u.sun_path));
    U(closesocket)(s);
    au_unlink_leaf("bind_big.sock");
}

TEST(afu_bind_len_between_family_and_full)
{
    /* Length 2 + n names the first n bytes of the path (the rest is ignored even when present). */
    SOCKADDR_UN a, got;
    char want[MAX_PATH];
    int l = sizeof(got), plen;
    UP();
    SOCK_OR_RETURN(s);
    au_addr_leaf(&a, "bind_cut.sock");
    plen = (int)strlen(a.sun_path);
    /* bind exactly the directory part plus "bind_cut" (drop ".sock") */
    strcpy(want, a.sun_path);
    want[plen - 5] = 0;
    AU_EQ(U(bind)(s, (struct sockaddr *)&a, 2 + plen - 5), 0);
    CHECK(exists_a(want));
    CHECK(!exists_a(a.sun_path));
    AU_EQ(U(getsockname)(s, (struct sockaddr *)&got, &l), 0);
    CHECK(!strcmp(got.sun_path, want));
    U(closesocket)(s);
    DeleteFileA(want);
}

/* ---- path field limits -------------------------------------------------------------------------- */
static int fill_path_len(char *out, size_t total)
{
    /* Scratch directory + 'p' padding + ".s" so that the string is exactly total characters. */
    const char *d = au_path("");
    size_t dl = strlen(d);
    if (dl + 3 > total) return 0;
    memcpy(out, d, dl);
    memset(out + dl, 'p', total - dl - 2);
    out[total - 2] = '.'; out[total - 1] = 's';
    out[total] = 0;
    return 1;
}

TEST(afu_bind_path_107_chars_with_terminator)
{
    SOCKADDR_UN a;
    char p[MAX_PATH];
    UP();
    SOCK_OR_RETURN(s);
    if (!fill_path_len(p, 107)) { t_skip("scratch path too long"); U(closesocket)(s); return; }
    au_addr(&a, p);
    AU_EQ(au_bind_to(s, &a), 0);
    CHECK(exists_a(p));
    U(closesocket)(s);
    DeleteFileA(p);
}

TEST(afu_bind_path_108_chars_unterminated)
{
    /* All 108 path bytes used, no terminator: the path length is capped at the field size. */
    SOCKADDR_UN a;
    char p[MAX_PATH];
    UP();
    SOCK_OR_RETURN(s);
    if (!fill_path_len(p, 108)) { t_skip("scratch path too long"); U(closesocket)(s); return; }
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    memcpy(a.sun_path, p, 108);
    AU_EQ(au_bind_to(s, &a), 0);
    CHECK(exists_a(p));
    U(closesocket)(s);
    DeleteFileA(p);
}

TEST(afu_bind_path_unterminated_ignores_following_bytes)
{
    /* The path is cut at the field end: junk after the 108 bytes of the full-size struct cannot extend it. */
    union { SOCKADDR_UN u; char raw[160]; } b;
    char p[MAX_PATH], q[MAX_PATH];
    UP();
    SOCK_OR_RETURN(s);
    if (!fill_path_len(p, 108)) { t_skip("scratch path too long"); U(closesocket)(s); return; }
    memset(&b, 'Z', sizeof(b));
    b.u.sun_family = AF_UNIX;
    memcpy(b.u.sun_path, p, 108);
    AU_EQ(U(bind)(s, (struct sockaddr *)&b, (int)sizeof(b)), 0);
    CHECK(exists_a(p));
    strcpy(q, p); strcat(q, "ZZ");
    CHECK(!exists_a(q));
    U(closesocket)(s);
    DeleteFileA(p);
}

TEST(afu_bind_path_long_directory_component)
{
    /* A 100 character leaf in a normal directory still binds (well under the field limit). */
    SOCKADDR_UN a;
    char leaf[128];
    const char *d = au_path("");
    UP();
    SOCK_OR_RETURN(s);
    if (strlen(d) + 20 > 107) { t_skip("scratch path too long"); U(closesocket)(s); return; }
    memset(leaf, 'q', 107 - strlen(d) - 5);
    leaf[107 - strlen(d) - 5] = 0;
    strcat(leaf, ".sock");
    au_addr_leaf(&a, leaf);
    AU_EQ(strlen(a.sun_path), 107);
    AU_EQ(au_bind_to(s, &a), 0);
    CHECK(exists_a(a.sun_path));
    U(closesocket)(s);
    DeleteFileA(a.sun_path);
}

TEST(afu_bind_empty_path_full_length)
{
    /* An all-zero path means "no file name": nothing is created and the bind succeeds. */
    SOCKADDR_UN a;
    UP();
    SOCK_OR_RETURN(s);
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    AU_EQ(au_bind_to(s, &a), 0);
    U(closesocket)(s);
}

TEST(afu_bind_empty_path_twice_both_succeed)
{
    SOCKADDR_UN a;
    SOCKET s2;
    UP();
    SOCK_OR_RETURN(s);
    s2 = au_sock();
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    AU_EQ(au_bind_to(s, &a), 0);
    au_seterr(0);
    AU_EQ(au_bind_to(s2, &a), 0);
    U(closesocket)(s); U(closesocket)(s2);
}

TEST(afu_bind_family_only_twice_both_succeed)
{
    SOCKADDR_UN a;
    SOCKET s2;
    UP();
    SOCK_OR_RETURN(s);
    s2 = au_sock();
    au_addr(&a, "never.sock");
    AU_EQ(U(bind)(s, (struct sockaddr *)&a, 2), 0);
    AU_EQ(U(bind)(s2, (struct sockaddr *)&a, 2), 0);
    U(closesocket)(s); U(closesocket)(s2);
}

static int count_sock_files(void)
{
    WIN32_FIND_DATAA fd;
    char pat[MAX_PATH];
    HANDLE h;
    int n = 0;
    snprintf(pat, sizeof(pat), "%s*", au_path(""));
    h = FindFirstFileA(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) { do n++; while (FindNextFileA(h, &fd)); FindClose(h); }
    return n;
}

TEST(afu_bind_unnamed_creates_no_file)
{
    SOCKADDR_UN a;
    int before, after;
    UP();
    SOCK_OR_RETURN(s);
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    before = count_sock_files();
    AU_EQ(au_bind_to(s, &a), 0);
    after = count_sock_files();
    AU_EQ(after, before);
    U(closesocket)(s);
}

/* ---- path spellings ----------------------------------------------------------------------------- */
TEST(afu_bind_path_forward_slashes)
{
    SOCKADDR_UN a;
    char *c;
    UP();
    SOCK_OR_RETURN(s);
    au_addr_leaf(&a, "fwd_slash.sock");
    for (c = a.sun_path; *c; c++) if (*c == '\\') *c = '/';
    AU_EQ(au_bind_to(s, &a), 0);
    CHECK(exists_a(au_path("fwd_slash.sock")));
    U(closesocket)(s);
    au_unlink_leaf("fwd_slash.sock");
}

TEST(afu_bind_path_dotdot_component)
{
    SOCKADDR_UN a;
    char sub[MAX_PATH], p[MAX_PATH];
    UP();
    SOCK_OR_RETURN(s);
    snprintf(sub, sizeof(sub), "%ssubdd", au_path(""));
    CreateDirectoryA(sub, NULL);
    snprintf(p, sizeof(p), "%s\\..\\dotdot.sock", sub);
    au_addr(&a, p);
    AU_EQ(au_bind_to(s, &a), 0);
    CHECK(exists_a(au_path("dotdot.sock")));
    U(closesocket)(s);
    au_unlink_leaf("dotdot.sock");
    RemoveDirectoryA(sub);
}

TEST(afu_bind_path_in_subdirectory)
{
    SOCKADDR_UN a;
    char sub[MAX_PATH], p[MAX_PATH];
    UP();
    SOCK_OR_RETURN(s);
    snprintf(sub, sizeof(sub), "%ssubdir", au_path(""));
    CreateDirectoryA(sub, NULL);
    snprintf(p, sizeof(p), "%s\\inner.sock", sub);
    au_addr(&a, p);
    AU_EQ(au_bind_to(s, &a), 0);
    CHECK(exists_a(p));
    U(closesocket)(s);
    DeleteFileA(p);
    RemoveDirectoryA(sub);
}

TEST(afu_bind_path_extended_prefix)
{
    /* The Win32 extended prefix form names the same file. */
    SOCKADDR_UN a;
    char p[MAX_PATH];
    UP();
    SOCK_OR_RETURN(s);
    snprintf(p, sizeof(p), "\\\\?\\%s", au_path("ext_prefix.sock"));
    au_addr(&a, p);
    AU_EQ(au_bind_to(s, &a), 0);
    CHECK(exists_a(au_path("ext_prefix.sock")));
    U(closesocket)(s);
    au_unlink_leaf("ext_prefix.sock");
}

TEST(afu_bind_path_utf8_name)
{
    /* The path bytes are UTF-8: U+00E9 as C3 A9 yields a file named with that single character. */
    SOCKADDR_UN a;
    WCHAR wp[MAX_PATH], wd[MAX_PATH];
    UP();
    SOCK_OR_RETURN(s);
    au_addr_leaf(&a, "utf8_\xC3\xA9.sock");
    AU_EQ(au_bind_to(s, &a), 0);
    MultiByteToWideChar(CP_ACP, 0, au_path(""), -1, wd, MAX_PATH);
    swprintf(wp, MAX_PATH, L"%ls" L"utf8_%lc.sock", wd, (wchar_t)0xE9);
    CHECK(GetFileAttributesW(wp) != INVALID_FILE_ATTRIBUTES);
    U(closesocket)(s);
    DeleteFileW(wp);
}

TEST(afu_bind_path_drive_relative_cwd)
{
    /* A relative name is resolved against the current directory at bind time. */
    SOCKADDR_UN a;
    char saved[MAX_PATH];
    UP();
    SOCK_OR_RETURN(s);
    GetCurrentDirectoryA(sizeof(saved), saved);
    SetCurrentDirectoryA(au_path(""));
    au_addr(&a, "cwd_rel.sock");
    AU_EQ(au_bind_to(s, &a), 0);
    SetCurrentDirectoryA(saved);
    CHECK(exists_a(au_path("cwd_rel.sock")));
    U(closesocket)(s);
    au_unlink_leaf("cwd_rel.sock");
}

/* ---- collisions --------------------------------------------------------------------------------- */
TEST(afu_bind_over_regular_file_is_addrinuse)
{
    SOCKADDR_UN a;
    HANDLE h;
    UP();
    SOCK_OR_RETURN(s);
    au_addr_leaf(&a, "plain_file.sock");
    h = CreateFileA(a.sun_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { t_skip("scratch file"); U(closesocket)(s); return; }
    CloseHandle(h);
    au_seterr(0);
    AU_EQ(au_bind_to(s, &a), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEADDRINUSE);
    U(closesocket)(s);
    DeleteFileA(a.sun_path);
}

TEST(afu_bind_over_directory_fails)
{
    SOCKADDR_UN a;
    UP();
    SOCK_OR_RETURN(s);
    au_addr_leaf(&a, "dirname.sock");
    CreateDirectoryA(a.sun_path, NULL);
    au_seterr(0);
    AU_EQ(au_bind_to(s, &a), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEINVAL);
    U(closesocket)(s);
    RemoveDirectoryA(a.sun_path);
}

TEST(afu_bind_while_first_socket_open_is_addrinuse)
{
    SOCKADDR_UN a;
    SOCKET s2;
    UP();
    SOCK_OR_RETURN(s);
    s2 = au_sock();
    AU_EQ(au_bind_leaf(s, "dup_bind.sock", &a), 0);
    au_seterr(0);
    AU_EQ(au_bind_to(s2, &a), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEADDRINUSE);
    U(closesocket)(s); U(closesocket)(s2);
    au_unlink_leaf("dup_bind.sock");
}

TEST(afu_bind_case_insensitive_collision)
{
    /* The scratch volume is case-insensitive; the file name is compared as the file system does. */
    SOCKADDR_UN a, b;
    SOCKET s2;
    UP();
    SOCK_OR_RETURN(s);
    s2 = au_sock();
    au_addr_leaf(&a, "CaseName.sock");
    au_addr_leaf(&b, "casename.SOCK");
    AU_EQ(au_bind_to(s, &a), 0);
    au_seterr(0);
    AU_EQ(au_bind_to(s2, &b), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEADDRINUSE);
    U(closesocket)(s); U(closesocket)(s2);
    DeleteFileA(a.sun_path);
}

TEST(afu_bind_missing_directory_fails)
{
    SOCKADDR_UN a;
    char p[MAX_PATH];
    UP();
    SOCK_OR_RETURN(s);
    snprintf(p, sizeof(p), "%sno_such_dir\\x.sock", au_path(""));
    au_addr(&a, p);
    au_seterr(0);
    AU_EQ(au_bind_to(s, &a), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENETDOWN);
    U(closesocket)(s);
}

TEST(afu_bind_failed_leaves_socket_bindable)
{
    /* A refused bind does not consume the socket's one bind: a later valid bind succeeds. */
    SOCKADDR_UN a, bad;
    UP();
    SOCK_OR_RETURN(s);
    au_addr_leaf(&bad, "failed_first.sock");
    bad.sun_family = AF_INET;
    AU_EQ(au_bind_to(s, &bad), SOCKET_ERROR);
    AU_EQ(au_bind_leaf(s, "failed_then_ok.sock", &a), 0);
    CHECK(exists_a(a.sun_path));
    U(closesocket)(s);
    au_unlink_leaf("failed_then_ok.sock");
}

/* ---- name reuse -------------------------------------------------------------------------------- */
TEST(afu_bind_reuse_after_delete)
{
    SOCKADDR_UN a;
    SOCKET s2;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "reuse.sock", &a), 0);
    U(closesocket)(s);
    CHECK(exists_a(a.sun_path));
    CHECK(DeleteFileA(a.sun_path));
    s2 = au_sock();
    AU_EQ(au_bind_to(s2, &a), 0);
    CHECK(exists_a(a.sun_path));
    U(closesocket)(s2);
    au_unlink_leaf("reuse.sock");
}

TEST(afu_bind_reuse_while_old_socket_open_after_delete)
{
    /* Removing the file frees the name even while the first socket is still open. */
    SOCKADDR_UN a;
    SOCKET s2;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "reuse_open.sock", &a), 0);
    if (!DeleteFileA(a.sun_path)) { AU_OBS("delete bound file", "error %lu", GetLastError()); U(closesocket)(s); return; }
    s2 = au_sock();
    AU_EQ(au_bind_to(s2, &a), 0);
    U(closesocket)(s); U(closesocket)(s2);
    au_unlink_leaf("reuse_open.sock");
}

TEST(afu_bind_file_survives_close)
{
    SOCKADDR_UN a;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "survive.sock", &a), 0);
    U(closesocket)(s);
    CHECK(exists_a(a.sun_path));
    DeleteFileA(a.sun_path);
    CHECK(!exists_a(a.sun_path));
}

TEST(afu_bind_file_survives_listening_close)
{
    struct au_trio t;
    UP();
    if (!au_trio_open(&t, "survive_l.sock")) return;
    U(closesocket)(t.srv); U(closesocket)(t.cli); U(closesocket)(t.lis);
    t.srv = t.cli = t.lis = INVALID_SOCKET;
    CHECK(exists_a(t.path));
    DeleteFileA(t.path);
}

TEST(afu_bind_many_sequential_names)
{
    int i;
    UP();
    for (i = 0; i < 16; i++) {
        char leaf[32];
        SOCKET s = au_sock();
        if (s == INVALID_SOCKET) return;
        snprintf(leaf, sizeof(leaf), "seq_%d.sock", i);
        AU_EQ(au_bind_leaf(s, leaf, NULL), 0);
        U(closesocket)(s);
        au_unlink_leaf(leaf);
    }
}

TEST(afu_bind_many_open_at_once)
{
    SOCKET s[8];
    int i;
    UP();
    for (i = 0; i < 8; i++) s[i] = INVALID_SOCKET;
    for (i = 0; i < 8; i++) {
        char leaf[32];
        s[i] = au_sock();
        if (s[i] == INVALID_SOCKET) break;
        snprintf(leaf, sizeof(leaf), "many_%d.sock", i);
        AU_EQ(au_bind_leaf(s[i], leaf, NULL), 0);
    }
    for (i = 0; i < 8; i++) {
        char leaf[32];
        if (s[i] != INVALID_SOCKET) U(closesocket)(s[i]);
        snprintf(leaf, sizeof(leaf), "many_%d.sock", i);
        au_unlink_leaf(leaf);
    }
}

/* ---- state errors ----------------------------------------------------------------------------- */
TEST(afu_bind_twice_is_inval)
{
    SOCKADDR_UN a;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "twice1.sock", NULL), 0);
    au_addr_leaf(&a, "twice2.sock");
    au_seterr(0);
    AU_EQ(au_bind_to(s, &a), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEINVAL);
    CHECK(!exists_a(a.sun_path));
    U(closesocket)(s);
    au_unlink_leaf("twice1.sock");
}

TEST(afu_bind_same_name_twice_same_socket_is_inval)
{
    SOCKADDR_UN a;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "twice_same.sock", &a), 0);
    au_seterr(0);
    AU_EQ(au_bind_to(s, &a), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEINVAL);
    U(closesocket)(s);
    au_unlink_leaf("twice_same.sock");
}

TEST(afu_bind_after_listen_is_inval)
{
    SOCKADDR_UN a;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "after_listen1.sock", NULL), 0);
    AU_EQ(U(listen)(s, 1), 0);
    au_addr_leaf(&a, "after_listen2.sock");
    au_seterr(0);
    AU_EQ(au_bind_to(s, &a), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEINVAL);
    U(closesocket)(s);
    au_unlink_leaf("after_listen1.sock");
}

TEST(afu_bind_after_connect_is_inval)
{
    SOCKADDR_UN a;
    TRIO(t, "after_conn.sock");
    au_addr_leaf(&a, "after_conn_cli.sock");
    au_seterr(0);
    AU_EQ(au_bind_to(t.cli, &a), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEINVAL);
    CHECK(!exists_a(a.sun_path));
    au_trio_close(&t);
}

TEST(afu_bind_after_accept_on_accepted_is_inval)
{
    SOCKADDR_UN a;
    TRIO(t, "after_acc.sock");
    au_addr_leaf(&a, "after_acc_srv.sock");
    au_seterr(0);
    AU_EQ(au_bind_to(t.srv, &a), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEINVAL);
    au_trio_close(&t);
}

TEST(afu_bind_after_shutdown_unconnected)
{
    SOCKADDR_UN a;
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    int r = U(shutdown)(s, SD_BOTH);
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(au_err(), WSAENOTCONN);
    au_addr_leaf(&a, "after_shut.sock");
    r = au_bind_to(s, &a);
    AU_EQ(r, 0);
    U(closesocket)(s);
    au_unlink_leaf("after_shut.sock");
}
