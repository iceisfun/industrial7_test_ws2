/* AF_UNIX stream sockets: bind argument-length rules (zero, family-only, truncated name), connection and
 * data transfer, the socket file on disk (reparse-point attributes, tag, opening, deletion, address in
 * use), and the sockaddr returned by getsockname / getpeername for listener, client and accepted
 * socket under four path spellings (relative, dot-relative, absolute, NT-prefixed).
 * All socket files live in the per-process scratch directory. */
#include "lift11.h"

#ifndef FSCTL_GET_REPARSE_POINT
#define FSCTL_GET_REPARSE_POINT 0x000900A8
#endif

struct l11_reparse_hdr { ULONG tag; USHORT data_len; USHORT reserved; };

static SOCKET l11_unix_socket(void)
{
    SOCKET s = U(socket)(AF_UNIX, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET && l11_err() == WSAEAFNOSUPPORT) t_skip("AF_UNIX not supported");
    return s;
}

/* Run fn with the scratch directory as current directory; restore afterwards. */
static char l11_saved_cwd[MAX_PATH];
static void l11_enter_tmp(void)
{
    GetCurrentDirectoryA(sizeof(l11_saved_cwd), l11_saved_cwd);
    SetCurrentDirectoryA(t_tmpdir());
}
static void l11_leave_tmp(void) { SetCurrentDirectoryA(l11_saved_cwd); }

static SOCKET l11_accept_bounded(SOCKET lis)
{
    fd_set r;
    struct timeval tv = {3, 0};
    FD_ZERO(&r); FD_SET(lis, &r);
    if (U(select)(0, &r, NULL, NULL, &tv) != 1) return INVALID_SOCKET;
    return U(accept)(lis, NULL, NULL);
}

/* Connect client to addr through a non-blocking connect, accept on lis, restore blocking mode. */
static SOCKET l11_unix_connect(SOCKET lis, SOCKET cli, const SOCKADDR_UN *a)
{
    SOCKET srv;
    int r;
    CHECK(l11_blocking(cli, FALSE) == 0);
    r = U(connect)(cli, (const struct sockaddr *)a, sizeof(*a));
    CHECKF(r == 0 || l11_err() == WSAEWOULDBLOCK, "connect ret %d err %d", r, l11_err());
    srv = l11_accept_bounded(lis);
    CHECK(srv != INVALID_SOCKET);
    CHECK(l11_blocking(cli, TRUE) == 0);
    return srv;
}

TEST(afunix_bind_zero_length_is_efault)
{
    SOCKET s;
    SOCKADDR_UN a = { AF_UNIX, "zero.sock" };
    UP();
    s = l11_unix_socket();
    if (s == INVALID_SOCKET) return;
    l11_seterr(0xdeadbeef);
    L_EQ(U(bind)(s, (SOCKADDR *)&a, 0), SOCKET_ERROR);
    L_EQ(l11_err(), WSAEFAULT);
    U(closesocket)(s);
}

TEST(afunix_bind_family_only_then_listen)
{
    SOCKET s;
    SOCKADDR_UN a = { AF_UNIX, "famonly.sock" };
    UP();
    s = l11_unix_socket();
    if (s == INVALID_SOCKET) return;
    L_EQ(U(bind)(s, (SOCKADDR *)&a, 2), 0);
    L_EQ(U(listen)(s, 1), 0);
    U(closesocket)(s);
}

TEST(afunix_bind_truncated_name_uses_given_bytes_only)
{
    /* namelen 3 = family + the first path byte: the socket is named by that single character. */
    SOCKET s;
    SOCKADDR_UN a = { AF_UNIX, "trunc_name.sock" }, out = {0}, want = {0};
    int outlen = sizeof(out);
    UP();
    l11_enter_tmp();
    s = l11_unix_socket();
    if (s == INVALID_SOCKET) { l11_leave_tmp(); return; }
    L_EQ(U(bind)(s, (SOCKADDR *)&a, 3), 0);
    memcpy(&want, &a, 3);
    L_EQ(U(getsockname)(s, (SOCKADDR *)&out, &outlen), 0);
    CHECK(!memcmp(want.sun_path, out.sun_path, sizeof(out.sun_path)));
    L_EQ(outlen, (int)(sizeof(out.sun_family) + strlen(out.sun_path) + 1));
    U(closesocket)(s);
    CHECK(DeleteFileA(want.sun_path));
    L_EQ(GetFileAttributesA(want.sun_path), INVALID_FILE_ATTRIBUTES);
    l11_leave_tmp();
}

TEST(afunix_stream_data_transfer_both_directions)
{
    static const char msg[] = "ws2_32/AF_UNIX socket test";
    SOCKET lis, cli, srv;
    SOCKADDR_UN a = { AF_UNIX, "xfer.sock" };
    char b[sizeof(msg)];
    UP();
    l11_enter_tmp();
    lis = l11_unix_socket();
    if (lis == INVALID_SOCKET) { l11_leave_tmp(); return; }
    cli = U(socket)(AF_UNIX, SOCK_STREAM, 0);
    L_EQ(U(bind)(lis, (SOCKADDR *)&a, sizeof(a)), 0);
    L_EQ(U(listen)(lis, 1), 0);
    srv = l11_unix_connect(lis, cli, &a);
    if (srv != INVALID_SOCKET) {
        l11_rcvtimeo(cli, 3000); l11_rcvtimeo(srv, 3000);
        L_EQ(U(send)(srv, msg, sizeof(msg), 0), (int)sizeof(msg));
        memset(b, 0, sizeof(b));
        L_EQ(U(recv)(cli, b, sizeof(msg), 0), (int)sizeof(msg));
        CHECK(!memcmp(b, msg, sizeof(msg)));
        L_EQ(U(sendto)(srv, msg, sizeof(msg), 0, NULL, 0), (int)sizeof(msg));
        memset(b, 0, sizeof(b));
        L_EQ(U(recvfrom)(cli, b, sizeof(msg), 0, NULL, NULL), (int)sizeof(msg));
        CHECK(!memcmp(b, msg, sizeof(msg)));
        L_EQ(U(send)(cli, msg, sizeof(msg), 0), (int)sizeof(msg));
        memset(b, 0, sizeof(b));
        L_EQ(U(recv)(srv, b, sizeof(msg), 0), (int)sizeof(msg));
        CHECK(!memcmp(b, msg, sizeof(msg)));
        L_EQ(U(sendto)(cli, msg, sizeof(msg), 0, NULL, 0), (int)sizeof(msg));
        memset(b, 0, sizeof(b));
        L_EQ(U(recvfrom)(srv, b, sizeof(msg), 0, NULL, NULL), (int)sizeof(msg));
        CHECK(!memcmp(b, msg, sizeof(msg)));
        U(closesocket)(srv);
    }
    U(closesocket)(cli); U(closesocket)(lis);
    CHECK(DeleteFileA(a.sun_path));
    L_EQ(GetFileAttributesA(a.sun_path), INVALID_FILE_ATTRIBUTES);
    l11_leave_tmp();
}

TEST(afunix_bind_over_existing_socket_file_is_addrinuse)
{
    SOCKET s;
    SOCKADDR_UN a = { AF_UNIX, "inuse.sock" };
    UP();
    l11_enter_tmp();
    s = l11_unix_socket();
    if (s == INVALID_SOCKET) { l11_leave_tmp(); return; }
    L_EQ(U(bind)(s, (SOCKADDR *)&a, sizeof(a)), 0);
    U(closesocket)(s);
    /* The file outlives the socket; a second bind to the same name collides with it. */
    s = U(socket)(AF_UNIX, SOCK_STREAM, 0);
    l11_seterr(0xdeadbeef);
    L_EQ(U(bind)(s, (SOCKADDR *)&a, sizeof(a)), SOCKET_ERROR);
    L_EQ(l11_err(), WSAEADDRINUSE);
    U(closesocket)(s);
    CHECK(DeleteFileA(a.sun_path));
    L_EQ(GetFileAttributesA(a.sun_path), INVALID_FILE_ATTRIBUTES);
    l11_leave_tmp();
}

static void l11_unix_path_case(const char *path)
{
    SOCKET lis, cli, srv = INVALID_SOCKET;
    SOCKADDR_UN a = { AF_UNIX }, empty = { AF_UNIX };
    char buf[sizeof(SOCKADDR_UN) * 2];
    SOCKADDR_UN *out = (SOCKADDR_UN *)buf;
    int size, ret;
    DWORD attr;
    const DWORD want_attr = FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_ARCHIVE;

    strcpy(a.sun_path, path);
    DeleteFileA(a.sun_path);
    lis = l11_unix_socket();
    if (lis == INVALID_SOCKET) return;
    L_EQ(U(bind)(lis, (SOCKADDR *)&a, sizeof(a)), 0);
    attr = GetFileAttributesA(path);
    L_EQ(attr, want_attr);
    L_EQ(U(listen)(lis, 1), 0);
    cli = U(socket)(AF_UNIX, SOCK_STREAM, 0);
    srv = l11_unix_connect(lis, cli, &a);

    /* Listener and accepted socket report the bound name with a minimal length; the client has the
     * unnamed (all zero path) local address and the server path as peer. */
    memset(buf, 0x55, sizeof(buf)); size = sizeof(buf);
    L_EQ(U(getsockname)(lis, (SOCKADDR *)buf, &size), 0);
    L_EQ(out->sun_family, AF_UNIX);
    L_EQ(size, (int)(sizeof(a.sun_family) + strlen(a.sun_path) + 1));
    CHECK(!strcmp(a.sun_path, out->sun_path));
    L_EQ((unsigned char)buf[size], 0x55);

    memset(buf, 0x55, sizeof(buf)); size = sizeof(buf);
    L_EQ(U(getsockname)(cli, (SOCKADDR *)buf, &size), 0);
    L_EQ(out->sun_family, AF_UNIX);
    L_EQ(size, (int)sizeof(a));
    CHECK(!memcmp(empty.sun_path, out->sun_path, sizeof(empty.sun_path)));

    if (srv != INVALID_SOCKET) {
        memset(buf, 0x55, sizeof(buf)); size = sizeof(buf);
        L_EQ(U(getsockname)(srv, (SOCKADDR *)buf, &size), 0);
        L_EQ(out->sun_family, AF_UNIX);
        L_EQ(size, (int)(sizeof(a.sun_family) + strlen(a.sun_path) + 1));
        CHECK(!strcmp(a.sun_path, out->sun_path));
        L_EQ((unsigned char)buf[size], 0x55);
    }

    memset(buf, 0x55, sizeof(buf)); size = sizeof(buf);
    l11_seterr(0xdeadbeef);
    L_EQ(U(getpeername)(lis, (SOCKADDR *)buf, &size), SOCKET_ERROR);
    L_EQ(l11_err(), WSAENOTCONN);
    L_EQ((unsigned char)buf[0], 0x55);
    L_EQ(size, (int)sizeof(buf));

    memset(buf, 0x55, sizeof(buf)); size = sizeof(buf);
    L_EQ(U(getpeername)(cli, (SOCKADDR *)buf, &size), 0);
    L_EQ(out->sun_family, AF_UNIX);
    L_EQ(size, (int)sizeof(a));
    CHECK(!memcmp(a.sun_path, out->sun_path, sizeof(a.sun_path)));

    if (srv != INVALID_SOCKET) {
        memset(buf, 0x55, sizeof(buf)); size = sizeof(buf);
        L_EQ(U(getpeername)(srv, (SOCKADDR *)buf, &size), 0);
        L_EQ(out->sun_family, AF_UNIX);
        L_EQ(size, (int)sizeof(a));
        CHECK(!memcmp(empty.sun_path, out->sun_path, sizeof(empty.sun_path)));
    }

    U(closesocket)(lis); U(closesocket)(cli);
    if (srv != INVALID_SOCKET) U(closesocket)(srv);

    /* The socket file persists as a reparse point that plain opens refuse. */
    attr = GetFileAttributesA(path);
    L_EQ(attr, want_attr);
    if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
        struct l11_reparse_hdr *hdr = (struct l11_reparse_hdr *)buf;
        HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        CHECK(h == INVALID_HANDLE_VALUE);
        L_EQ(GetLastError(), ERROR_CANT_ACCESS_FILE);
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        CHECK(h != INVALID_HANDLE_VALUE);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD got = 0;
            memset(buf, 0, sizeof(buf));
            ret = DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, NULL, 0, buf, sizeof(buf), &got, NULL);
            CHECK(ret);
            L_EQ(hdr->tag, IO_REPARSE_TAG_AF_UNIX);
            L_EQ(hdr->data_len, 0);
            CloseHandle(h);
        }
    }
    CHECK(DeleteFileA(path));
    L_EQ(GetFileAttributesA(path), INVALID_FILE_ATTRIBUTES);
}

TEST(afunix_path_relative_name)
{
    UP();
    l11_enter_tmp();
    l11_unix_path_case("path_rel.sock");
    l11_leave_tmp();
}

TEST(afunix_path_dot_relative_name)
{
    UP();
    l11_enter_tmp();
    l11_unix_path_case(".\\path_dot.sock");
    l11_leave_tmp();
}

TEST(afunix_path_absolute_dos_name)
{
    char p[MAX_PATH];
    UP();
    t_tmpfile(p, sizeof(p), "path_abs.sock");
    l11_unix_path_case(p);
}

TEST(afunix_path_nt_prefixed_name)
{
    char p[MAX_PATH + 8], dos[MAX_PATH];
    UP();
    t_tmpfile(dos, sizeof(dos), "path_nt.sock");
    snprintf(p, sizeof(p), "\\??\\%s", dos);
    l11_unix_path_case(p);
}
