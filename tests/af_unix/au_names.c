/* AF_UNIX stream sockets: getsockname / getpeername beyond the plain listener-client-accepted matrix:
 * state errors, argument validation, name lengths for the different bind forms, names that survive
 * connection and close of the peer, and the string conversion entry points for the family. */
#include "au.h"
#include <wchar.h>

static const char *probe_bind_forms[] = { "name_a.sock", "n.s", "name_with_underscores_and_digits_0123456789.sock" };

TEST(afu_name_unbound_getsockname_is_inval)
{
    SOCKADDR_UN a;
    int l = sizeof(a);
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    AU_EQ(U(getsockname)(s, (struct sockaddr *)&a, &l), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEINVAL);
    U(closesocket)(s);
}

TEST(afu_name_unbound_getpeername_is_notconn)
{
    SOCKADDR_UN a;
    int l = sizeof(a);
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    AU_EQ(U(getpeername)(s, (struct sockaddr *)&a, &l), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENOTCONN);
    U(closesocket)(s);
}

TEST(afu_name_bound_getpeername_is_notconn)
{
    SOCKADDR_UN a;
    int l = sizeof(a);
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "nm_bound.sock", NULL), 0);
    au_seterr(0);
    AU_EQ(U(getpeername)(s, (struct sockaddr *)&a, &l), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENOTCONN);
    U(closesocket)(s);
    au_unlink_leaf("nm_bound.sock");
}

TEST(afu_name_getsockname_len_zero_is_fault)
{
    SOCKADDR_UN a;
    int l = 0;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "nm_len0.sock", NULL), 0);
    au_seterr(0);
    AU_EQ(U(getsockname)(s, (struct sockaddr *)&a, &l), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    U(closesocket)(s);
    au_unlink_leaf("nm_len0.sock");
}

TEST(afu_name_getsockname_len_one_is_fault)
{
    SOCKADDR_UN a;
    int l = 1;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "nm_len1.sock", NULL), 0);
    au_seterr(0);
    AU_EQ(U(getsockname)(s, (struct sockaddr *)&a, &l), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    U(closesocket)(s);
    au_unlink_leaf("nm_len1.sock");
}

TEST(afu_name_getsockname_short_buffer_reports_need)
{
    /* A buffer that holds the family but not the whole path: the call refuses or truncates. Record which. */
    SOCKADDR_UN want;
    char buf[16];
    int l = 4, r;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "nm_short.sock", &want), 0);
    memset(buf, 0x55, sizeof(buf));
    au_seterr(0);
    r = U(getsockname)(s, (struct sockaddr *)buf, &l);
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    CHECK((unsigned char)buf[8] == 0x55);
    U(closesocket)(s);
    au_unlink_leaf("nm_short.sock");
}

TEST(afu_name_getsockname_exact_fit_buffer)
{
    SOCKADDR_UN want, got;
    int need, l;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "nm_fit.sock", &want), 0);
    need = (int)(2 + strlen(want.sun_path) + 1);
    memset(&got, 0x55, sizeof(got));
    l = need;
    AU_EQ(U(getsockname)(s, (struct sockaddr *)&got, &l), 0);
    AU_EQ(l, need);
    CHECK(!strcmp(got.sun_path, want.sun_path));
    U(closesocket)(s);
    au_unlink_leaf("nm_fit.sock");
}

TEST(afu_name_getsockname_len_updated_from_larger_input)
{
    SOCKADDR_UN want;
    char buf[400];
    int l = sizeof(buf);
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "nm_big.sock", &want), 0);
    memset(buf, 0x77, sizeof(buf));
    AU_EQ(U(getsockname)(s, (struct sockaddr *)buf, &l), 0);
    AU_EQ(l, (int)(2 + strlen(want.sun_path) + 1));
    CHECK((unsigned char)buf[l] == 0x77);
    U(closesocket)(s);
    au_unlink_leaf("nm_big.sock");
}

static void bind_form(const char *leaf)
{
    SOCKADDR_UN want, got;
    int l = sizeof(got);
    SOCKET s;
    if (!au_up()) return;
    s = au_sock();
    if (s == INVALID_SOCKET) return;
    AU_EQ(au_bind_leaf(s, leaf, &want), 0);
    memset(&got, 0x55, sizeof(got));
    AU_EQ(U(getsockname)(s, (struct sockaddr *)&got, &l), 0);
    AU_EQ(got.sun_family, AF_UNIX);
    CHECK(!strcmp(got.sun_path, want.sun_path));
    AU_EQ(l, (int)(2 + strlen(want.sun_path) + 1));
    U(closesocket)(s);
    au_unlink_leaf(leaf);
}
TEST(afu_name_form_plain) { bind_form(probe_bind_forms[0]); }
TEST(afu_name_form_single_char_leaf) { bind_form(probe_bind_forms[1]); }
TEST(afu_name_form_long_leaf) { bind_form(probe_bind_forms[2]); }

TEST(afu_name_family_only_bind)
{
    SOCKADDR_UN a, got;
    int l = sizeof(got);
    UP();
    SOCK_OR_RETURN(s);
    au_addr(&a, "ignored.sock");
    AU_EQ(U(bind)(s, (struct sockaddr *)&a, 2), 0);
    memset(&got, 0x55, sizeof(got));
    AU_EQ(U(getsockname)(s, (struct sockaddr *)&got, &l), 0);
    AU_EQ(got.sun_family, AF_UNIX);
    AU_EQ(l, (int)sizeof(SOCKADDR_UN));
    U(closesocket)(s);
}

TEST(afu_name_empty_path_bind)
{
    SOCKADDR_UN a, got;
    int l = sizeof(got);
    UP();
    SOCK_OR_RETURN(s);
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    AU_EQ(au_bind_to(s, &a), 0);
    memset(&got, 0x55, sizeof(got));
    AU_EQ(U(getsockname)(s, (struct sockaddr *)&got, &l), 0);
    AU_EQ(got.sun_family, AF_UNIX);
    AU_EQ(l, (int)sizeof(SOCKADDR_UN));
    CHECK(got.sun_path[0] == 0);
    U(closesocket)(s);
}

TEST(afu_name_forward_slash_bind_reports)
{
    SOCKADDR_UN a, got;
    int l = sizeof(got);
    char *c;
    UP();
    SOCK_OR_RETURN(s);
    au_addr_leaf(&a, "nm_fwd.sock");
    for (c = a.sun_path; *c; c++) if (*c == '\\') *c = '/';
    AU_EQ(au_bind_to(s, &a), 0);
    memset(&got, 0, sizeof(got));
    AU_EQ(U(getsockname)(s, (struct sockaddr *)&got, &l), 0);
    CHECK(!strcmp(got.sun_path, a.sun_path));
    U(closesocket)(s);
    au_unlink_leaf("nm_fwd.sock");
}

TEST(afu_name_dotdot_bind_reports)
{
    SOCKADDR_UN a, got;
    int l = sizeof(got);
    char p[MAX_PATH];
    UP();
    SOCK_OR_RETURN(s);
    snprintf(p, sizeof(p), "%s\\..\\nm_dd.sock", au_path("sub_dd"));
    CreateDirectoryA(au_path("sub_dd"), NULL);
    au_addr(&a, p);
    AU_EQ(au_bind_to(s, &a), 0);
    memset(&got, 0, sizeof(got));
    AU_EQ(U(getsockname)(s, (struct sockaddr *)&got, &l), 0);
    CHECK(!strcmp(got.sun_path, a.sun_path));
    U(closesocket)(s);
    au_unlink_leaf("nm_dd.sock");
    RemoveDirectoryA(au_path("sub_dd"));
}

TEST(afu_name_utf8_bind_reports_same_bytes)
{
    SOCKADDR_UN a, got;
    int l = sizeof(got);
    UP();
    SOCK_OR_RETURN(s);
    au_addr_leaf(&a, "nm_u8_\xC3\xA9\xE2\x82\xAC.sock");
    AU_EQ(au_bind_to(s, &a), 0);
    memset(&got, 0, sizeof(got));
    AU_EQ(U(getsockname)(s, (struct sockaddr *)&got, &l), 0);
    CHECK(!strcmp(got.sun_path, a.sun_path));
    U(closesocket)(s);
    {
        WCHAR wp[MAX_PATH], wd[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, au_path(""), -1, wd, MAX_PATH);
        swprintf(wp, MAX_PATH, L"%lsnm_u8_%lc%lc.sock", wd, (wchar_t)0xE9, (wchar_t)0x20AC);
        DeleteFileW(wp);
    }
}

TEST(afu_name_named_client_reports_own_and_peer)
{
    SOCKADDR_UN la, ca, got;
    SOCKET c, s;
    int l;
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "nm_srv.sock", &la), 0);
    AU_EQ(U(listen)(lis, 1), 0);
    c = au_sock();
    AU_EQ(au_bind_leaf(c, "nm_cli.sock", &ca), 0);
    s = au_connect_accept(lis, c, &la);
    if (s == INVALID_SOCKET) goto out;
    l = sizeof(got); memset(&got, 0, sizeof(got));
    AU_EQ(U(getsockname)(c, (struct sockaddr *)&got, &l), 0);
    CHECK(!strcmp(got.sun_path, ca.sun_path));
    l = sizeof(got); memset(&got, 0, sizeof(got));
    AU_EQ(U(getpeername)(c, (struct sockaddr *)&got, &l), 0);
    CHECK(!strcmp(got.sun_path, la.sun_path));
    l = sizeof(got); memset(&got, 0, sizeof(got));
    AU_EQ(U(getpeername)(s, (struct sockaddr *)&got, &l), 0);
    CHECK(!strcmp(got.sun_path, ca.sun_path));
    l = sizeof(got); memset(&got, 0, sizeof(got));
    AU_EQ(U(getsockname)(s, (struct sockaddr *)&got, &l), 0);
    CHECK(!strcmp(got.sun_path, la.sun_path));
    U(closesocket)(s);
out:
    U(closesocket)(c); U(closesocket)(lis);
    au_unlink_leaf("nm_srv.sock"); au_unlink_leaf("nm_cli.sock");
}

TEST(afu_name_getpeername_after_peer_close)
{
    SOCKADDR_UN got;
    int l = sizeof(got), r;
    TRIO(t, "nm_peerclose.sock");
    U(closesocket)(t.srv); t.srv = INVALID_SOCKET;
    Sleep(50);
    au_seterr(0);
    r = U(getpeername)(t.cli, (struct sockaddr *)&got, &l);
    AU_EQ(r, 0);
    AU_EQ(got.sun_family, AF_UNIX);
    au_trio_close(&t);
}

TEST(afu_name_getsockname_after_shutdown)
{
    SOCKADDR_UN got;
    int l = sizeof(got);
    TRIO(t, "nm_shut.sock");
    AU_EQ(U(shutdown)(t.cli, SD_BOTH), 0);
    AU_EQ(U(getsockname)(t.srv, (struct sockaddr *)&got, &l), 0);
    AU_EQ(got.sun_family, AF_UNIX);
    au_trio_close(&t);
}

TEST(afu_name_getsockname_stable_across_calls)
{
    SOCKADDR_UN a, b;
    int l1 = sizeof(a), l2 = sizeof(b);
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "nm_stable.sock", NULL), 0);
    memset(&a, 0, sizeof(a)); memset(&b, 0, sizeof(b));
    AU_EQ(U(getsockname)(s, (struct sockaddr *)&a, &l1), 0);
    AU_EQ(U(listen)(s, 1), 0);
    AU_EQ(U(getsockname)(s, (struct sockaddr *)&b, &l2), 0);
    AU_EQ(l1, l2);
    CHECK(!memcmp(&a, &b, sizeof(a)));
    U(closesocket)(s);
    au_unlink_leaf("nm_stable.sock");
}

/* ---- string conversion entry points -------------------------------------------------------------- */
TEST(afu_name_address_to_string_unix)
{
    SOCKADDR_UN a;
    WCHAR buf[128];
    DWORD len = 128;
    int r;
    UP();
    { SOCKET p = au_sock(); if (p == INVALID_SOCKET) return; U(closesocket)(p); }
    au_addr(&a, "x.sock");
    wmemset(buf, 0x5555, 128);
    au_seterr(0);
    r = U(WSAAddressToStringW)((LPSOCKADDR)&a, sizeof(a), NULL, buf, &len);
    AU_EQ(r, 0);
    AU_EQ(buf[0], 0);
}

TEST(afu_name_string_to_address_unix)
{
    SOCKADDR_UN a;
    INT l = sizeof(a);
    WCHAR s[] = L"x.sock";
    int r;
    UP();
    { SOCKET p = au_sock(); if (p == INVALID_SOCKET) return; U(closesocket)(p); }
    memset(&a, 0x55, sizeof(a));
    au_seterr(0);
    r = U(WSAStringToAddressW)(s, AF_UNIX, NULL, (LPSOCKADDR)&a, &l);
    AU_EQ(r, 0);
    AU_EQ(l, (int)sizeof(SOCKADDR_UN));
    AU_EQ(a.sun_family, AF_UNIX);
}
