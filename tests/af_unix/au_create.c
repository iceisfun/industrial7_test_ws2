/* AF_UNIX stream sockets: creation rules. Which (family, type, protocol) triples are accepted, what the
 * socket reports about itself (type, protocol info, accept state), handle properties, duplication and
 * close behaviour. The Winsock helper for AF_UNIX maps exactly one triple: stream, protocol 0. */
#include "au.h"

TEST(afu_layout_sockaddr_un)
{
    SOCKADDR_UN a;
    CHECK(AF_UNIX == 1);
    CHECK(sizeof(a) == 110);
    CHECK(sizeof(a.sun_family) == 2);
    CHECK(offsetof(SOCKADDR_UN, sun_path) == 2);
    CHECK(sizeof(a.sun_path) == 108);
}

TEST(afu_create_stream_socket)
{
    UP();
    SOCK_OR_RETURN(s);
    CHECK(s != 0);
    AU_EQ(U(closesocket)(s), 0);
}

TEST(afu_create_via_socket_entry)
{
    SOCKET s;
    UP();
    s = U(socket)(AF_UNIX, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { t_skip("AF_UNIX not supported"); return; }
    AU_EQ(U(closesocket)(s), 0);
}

TEST(afu_create_wsasocket_flag_combinations)
{
    static const DWORD flags[] = { 0, WSA_FLAG_OVERLAPPED, WSA_FLAG_NO_HANDLE_INHERIT,
                                   WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT };
    int i;
    UP();
    for (i = 0; i < 4; i++) {
        SOCKET s = au_sock_flags(flags[i]);
        if (s == INVALID_SOCKET) return;
        AU_EQ(U(closesocket)(s), 0);
    }
}

TEST(afu_create_handle_inheritance_default)
{
    /* Documented: sockets are inheritable unless WSA_FLAG_NO_HANDLE_INHERIT is passed. */
    SOCKET a, b;
    DWORD fa = 0, fb = 0;
    UP();
    a = au_sock_flags(WSA_FLAG_OVERLAPPED);
    if (a == INVALID_SOCKET) return;
    b = au_sock_flags(WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    CHECK(GetHandleInformation((HANDLE)a, &fa));
    CHECK(GetHandleInformation((HANDLE)b, &fb));
    CHECK(fa & HANDLE_FLAG_INHERIT);
    CHECK(!(fb & HANDLE_FLAG_INHERIT));
    U(closesocket)(a); U(closesocket)(b);
}

TEST(afu_create_distinct_handles)
{
    SOCKET s[8];
    int i, j;
    UP();
    for (i = 0; i < 8; i++) s[i] = INVALID_SOCKET;
    for (i = 0; i < 8; i++) { s[i] = au_sock(); if (s[i] == INVALID_SOCKET) break; }
    if (i < 8) { for (j = 0; j < i; j++) U(closesocket)(s[j]); if (i) t_note("partial creation"); return; }
    for (i = 0; i < 8; i++) for (j = i + 1; j < 8; j++) CHECK(s[i] != s[j]);
    for (i = 0; i < 8; i++) AU_EQ(U(closesocket)(s[i]), 0);
}

TEST(afu_create_close_loop)
{
    int i;
    UP();
    for (i = 0; i < 64; i++) {
        SOCKET s = au_sock();
        if (s == INVALID_SOCKET) return;
        AU_EQ(U(closesocket)(s), 0);
    }
}

/* ---- the single accepted triple: everything else is refused ------------------------------------- */
struct triple { const char *name; int type, proto, err; };
static const struct triple g_bad_triples[] = {
    { "dgram_p0", SOCK_DGRAM, 0, WSAEAFNOSUPPORT }, { "raw_p0", SOCK_RAW, 0, WSAEAFNOSUPPORT },
    { "rdm_p0", SOCK_RDM, 0, WSAESOCKTNOSUPPORT }, { "seqpacket_p0", SOCK_SEQPACKET, 0, WSAESOCKTNOSUPPORT },
    { "stream_p1", SOCK_STREAM, 1, WSAEPROTONOSUPPORT }, { "stream_tcp", SOCK_STREAM, IPPROTO_TCP, WSAEPROTONOSUPPORT },
    { "stream_udp", SOCK_STREAM, IPPROTO_UDP, WSAEPROTONOSUPPORT }, { "stream_p255", SOCK_STREAM, 255, WSAEPROTONOSUPPORT },
    { "dgram_udp", SOCK_DGRAM, IPPROTO_UDP, WSAEAFNOSUPPORT }, { "dgram_p1", SOCK_DGRAM, 1, WSAEAFNOSUPPORT },
};
static void bad_triple(const struct triple *t)
{
    SOCKET s;
    int e;
    au_seterr(0);
    s = U(socket)(AF_UNIX, t->type, t->proto);
    e = au_err();
    if (s != INVALID_SOCKET) { U(closesocket)(s); }
    CHECKF(s == INVALID_SOCKET, "%s created a socket", t->name);
    if (s != INVALID_SOCKET) return;
    AU_EQ(e, t->err);
}
TEST(afu_create_refused_triples)
{
    size_t i;
    UP();
    { SOCKET s = au_sock(); if (s == INVALID_SOCKET) return; U(closesocket)(s); }
    for (i = 0; i < sizeof(g_bad_triples) / sizeof(g_bad_triples[0]); i++) bad_triple(&g_bad_triples[i]);
}
#define BAD_TRIPLE_TEST(idx) TEST(afu_create_refused_##idx) \
{ SOCKET p; UP(); p = au_sock(); if (p == INVALID_SOCKET) return; U(closesocket)(p); bad_triple(&g_bad_triples[idx]); }
BAD_TRIPLE_TEST(0) BAD_TRIPLE_TEST(1) BAD_TRIPLE_TEST(2) BAD_TRIPLE_TEST(3) BAD_TRIPLE_TEST(4)
BAD_TRIPLE_TEST(5) BAD_TRIPLE_TEST(6) BAD_TRIPLE_TEST(7) BAD_TRIPLE_TEST(8) BAD_TRIPLE_TEST(9)

TEST(afu_create_dgram_via_wsasocket_refused)
{
    SOCKET s, p;
    UP();
    p = au_sock(); if (p == INVALID_SOCKET) return; U(closesocket)(p);
    au_seterr(0);
    s = U(WSASocketW)(AF_UNIX, SOCK_DGRAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    CHECK(s == INVALID_SOCKET);
    if (s != INVALID_SOCKET) U(closesocket)(s); else AU_EQ(au_err(), WSAEAFNOSUPPORT);
}

/* ---- self description ---------------------------------------------------------------------------- */
TEST(afu_info_so_type_is_stream)
{
    int v = -1, l = sizeof(v);
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&v, &l), 0);
    AU_EQ(v, SOCK_STREAM);
    AU_EQ(l, 4);
    U(closesocket)(s);
}

TEST(afu_info_protocol_infow)
{
    WSAPROTOCOL_INFOW pi;
    int l = sizeof(pi);
    UP();
    SOCK_OR_RETURN(s);
    memset(&pi, 0xcc, sizeof(pi));
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pi, &l), 0);
    AU_EQ(l, (int)sizeof(pi));
    AU_EQ(pi.iAddressFamily, AF_UNIX);
    AU_EQ(pi.iSocketType, SOCK_STREAM);
    AU_EQ(pi.iProtocol, 0);
    AU_EQ(pi.iVersion, 2);
    U(closesocket)(s);
}

TEST(afu_info_protocol_infow_service_flags)
{
    /* A connection-oriented, reliable, ordered byte stream. */
    WSAPROTOCOL_INFOW pi;
    int l = sizeof(pi);
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pi, &l), 0);
    CHECK(!(pi.dwServiceFlags1 & XP1_CONNECTIONLESS));
    CHECK(pi.dwServiceFlags1 & XP1_GUARANTEED_DELIVERY);
    CHECK(pi.dwServiceFlags1 & XP1_GUARANTEED_ORDER);
    CHECK(!(pi.dwServiceFlags1 & XP1_MESSAGE_ORIENTED));
    CHECK(pi.dwServiceFlags1 & XP1_GRACEFUL_CLOSE);
    U(closesocket)(s);
}

TEST(afu_info_protocol_infow_address_lengths)
{
    WSAPROTOCOL_INFOW pi;
    int l = sizeof(pi);
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pi, &l), 0);
    AU_EQ(pi.iMaxSockAddr, (int)sizeof(SOCKADDR_UN));
    AU_EQ(pi.iMinSockAddr, 2);
    U(closesocket)(s);
}

TEST(afu_info_protocol_infoa_matches_w)
{
    WSAPROTOCOL_INFOA pa;
    WSAPROTOCOL_INFOW pw;
    int la = sizeof(pa), lw = sizeof(pw);
    UP();
    SOCK_OR_RETURN(s);
    if (U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOA, (char *)&pa, &la) != 0) { AU_OBS("SO_PROTOCOL_INFOA", "err %d", au_err()); U(closesocket)(s); return; }
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pw, &lw), 0);
    AU_EQ(pa.iAddressFamily, pw.iAddressFamily);
    AU_EQ(pa.iSocketType, pw.iSocketType);
    AU_EQ(pa.dwProviderReserved, pw.dwProviderReserved);
    CHECK(!memcmp(&pa.ProviderId, &pw.ProviderId, sizeof(GUID)));
    U(closesocket)(s);
}

TEST(afu_info_provider_in_catalog)
{
    /* The socket's provider id names an entry of the catalog that has the same family/type. */
    WSAPROTOCOL_INFOW pi, *buf;
    DWORD len = 0;
    int l = sizeof(pi), n, i, found = 0;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pi, &l), 0);
    U(closesocket)(s);
    U(WSAEnumProtocolsW)(NULL, NULL, &len);
    if (!len) { t_skip("no catalog"); return; }
    buf = (WSAPROTOCOL_INFOW *)HeapAlloc(GetProcessHeap(), 0, len);
    n = U(WSAEnumProtocolsW)(NULL, buf, &len);
    for (i = 0; i < n; i++) {
        if (!memcmp(&buf[i].ProviderId, &pi.ProviderId, sizeof(GUID)) && buf[i].iAddressFamily == AF_UNIX &&
            buf[i].iSocketType == SOCK_STREAM) found = 1;
    }
    CHECK(found);
    HeapFree(GetProcessHeap(), 0, buf);
}

TEST(afu_info_catalog_has_no_unix_dgram)
{
    WSAPROTOCOL_INFOW *buf;
    DWORD len = 0;
    int n, i, unix_n = 0, bad = 0;
    UP();
    { SOCKET p = au_sock(); if (p == INVALID_SOCKET) return; U(closesocket)(p); }
    U(WSAEnumProtocolsW)(NULL, NULL, &len);
    buf = (WSAPROTOCOL_INFOW *)HeapAlloc(GetProcessHeap(), 0, len);
    n = U(WSAEnumProtocolsW)(NULL, buf, &len);
    for (i = 0; i < n; i++) if (buf[i].iAddressFamily == AF_UNIX) { unix_n++; if (buf[i].iSocketType != SOCK_STREAM) bad++; }
    CHECK(unix_n >= 1);
    CHECK(bad == 0);
    HeapFree(GetProcessHeap(), 0, buf);
}

TEST(afu_create_from_protocol_info)
{
    WSAPROTOCOL_INFOW pi;
    int l = sizeof(pi);
    SOCKET t;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pi, &l), 0);
    t = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi, 0, WSA_FLAG_OVERLAPPED);
    CHECK(t != INVALID_SOCKET);
    if (t != INVALID_SOCKET) {
        int v = 0, vl = sizeof(v);
        AU_EQ(U(getsockopt)(t, SOL_SOCKET, SO_TYPE, (char *)&v, &vl), 0);
        AU_EQ(v, SOCK_STREAM);
        U(closesocket)(t);
    }
    U(closesocket)(s);
}

TEST(afu_create_explicit_values_with_protocol_info)
{
    WSAPROTOCOL_INFOW pi;
    int l = sizeof(pi);
    SOCKET t;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&pi, &l), 0);
    t = U(WSASocketW)(AF_UNIX, SOCK_STREAM, 0, &pi, 0, WSA_FLAG_OVERLAPPED);
    CHECK(t != INVALID_SOCKET);
    if (t != INVALID_SOCKET) U(closesocket)(t);
    U(closesocket)(s);
}

/* ---- accept state, error state ------------------------------------------------------------------ */
TEST(afu_state_acceptconn_before_after_listen)
{
    int v = 7, l = sizeof(v);
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &l), 0);
    AU_EQ(v, 0);
    AU_EQ(au_bind_leaf(s, "st_accept.sock", NULL), 0);
    AU_EQ(U(listen)(s, 1), 0);
    v = 7; l = sizeof(v);
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &l), 0);
    AU_EQ(v, 1);
    U(closesocket)(s);
    au_unlink_leaf("st_accept.sock");
}

TEST(afu_state_so_error_clean)
{
    int v = 7, l = sizeof(v);
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_ERROR, (char *)&v, &l), 0);
    AU_EQ(v, 0);
    U(closesocket)(s);
}

TEST(afu_state_buffer_sizes_positive)
{
    int v = 0, l = sizeof(v);
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_RCVBUF, (char *)&v, &l), 0);
    CHECK(v > 0);
    v = 0; l = sizeof(v);
    AU_EQ(U(getsockopt)(s, SOL_SOCKET, SO_SNDBUF, (char *)&v, &l), 0);
    CHECK(v > 0);
    U(closesocket)(s);
}

/* ---- close semantics ------------------------------------------------------------------------------ */
TEST(afu_close_twice_is_notsock)
{
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(U(closesocket)(s), 0);
    au_seterr(0);
    AU_EQ(U(closesocket)(s), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENOTSOCK);
}

TEST(afu_close_invalid_socket_is_notsock)
{
    UP();
    { SOCKET p = au_sock(); if (p == INVALID_SOCKET) return; U(closesocket)(p); }
    au_seterr(0);
    AU_EQ(U(closesocket)(INVALID_SOCKET), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENOTSOCK);
}

TEST(afu_close_then_use_is_notsock)
{
    char b[4];
    SOCKADDR_UN a;
    int l;
    UP();
    SOCK_OR_RETURN(s);
    U(closesocket)(s);
    au_seterr(0);
    AU_EQ(U(send)(s, "x", 1, 0), SOCKET_ERROR); AU_EQ(au_err(), WSAENOTSOCK);
    au_seterr(0);
    AU_EQ(U(recv)(s, b, 4, 0), SOCKET_ERROR); AU_EQ(au_err(), WSAENOTSOCK);
    au_seterr(0);
    AU_EQ(U(listen)(s, 1), SOCKET_ERROR); AU_EQ(au_err(), WSAENOTSOCK);
    au_addr(&a, "x");
    au_seterr(0);
    AU_EQ(au_bind_to(s, &a), SOCKET_ERROR); AU_EQ(au_err(), WSAENOTSOCK);
    l = sizeof(a);
    au_seterr(0);
    AU_EQ(U(getsockname)(s, (struct sockaddr *)&a, &l), SOCKET_ERROR); AU_EQ(au_err(), WSAENOTSOCK);
    au_seterr(0);
    AU_EQ(U(accept)(s, NULL, NULL), INVALID_SOCKET); AU_EQ(au_err(), WSAENOTSOCK);
    au_seterr(0);
    AU_EQ(U(shutdown)(s, SD_BOTH), SOCKET_ERROR); AU_EQ(au_err(), WSAENOTSOCK);
}

TEST(afu_close_non_socket_handle_is_notsock)
{
    /* A file handle is not a socket. */
    HANDLE h;
    char p[MAX_PATH];
    UP();
    { SOCKET q = au_sock(); if (q == INVALID_SOCKET) return; U(closesocket)(q); }
    t_tmpfile(p, sizeof(p), "plainfile.tmp");
    h = CreateFileA(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { t_skip("scratch file"); return; }
    au_seterr(0);
    AU_EQ(U(closesocket)((SOCKET)h), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENOTSOCK);
    CloseHandle(h);
    DeleteFileA(p);
}

/* ---- duplication ------------------------------------------------------------------------------------ */
TEST(afu_dup_info_roundtrip)
{
    WSAPROTOCOL_INFOW pi;
    SOCKET d;
    UP();
    SOCK_OR_RETURN(s);
    memset(&pi, 0, sizeof(pi));
    if (U(WSADuplicateSocketW)(s, GetCurrentProcessId(), &pi) != 0) { AU_OBS("WSADuplicateSocketW", "err %d", au_err()); U(closesocket)(s); return; }
    AU_EQ(pi.iAddressFamily, AF_UNIX);
    AU_EQ(pi.iSocketType, SOCK_STREAM);
    d = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi, 0, WSA_FLAG_OVERLAPPED);
    CHECK(d != INVALID_SOCKET);
    if (d != INVALID_SOCKET) {
        CHECK(d != s);
        U(closesocket)(d);
    }
    U(closesocket)(s);
}

TEST(afu_dup_shares_bound_name)
{
    WSAPROTOCOL_INFOW pi;
    SOCKADDR_UN a, b;
    int l;
    SOCKET d;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "dup_name.sock", &a), 0);
    if (U(WSADuplicateSocketW)(s, GetCurrentProcessId(), &pi) != 0) { AU_OBS("dup", "err %d", au_err()); goto out; }
    d = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi, 0, WSA_FLAG_OVERLAPPED);
    if (d == INVALID_SOCKET) { CHECK(0); goto out; }
    memset(&b, 0, sizeof(b)); l = sizeof(b);
    AU_EQ(U(getsockname)(d, (struct sockaddr *)&b, &l), 0);
    CHECK(!strcmp(a.sun_path, b.sun_path));
    U(closesocket)(d);
out:
    U(closesocket)(s);
    au_unlink_leaf("dup_name.sock");
}

TEST(afu_dup_handle_kernel_duplicate_works)
{
    /* DuplicateHandle of the socket handle yields a second reference to the same endpoint. */
    HANDLE h = NULL;
    SOCKADDR_UN a;
    int l = sizeof(a);
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(au_bind_leaf(s, "dup_handle.sock", NULL), 0);
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &h, 0, FALSE, DUPLICATE_SAME_ACCESS));
    if (h) {
        AU_EQ(U(getsockname)((SOCKET)h, (struct sockaddr *)&a, &l), 0);
        U(closesocket)((SOCKET)h);
    }
    U(closesocket)(s);
    au_unlink_leaf("dup_handle.sock");
}
