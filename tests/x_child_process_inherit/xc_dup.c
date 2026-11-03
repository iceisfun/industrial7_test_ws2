/* x_child_process_inherit / dup: WSADuplicateSocketW protocol-info blobs. The blob contract (size, stable fields,
 * agreement with the provider catalog and with SO_PROTOCOL_INFOW), the argument errors, WSASocketW(FROM_PROTOCOL_INFO)
 * in a target process for TCP, UDP and listeners under every handle-inheritance flag combination, shared data between
 * the two owners, explicit family/type values next to a blob, and SO_UPDATE_ACCEPT_CONTEXT performed by a child. */
#include "xc.h"

CHILD(idle) { Sleep(XC_CHILD_TIMEOUT); return 0; }

/* ---------------- the blob itself ---------------- */
static int dup_to_idle(SOCKET s, WSAPROTOCOL_INFOW *pi, int *err, HANDLE *proc)
{
    int rc; *proc = xc_idle();
    if (!*proc) return -2;
    memset(pi, 0xcc, sizeof *pi);
    rc = U(WSADuplicateSocketW)(s, GetProcessId(*proc), pi);
    *err = rc ? xc_werr() : 0;
    return rc;
}
TEST(dup_blob_size_is_protocol_info_w)
{
    CHECK(sizeof(WSAPROTOCOL_INFOW) == 628);
    CHECK(sizeof(WSAPROTOCOL_INFOA) == 372);
}
struct fam { int af, type, proto; const char *name; };
static const struct fam fams[] = {
    { AF_INET, SOCK_STREAM, IPPROTO_TCP, "tcp4" }, { AF_INET, SOCK_DGRAM, IPPROTO_UDP, "udp4" },
    { AF_INET6, SOCK_STREAM, IPPROTO_TCP, "tcp6" }, { AF_INET6, SOCK_DGRAM, IPPROTO_UDP, "udp6" },
    { AF_UNIX, SOCK_STREAM, 0, "unix" },
};
TEST(dup_blob_fields_per_family)
{
    unsigned i; UP();
    for (i = 0; i < sizeof fams / sizeof fams[0]; i++) {
        const struct fam *f = &fams[i]; SOCKET s = U(WSASocketW)(f->af, f->type, 0, NULL, 0, OVLD); WSAPROTOCOL_INFOW pi, o; int e = 0, ol = sizeof o; HANDLE p;
        if (s == INVALID_SOCKET) { t_note("%s: socket unavailable (%d)", f->name, xc_werr()); continue; }
        XEQ(dup_to_idle(s, &pi, &e, &p), 0);
        XEQ(pi.iAddressFamily, f->af);
        XEQ(pi.iSocketType, f->type);
        if (f->proto) XEQ(pi.iProtocol, f->proto);
        CHECKF((pi.dwServiceFlags1 & XP1_IFS_HANDLES) != 0, "%s flags 0x%lx", f->name, pi.dwServiceFlags1);
        XEQ(pi.ProtocolChain.ChainLen, 1);
        CHECK(pi.dwCatalogEntryId != 0);
        XEQ(pi.iVersion, 2);
        XEQ(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&o, &ol), 0);
        XEQ(ol, sizeof o);
        XEQ(o.dwCatalogEntryId, pi.dwCatalogEntryId);
        XEQ(o.iAddressFamily, pi.iAddressFamily);
        XEQ(o.iSocketType, pi.iSocketType);
        XEQ(o.iProtocol, pi.iProtocol);
        XEQ(o.dwServiceFlags1, pi.dwServiceFlags1);
        XEQ(memcmp(&o.ProviderId, &pi.ProviderId, sizeof(GUID)), 0);
        t_note("%s: sz=%ls flags2=0x%lx pflags=0x%lx maxmsg=%lu", f->name, pi.szProtocol, pi.dwServiceFlags2, pi.dwProviderFlags, pi.dwMessageSize);
        xc_close(s); xc_kill(p);
    }
}
TEST(dup_blob_matches_catalog_entry)
{
    SOCKET s; WSAPROTOCOL_INFOW pi, *cat; DWORD len = 0; int n, i, e, found = 0; HANDLE p;
    UP(); s = xc_make(AF_INET, SOCK_STREAM, OVLD);
    if (s == INVALID_SOCKET) { t_skip("socket"); return; }
    XEQ(dup_to_idle(s, &pi, &e, &p), 0);
    U(WSAEnumProtocolsW)(NULL, NULL, &len);
    cat = (WSAPROTOCOL_INFOW *)HeapAlloc(GetProcessHeap(), 0, len ? len : 1);
    n = U(WSAEnumProtocolsW)(NULL, cat, &len);
    for (i = 0; i < n; i++) if (cat[i].dwCatalogEntryId == pi.dwCatalogEntryId) {
        found = 1;
        XEQ(memcmp(&cat[i].ProviderId, &pi.ProviderId, sizeof(GUID)), 0);
        XEQ(cat[i].iAddressFamily, pi.iAddressFamily);
        XEQ(cat[i].iSocketType, pi.iSocketType);
        XEQ(cat[i].iProtocol, pi.iProtocol);
        XEQ(lstrcmpW(cat[i].szProtocol, pi.szProtocol), 0);
    }
    CHECK(found);
    HeapFree(GetProcessHeap(), 0, cat);
    xc_close(s); xc_kill(p);
}
TEST(dup_two_blobs_share_stable_fields)
{
    SOCKET s; WSAPROTOCOL_INFOW a, b; int e; HANDLE pa, pb; DWORD ra, rb;
    UP(); s = xc_make(AF_INET, SOCK_STREAM, OVLD);
    if (s == INVALID_SOCKET) { t_skip("socket"); return; }
    XEQ(dup_to_idle(s, &a, &e, &pa), 0);
    XEQ(dup_to_idle(s, &b, &e, &pb), 0);
    XEQ(a.dwServiceFlags1, b.dwServiceFlags1);
    XEQ(a.iAddressFamily, b.iAddressFamily);
    XEQ(a.iSocketType, b.iSocketType);
    XEQ(a.iProtocol, b.iProtocol);
    XEQ(a.dwCatalogEntryId, b.dwCatalogEntryId);
    XEQ(memcmp(&a.ProviderId, &b.ProviderId, sizeof(GUID)), 0);
    XEQ(lstrcmpW(a.szProtocol, b.szProtocol), 0);
    ra = a.dwProviderReserved; rb = b.dwProviderReserved;
    t_note("provider-reserved differs between two duplications: %s", ra != rb ? "yes" : "no");
    xc_close(s); xc_kill(pa); xc_kill(pb);
}
TEST(dup_blob_same_for_noinherit_and_plain_socket)
{
    SOCKET a, b; WSAPROTOCOL_INFOW x, y; int e; HANDLE pa, pb;
    UP(); a = xc_make(AF_INET, SOCK_STREAM, OVLD); b = xc_make(AF_INET, SOCK_STREAM, OVLD | NOINH);
    if (a == INVALID_SOCKET || b == INVALID_SOCKET) { t_skip("socket"); return; }
    XEQ(dup_to_idle(a, &x, &e, &pa), 0);
    XEQ(dup_to_idle(b, &y, &e, &pb), 0);
    XEQ(x.dwCatalogEntryId, y.dwCatalogEntryId);
    XEQ(x.dwServiceFlags1, y.dwServiceFlags1);
    XEQ(memcmp(&x.ProviderId, &y.ProviderId, sizeof(GUID)), 0);
    xc_close(a); xc_close(b); xc_kill(pa); xc_kill(pb);
}

/* ---------------- argument errors ---------------- */
TEST(dup_invalid_socket_is_notsock)
{
    WSAPROTOCOL_INFOW pi; HANDLE p = NULL;
    UP(); p = xc_idle();
    memset(&pi, 0, sizeof pi);
    xc_setwerr(0);
    XEQ(U(WSADuplicateSocketW)(INVALID_SOCKET, GetProcessId(p), &pi), SOCKET_ERROR);
    XEQ(xc_werr(), WSAENOTSOCK);
    xc_kill(p);
}
TEST(dup_closed_socket_is_notsock)
{
    SOCKET s; WSAPROTOCOL_INFOW pi; HANDLE p;
    UP(); s = xc_make(AF_INET, SOCK_STREAM, OVLD);
    if (s == INVALID_SOCKET) { t_skip("socket"); return; }
    xc_close(s); p = xc_idle();
    xc_setwerr(0);
    XEQ(U(WSADuplicateSocketW)(s, GetProcessId(p), &pi), SOCKET_ERROR);
    XEQ(xc_werr(), WSAENOTSOCK);
    xc_kill(p);
}
TEST(dup_file_handle_is_notsock)
{
    char path[MAX_PATH]; HANDLE f, p; WSAPROTOCOL_INFOW pi;
    UP(); t_tmpfile(path, sizeof path, "dupfile.bin");
    f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) { t_skip("scratch file"); return; }
    p = xc_idle();
    xc_setwerr(0);
    XEQ(U(WSADuplicateSocketW)((SOCKET)(ULONG_PTR)f, GetProcessId(p), &pi), SOCKET_ERROR);
    XEQ(xc_werr(), WSAENOTSOCK);
    CloseHandle(f); xc_kill(p);
}
TEST(dup_bad_process_id_values)
{
    static const DWORD pids[] = { 0, 0xffffffffu, 0x7ffffffcu };
    SOCKET s; unsigned i; WSAPROTOCOL_INFOW pi;
    UP(); s = xc_make(AF_INET, SOCK_STREAM, OVLD);
    if (s == INVALID_SOCKET) { t_skip("socket"); return; }
    for (i = 0; i < 3; i++) {
        int rc; xc_setwerr(0);
        rc = U(WSADuplicateSocketW)(s, pids[i], &pi);
        XEQ(rc, SOCKET_ERROR);
        XEQ(xc_werr(), WSAEINVAL);
    }
    xc_close(s);
}
TEST(dup_socket_stays_usable_after_failed_duplication)
{
    SOCKET c, s; WSAPROTOCOL_INFOW pi; char b;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    XEQ(U(WSADuplicateSocketW)(c, 0, &pi), SOCKET_ERROR);
    XEQ(xc_send(c, "k", 1), 1);
    XEQ(xc_recv_n(s, &b, 1), 1);
    xc_close(c); xc_close(s);
}
TEST(dup_to_own_process_gives_second_handle)
{
    SOCKET s; WSAPROTOCOL_INFOW pi; int rc;
    UP(); s = xc_make(AF_INET, SOCK_STREAM, OVLD);
    if (s == INVALID_SOCKET) { t_skip("socket"); return; }
    xc_setwerr(0);
    rc = U(WSADuplicateSocketW)(s, GetCurrentProcessId(), &pi);
    XEQ(rc, 0);                                       /* duplicating into the calling process is allowed */
    if (rc == 0) {
        SOCKET d = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi, 0, OVLD);
        CHECK(d != INVALID_SOCKET);
        CHECK(d != s);
        xc_close(d);
    }
    xc_close(s);
}

/* ---------------- WSASocketW(FROM_PROTOCOL_INFO) in the target ---------------- */
/* kind: t = connected stream, u = bound datagram, l = listener. Result bits are the failed steps. */
CHILD(from_info)
{
    WSAPROTOCOL_INFOW pi; SOCKET s; unsigned fails = 0; int flags = xc_arg_int(argv, 3); const char *kind = argv[2]; char b[8] = {0}; DWORD f = 0;
    xc_child_up();
    STEP(0, xc_read_blob(argv, 1, &pi));
    s = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi, 0, (DWORD)flags);
    STEP(1, s != INVALID_SOCKET);
    if (s == INVALID_SOCKET) return (int)(fails | (xc_e8(xc_werr()) << 16));
    xc_rcvtimeo(s, XC_WAIT);
    STEP(2, xc_type_of(s) == (kind[0] == 'u' ? SOCK_DGRAM : SOCK_STREAM));
    STEP(3, xc_name_port(s, 0) == xc_arg_int(argv, 4));
    STEP(4, GetHandleInformation(H(s), &f) && (f & HANDLE_FLAG_INHERIT) != 0);   /* the flag is not applied to a duplicated socket */
    if (kind[0] == 't') {
        STEP(5, xc_name_port(s, 1) == xc_arg_int(argv, 5));
        STEP(6, xc_recv_n(s, b, 3) == 3 && !memcmp(b, "abc", 3));
        STEP(7, xc_send(s, "z", 1) == 1);
    } else if (kind[0] == 'u') {
        struct sockaddr_in fr; int fl = sizeof fr;
        STEP(6, U(recvfrom)(s, b, sizeof b, 0, (struct sockaddr *)&fr, &fl) == 4 && !memcmp(b, "dgrm", 4));
        STEP(7, xc_port_of(&fr) == xc_arg_int(argv, 5));
    } else {
        SOCKET a = xc_accept(s, XC_WAIT);
        STEP(6, a != INVALID_SOCKET);
        if (a != INVALID_SOCKET) { STEP(7, xc_send(a, "k", 1) == 1); U(closesocket)(a); }
    }
    U(closesocket)(s);
    return (int)fails;
}
static void from_info_tcp(int sflags, int cflags)
{
    SOCKET c, s; char a[96], b; DWORD code; int rc, e; HANDLE p;
    UP(); PAIR_OR_SKIP(c, s, sflags);
    p = xc_spawn_blob("from_info", XARGS(a, "t %d %d %d", cflags, xc_name_port(c, 0), xc_name_port(c, 1)), c, NULL, 0, &rc, &e);
    CHECK(p != NULL); XEQ(rc, 0);
    XEQ(xc_send(s, "abc", 3), 3);
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'z');
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    xc_close(c); xc_close(s);
}
TEST(dup_child_tcp_sync_flags0)             { from_info_tcp(SYNC, 0); }
TEST(dup_child_tcp_overlapped)              { from_info_tcp(OVLD, OVLD); }
TEST(dup_child_tcp_noinherit_child_flag)    { from_info_tcp(OVLD, OVLD | NOINH); }
TEST(dup_child_tcp_noinherit_parent_socket) { from_info_tcp(OVLD | NOINH, OVLD); }
TEST(dup_child_tcp_plain_parent_sync_child) { from_info_tcp(PLAIN, SYNC); }
static void from_info_udp(int sflags, int cflags)
{
    SOCKET u, tx; struct sockaddr_in ua, ta; char a[96]; DWORD code; int rc, e; HANDLE p;
    UP(); u = xc_bound(SOCK_DGRAM, sflags, &ua); tx = xc_bound(SOCK_DGRAM, PLAIN, &ta);
    if (u == INVALID_SOCKET || tx == INVALID_SOCKET) { t_skip("setup"); return; }
    p = xc_spawn_blob("from_info", XARGS(a, "u %d %d %d", cflags, xc_port_of(&ua), xc_port_of(&ta)), u, NULL, 0, &rc, &e);
    CHECK(p != NULL); XEQ(rc, 0);
    XEQ(U(sendto)(tx, "dgrm", 4, 0, (struct sockaddr *)&ua, sizeof ua), 4);
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    CHECK(!xc_readable(u, 0));
    xc_close(u); xc_close(tx);
}
TEST(dup_child_udp_overlapped)          { from_info_udp(OVLD, OVLD); }
TEST(dup_child_udp_sync)                { from_info_udp(SYNC, SYNC); }
TEST(dup_child_udp_noinherit)           { from_info_udp(OVLD | NOINH, OVLD | NOINH); }
static void from_info_lst(int lflags, int cflags)
{
    SOCKET l, c; struct sockaddr_in la; char a[96], b; DWORD code; int rc, e; HANDLE p;
    UP(); l = xc_listener(lflags, &la);
    if (l == INVALID_SOCKET) { t_skip("setup"); return; }
    p = xc_spawn_blob("from_info", XARGS(a, "l %d %d 0", cflags, xc_port_of(&la)), l, NULL, 0, &rc, &e);
    CHECK(p != NULL); XEQ(rc, 0);
    c = xc_make(AF_INET, SOCK_STREAM, PLAIN); xc_rcvtimeo(c, XC_WAIT);
    XEQ(U(connect)(c, (struct sockaddr *)&la, sizeof la), 0);
    XEQ(xc_recv_n(c, &b, 1), 1); XEQ(b, 'k');
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    xc_close(c); xc_close(l);
}
TEST(dup_child_listener_overlapped)     { from_info_lst(OVLD, OVLD); }
TEST(dup_child_listener_noinherit)      { from_info_lst(OVLD | NOINH, OVLD | NOINH); }

/* ---------------- shared data between owners ---------------- */
CHILD(take_two)
{
    WSAPROTOCOL_INFOW pi; SOCKET s; unsigned fails = 0; char b[4] = {0};
    xc_child_up();
    STEP(0, xc_read_blob(argv, 1, &pi));
    s = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi, 0, OVLD);
    STEP(1, s != INVALID_SOCKET);
    if (s == INVALID_SOCKET) return (int)fails;
    xc_rcvtimeo(s, XC_WAIT);
    STEP(2, xc_recv_n(s, b, 2) == 2 && !memcmp(b, "ab", 2));
    return (int)fails;                                /* exit closes the child's handle only */
}
TEST(dup_shared_receive_queue_split_between_owners)
{
    SOCKET c, s; char a[32], b[4] = {0}; DWORD code; int rc, e; HANDLE p;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    XEQ(xc_send(s, "abcd", 4), 4);
    p = xc_spawn_blob("take_two", "", c, NULL, 0, &rc, &e);
    CHECK(p != NULL); XEQ(rc, 0);
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    XEQ(xc_recv_n(c, b, 2), 2);
    CHECK(!memcmp(b, "cd", 2));                       /* the child took the first two bytes */
    xc_close(c); xc_close(s);
}
CHILD(hold_dup)
{
    WSAPROTOCOL_INFOW pi; SOCKET s; unsigned fails = 0; char g = 0;
    xc_child_up();
    STEP(0, xc_read_blob(argv, 1, &pi));
    s = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi, 0, OVLD);
    STEP(1, s != INVALID_SOCKET);
    if (s == INVALID_SOCKET) return (int)fails;
    xc_rcvtimeo(s, XC_WAIT);
    STEP(2, xc_send(s, "R", 1) == 1);
    STEP(3, U(recv)(s, &g, 1, 0) == 1 && g == 'G');
    STEP(4, xc_send(s, "X", 1) == 1);
    return (int)fails;
}
TEST(dup_parent_close_keeps_connection_while_duplicate_lives)
{
    SOCKET c, s; char b; DWORD code; int rc, e; HANDLE p;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    p = xc_spawn_blob("hold_dup", "", c, NULL, 0, &rc, &e);
    CHECK(p != NULL); XEQ(rc, 0);
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'R');
    xc_close(c);
    CHECK(!xc_readable(s, 200));
    XEQ(xc_send(s, "G", 1), 1);
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'X');
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    xc_setwerr(0);
    XEQ(U(recv)(s, &b, 1, 0), SOCKET_ERROR);
    XEQ(xc_werr(), WSAECONNRESET);
    xc_close(s);
}
/* The blob names a kernel-level duplicate that exists from the moment of the call: the parent closing at once is fine. */
TEST(dup_parent_closes_immediately_child_still_works)
{
    SOCKET c, s; char b; DWORD code; int rc, e; HANDLE p;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    p = xc_spawn_blob("hold_dup", "", c, NULL, 0, &rc, &e);
    CHECK(p != NULL); XEQ(rc, 0);
    xc_close(c);
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'R');
    XEQ(xc_send(s, "G", 1), 1);
    XEQ(xc_recv_n(s, &b, 1), 1); XEQ(b, 'X');
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    xc_close(s);
}
/* A duplication whose target never creates the socket keeps the endpoint alive until that process exits. */
TEST(dup_unclaimed_duplicate_keeps_endpoint_until_target_exits)
{
    SOCKET c, s; char b; WSAPROTOCOL_INFOW pi; int e; HANDLE p; DWORD code;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    XEQ(dup_to_idle(c, &pi, &e, &p), 0);
    xc_close(c);
    CHECK(!xc_readable(s, 200));                      /* no FIN: the duplicate in the idle process owns it */
    xc_kill(p);                                       /* the process dies, the duplicate goes with it */
    xc_setwerr(0);
    XEQ(U(recv)(s, &b, 1, 0), SOCKET_ERROR);          /* a handle released by process death resets the stream */
    XEQ(xc_werr(), WSAECONNRESET);
    xc_close(s);
}

/* ---------------- explicit values next to a blob ---------------- */
CHILD(from_info_explicit)
{
    WSAPROTOCOL_INFOW pi; SOCKET s; int af = xc_arg_int(argv, 2), ty = xc_arg_int(argv, 3), pr = xc_arg_int(argv, 4);
    xc_child_up();
    if (!xc_read_blob(argv, 1, &pi)) return 250;
    s = U(WSASocketW)(af, ty, pr, &pi, 0, OVLD);
    if (s != INVALID_SOCKET) { int t = xc_type_of(s); U(closesocket)(s); return t == SOCK_STREAM ? 0 : 100; }
    return (int)xc_e8(xc_werr());
}
static DWORD explicit_case(int af, int ty, int pr)
{
    SOCKET c, s; char a[64]; int rc, e; HANDLE p;
    if (!xc_up()) return 255;
    if (!xc_pair(OVLD, &c, &s)) return 254;
    p = xc_spawn_blob("from_info_explicit", XARGS(a, "%d %d %d", af, ty, pr), c, NULL, 0, &rc, &e);
    if (!p || rc) { xc_close(c); xc_close(s); return 253; }
    {
        DWORD code = xc_wait(p, XC_CHILD_TIMEOUT);
        xc_close(c); xc_close(s);
        return code;
    }
}
TEST(dup_child_explicit_matching_values)
{
    XEQ(explicit_case(AF_INET, SOCK_STREAM, IPPROTO_TCP), 0);
    XEQ(explicit_case(FROM_PROTOCOL_INFO, SOCK_STREAM, FROM_PROTOCOL_INFO), 0);
    XEQ(explicit_case(AF_INET, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO), 0);
}
/* With a blob present, explicit family/type/protocol values are ignored: the socket is the blob's. */
TEST(dup_child_explicit_values_are_ignored_next_to_blob)
{
    XEQ(explicit_case(AF_INET6, SOCK_STREAM, IPPROTO_TCP), 0);
    XEQ(explicit_case(AF_INET, SOCK_DGRAM, IPPROTO_TCP), 0);
    XEQ(explicit_case(AF_INET, SOCK_STREAM, IPPROTO_UDP), 0);
    XEQ(explicit_case(AF_UNIX, SOCK_RAW, 99), 0);
}

/* ---------------- SO_UPDATE_ACCEPT_CONTEXT in a child ---------------- */
static LPFN_ACCEPTEX get_acceptex(SOCKET l)
{
    LPFN_ACCEPTEX fn = NULL; GUID g = WSAID_ACCEPTEX; DWORD n = 0;
    if (U(WSAIoctl)(l, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &fn, sizeof fn, &n, NULL, NULL)) return NULL;
    return fn;
}
/* AcceptEx completed in the parent; the child sees the accepted socket and the listener. The context option names a
 * listener the child's library has not seen yet; touching the listener first changes the outcome. */
CHILD(uac_child)
{
    SOCKET a = xc_arg_sock(argv, 1), l = xc_arg_sock(argv, 2); unsigned fails = 0; int pe, ne;
    struct sockaddr_in n; int nl = sizeof n; const char *mode = argv[5];
    xc_child_up();
    xc_setwerr(0);
    pe = U(getpeername)(a, (struct sockaddr *)&n, &nl);
    ne = xc_werr();
    STEP(0, pe == SOCKET_ERROR && ne == WSAENOTCONN);       /* not yet bound to the connection */
    if (mode[0] == 't') STEP(5, xc_name_port(l, 0) == xc_arg_int(argv, 4));
    xc_setwerr(0);
    pe = U(setsockopt)(a, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&l, sizeof l);
    STEP(1, pe == 0);
    if (pe) return (int)(fails | (xc_e8(xc_werr()) << 16));
    nl = sizeof n;
    STEP(2, U(getpeername)(a, (struct sockaddr *)&n, &nl) == 0 && xc_port_of(&n) == xc_arg_int(argv, 3));
    nl = sizeof n;
    STEP(3, U(getsockname)(a, (struct sockaddr *)&n, &nl) == 0 && xc_port_of(&n) == xc_arg_int(argv, 4));
    STEP(4, xc_send(a, "uac", 3) == 3);
    return (int)fails;
}
static void uac_case(const char *mode, DWORD want_code)
{
    SOCKET l, a, c; struct sockaddr_in la, ca; LPFN_ACCEPTEX fn; char buf[64], arg[128]; OVERLAPPED ov; DWORD got = 0, code; HANDLE h[2]; int cl = sizeof ca;
    UP(); l = xc_listener(OVLD, &la); a = xc_make(AF_INET, SOCK_STREAM, OVLD);
    if (l == INVALID_SOCKET || a == INVALID_SOCKET) { t_skip("setup"); return; }
    fn = get_acceptex(l);
    if (!fn) { t_skip("AcceptEx unavailable"); return; }
    memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    CHECK(fn(l, a, buf, 0, 32, 32, &got, &ov) || xc_werr() == ERROR_IO_PENDING);
    c = xc_make(AF_INET, SOCK_STREAM, PLAIN); xc_rcvtimeo(c, XC_WAIT);
    XEQ(U(connect)(c, (struct sockaddr *)&la, sizeof la), 0);
    XEQ(U(getsockname)(c, (struct sockaddr *)&ca, &cl), 0);
    XEQ(WaitForSingleObject(ov.hEvent, XC_WAIT), WAIT_OBJECT_0);
    h[0] = H(a); h[1] = H(l);
    code = xc_run("uac_child", XARGS(arg, "%llu %llu %d %d %s", xc_u(a), xc_u(l), xc_port_of(&ca), xc_port_of(&la), mode), h, 2);
    XEQ(code, want_code);
    if (want_code == 0) CHECK(xc_expect(c, "uac"));
    CloseHandle(ov.hEvent);
    xc_close(c); xc_close(a); xc_close(l);
}
TEST(dup_uac_in_child_untouched_listener_is_notsock)  { uac_case("plain", 0x260002); }
TEST(dup_uac_in_child_after_touching_listener_works)  { uac_case("touch", 0); }
/* AcceptEx issued by the child itself on an inherited listener. */
CHILD(acceptex_in_child)
{
    SOCKET l = xc_arg_sock(argv, 1), a; unsigned fails = 0; LPFN_ACCEPTEX fn; char buf[64]; OVERLAPPED ov; DWORD got = 0; struct sockaddr_in n; int nl = sizeof n;
    xc_child_up();
    a = xc_make(AF_INET, SOCK_STREAM, OVLD);
    fn = get_acceptex(l);
    STEP(0, a != INVALID_SOCKET && fn != NULL);
    if (!fn || a == INVALID_SOCKET) return (int)fails;
    memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    STEP(1, fn(l, a, buf, 0, 32, 32, &got, &ov) || xc_werr() == ERROR_IO_PENDING);
    STEP(3, WaitForSingleObject(ov.hEvent, XC_WAIT) == WAIT_OBJECT_0);
    STEP(4, U(setsockopt)(a, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&l, sizeof l) == 0);
    STEP(5, U(getsockname)(a, (struct sockaddr *)&n, &nl) == 0 && xc_port_of(&n) == xc_arg_int(argv, 2));
    STEP(6, xc_send(a, "ex", 2) == 2);
    U(closesocket)(a);
    return (int)fails;
}
TEST(dup_acceptex_issued_by_child_on_inherited_listener)
{
    SOCKET l, c; struct sockaddr_in la; char arg[64]; DWORD code; HANDLE h[1], p;
    UP(); l = xc_listener(OVLD, &la);
    if (l == INVALID_SOCKET) { t_skip("setup"); return; }
    h[0] = H(l);
    p = xc_spawn("acceptex_in_child", XARGS(arg, "%llu %d", xc_u(l), xc_port_of(&la)), h, 1, NULL);
    CHECK(p != NULL);
    c = xc_make(AF_INET, SOCK_STREAM, PLAIN); xc_rcvtimeo(c, XC_WAIT);
    XEQ(U(connect)(c, (struct sockaddr *)&la, sizeof la), 0);
    CHECK(xc_expect(c, "ex"));
    code = xc_wait(p, XC_CHILD_TIMEOUT);
    XEQ(code, 0);
    xc_close(c); xc_close(l);
}
/* The context option rejects a socket that is not a listener. */
CHILD(uac_bad)
{
    SOCKET a = xc_arg_sock(argv, 1), other = xc_arg_sock(argv, 2); int r; unsigned e;
    xc_child_up();
    xc_type_of(a); xc_type_of(other);                 /* make both known to the library first */
    xc_setwerr(0);
    r = U(setsockopt)(a, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&other, sizeof other);
    e = r ? xc_e8(xc_werr()) : 0;
    return (int)e;
}
TEST(dup_uac_with_datagram_socket_context_is_accepted)
{
    SOCKET l, a, c, u; struct sockaddr_in la; LPFN_ACCEPTEX fn; char buf[64], arg[96]; OVERLAPPED ov; DWORD got = 0, code; HANDLE h[2];
    UP(); l = xc_listener(OVLD, &la); a = xc_make(AF_INET, SOCK_STREAM, OVLD); u = xc_make(AF_INET, SOCK_DGRAM, OVLD);
    if (l == INVALID_SOCKET || a == INVALID_SOCKET || u == INVALID_SOCKET) { t_skip("setup"); return; }
    fn = get_acceptex(l);
    if (!fn) { t_skip("AcceptEx unavailable"); return; }
    memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    CHECK(fn(l, a, buf, 0, 32, 32, &got, &ov) || xc_werr() == ERROR_IO_PENDING);
    c = xc_make(AF_INET, SOCK_STREAM, PLAIN);
    XEQ(U(connect)(c, (struct sockaddr *)&la, sizeof la), 0);
    XEQ(WaitForSingleObject(ov.hEvent, XC_WAIT), WAIT_OBJECT_0);
    h[0] = H(a); h[1] = H(u);
    code = xc_run("uac_bad", XARGS(arg, "%llu %llu", xc_u(a), xc_u(u)), h, 2);
    XEQ(code, 0);                                     /* the option does not validate the kind of the context socket */
    CloseHandle(ov.hEvent);
    xc_close(c); xc_close(a); xc_close(l); xc_close(u);
}
