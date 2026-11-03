/* AF_UNIX stream sockets: ioctls. ioctlsocket commands, WSAIoctl control codes (a sweep recording how
 * each one answers on this family), extension function lookup, and ConnectEx / AcceptEx /
 * DisconnectEx / TransmitFile on AF_UNIX sockets. */
#include "au.h"

#ifndef SIO_BASE_HANDLE
#define SIO_BASE_HANDLE _WSAIOR(IOC_WS2, 34)
#endif
#ifndef SIO_BSP_HANDLE
#define SIO_BSP_HANDLE _WSAIOR(IOC_WS2, 27)
#endif
#ifndef SIO_BSP_HANDLE_SELECT
#define SIO_BSP_HANDLE_SELECT _WSAIOR(IOC_WS2, 28)
#endif
#ifndef SIO_BSP_HANDLE_POLL
#define SIO_BSP_HANDLE_POLL _WSAIOR(IOC_WS2, 29)
#endif

/* ---- ioctlsocket ------------------------------------------------------------------------------- */
TEST(afu_ioc_fionbio_roundtrip)
{
    u_long v = 1;
    char b[4];
    TRIO(t, "ioc_nbio.sock");
    AU_EQ(U(ioctlsocket)(t.srv, FIONBIO, &v), 0);
    au_seterr(0);
    AU_EQ(U(recv)(t.srv, b, 4, 0), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEWOULDBLOCK);
    v = 0;
    AU_EQ(U(ioctlsocket)(t.srv, FIONBIO, &v), 0);
    au_rcvtimeo(t.srv, 100);
    au_seterr(0);
    AU_EQ(U(recv)(t.srv, b, 4, 0), SOCKET_ERROR);
    AU_EQ(au_err(), WSAETIMEDOUT);
    au_trio_close(&t);
}

TEST(afu_ioc_fionbio_on_unconnected_and_listener)
{
    u_long v = 1;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(U(ioctlsocket)(s, FIONBIO, &v), 0);
    AU_EQ(au_bind_leaf(s, "ioc_nbl.sock", NULL), 0);
    AU_EQ(U(listen)(s, 1), 0);
    AU_EQ(U(ioctlsocket)(s, FIONBIO, &v), 0);
    U(closesocket)(s);
    au_unlink_leaf("ioc_nbl.sock");
}

TEST(afu_ioc_fionread_counts_pending)
{
    u_long n = 99;
    int r;
    TRIO(t, "ioc_nread.sock");
    r = U(ioctlsocket)(t.srv, FIONREAD, &n);
    AU_EQ(r, 0);
    AU_EQ(n, 0);
    U(send)(t.cli, "12345", 5, 0);
    AU_EQ(au_readable(t.srv, 3000), 1);
    Sleep(20);
    n = 0;
    r = U(ioctlsocket)(t.srv, FIONREAD, &n);
    AU_EQ(r, 0);
    AU_EQ(n, 5);
    au_trio_close(&t);
}

TEST(afu_ioc_fionread_unconnected)
{
    u_long n = 99;
    int r;
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    r = U(ioctlsocket)(s, FIONREAD, &n);
    AU_EQ(r, 0);
    AU_EQ(n, 0);
    U(closesocket)(s);
}

TEST(afu_ioc_fionread_after_partial_read)
{
    u_long n = 0;
    char b[4];
    int r;
    TRIO(t, "ioc_nread2.sock");
    U(send)(t.cli, "abcdef", 6, 0);
    AU_EQ(au_readable(t.srv, 3000), 1);
    AU_EQ(U(recv)(t.srv, b, 2, 0), 2);
    r = U(ioctlsocket)(t.srv, FIONREAD, &n);
    AU_EQ(r, 0);
    AU_EQ(n, 4);
    au_trio_close(&t);
}

TEST(afu_ioc_siocatmark)
{
    u_long v = 99;
    int r;
    TRIO(t, "ioc_mark.sock");
    au_seterr(0);
    r = U(ioctlsocket)(t.srv, SIOCATMARK, &v);
    AU_EQ(r, 0);
    AU_EQ(v, 1);
    au_trio_close(&t);
}

TEST(afu_ioc_unknown_command)
{
    u_long v = 0;
    int r;
    TRIO(t, "ioc_unk.sock");
    au_seterr(0);
    r = U(ioctlsocket)(t.srv, 0x4a5b6c7d, &v);
    AU_EQ(r, SOCKET_ERROR);
    AU_EQ(au_err(), WSAEOPNOTSUPP);
    au_trio_close(&t);
}

TEST(afu_ioc_ioctlsocket_after_close_notsock)
{
    u_long v = 0;
    SOCKET s;
    UP();
    s = au_sock();
    if (s == INVALID_SOCKET) return;
    U(closesocket)(s);
    au_seterr(0);
    AU_EQ(U(ioctlsocket)(s, FIONBIO, &v), SOCKET_ERROR);
    AU_EQ(au_err(), WSAENOTSOCK);
}

/* ---- WSAIoctl sweep ------------------------------------------------------------------------------ */
struct sio { const char *name; DWORD code; DWORD inlen, outlen; int err, bytes; };
static const struct sio g_sio[] = {
    { "SIO_ADDRESS_LIST_QUERY", SIO_ADDRESS_LIST_QUERY, 0, 256, 0, 8 },
    { "SIO_ADDRESS_LIST_CHANGE", SIO_ADDRESS_LIST_CHANGE, 0, 0, 10035, 0 },
    { "SIO_ADDRESS_LIST_SORT", SIO_ADDRESS_LIST_SORT, 16, 16, 10045, 0 },
    { "SIO_ENABLE_CIRCULAR_QUEUEING", SIO_ENABLE_CIRCULAR_QUEUEING, 0, 0, 10022, 0 },
    { "SIO_FLUSH", SIO_FLUSH, 0, 0, 10045, 0 },
    { "SIO_GET_BROADCAST_ADDRESS", SIO_GET_BROADCAST_ADDRESS, 0, 32, 10022, 0 },
    { "SIO_GET_QOS", SIO_GET_QOS, 0, 128, 0, 80 },
    { "SIO_GET_GROUP_QOS", SIO_GET_GROUP_QOS, 0, 128, 0, 80 },
    { "SIO_MULTIPOINT_LOOPBACK", SIO_MULTIPOINT_LOOPBACK, 4, 0, 10045, 0 },
    { "SIO_MULTICAST_SCOPE", SIO_MULTICAST_SCOPE, 4, 0, 10045, 0 },
    { "SIO_SET_QOS", SIO_SET_QOS, 4, 0, 10014, 0 },
    { "SIO_SET_GROUP_QOS", SIO_SET_GROUP_QOS, 4, 0, 10014, 0 },
    { "SIO_TRANSLATE_HANDLE", SIO_TRANSLATE_HANDLE, 4, 16, 10042, 0 },
    { "SIO_ROUTING_INTERFACE_QUERY", SIO_ROUTING_INTERFACE_QUERY, 16, 16, 10047, 0 },
    { "SIO_ROUTING_INTERFACE_CHANGE", SIO_ROUTING_INTERFACE_CHANGE, 16, 0, 10047, 0 },
    { "SIO_NSP_NOTIFY_CHANGE", SIO_NSP_NOTIFY_CHANGE, 0, 0, 10045, 0 },
    { "SIO_RCVALL", SIO_RCVALL, 4, 0, -1, 0 },
    { "SIO_RCVALL_MCAST", SIO_RCVALL_MCAST, 4, 0, 10045, 0 },
    { "SIO_RCVALL_IGMPMCAST", SIO_RCVALL_IGMPMCAST, 4, 0, 10045, 0 },
    { "SIO_KEEPALIVE_VALS", SIO_KEEPALIVE_VALS, 12, 0, 10045, 0 },
    { "SIO_ABSORB_RTRALERT", SIO_ABSORB_RTRALERT, 4, 0, 10045, 0 },
    { "SIO_UCAST_IF", SIO_UCAST_IF, 4, 0, 10045, 0 },
    { "SIO_LIMIT_BROADCASTS", SIO_LIMIT_BROADCASTS, 4, 0, 10045, 0 },
    { "SIO_INDEX_BIND", SIO_INDEX_BIND, 4, 0, 10045, 0 },
    { "SIO_INDEX_MCASTIF", SIO_INDEX_MCASTIF, 4, 0, 10045, 0 },
    { "SIO_INDEX_ADD_MCAST", SIO_INDEX_ADD_MCAST, 4, 0, 10045, 0 },
    { "SIO_INDEX_DEL_MCAST", SIO_INDEX_DEL_MCAST, 4, 0, 10045, 0 },
    { "SIO_UDP_CONNRESET", SIO_UDP_CONNRESET, 4, 0, 10022, 0 },
    { "SIO_UDP_NETRESET", _WSAIOW(IOC_VENDOR, 15), 4, 0, 10022, 0 },
    { "SIO_TCP_INITIAL_RTO", _WSAIOW(IOC_VENDOR, 17), 8, 0, 10045, 0 },
    { "SIO_APPLY_TRANSPORT_SETTING", _WSAIOW(IOC_VENDOR, 35), 8, 0, 10045, 0 },
    { "SIO_QUERY_TRANSPORT_SETTING", _WSAIOW(IOC_VENDOR, 36), 8, 16, 10045, 0 },
    { "SIO_LOOPBACK_FAST_PATH", _WSAIOW(IOC_VENDOR, 16), 4, 0, 10045, 0 },
    { "SIO_QUERY_RSS_PROCESSOR_INFO", _WSAIOR(IOC_VENDOR, 37), 0, 64, 10045, 0 },
    { "SIO_IDEAL_SEND_BACKLOG_QUERY", _WSAIOR(IOC_WS2, 59), 0, 4, 10045, 0 },
    { "SIO_IDEAL_SEND_BACKLOG_CHANGE", _WSAIO(IOC_WS2, 61), 0, 0, 10045, 0 },
    { "SIO_SET_PRIORITY_HINT", _WSAIOW(IOC_VENDOR, 31), 4, 0, 10045, 0 },
    { "SIO_BASE_HANDLE", SIO_BASE_HANDLE, 0, 8, 0, 8 },
    { "SIO_BSP_HANDLE", SIO_BSP_HANDLE, 0, 8, 0, 8 },
    { "SIO_BSP_HANDLE_SELECT", SIO_BSP_HANDLE_SELECT, 0, 8, 0, 8 },
    { "SIO_BSP_HANDLE_POLL", SIO_BSP_HANDLE_POLL, 0, 8, 0, 8 },
    { "SIO_ASSOCIATE_HANDLE", SIO_ASSOCIATE_HANDLE, 8, 0, 10042, 0 },
    { "SIO_ENABLE_CIRCULAR_QUEUEING2", _WSAIO(IOC_WS2, 2), 0, 0, 10022, 0 },
};
#define NSIO ((int)(sizeof(g_sio) / sizeof(g_sio[0])))

static void sio_probe(int i, int connected)
{
    char inb[64], outb[256];
    DWORD ret = 0;
    int r, e;
    struct au_trio t;
    SOCKET s;
    if (!au_up()) return;
    if (connected) { if (!au_trio_open(&t, "ioc_sweep.sock")) return; s = t.cli; }
    else { s = au_sock(); if (s == INVALID_SOCKET) return; }
    memset(inb, 0, sizeof(inb));
    memset(outb, 0, sizeof(outb));
    /* Non-blocking: the change-notification codes would otherwise wait for a network event. */
    au_blocking(s, FALSE);
    au_seterr(0);
    r = U(WSAIoctl)(s, g_sio[i].code, g_sio[i].inlen ? inb : NULL, g_sio[i].inlen, g_sio[i].outlen ? outb : NULL, g_sio[i].outlen, &ret, NULL, NULL);
    e = r ? au_err() : 0;
    if (g_sio[i].err >= 0) {
        if (g_sio[i].err == 0) { AU_EQ(r, 0); AU_EQ(ret, g_sio[i].bytes); }
        else { AU_EQ(r, SOCKET_ERROR); AU_EQ(e, g_sio[i].err); }
    } else AU_OBS(g_sio[i].name, "%s ret %d err %d bytes %lu", connected ? "connected" : "fresh", r, e, ret);
    if (connected) au_trio_close(&t); else U(closesocket)(s);
}
#define SIO_T(i) \
    TEST(afu_ioc_sweep_fresh_##i) { sio_probe(i, 0); } \
    TEST(afu_ioc_sweep_connected_##i) { sio_probe(i, 1); }
SIO_T(0) SIO_T(1) SIO_T(2) SIO_T(3) SIO_T(4) SIO_T(5) SIO_T(6) SIO_T(7) SIO_T(8) SIO_T(9) SIO_T(10) SIO_T(11)
SIO_T(12) SIO_T(13) SIO_T(14) SIO_T(15) SIO_T(16) SIO_T(17) SIO_T(18) SIO_T(19) SIO_T(20) SIO_T(21) SIO_T(22)
SIO_T(23) SIO_T(24) SIO_T(25) SIO_T(26) SIO_T(27) SIO_T(28) SIO_T(29) SIO_T(30) SIO_T(31) SIO_T(32) SIO_T(33)
SIO_T(34) SIO_T(35) SIO_T(36) SIO_T(37) SIO_T(38) SIO_T(39) SIO_T(40) SIO_T(41) SIO_T(42)

TEST(afu_ioc_base_handle_is_the_socket)
{
    SOCKET base = 0;
    DWORD ret = 0;
    UP();
    SOCK_OR_RETURN(s);
    AU_EQ(U(WSAIoctl)(s, SIO_BASE_HANDLE, NULL, 0, &base, sizeof(base), &ret, NULL, NULL), 0);
    AU_EQ(ret, sizeof(base));
    AU_EQ(base, s);
    U(closesocket)(s);
}

TEST(afu_ioc_output_buffer_too_small_is_fault)
{
    char tiny[1];
    DWORD ret = 0;
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    AU_EQ(U(WSAIoctl)(s, SIO_BASE_HANDLE, NULL, 0, tiny, 1, &ret, NULL, NULL), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    U(closesocket)(s);
}

TEST(afu_ioc_null_bytes_returned_is_fault)
{
    SOCKET base;
    UP();
    SOCK_OR_RETURN(s);
    au_seterr(0);
    AU_EQ(U(WSAIoctl)(s, SIO_BASE_HANDLE, NULL, 0, &base, sizeof(base), NULL, NULL, NULL), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEFAULT);
    U(closesocket)(s);
}

TEST(afu_ioc_unknown_code_sweep)
{
    DWORD codes[] = { 0x98000099, 0x88000099, 0x48000099, 0x08000099, 0xd8000001 };
    int i;
    UP();
    SOCK_OR_RETURN(s);
    for (i = 0; i < 5; i++) {
        char in[8] = {0}, out[8] = {0};
        DWORD ret = 0;
        au_seterr(0);
        int r = U(WSAIoctl)(s, codes[i], in, 8, out, 8, &ret, NULL, NULL);
        AU_EQ(r, SOCKET_ERROR);
        AU_EQ(au_err(), WSAEOPNOTSUPP);
    }
    U(closesocket)(s);
}

/* ---- extension function lookup ------------------------------------------------------------------- */
static void *ext_fn(SOCKET s, GUID g, int *err)
{
    void *fn = NULL;
    DWORD ret = 0;
    int r;
    au_seterr(0);
    r = U(WSAIoctl)(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof(g), &fn, sizeof(fn), &ret, NULL, NULL);
    if (err) *err = r ? au_err() : 0;
    return r == 0 ? fn : NULL;
}

TEST(afu_ext_lookup_all_known)
{
    static const struct { const char *nm; GUID g; } tab[] = {
        { "AcceptEx", WSAID_ACCEPTEX }, { "ConnectEx", WSAID_CONNECTEX }, { "DisconnectEx", WSAID_DISCONNECTEX },
        { "GetAcceptExSockaddrs", WSAID_GETACCEPTEXSOCKADDRS }, { "TransmitFile", WSAID_TRANSMITFILE },
        { "TransmitPackets", WSAID_TRANSMITPACKETS }, { "WSARecvMsg", WSAID_WSARECVMSG }, { "WSASendMsg", WSAID_WSASENDMSG },
    };
    int i, e;
    UP();
    SOCK_OR_RETURN(s);
    for (i = 0; i < (int)(sizeof(tab) / sizeof(tab[0])); i++) {
        void *f = ext_fn(s, tab[i].g, &e);
        CHECKF(f != NULL, "%s", tab[i].nm);
    }
    U(closesocket)(s);
}

TEST(afu_ext_wsapoll_guid_is_not_an_extension)
{
    GUID g = WSAID_WSAPOLL;
    int e;
    UP();
    SOCK_OR_RETURN(s);
    CHECK(ext_fn(s, g, &e) == NULL);
    AU_EQ(e, WSAEINVAL);
    U(closesocket)(s);
}

TEST(afu_ext_connectex_resolves)
{
    int e;
    UP();
    SOCK_OR_RETURN(s);
    CHECK(ext_fn(s, (GUID)WSAID_CONNECTEX, &e) != NULL);
    U(closesocket)(s);
}

TEST(afu_ext_acceptex_resolves)
{
    int e;
    UP();
    SOCK_OR_RETURN(s);
    CHECK(ext_fn(s, (GUID)WSAID_ACCEPTEX, &e) != NULL);
    U(closesocket)(s);
}

TEST(afu_ext_same_pointers_as_tcp)
{
    SOCKET tcp;
    int e;
    UP();
    SOCK_OR_RETURN(s);
    tcp = U(socket)(AF_INET, SOCK_STREAM, 0);
    if (tcp == INVALID_SOCKET) { U(closesocket)(s); t_skip("no tcp"); return; }
    void *a = ext_fn(s, (GUID)WSAID_CONNECTEX, &e), *b = ext_fn(tcp, (GUID)WSAID_CONNECTEX, &e);
    CHECK(a == b);
    a = ext_fn(s, (GUID)WSAID_ACCEPTEX, &e); b = ext_fn(tcp, (GUID)WSAID_ACCEPTEX, &e);
    CHECK(a == b);
    U(closesocket)(tcp); U(closesocket)(s);
}

TEST(afu_ext_unknown_guid_fails)
{
    GUID g = { 0x12345678, 0x1234, 0x5678, { 1, 2, 3, 4, 5, 6, 7, 8 } };
    int e;
    UP();
    SOCK_OR_RETURN(s);
    CHECK(ext_fn(s, g, &e) == NULL);
    AU_EQ(e, WSAEINVAL);
    U(closesocket)(s);
}

/* ---- ConnectEx ----------------------------------------------------------------------------------- */
typedef BOOL (WINAPI *connectex_t)(SOCKET, const struct sockaddr *, int, PVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *acceptex_t)(SOCKET, SOCKET, PVOID, DWORD, DWORD, DWORD, LPDWORD, LPOVERLAPPED);

TEST(afu_cex_connect_to_listener)
{
    connectex_t cex;
    OVERLAPPED ov;
    SOCKADDR_UN any;
    SOCKET s;
    DWORD got = 0, fl = 0;
    BOOL ok;
    int e;
    TRIO(t, "cex_ok.sock");
    SOCKET c = au_sock();
    cex = (connectex_t)ext_fn(c, (GUID)WSAID_CONNECTEX, &e);
    if (!cex) { t_skip("no ConnectEx"); U(closesocket)(c); au_trio_close(&t); return; }
    memset(&any, 0, sizeof(any)); any.sun_family = AF_UNIX;
    AU_EQ(U(bind)(c, (struct sockaddr *)&any, 2), 0);
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = U(WSACreateEvent)();
    au_seterr(0);
    ok = cex(c, (struct sockaddr *)&t.addr, sizeof(t.addr), NULL, 0, &got, &ov);
    if (!ok) {
        AU_EQ(au_err(), ERROR_IO_PENDING);
        AU_EQ(WaitForSingleObject(ov.hEvent, 3000), WAIT_OBJECT_0);
        CHECK(U(WSAGetOverlappedResult)(c, (WSAOVERLAPPED *)&ov, &got, FALSE, &fl));
    }
    s = au_accept_bounded(t.lis);
    CHECK(s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        char b[4] = {0};
        AU_EQ(U(setsockopt)(c, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0), 0);
        au_rcvtimeo(s, 3000);
        AU_EQ(U(send)(c, "cx", 2, 0), 2);
        AU_EQ(au_recv_n(s, b, 2), 2);
        CHECK(!memcmp(b, "cx", 2));
        U(closesocket)(s);
    }
    U(WSACloseEvent)(ov.hEvent);
    U(closesocket)(c);
    au_trio_close(&t);
}

TEST(afu_cex_unbound_socket_is_inval)
{
    connectex_t cex;
    OVERLAPPED ov;
    DWORD got = 0;
    BOOL ok;
    int e;
    TRIO(t, "cex_unb.sock");
    SOCKET c = au_sock();
    cex = (connectex_t)ext_fn(c, (GUID)WSAID_CONNECTEX, &e);
    if (!cex) { t_skip("no ConnectEx"); U(closesocket)(c); au_trio_close(&t); return; }
    memset(&ov, 0, sizeof(ov));
    au_seterr(0);
    ok = cex(c, (struct sockaddr *)&t.addr, sizeof(t.addr), NULL, 0, &got, &ov);
    CHECK(!ok);
    AU_EQ(au_err(), WSAEINVAL);
    U(closesocket)(c);
    au_trio_close(&t);
}

TEST(afu_cex_with_send_data)
{
    connectex_t cex;
    OVERLAPPED ov;
    SOCKADDR_UN any;
    SOCKET s;
    DWORD got = 0, fl = 0;
    char b[8] = {0};
    int e;
    TRIO(t, "cex_data.sock");
    SOCKET c = au_sock();
    cex = (connectex_t)ext_fn(c, (GUID)WSAID_CONNECTEX, &e);
    if (!cex) { t_skip("no ConnectEx"); U(closesocket)(c); au_trio_close(&t); return; }
    memset(&any, 0, sizeof(any)); any.sun_family = AF_UNIX;
    AU_EQ(U(bind)(c, (struct sockaddr *)&any, 2), 0);
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = U(WSACreateEvent)();
    if (!cex(c, (struct sockaddr *)&t.addr, sizeof(t.addr), (PVOID)"hello", 5, &got, &ov)) {
        AU_EQ(au_err(), ERROR_IO_PENDING);
        AU_EQ(WaitForSingleObject(ov.hEvent, 3000), WAIT_OBJECT_0);
        CHECK(U(WSAGetOverlappedResult)(c, (WSAOVERLAPPED *)&ov, &got, FALSE, &fl));
    }
    AU_EQ(got, 5);
    s = au_accept_bounded(t.lis);
    if (s != INVALID_SOCKET) { au_rcvtimeo(s, 3000); AU_EQ(au_recv_n(s, b, 5), 5); CHECK(!memcmp(b, "hello", 5)); U(closesocket)(s); }
    U(WSACloseEvent)(ov.hEvent);
    U(closesocket)(c);
    au_trio_close(&t);
}

TEST(afu_cex_missing_path_fails)
{
    connectex_t cex;
    OVERLAPPED ov;
    SOCKADDR_UN any, dst;
    DWORD got = 0;
    BOOL ok;
    int e;
    UP();
    SOCK_OR_RETURN(c);
    cex = (connectex_t)ext_fn(c, (GUID)WSAID_CONNECTEX, &e);
    if (!cex) { t_skip("no ConnectEx"); U(closesocket)(c); return; }
    memset(&any, 0, sizeof(any)); any.sun_family = AF_UNIX;
    AU_EQ(U(bind)(c, (struct sockaddr *)&any, 2), 0);
    au_addr_leaf(&dst, "cex_missing.sock");
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = U(WSACreateEvent)();
    au_seterr(0);
    ok = cex(c, (struct sockaddr *)&dst, sizeof(dst), NULL, 0, &got, &ov);
    CHECK(!ok);
    AU_EQ(au_err(), WSAECONNREFUSED);
    U(WSACloseEvent)(ov.hEvent);
    U(closesocket)(c);
}

TEST(afu_cex_family_mismatch)
{
    connectex_t cex;
    OVERLAPPED ov;
    SOCKADDR_UN any;
    struct sockaddr_in in;
    DWORD got = 0;
    int e;
    UP();
    SOCK_OR_RETURN(c);
    cex = (connectex_t)ext_fn(c, (GUID)WSAID_CONNECTEX, &e);
    if (!cex) { t_skip("no ConnectEx"); U(closesocket)(c); return; }
    memset(&any, 0, sizeof(any)); any.sun_family = AF_UNIX;
    AU_EQ(U(bind)(c, (struct sockaddr *)&any, 2), 0);
    memset(&in, 0, sizeof(in)); in.sin_family = AF_INET; in.sin_addr.s_addr = 0x0100007f; in.sin_port = 0x5000;
    memset(&ov, 0, sizeof(ov));
    au_seterr(0);
    CHECK(!cex(c, (struct sockaddr *)&in, sizeof(in), NULL, 0, &got, &ov));
    AU_EQ(au_err(), WSAEINVAL);
    U(closesocket)(c);
}

/* ---- AcceptEx ----------------------------------------------------------------------------------- */
TEST(afu_aex_accept_connection)
{
    acceptex_t aex;
    OVERLAPPED ov;
    SOCKET c, a;
    char buf[2 * (sizeof(SOCKADDR_UN) + 16) + 8];
    DWORD got = 0, fl = 0;
    BOOL ok;
    int e;
    SOCKADDR_UN addr;
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "aex_ok.sock", &addr), 0);
    AU_EQ(U(listen)(lis, 2), 0);
    aex = (acceptex_t)ext_fn(lis, (GUID)WSAID_ACCEPTEX, &e);
    if (!aex) { t_skip("no AcceptEx"); U(closesocket)(lis); au_unlink_leaf("aex_ok.sock"); return; }
    a = au_sock();
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = U(WSACreateEvent)();
    au_seterr(0);
    ok = aex(lis, a, buf, 0, sizeof(SOCKADDR_UN) + 16, sizeof(SOCKADDR_UN) + 16, &got, &ov);
    CHECK(!ok);
    AU_EQ(au_err(), ERROR_IO_PENDING);
    if (!ok && au_err() == ERROR_IO_PENDING) {
        c = au_sock();
        au_blocking(c, FALSE);
        U(connect)(c, (struct sockaddr *)&addr, sizeof(addr));
        AU_EQ(WaitForSingleObject(ov.hEvent, 3000), WAIT_OBJECT_0);
        CHECK(U(WSAGetOverlappedResult)(lis, (WSAOVERLAPPED *)&ov, &got, FALSE, &fl));
        AU_EQ(U(setsockopt)(a, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&lis, sizeof(lis)), 0);
        U(closesocket)(c);
    }
    U(WSACloseEvent)(ov.hEvent);
    U(closesocket)(a); U(closesocket)(lis);
    au_unlink_leaf("aex_ok.sock");
}

TEST(afu_aex_address_buffer_too_small)
{
    acceptex_t aex;
    OVERLAPPED ov;
    SOCKET a;
    char buf[64];
    DWORD got = 0;
    BOOL ok;
    int e;
    UP();
    SOCK_OR_RETURN(lis);
    AU_EQ(au_bind_leaf(lis, "aex_small.sock", NULL), 0);
    AU_EQ(U(listen)(lis, 2), 0);
    aex = (acceptex_t)ext_fn(lis, (GUID)WSAID_ACCEPTEX, &e);
    if (!aex) { t_skip("no AcceptEx"); U(closesocket)(lis); au_unlink_leaf("aex_small.sock"); return; }
    a = au_sock();
    memset(&ov, 0, sizeof(ov));
    au_seterr(0);
    ok = aex(lis, a, buf, 0, 8, 8, &got, &ov);
    CHECK(!ok);
    AU_OBS("AcceptEx with 8-byte address slots", "err %d", au_err());
    U(closesocket)(a); U(closesocket)(lis);
    au_unlink_leaf("aex_small.sock");
}

TEST(afu_aex_on_non_listening_socket)
{
    acceptex_t aex;
    OVERLAPPED ov;
    SOCKET a;
    char buf[2 * (sizeof(SOCKADDR_UN) + 16)];
    DWORD got = 0;
    int e;
    UP();
    SOCK_OR_RETURN(s);
    aex = (acceptex_t)ext_fn(s, (GUID)WSAID_ACCEPTEX, &e);
    if (!aex) { t_skip("no AcceptEx"); U(closesocket)(s); return; }
    a = au_sock();
    memset(&ov, 0, sizeof(ov));
    au_seterr(0);
    CHECK(!aex(s, a, buf, 0, sizeof(SOCKADDR_UN) + 16, sizeof(SOCKADDR_UN) + 16, &got, &ov));
    AU_EQ(au_err(), WSAEINVAL);
    U(closesocket)(a); U(closesocket)(s);
}

/* ---- DisconnectEx / TransmitFile ------------------------------------------------------------------ */
typedef BOOL (WINAPI *disconnectex_t)(SOCKET, LPOVERLAPPED, DWORD, DWORD);
/* Wait for an overlapped operation for a bounded time; cancel it when it does not finish. */
static int ov_finish(SOCKET s, OVERLAPPED *ov, BOOL started_ok, DWORD *bytes)
{
    DWORD fl = 0;
    if (!started_ok) {
        if (au_err() != ERROR_IO_PENDING) return 0;
        if (WaitForSingleObject(ov->hEvent, 3000) != WAIT_OBJECT_0) {
            CancelIoEx((HANDLE)s, ov);
            WaitForSingleObject(ov->hEvent, 3000);
            return 0;
        }
    }
    return U(WSAGetOverlappedResult)(s, (WSAOVERLAPPED *)ov, bytes, FALSE, &fl);
}

TEST(afu_dex_disconnect_gives_peer_eof)
{
    disconnectex_t dex;
    OVERLAPPED ov;
    DWORD n = 0;
    char b[4];
    int e, done;
    BOOL ok;
    TRIO(t, "dex.sock");
    dex = (disconnectex_t)ext_fn(t.cli, (GUID)WSAID_DISCONNECTEX, &e);
    if (!dex) { t_skip("no DisconnectEx"); au_trio_close(&t); return; }
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = U(WSACreateEvent)();
    au_seterr(0);
    ok = dex(t.cli, &ov, 0, 0);
    CHECK(ok || au_err() == ERROR_IO_PENDING);
    done = ov_finish(t.cli, &ov, ok, &n);
    CHECK(done);
    if (done) AU_EQ(U(recv)(t.srv, b, 4, 0), 0);
    U(WSACloseEvent)(ov.hEvent);
    au_trio_close(&t);
}

typedef BOOL (WINAPI *transmitfile_t)(SOCKET, HANDLE, DWORD, DWORD, LPOVERLAPPED, LPTRANSMIT_FILE_BUFFERS, DWORD);
TEST(afu_tf_transmit_file)
{
    transmitfile_t tf;
    HANDLE f;
    OVERLAPPED ov;
    char path[MAX_PATH], b[16] = {0};
    DWORD w, n = 0;
    int e, done;
    BOOL ok;
    TRIO(t, "tf.sock");
    tf = (transmitfile_t)ext_fn(t.cli, (GUID)WSAID_TRANSMITFILE, &e);
    if (!tf) { t_skip("no TransmitFile"); au_trio_close(&t); return; }
    t_tmpfile(path, sizeof(path), "tf_src.bin");
    f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) { t_skip("scratch file"); au_trio_close(&t); return; }
    WriteFile(f, "fileBYTES!", 10, &w, NULL);
    SetFilePointer(f, 0, NULL, FILE_BEGIN);
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = U(WSACreateEvent)();
    au_seterr(0);
    ok = tf(t.cli, f, 10, 0, &ov, NULL, 0);
    AU_OBS("TransmitFile on AF_UNIX", "ok %d err %d", ok, ok ? 0 : au_err());
    done = ov_finish(t.cli, &ov, ok, &n);
    AU_OBS("TransmitFile completion", "%d bytes %lu", done, n);
    if (done) { au_rcvtimeo(t.srv, 3000); AU_EQ(au_recv_n(t.srv, b, 10), 10); CHECK(!memcmp(b, "fileBYTES!", 10)); }
    U(WSACloseEvent)(ov.hEvent);
    CloseHandle(f);
    DeleteFileA(path);
    au_trio_close(&t);
}
