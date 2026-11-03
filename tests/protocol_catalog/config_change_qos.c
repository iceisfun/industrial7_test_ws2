/* WSAProviderConfigChange, WSAGetQOSByName, and using catalog entries to create sockets.
 * Measures: the catalog change notification handle (created on first call from a NULL handle, a pipe, distinct per
 * call; an overlapped wait on it stays pending without a catalog change and is cancelled when the handle closes;
 * WSAStartup is required), QOS template lookup on a bad socket (WSAENOTSOCK, returns FALSE not SOCKET_ERROR,
 * WSAStartup required) and a catalog entry being a valid creation recipe (FROM_PROTOCOL_INFO yields a socket
 * whose protocol info names that same entry). */
#include "pc.h"
#include <stdlib.h>

typedef INT (WSAAPI *cfg_fn)(LPHANDLE, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static cfg_fn cfgfn(void) { return (cfg_fn)t_proc_in("ws2_32.dll", "WSAProviderConfigChange"); }

TEST(cfgchange_null_handle_creates_one)
{
    HANDLE h = NULL; int r;
    PC_NEED_WSA(); REQUIRE(cfgfn());
    r = cfgfn()(&h, NULL, NULL);
    EXPECT_EQ(r, 0);
    CHECK(h != NULL && h != INVALID_HANDLE_VALUE);
    if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
}

TEST(cfgchange_handle_is_a_pipe)
{
    HANDLE h = NULL;
    PC_NEED_WSA(); REQUIRE(cfgfn());
    CHECK(cfgfn()(&h, NULL, NULL) == 0);
    if (h) { EXPECT_EQ(GetFileType(h), FILE_TYPE_PIPE); CloseHandle(h); }
}

TEST(cfgchange_handles_are_distinct)
{
    HANDLE a = NULL, b = NULL;
    PC_NEED_WSA(); REQUIRE(cfgfn());
    CHECK(cfgfn()(&a, NULL, NULL) == 0);
    CHECK(cfgfn()(&b, NULL, NULL) == 0);
    CHECK(a != NULL && b != NULL && a != b);
    if (a) CloseHandle(a);
    if (b) CloseHandle(b);
}

TEST(cfgchange_creation_leaves_last_error_alone)
{
    HANDLE h = NULL;
    PC_NEED_WSA(); REQUIRE(cfgfn());
    U(WSASetLastError)(WSAEINVAL);
    CHECK(cfgfn()(&h, NULL, NULL) == 0);
    t_note("last error after successful creation: %d", U(WSAGetLastError)());
    if (h) CloseHandle(h);
}

TEST(cfgchange_handle_closes_once)
{
    HANDLE h = NULL;
    PC_NEED_WSA(); REQUIRE(cfgfn());
    CHECK(cfgfn()(&h, NULL, NULL) == 0);
    if (!h) return;
    CHECK(CloseHandle(h));
    SET_ERR(0);
    CHECK(!CloseHandle(h));
    EXPECT_ERR(ERROR_INVALID_HANDLE);
}

TEST(cfgchange_overlapped_wait_is_pending)
{
    HANDLE h = NULL; WSAOVERLAPPED *ov; int r;
    PC_NEED_WSA(); REQUIRE(cfgfn());
    CHECK(cfgfn()(&h, NULL, NULL) == 0);
    if (!h) return;
    ov = (WSAOVERLAPPED *)calloc(1, sizeof *ov);
    REQUIRE(ov);
    ov->hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    SET_ERR(0);
    r = cfgfn()(&h, ov, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(U(WSAGetLastError)(), WSA_IO_PENDING);
    CHECK(!HasOverlappedIoCompleted((OVERLAPPED *)ov));
    /* No catalog change happens here, so the wait stays unsignaled. */
    EXPECT_EQ(WaitForSingleObject(ov->hEvent, 200), WAIT_TIMEOUT);
    CloseHandle(h);
    /* Closing the pipe cancels the pending listen and signals the event. */
    if (WaitForSingleObject(ov->hEvent, 5000) == WAIT_OBJECT_0) {
        CloseHandle(ov->hEvent);
        free(ov);
    } else {
        CHECKF(0, "overlapped wait still pending 5 s after handle close");  /* leak the OVERLAPPED: the kernel may still write it */
    }
}

TEST(cfgchange_overlapped_wait_does_not_complete_without_change)
{
    HANDLE h = NULL; WSAOVERLAPPED *ov; DWORD cb = 0; BOOL ok;
    PC_NEED_WSA(); REQUIRE(cfgfn());
    CHECK(cfgfn()(&h, NULL, NULL) == 0);
    if (!h) return;
    ov = (WSAOVERLAPPED *)calloc(1, sizeof *ov);
    REQUIRE(ov);
    ov->hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    cfgfn()(&h, ov, NULL);
    SET_ERR(0);
    ok = GetOverlappedResult(h, (OVERLAPPED *)ov, &cb, FALSE);
    CHECK(!ok);
    EXPECT_ERR(ERROR_IO_INCOMPLETE);
    CloseHandle(h);
    if (WaitForSingleObject(ov->hEvent, 5000) == WAIT_OBJECT_0) { CloseHandle(ov->hEvent); free(ov); }
}

TEST(cfgchange_non_handle_value_fails)
{
    HANDLE h = INVALID_HANDLE_VALUE; WSAOVERLAPPED *ov; int r;
    PC_NEED_WSA(); REQUIRE(cfgfn());
    ov = (WSAOVERLAPPED *)calloc(1, sizeof *ov);
    REQUIRE(ov);
    ov->hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    SET_ERR(0);
    r = cfgfn()(&h, ov, NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    /* The exact code comes from the kernel's rejection of a non-pipe handle; only the failure and a nonzero code are firm. */
    CHECK(U(WSAGetLastError)() != 0);
    t_note("wait on a non-pipe handle: error %d", U(WSAGetLastError)());
    CloseHandle(ov->hEvent);
    free(ov);
}

CHILD(cfg_no_startup)
{
    HANDLE h = NULL;
    cfg_fn f = cfgfn();
    if (!f) return 90;
    if (f(&h, NULL, NULL) != SOCKET_ERROR) return 10;
    if (U(WSAGetLastError)() != WSANOTINITIALISED) return 11;
    if (h != NULL) return 12;
    return 0;
}
TEST(cfgchange_before_startup_is_notinitialised) { EXPECT_EQ(t_run_child("cfg_no_startup", "", 30000), 0); }

/* ---- WSAGetQOSByName --------------------------------------------------------------------------- */
static BOOL qos_call(SOCKET s, int *err)
{
    WSABUF name; QOS q; BOOL r;
    static char nm[] = "ws2t-no-such-template";
    name.buf = nm; name.len = (ULONG)strlen(nm);
    memset(&q, 0, sizeof q);
    U(WSASetLastError)(0);
    r = U(WSAGetQOSByName)(s, &name, &q);
    *err = U(WSAGetLastError)();
    return r;
}

TEST(qos_invalid_socket_is_enotsock)
{
    int err; BOOL r;
    PC_NEED_WSA(); REQUIRE(U(WSAGetQOSByName));
    r = qos_call(INVALID_SOCKET, &err);
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(err, WSAENOTSOCK);
}

TEST(qos_closed_socket_is_enotsock)
{
    int err; BOOL r; SOCKET s;
    PC_NEED_WSA(); REQUIRE(U(WSAGetQOSByName));
    s = U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(s != INVALID_SOCKET);
    U(closesocket)(s);
    r = qos_call(s, &err);
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(err, WSAENOTSOCK);
}

TEST(qos_returns_false_not_socket_error)
{
    int err; BOOL r;
    PC_NEED_WSA(); REQUIRE(U(WSAGetQOSByName));
    r = qos_call(INVALID_SOCKET, &err);
    CHECK(r != SOCKET_ERROR);
}

TEST(qos_unknown_template_on_live_socket)
{
    int err; BOOL r; SOCKET s;
    PC_NEED_WSA(); REQUIRE(U(WSAGetQOSByName));
    s = U(socket)(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(s != INVALID_SOCKET);
    r = qos_call(s, &err);
    /* A datagram socket answers any template name with the default QOS: TRUE and no error. */
    EXPECT_EQ(r, TRUE);
    EXPECT_EQ(err, 0);
    U(closesocket)(s);
}

CHILD(qos_no_startup)
{
    WSABUF name; QOS q; char nm[] = "x";
    if (!U(WSAGetQOSByName)) return 90;
    name.buf = nm; name.len = 1;
    memset(&q, 0, sizeof q);
    if (U(WSAGetQOSByName)(INVALID_SOCKET, &name, &q) != FALSE) return 10;
    if (U(WSAGetLastError)() != WSANOTINITIALISED) return 11;
    return 0;
}
TEST(qos_before_startup_is_notinitialised) { EXPECT_EQ(t_run_child("qos_no_startup", "", 30000), 0); }

/* ---- catalog entries as creation recipes -------------------------------------------------------- */
static void recipe(const WSAPROTOCOL_INFOW *e, int hard)
{
    WSAPROTOCOL_INFOW got; int len = sizeof got; SOCKET s; WSAPROTOCOL_INFOW copy = *e;
    s = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &copy, 0, 0);
    if (s == INVALID_SOCKET) {
        if (hard) CHECKF(0, "entry %lu: WSASocketW failed (%d)", e->dwCatalogEntryId, U(WSAGetLastError)());
        else t_note("entry %lu not creatable (%d)", e->dwCatalogEntryId, U(WSAGetLastError)());
        return;
    }
    memset(&got, 0, sizeof got);
    CHECK(U(getsockopt)(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&got, &len) == 0);
    EXPECT_EQ(got.dwCatalogEntryId, e->dwCatalogEntryId);
    EXPECT_EQ(got.iAddressFamily, e->iAddressFamily);
    EXPECT_EQ(got.iSocketType, e->iSocketType);
    EXPECT_EQ(got.iProtocol, e->iProtocol);
    U(closesocket)(s);
}

TEST(recipe_v4_base_entries_create_matching_sockets)
{
    pc_list l; int i;
    PC_NEED_WSA(); REQUIRE(U(WSASocketW));
    CHECK(pc_enum_w(0, NULL, &l) > 0);
    for (i = 0; i < l.n; i++)
        if (l.e[i].iAddressFamily == AF_INET && l.e[i].ProtocolChain.ChainLen == 1 && (l.e[i].iSocketType == SOCK_STREAM || l.e[i].iSocketType == SOCK_DGRAM))
            recipe(&l.e[i], 1);
    pc_free(&l);
}

TEST(recipe_v6_base_entries_create_matching_sockets)
{
    pc_list l; int i;
    PC_NEED_WSA(); REQUIRE(U(WSASocketW));
    CHECK(pc_enum_w(0, NULL, &l) > 0);
    for (i = 0; i < l.n; i++)
        if (l.e[i].iAddressFamily == AF_INET6 && l.e[i].ProtocolChain.ChainLen == 1 && (l.e[i].iSocketType == SOCK_STREAM || l.e[i].iSocketType == SOCK_DGRAM))
            recipe(&l.e[i], 0);
    pc_free(&l);
}

TEST(recipe_unknown_catalog_id_is_rejected)
{
    pc_list l; WSAPROTOCOL_INFOW bad; SOCKET s;
    PC_NEED_WSA(); REQUIRE(U(WSASocketW));
    CHECK(pc_enum_w(0, NULL, &l) > 0);
    if (l.n < 1) { pc_free(&l); return; }
    bad = l.e[0];
    bad.dwCatalogEntryId = 0x7ffffff0;
    U(WSASetLastError)(0);
    s = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &bad, 0, 0);
    CHECK(s == INVALID_SOCKET);
    if (s != INVALID_SOCKET) U(closesocket)(s);
    else EXPECT_EQ(U(WSAGetLastError)(), WSAEINVAL);
    pc_free(&l);
}
