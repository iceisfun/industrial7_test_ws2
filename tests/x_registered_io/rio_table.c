/* The Registered I/O extension table: SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER with WSAID_MULTIPLE_RIO.
 *
 * Measured on Windows 10: the table is 112 bytes (cbSize plus thirteen function pointers) and every entry is
 * present. The lookup does not need a socket created with the registered-I/O flag and works on any address
 * family. The output buffer must hold the whole table (WSAEFAULT otherwise, buffer left untouched), the input
 * must hold at least one GUID (WSAEFAULT), an unknown GUID is WSAEOPNOTSUPP, and the RIO GUID is not served by
 * the single-function lookup (SIO_GET_EXTENSION_FUNCTION_POINTER answers WSAEINVAL). */
#include "rio.h"

static const char *ENTRY_NAMES[13] = {
    "RIOReceive", "RIOReceiveEx", "RIOSend", "RIOSendEx", "RIOCloseCompletionQueue", "RIOCreateCompletionQueue",
    "RIOCreateRequestQueue", "RIODequeueCompletion", "RIODeregisterBuffer", "RIONotify", "RIORegisterBuffer",
    "RIOResizeCompletionQueue", "RIOResizeRequestQueue",
};

static int lookup(SOCKET s, DWORD inlen, DWORD outlen, const GUID *g, void *out, DWORD *ret)
{
    char gb[64]; memset(gb, 0, sizeof gb); memcpy(gb, g, sizeof *g);
    WSASetLastError(0);
    return WSAIoctl(s, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, gb, inlen, out, outlen, ret, NULL, NULL);
}

TEST(rio_table_size_is_112)
{
    NEED_RIO(t);
    EXPECT_EQ(t->cbSize, 112);
    EXPECT_EQ(sizeof(RIO_TABLE), 112);
}
TEST(rio_table_all_entries_present)
{
    NEED_RIO(t);
    void **p = (void **)&t->Receive;
    for (int i = 0; i < 13; i++) CHECKF(p[i] != NULL, "entry %s missing", ENTRY_NAMES[i]);
}
TEST(rio_table_entries_are_distinct)
{
    NEED_RIO(t);
    void **p = (void **)&t->Receive;
    for (int i = 0; i < 13; i++) for (int j = i + 1; j < 13; j++) CHECKF(p[i] != p[j], "%s == %s", ENTRY_NAMES[i], ENTRY_NAMES[j]);
}
/* The RIO functions are not named exports of mswsock.dll, but the table points into its image. */
TEST(rio_table_entries_live_in_mswsock)
{
    NEED_RIO(t);
    void **p = (void **)&t->Receive;
    HMODULE m = t_module("mswsock.dll");
    for (int i = 0; i < 13; i++) {
        HMODULE h = NULL;
        BOOL ok = GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)p[i], &h);
        CHECKF(ok && h == m, "%s is not inside mswsock.dll", ENTRY_NAMES[i]);
    }
}

TEST(rio_table_lookup_on_every_socket_kind)
{
    NEED_RIO(t);
    static const struct { const char *n; int af, type, proto; DWORD fl; } k[] = {
        {"udp4 rio", AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL}, {"udp4 overlapped", AF_INET, SOCK_DGRAM, IPPROTO_UDP, WSA_FLAG_OVERLAPPED},
        {"udp4 no flags", AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0}, {"tcp4 rio", AF_INET, SOCK_STREAM, IPPROTO_TCP, RIO_FL},
        {"tcp4 overlapped", AF_INET, SOCK_STREAM, IPPROTO_TCP, WSA_FLAG_OVERLAPPED}, {"tcp6 rio", AF_INET6, SOCK_STREAM, IPPROTO_TCP, RIO_FL},
        {"udp6 rio", AF_INET6, SOCK_DGRAM, IPPROTO_UDP, RIO_FL}, {"udp4 registered-io only", AF_INET, SOCK_DGRAM, IPPROTO_UDP, WSA_FLAG_REGISTERED_IO},
    };
    for (unsigned i = 0; i < sizeof k / sizeof *k; i++) {
        SOCKET s = rio_sock(k[i].af, k[i].type, k[i].proto, k[i].fl);
        RIO_TABLE tt; DWORD n = 77;
        CHECKF(s != INVALID_SOCKET, "%s: socket", k[i].n);
        if (s == INVALID_SOCKET) continue;
        memset(&tt, 0, sizeof tt);
        EXPECT_EQ(lookup(s, 16, sizeof tt, &RIO_GUID, &tt, &n), 0);
        EXPECT_EQ(n, 112);
        EXPECT_EQ(tt.cbSize, 112);
        CHECKF(!memcmp(&tt, t, sizeof tt), "%s: table differs from the first lookup", k[i].n);
        closesocket(s);
    }
}
TEST(rio_table_pointers_stable_across_lookups)
{
    NEED_RIO(t);
    SOCKET s = rio_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL); RIO_TABLE a, b; DWORD n;
    memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    EXPECT_EQ(lookup(s, 16, sizeof a, &RIO_GUID, &a, &n), 0);
    EXPECT_EQ(lookup(s, 16, sizeof b, &RIO_GUID, &b, &n), 0);
    CHECK(!memcmp(&a, &b, sizeof a));
    closesocket(s);
}
TEST(rio_table_cbsize_in_output_is_ignored)
{
    NEED_RIO(t);
    SOCKET s = rio_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL); RIO_TABLE a; DWORD n = 0;
    static const DWORD pre[] = {0, 1, 112, 0xffffffff};
    for (unsigned i = 0; i < 4; i++) {
        memset(&a, 0, sizeof a); a.cbSize = pre[i];
        EXPECT_EQ(lookup(s, 16, sizeof a, &RIO_GUID, &a, &n), 0);
        EXPECT_EQ(a.cbSize, 112);
    }
    closesocket(s);
}

/* Output buffer size: anything below the full table is WSAEFAULT and leaves the buffer alone; 8 bytes more is fine
 * and only 112 bytes are reported. */
TEST(rio_table_output_size_matrix)
{
    NEED_RIO(t);
    static const struct { DWORD outlen; int ok; } m[] = {
        {0, 0}, {4, 0}, {8, 0}, {16, 0}, {104, 0}, {111, 0}, {112, 1}, {113, 1}, {120, 1}, {200, 1},
    };
    SOCKET s = rio_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL);
    for (unsigned i = 0; i < sizeof m / sizeof *m; i++) {
        unsigned char buf[256]; DWORD n = 77; int r;
        memset(buf, 0xCD, sizeof buf);
        r = lookup(s, 16, m[i].outlen, &RIO_GUID, buf, &n);
        if (m[i].ok) {
            CHECKF(r == 0, "outlen %lu", m[i].outlen); EXPECT_EQ(n, 112);
            EXPECT_EQ(((RIO_TABLE *)buf)->cbSize, 112);
            EXPECT_EQ(buf[112], 0xCD);   /* nothing past the table is written */
        } else {
            CHECKF(r == -1, "outlen %lu", m[i].outlen); EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
            EXPECT_EQ(n, 77);            /* bytes-returned untouched */
            EXPECT_EQ(buf[0], 0xCD);
        }
    }
    closesocket(s);
}
TEST(rio_table_input_size_matrix)
{
    NEED_RIO(t);
    static const struct { DWORD inlen; int ok; } m[] = {{0, 0}, {1, 0}, {15, 0}, {16, 1}, {17, 1}, {32, 1}, {48, 1}};
    SOCKET s = rio_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL);
    for (unsigned i = 0; i < sizeof m / sizeof *m; i++) {
        RIO_TABLE tt; DWORD n = 77; int r;
        memset(&tt, 0xCD, sizeof tt);
        r = lookup(s, m[i].inlen, sizeof tt, &RIO_GUID, &tt, &n);
        if (m[i].ok) { CHECKF(r == 0, "inlen %lu", m[i].inlen); EXPECT_EQ(n, 112); }
        else { CHECKF(r == -1, "inlen %lu", m[i].inlen); EXPECT_EQ(WSAGetLastError(), WSAEFAULT); }
    }
    closesocket(s);
}
TEST(rio_table_null_arguments_are_efault)
{
    NEED_RIO(t);
    SOCKET s = rio_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL);
    RIO_TABLE tt; DWORD n = 77; GUID g = RIO_GUID;
    WSASetLastError(0);
    EXPECT_EQ(WSAIoctl(s, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, NULL, 16, &tt, sizeof tt, &n, NULL, NULL), -1);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    WSASetLastError(0);
    EXPECT_EQ(WSAIoctl(s, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, &g, 16, NULL, sizeof tt, &n, NULL, NULL), -1);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    WSASetLastError(0);
    EXPECT_EQ(WSAIoctl(s, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, &g, 16, &tt, sizeof tt, NULL, NULL, NULL), -1);
    EXPECT_EQ(WSAGetLastError(), WSAEFAULT);
    closesocket(s);
}
TEST(rio_table_unknown_guid_is_eopnotsupp)
{
    NEED_RIO(t);
    static const GUID bad[] = {
        {1, 2, 3, {4, 5, 6, 7, 8, 9, 10, 11}}, {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}},
        {0x8509e081, 0x96dd, 0x4005, {0xb1, 0x65, 0x9e, 0x2e, 0xe8, 0xc7, 0x9e, 0x3e}},   /* RIO GUID with the last byte changed */
        WSAID_ACCEPTEX, WSAID_CONNECTEX, WSAID_GETACCEPTEXSOCKADDRS,
    };
    SOCKET s = rio_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL);
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        RIO_TABLE tt; DWORD n = 77;
        memset(&tt, 0xCD, sizeof tt);
        CHECKF(lookup(s, 16, sizeof tt, &bad[i], &tt, &n) == -1, "guid #%u", i);
        EXPECT_EQ(WSAGetLastError(), WSAEOPNOTSUPP);
        EXPECT_EQ(n, 0);
        EXPECT_EQ(((RIO_TABLE *)&tt)->cbSize, 0xCDCDCDCD);
    }
    closesocket(s);
}
TEST(rio_table_not_served_by_single_function_lookup)
{
    NEED_RIO(t);
    SOCKET s = rio_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP, RIO_FL);
    GUID g = RIO_GUID; void *fp = (void *)1; DWORD n = 77;
    WSASetLastError(0);
    EXPECT_EQ(WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &fp, sizeof fp, &n, NULL, NULL), -1);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    EXPECT_EQ(n, 77);   /* bytes-returned untouched */
    closesocket(s);
}
TEST(rio_table_sio_code_value)
{
    /* SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER = _WSAIORW(IOC_WS2, 36) */
    EXPECT_EQ(SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, 0xC8000024);
}
