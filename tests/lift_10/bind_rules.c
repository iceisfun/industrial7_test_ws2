/* bind() argument validation and address rules.
 * Measures the error for each malformed name (NULL pointer, zero or short length, unknown family), that a
 * documentation-range IPv4 address is not assignable (WSAEADDRNOTAVAIL) for TCP and UDP, that a bound socket
 * cannot be bound again (WSAEINVAL) and that a second socket cannot take the same endpoint (WSAEADDRINUSE),
 * then walks the unicast addresses of the running adapters: each is bindable, and for IPv6 the length, scope-id
 * and getsockname rules apply.  Also the Bluetooth RFCOMM rules, skipped when the family is absent.
 */
#include "w.h"

static struct sockaddr_in testnet_addr(void)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = w_swap32(0xc0000200);   /* 192.0.2.0: reserved for documentation, never local */
    return a;
}

#define BIND_FAILS(s, name, len, err) do { \
    p_WSASetLastError(W_SENT); \
    int r_ = p_bind((s), (const struct sockaddr *)(name), (len)); \
    EXPECT_EQ(r_, SOCKET_ERROR); \
    EXPECT_EQ(p_WSAGetLastError(), (err)); } while (0)

TEST(lift10_bind_null_name_zero_length_is_efault)
{
    SOCKET s;
    W_BEGIN();
    s = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BIND_FAILS(s, NULL, 0, WSAEFAULT);
    p_closesocket(s);
}

TEST(lift10_bind_null_name_with_length_is_efault)
{
    SOCKET s;
    W_BEGIN();
    s = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BIND_FAILS(s, NULL, sizeof(struct sockaddr), WSAEFAULT);
    p_closesocket(s);
}

TEST(lift10_bind_zero_length_is_efault)
{
    SOCKET s;
    struct sockaddr_in a = w_loop();
    W_BEGIN();
    s = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BIND_FAILS(s, &a, 0, WSAEFAULT);
    p_closesocket(s);
}

TEST(lift10_bind_unknown_family_is_eafnosupport)
{
    SOCKET s;
    struct sockaddr_in a;
    W_BEGIN();
    s = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&a, 0, sizeof a);
    a.sin_family = 0xdead;
    BIND_FAILS(s, &a, sizeof a, WSAEAFNOSUPPORT);
    p_closesocket(s);
}

TEST(lift10_bind_one_byte_short_inet_name_is_efault)
{
    SOCKET s;
    struct sockaddr_in a = w_loop();
    W_BEGIN();
    s = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BIND_FAILS(s, &a, sizeof a - 1, WSAEFAULT);
    p_closesocket(s);
}

TEST(lift10_bind_tcp_documentation_address_is_eaddrnotavail)
{
    SOCKET s;
    struct sockaddr_in a = testnet_addr();
    W_BEGIN();
    s = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BIND_FAILS(s, &a, sizeof a, WSAEADDRNOTAVAIL);
    p_closesocket(s);
}

TEST(lift10_bind_udp_documentation_address_is_eaddrnotavail)
{
    SOCKET s;
    struct sockaddr_in a = testnet_addr();
    W_BEGIN();
    s = p_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    BIND_FAILS(s, &a, sizeof a, WSAEADDRNOTAVAIL);
    p_closesocket(s);
}

TEST(lift10_bind_loopback_succeeds_for_tcp_and_udp)
{
    struct sockaddr_in a = w_loop();
    SOCKET s;
    int ret, type;
    W_BEGIN();
    for (type = SOCK_STREAM; type <= SOCK_DGRAM; type++) {
        s = p_socket(AF_INET, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP);
        p_WSASetLastError(W_SENT);
        ret = p_bind(s, (struct sockaddr *)&a, sizeof a);
        CHECKF(ret == 0, "type %d ret %d", type, ret);
        /* success leaves the thread error cleared or untouched depending on the Windows build */
        CHECKF(p_WSAGetLastError() == 0 || p_WSAGetLastError() == W_SENT, "type %d err %d", type, p_WSAGetLastError());
        p_closesocket(s);
    }
}

TEST(lift10_bind_second_bind_on_bound_socket_is_einval)
{
    struct sockaddr_in a = w_loop();
    SOCKET s;
    W_BEGIN();
    s = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int first = p_bind(s, (struct sockaddr *)&a, sizeof a);
    EXPECT_EQ(first, 0);
    BIND_FAILS(s, &a, sizeof a, WSAEINVAL);
    p_closesocket(s);
}

TEST(lift10_bind_same_endpoint_twice_is_eaddrinuse)
{
    struct sockaddr_in a = w_loop(), got;
    SOCKET s, s2;
    int len = sizeof got;
    W_BEGIN();
    s = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int first = p_bind(s, (struct sockaddr *)&a, sizeof a);
    int second;
    EXPECT_EQ(first, 0);
    second = p_getsockname(s, (struct sockaddr *)&got, &len);
    EXPECT_EQ(second, 0);
    s2 = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BIND_FAILS(s2, &got, sizeof got, WSAEADDRINUSE);
    p_closesocket(s2);
    p_closesocket(s);
}

/* ---- adapter addresses ------------------------------------------------- */

typedef ULONG (WINAPI *GetAdaptersAddresses_pfn)(ULONG, ULONG, PVOID, IP_ADAPTER_ADDRESSES *, ULONG *);

static IP_ADAPTER_ADDRESSES *adapters(void)
{
    GetAdaptersAddresses_pfn fn = (GetAdaptersAddresses_pfn)t_proc_in("iphlpapi.dll", "GetAdaptersAddresses");
    ULONG size = 4096, err;
    IP_ADAPTER_ADDRESSES *buf;
    int tries;
    if (!fn) return NULL;
    for (tries = 0; tries < 4; tries++) {
        buf = (IP_ADAPTER_ADDRESSES *)malloc(size);
        if (!buf) return NULL;
        err = fn(AF_UNSPEC, 0, NULL, buf, &size);
        if (err == ERROR_SUCCESS) return buf;
        free(buf);
        if (err != ERROR_BUFFER_OVERFLOW) return NULL;
    }
    return NULL;
}

/* Calls fn for every unicast address of every adapter that is up. */
typedef void (*addr_fn)(const IP_ADAPTER_UNICAST_ADDRESS *ua, int *count);
static int for_each_up_address(addr_fn fn, int family_filter)
{
    IP_ADAPTER_ADDRESSES *all = adapters(), *ad;
    int count = 0;
    if (!all) return -1;
    for (ad = all; ad; ad = ad->Next) {
        const IP_ADAPTER_UNICAST_ADDRESS *ua;
        if (ad->OperStatus != IfOperStatusUp) continue;
        for (ua = ad->FirstUnicastAddress; ua; ua = ua->Next) {
            if (family_filter && ua->Address.lpSockaddr->sa_family != family_filter) continue;
            fn(ua, &count);
        }
    }
    free(all);
    return count;
}

static void bind_own_address(const IP_ADAPTER_UNICAST_ADDRESS *ua, int *count)
{
    SOCKET s = p_socket(ua->Address.lpSockaddr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    int ret;
    CHECK(s != INVALID_SOCKET);
    if (s == INVALID_SOCKET) return;
    ret = p_bind(s, ua->Address.lpSockaddr, ua->Address.iSockaddrLength);
    CHECKF(ret == 0, "bind to own adapter address failed, error %d", p_WSAGetLastError());
    ++*count;
    p_closesocket(s);
}

TEST(lift10_bind_every_adapter_unicast_address_succeeds)
{
    int n;
    W_BEGIN();
    n = for_each_up_address(bind_own_address, 0);
    if (n <= 0) { t_skip("no adapter addresses available"); return; }
}

static void v6_length_scope(const IP_ADAPTER_UNICAST_ADDRESS *ua, int *count)
{
    struct sockaddr_in6 addr6, got;
    SOCKET s;
    int ret, len;
    const struct sockaddr_in6 *orig = (const struct sockaddr_in6 *)ua->Address.lpSockaddr;

    memcpy(&addr6, orig, sizeof addr6);
    ++*count;
    CHECK(ua->Address.iSockaddrLength == (int)sizeof(struct sockaddr_in6));

    /* the pre-scope-id sockaddr_in6 length is too short for this family */
    s = p_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    ret = p_bind(s, (struct sockaddr *)orig, sizeof(struct sockaddr_in6_old));
    CHECK(ret == SOCKET_ERROR);
    CHECK(p_WSAGetLastError() == WSAEFAULT);

    /* an interface scope that does not exist makes the address unassignable */
    addr6.sin6_scope_id = 0xabacab;
    ret = p_bind(s, (struct sockaddr *)&addr6, sizeof addr6);
    CHECK(ret == SOCKET_ERROR);
    CHECK(p_WSAGetLastError() == WSAEADDRNOTAVAIL);

    /* scope 0 means "any scope" and is accepted */
    addr6.sin6_scope_id = 0;
    ret = p_bind(s, (struct sockaddr *)&addr6, sizeof addr6);
    CHECKF(ret == 0, "bind with scope 0 failed, error %d", p_WSAGetLastError());

    /* getsockname: short buffer rejected; full buffer reports family, a port, the address and the real scope */
    len = sizeof(struct sockaddr_in6_old);
    ret = p_getsockname(s, (struct sockaddr *)&got, &len);
    CHECK(ret == SOCKET_ERROR);
    CHECK(p_WSAGetLastError() == WSAEFAULT);

    len = sizeof got;
    memset(&got, 0, sizeof got);
    ret = p_getsockname(s, (struct sockaddr *)&got, &len);
    CHECK(ret == 0);
    CHECK(got.sin6_family == AF_INET6);
    CHECK(got.sin6_port != 0);
    CHECK(!memcmp(&got.sin6_addr, &orig->sin6_addr, sizeof got.sin6_addr));
    CHECK(got.sin6_scope_id == orig->sin6_scope_id);
    p_closesocket(s);
}

TEST(lift10_bind_ipv6_length_scope_and_getsockname_rules)
{
    int n;
    W_BEGIN();
    n = for_each_up_address(v6_length_scope, AF_INET6);
    if (n <= 0) { t_skip("no IPv6 adapter address available"); return; }
}

/* ---- Bluetooth --------------------------------------------------------- */

#define W_AF_BTH 32
#define W_BTHPROTO_RFCOMM 3
#pragma pack(push, 1)
struct w_sockaddr_bth { USHORT addressFamily; ULONGLONG btAddr; GUID serviceClassId; ULONG port; };
#pragma pack(pop)

TEST(lift10_bind_bluetooth_rfcomm_port_rules)
{
    SOCKET s, s2;
    struct w_sockaddr_bth a;
    int err, ret;
    W_BEGIN();
    s = p_socket(W_AF_BTH, SOCK_STREAM, W_BTHPROTO_RFCOMM);
    err = p_WSAGetLastError();
    if (s == INVALID_SOCKET) {
        CHECKF(err == WSAEAFNOSUPPORT || err == WSAEPROTONOSUPPORT, "unexpected error %d", err);
        t_skip("Bluetooth is not supported on this system");
        return;
    }
    memset(&a, 0, sizeof a);
    a.addressFamily = W_AF_BTH;
    a.port = 200;                      /* RFCOMM channels are 1..30 */
    ret = p_bind(s, (struct sockaddr *)&a, sizeof a);
    err = p_WSAGetLastError();
    CHECK(ret == SOCKET_ERROR);
    CHECKF(err == WSAEADDRNOTAVAIL || err == WSAENETDOWN, "error %d", err);

    a.port = 20;
    ret = p_bind(s, (struct sockaddr *)&a, sizeof a);
    err = p_WSAGetLastError();
    CHECKF(ret == 0 || err == WSAENETDOWN, "error %d", err);

    s2 = p_socket(W_AF_BTH, SOCK_STREAM, W_BTHPROTO_RFCOMM);
    CHECK(s2 != INVALID_SOCKET);
    a.port = (ULONG)-1;                /* BT_PORT_ANY */
    ret = p_bind(s2, (struct sockaddr *)&a, sizeof a);
    err = p_WSAGetLastError();
    CHECKF(ret == 0 || err == WSAENETDOWN, "error %d", err);
    p_closesocket(s);
    p_closesocket(s2);
}
