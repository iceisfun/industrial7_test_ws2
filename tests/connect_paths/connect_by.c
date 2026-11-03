/* WSAConnectByNameA/W and WSAConnectByList against loopback listeners.
 *
 * Measures: the order of argument checks (handle, reserved parameter, node, service, list), A/W parity,
 * numeric loopback names, list traversal (failed entries are skipped, the first that works is used,
 * entries of the wrong family are ignored), output addresses and lengths, and what a failed attempt leaves
 * behind.  Only numeric node names and local listeners are used; no resolver is needed.
 */
#include "cp.h"

typedef BOOL (WINAPI *cbnA_fn)(SOCKET, LPSTR, LPSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, const struct timeval *, LPWSAOVERLAPPED);
typedef BOOL (WINAPI *cbnW_fn)(SOCKET, LPWSTR, LPWSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, const struct timeval *, LPWSAOVERLAPPED);
typedef BOOL (WINAPI *cbl_fn)(SOCKET, PSOCKET_ADDRESS_LIST, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, const struct timeval *, LPWSAOVERLAPPED);

#define WAIT_MS 3000

static cbnA_fn pA(void) { return (cbnA_fn)t_proc("WSAConnectByNameA"); }
static cbnW_fn pW(void) { return (cbnW_fn)t_proc("WSAConnectByNameW"); }
static cbl_fn  pL(void) { return (cbl_fn)t_proc("WSAConnectByList"); }

#define NEED_A() do { if (!pA()) { t_skip("WSAConnectByNameA missing"); return; } NEED(); } while (0)
#define NEED_W() do { if (!pW()) { t_skip("WSAConnectByNameW missing"); return; } NEED(); } while (0)
#define NEED_L() do { if (!pL()) { t_skip("WSAConnectByList missing"); return; } NEED(); } while (0)

static void port_a(const struct sockaddr_in *a, char *out, size_t n)
{
    snprintf(out, n, "%u", (unsigned)cp_ns(a->sin_port));
}
static void port_w(const struct sockaddr_in *a, WCHAR *out, size_t n)
{
    char t[16];
    size_t i;
    port_a(a, t, sizeof t);
    for (i = 0; i < n - 1 && t[i]; i++) out[i] = (WCHAR)t[i];
    out[i] = 0;
}

/* Result of a failing call: BOOL FALSE plus the wanted error. */
#define CB_FAILS(call, want) do { cp_WSASetLastError(0); BOOL r_ = (call); \
    t_check(r_ == FALSE, __FILE__, __LINE__, #call " fails", "returned %d", r_); \
    int e_ = cp_WSAGetLastError(); \
    t_check(e_ == (want), __FILE__, __LINE__, #call " error == " #want, "got %d want %d", e_, (int)(want)); } while (0)

/* A SOCKET_ADDRESS_LIST of n entries, each pointing at the given sockaddr. */
static SOCKET_ADDRESS_LIST *mk_list(int n, void **sa, const int *len)
{
    SOCKET_ADDRESS_LIST *l = (SOCKET_ADDRESS_LIST *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                  sizeof(SOCKET_ADDRESS_LIST) + (n > 0 ? n - 1 : 0) * sizeof(SOCKET_ADDRESS));
    int i;
    l->iAddressCount = n;
    for (i = 0; i < n; i++) { l->Address[i].lpSockaddr = (LPSOCKADDR)sa[i]; l->Address[i].iSockaddrLength = len[i]; }
    return l;
}
static void free_list(SOCKET_ADDRESS_LIST *l) { HeapFree(GetProcessHeap(), 0, l); }

/* ---- WSAConnectByName: argument order ----------------------------------------------------------------- */

TEST(cpb_name_a_invalid_socket_is_enotsock)
{
    char svc[8] = "80";
    NEED_A();
    CB_FAILS(pA()(INVALID_SOCKET, "127.0.0.1", svc, NULL, NULL, NULL, NULL, NULL, NULL), WSAENOTSOCK);
    CB_FAILS(pA()(0, "127.0.0.1", svc, NULL, NULL, NULL, NULL, NULL, NULL), WSAENOTSOCK);
}

TEST(cpb_name_a_checks_the_strings_before_the_handle)
{
    /* The ANSI entry converts its strings first, so missing strings win over a bad handle. */
    NEED_A();
    CB_FAILS(pA()(INVALID_SOCKET, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL), WSAEINVAL);
    CB_FAILS(pA()(INVALID_SOCKET, NULL, "80", NULL, NULL, NULL, NULL, NULL, NULL), WSAEINVAL);
    CB_FAILS(pA()(INVALID_SOCKET, "127.0.0.1", NULL, NULL, NULL, NULL, NULL, NULL, NULL), WSAEINVAL);
}

TEST(cpb_name_w_invalid_socket_is_enotsock_before_other_checks)
{
    OVERLAPPED ov;
    NEED_W();
    memset(&ov, 0, sizeof ov);
    CB_FAILS(pW()(INVALID_SOCKET, L"127.0.0.1", L"80", NULL, NULL, NULL, NULL, NULL, NULL), WSAENOTSOCK);
    CB_FAILS(pW()(INVALID_SOCKET, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL), WSAENOTSOCK);
    CB_FAILS(pW()(INVALID_SOCKET, L"127.0.0.1", L"80", NULL, NULL, NULL, NULL, NULL, &ov), WSAENOTSOCK);
    CB_FAILS(pW()(0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL), WSAENOTSOCK);
}

TEST(cpb_name_reserved_parameter_must_be_null)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 1), s;
    char svc[16];
    WCHAR wsvc[16];
    OVERLAPPED ov;
    NEED_W();
    memset(&ov, 0, sizeof ov);
    port_a(&la, svc, sizeof svc);
    port_w(&la, wsvc, 16);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CB_FAILS(pW()(s, L"127.0.0.1", wsvc, NULL, NULL, NULL, NULL, NULL, &ov), WSAEINVAL);
    CB_FAILS(pA()(s, "127.0.0.1", svc, NULL, NULL, NULL, NULL, NULL, &ov), WSAEINVAL);
    CP_EQ(cp_wait(l, CP_R, 200), 0);          /* nothing was attempted */
    CP_EQ(cp_peer_err(s), WSAENOTCONN);
    cp_closesocket(s); cp_closesocket(l);
}

TEST(cpb_name_null_node_or_service_is_einval)
{
    SOCKET s;
    NEED_W();
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CB_FAILS(pW()(s, NULL, L"80", NULL, NULL, NULL, NULL, NULL, NULL), WSAEINVAL);
    CB_FAILS(pW()(s, L"127.0.0.1", NULL, NULL, NULL, NULL, NULL, NULL, NULL), WSAEINVAL);
    CB_FAILS(pW()(s, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL), WSAEINVAL);
    CB_FAILS(pA()(s, NULL, "80", NULL, NULL, NULL, NULL, NULL, NULL), WSAEINVAL);
    CB_FAILS(pA()(s, "127.0.0.1", NULL, NULL, NULL, NULL, NULL, NULL, NULL), WSAEINVAL);
    cp_closesocket(s);
}

TEST(cpb_name_event_handle_is_not_a_socket)
{
    HANDLE h;
    NEED_W();
    h = CreateEventA(NULL, FALSE, FALSE, NULL);
    CB_FAILS(pW()((SOCKET)h, L"127.0.0.1", L"80", NULL, NULL, NULL, NULL, NULL, NULL), WSAENOTSOCK);
    CB_FAILS(pA()((SOCKET)h, "127.0.0.1", "80", NULL, NULL, NULL, NULL, NULL, NULL), WSAENOTSOCK);
    CloseHandle(h);
}

TEST(cpb_name_closed_socket_is_enotsock)
{
    SOCKET s;
    NEED_W();
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_closesocket(s);
    CB_FAILS(pW()(s, L"127.0.0.1", L"80", NULL, NULL, NULL, NULL, NULL, NULL), WSAENOTSOCK);
    CB_FAILS(pA()(s, "127.0.0.1", "80", NULL, NULL, NULL, NULL, NULL, NULL), WSAENOTSOCK);
}

/* ---- WSAConnectByName: successful paths -------------------------------------------------------------- */

TEST(cpb_name_a_connects_to_numeric_loopback)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    char svc[16];
    NEED_A();
    port_a(&la, svc, sizeof svc);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(pA()(s, "127.0.0.1", svc, NULL, NULL, NULL, NULL, NULL, NULL));
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
}

TEST(cpb_name_w_connects_to_numeric_loopback)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    WCHAR svc[16];
    NEED_W();
    port_w(&la, svc, 16);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(pW()(s, L"127.0.0.1", svc, NULL, NULL, NULL, NULL, NULL, NULL));
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
}

TEST(cpb_name_a_and_w_report_the_same_remote_address)
{
    struct sockaddr_in la, ra, rw;
    SOCKET l = cp_listener(&la, 2), s1, s2;
    char svc[16];
    WCHAR wsvc[16];
    DWORD n1 = sizeof ra, n2 = sizeof rw;
    NEED_W();
    port_a(&la, svc, sizeof svc);
    port_w(&la, wsvc, 16);
    s1 = cp_socket(AF_INET, SOCK_STREAM, 0);
    s2 = cp_socket(AF_INET, SOCK_STREAM, 0);
    memset(&ra, 0, sizeof ra); memset(&rw, 0, sizeof rw);
    CHECK(pA()(s1, "127.0.0.1", svc, NULL, NULL, &n1, (LPSOCKADDR)&ra, NULL, NULL));
    CHECK(pW()(s2, L"127.0.0.1", wsvc, NULL, NULL, &n2, (LPSOCKADDR)&rw, NULL, NULL));
    CP_EQ(n1, n2);
    CP_EQ(n1, sizeof ra);
    CHECK(cp_same_addr(&ra, &la));
    CHECK(cp_same_addr(&rw, &la));
    cp_closesocket(s1); cp_closesocket(s2); cp_closesocket(l);
}

TEST(cpb_name_accepts_a_timeout)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 1), s;
    WCHAR svc[16];
    struct timeval tv;
    NEED_W();
    port_w(&la, svc, 16);
    tv.tv_sec = 5; tv.tv_usec = 0;
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(pW()(s, L"127.0.0.1", svc, NULL, NULL, NULL, NULL, &tv, NULL));
    cp_closesocket(s); cp_closesocket(l);
}

TEST(cpb_name_connection_is_usable_for_data)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    WCHAR svc[16];
    char b[4] = {0};
    NEED_W();
    port_w(&la, svc, 16);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(pW()(s, L"127.0.0.1", svc, NULL, NULL, NULL, NULL, NULL, NULL));
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    CP_EQ(cp_send(s, "hey", 3, 0), 3);
    CHECK(cp_wait(a, CP_R, WAIT_MS) & CP_R);
    CP_EQ(cp_recv(a, b, 3, 0), 3);
    CHECK(!memcmp(b, "hey", 3));
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
}

TEST(cpb_name_peer_and_sock_names_without_update_context_note)
{
    struct sockaddr_in la, p, n;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    WCHAR svc[16];
    int pl = sizeof p, nl = sizeof n, r1, r2;
    NEED_W();
    port_w(&la, svc, 16);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(pW()(s, L"127.0.0.1", svc, NULL, NULL, NULL, NULL, NULL, NULL));
    r1 = cp_getpeername(s, (struct sockaddr *)&p, &pl);
    r2 = cp_getsockname(s, (struct sockaddr *)&n, &nl);
    t_note("getpeername/getsockname right after WSAConnectByName without SO_UPDATE_CONNECT_CONTEXT -> %d/%d", r1, r2);
    cp_accept_one(l, &a, WAIT_MS);
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
}

TEST(cpb_name_numeric_ipv6_loopback)
{
    struct sockaddr_in6 la;
    SOCKET l = cp_listener6(&la, 1), s, a = INVALID_SOCKET;
    WCHAR svc[16];
    struct sockaddr_in a4;
    NEED_W();
    if (l == INVALID_SOCKET) { t_skip("IPv6 loopback unavailable"); return; }
    a4 = cp_lo4(la.sin6_port);
    port_w(&a4, svc, 16);
    s = cp_socket(AF_INET6, SOCK_STREAM, 0);
    CHECK(pW()(s, L"::1", svc, NULL, NULL, NULL, NULL, NULL, NULL));
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
}

TEST(cpb_name_v4_node_on_v6_socket_note)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    WCHAR svc[16];
    DWORD off = 0;
    BOOL r;
    NEED_W();
    port_w(&la, svc, 16);
    s = cp_socket(AF_INET6, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { cp_closesocket(l); t_skip("IPv6 unavailable"); return; }
    cp_setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof off);
    cp_WSASetLastError(0);
    r = pW()(s, L"127.0.0.1", svc, NULL, NULL, NULL, NULL, NULL, NULL);
    t_note("dual-stack socket, IPv4 numeric node -> %d (err %d)", r, r ? 0 : cp_WSAGetLastError());
    if (r) cp_accept_one(l, &a, WAIT_MS);
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
}

TEST(cpb_name_localhost_on_v4_socket_note)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    WCHAR svc[16];
    BOOL r;
    NEED_W();
    port_w(&la, svc, 16);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_WSASetLastError(0);
    r = pW()(s, L"localhost", svc, NULL, NULL, NULL, NULL, NULL, NULL);
    t_note("node \"localhost\" on an IPv4 socket -> %d (err %d)", r, r ? 0 : cp_WSAGetLastError());
    if (r) cp_accept_one(l, &a, WAIT_MS);
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
}

/* ---- WSAConnectByName: failures ----------------------------------------------------------------------- */

TEST(cpb_name_dead_port_fails_and_leaves_socket_unconnected)
{
    struct sockaddr_in d;
    SOCKET s;
    WCHAR svc[16];
    BOOL r;
    NEED_W();
    CHECK(cp_dead_port(&d));
    port_w(&d, svc, 16);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_WSASetLastError(0);
    r = pW()(s, L"127.0.0.1", svc, NULL, NULL, NULL, NULL, NULL, NULL);
    CP_EQ(r, FALSE);
    t_note("WSAConnectByName to a refused port: error %d", cp_WSAGetLastError());
    CP_EQ(cp_peer_err(s), WSAENOTCONN);
    cp_closesocket(s);
}

TEST(cpb_name_on_connected_socket_fails)
{
    SOCKET c, s;
    BOOL r;
    NEED_W();
    CHECK(cp_pair(&c, &s));
    cp_WSASetLastError(0);
    r = pW()(c, L"127.0.0.1", L"9", NULL, NULL, NULL, NULL, NULL, NULL);
    CP_EQ(r, FALSE);
    t_note("WSAConnectByName on a connected socket: error %d", cp_WSAGetLastError());
    cp_closesocket(c); cp_closesocket(s);
}

TEST(cpb_name_failure_then_success_on_the_same_socket_note)
{
    struct sockaddr_in d, la;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    WCHAR sd[16], sl[16];
    BOOL r;
    NEED_W();
    CHECK(cp_dead_port(&d));
    port_w(&d, sd, 16);
    port_w(&la, sl, 16);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CP_EQ(pW()(s, L"127.0.0.1", sd, NULL, NULL, NULL, NULL, NULL, NULL), FALSE);
    cp_WSASetLastError(0);
    r = pW()(s, L"127.0.0.1", sl, NULL, NULL, NULL, NULL, NULL, NULL);
    t_note("second attempt on the socket after a refusal -> %d (err %d)", r, r ? 0 : cp_WSAGetLastError());
    if (r) cp_accept_one(l, &a, WAIT_MS);
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
}

/* ---- WSAConnectByList: argument order ---------------------------------------------------------------- */

TEST(cpl_invalid_socket_is_enotsock_before_the_list_is_looked_at)
{
    struct sockaddr_in a = cp_lo4(cp_ns(9));
    void *sa[1]; int len[1];
    SOCKET_ADDRESS_LIST *lst;
    NEED_L();
    sa[0] = &a; len[0] = sizeof a;
    lst = mk_list(1, sa, len);
    CB_FAILS(pL()(INVALID_SOCKET, lst, NULL, NULL, NULL, NULL, NULL, NULL), WSAENOTSOCK);
    CB_FAILS(pL()(INVALID_SOCKET, NULL, NULL, NULL, NULL, NULL, NULL, NULL), WSAENOTSOCK);
    CB_FAILS(pL()(0, NULL, NULL, NULL, NULL, NULL, NULL, NULL), WSAENOTSOCK);
    free_list(lst);
}

TEST(cpl_null_list_is_einval)
{
    SOCKET s;
    NEED_L();
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CB_FAILS(pL()(s, NULL, NULL, NULL, NULL, NULL, NULL, NULL), WSAEINVAL);
    cp_closesocket(s);
}

TEST(cpl_empty_list_is_einval)
{
    SOCKET s;
    SOCKET_ADDRESS_LIST *lst;
    NEED_L();
    lst = mk_list(0, NULL, NULL);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CB_FAILS(pL()(s, lst, NULL, NULL, NULL, NULL, NULL, NULL), WSAEINVAL);
    cp_closesocket(s);
    free_list(lst);
}

TEST(cpl_reserved_parameter_must_be_null)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 1), s;
    void *sa[1]; int len[1];
    SOCKET_ADDRESS_LIST *lst;
    OVERLAPPED ov;
    NEED_L();
    memset(&ov, 0, sizeof ov);
    sa[0] = &la; len[0] = sizeof la;
    lst = mk_list(1, sa, len);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CB_FAILS(pL()(s, lst, NULL, NULL, NULL, NULL, NULL, &ov), WSAEINVAL);
    CP_EQ(cp_wait(l, CP_R, 200), 0);
    CP_EQ(cp_peer_err(s), WSAENOTCONN);
    cp_closesocket(s); cp_closesocket(l);
    free_list(lst);
}

TEST(cpl_event_handle_is_not_a_socket)
{
    struct sockaddr_in a = cp_lo4(cp_ns(9));
    void *sa[1]; int len[1];
    SOCKET_ADDRESS_LIST *lst;
    HANDLE h;
    NEED_L();
    sa[0] = &a; len[0] = sizeof a;
    lst = mk_list(1, sa, len);
    h = CreateEventA(NULL, FALSE, FALSE, NULL);
    CB_FAILS(pL()((SOCKET)h, lst, NULL, NULL, NULL, NULL, NULL, NULL), WSAENOTSOCK);
    CloseHandle(h);
    free_list(lst);
}

TEST(cpl_list_without_a_matching_family_is_einval)
{
    struct sockaddr_in6 a6 = cp_lo6(cp_ns(9));
    void *sa[1]; int len[1];
    SOCKET_ADDRESS_LIST *lst;
    SOCKET s;
    NEED_L();
    sa[0] = &a6; len[0] = sizeof a6;
    lst = mk_list(1, sa, len);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CB_FAILS(pL()(s, lst, NULL, NULL, NULL, NULL, NULL, NULL), WSAEINVAL);
    cp_closesocket(s);
    free_list(lst);
}

/* ---- WSAConnectByList: traversal -------------------------------------------------------------------- */

TEST(cpl_single_entry_connects)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    void *sa[1]; int len[1];
    SOCKET_ADDRESS_LIST *lst;
    NEED_L();
    sa[0] = &la; len[0] = sizeof la;
    lst = mk_list(1, sa, len);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(pL()(s, lst, NULL, NULL, NULL, NULL, NULL, NULL));
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
    free_list(lst);
}

TEST(cpl_remote_address_output_names_the_chosen_entry)
{
    struct sockaddr_in la, ra;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    void *sa[1]; int len[1];
    SOCKET_ADDRESS_LIST *lst;
    DWORD rl = sizeof ra;
    NEED_L();
    sa[0] = &la; len[0] = sizeof la;
    lst = mk_list(1, sa, len);
    memset(&ra, 0, sizeof ra);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(pL()(s, lst, NULL, NULL, &rl, (LPSOCKADDR)&ra, NULL, NULL));
    CP_EQ(rl, sizeof ra);
    CHECK(cp_same_addr(&ra, &la));
    cp_accept_one(l, &a, WAIT_MS);
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
    free_list(lst);
}

TEST(cpl_local_address_output_has_the_loopback_address)
{
    struct sockaddr_in la, loc;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    void *sa[1]; int len[1];
    SOCKET_ADDRESS_LIST *lst;
    DWORD ll = sizeof loc;
    NEED_L();
    sa[0] = &la; len[0] = sizeof la;
    lst = mk_list(1, sa, len);
    memset(&loc, 0, sizeof loc);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(pL()(s, lst, &ll, (LPSOCKADDR)&loc, NULL, NULL, NULL, NULL));
    CP_EQ(ll, sizeof loc);
    CP_EQ(loc.sin_family, AF_INET);
    CP_EQ(loc.sin_addr.s_addr, cp_htonl(INADDR_LOOPBACK));
    cp_accept_one(l, &a, WAIT_MS);
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
    free_list(lst);
}

TEST(cpl_refused_entry_is_skipped_and_the_next_one_used)
{
    struct sockaddr_in la, d, ra;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    void *sa[2]; int len[2];
    SOCKET_ADDRESS_LIST *lst;
    DWORD rl = sizeof ra;
    NEED_L();
    CHECK(cp_dead_port(&d));
    sa[0] = &d;  len[0] = sizeof d;
    sa[1] = &la; len[1] = sizeof la;
    lst = mk_list(2, sa, len);
    memset(&ra, 0, sizeof ra);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(pL()(s, lst, NULL, NULL, &rl, (LPSOCKADDR)&ra, NULL, NULL));
    CHECK(cp_same_addr(&ra, &la));
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
    free_list(lst);
}

TEST(cpl_several_refused_entries_before_the_good_one)
{
    struct sockaddr_in la, d1, d2, d3;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    SOCKET hold1, hold2, hold3;
    void *sa[4]; int len[4];
    SOCKET_ADDRESS_LIST *lst;
    NEED_L();
    /* three distinct dead ports: keep each listener open until the next one is bound so they differ */
    hold1 = cp_listener(&d1, 0); hold2 = cp_listener(&d2, 0); hold3 = cp_listener(&d3, 0);
    cp_closesocket(hold1); cp_closesocket(hold2); cp_closesocket(hold3);
    sa[0] = &d1; sa[1] = &d2; sa[2] = &d3; sa[3] = &la;
    len[0] = len[1] = len[2] = len[3] = sizeof la;
    lst = mk_list(4, sa, len);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(pL()(s, lst, NULL, NULL, NULL, NULL, NULL, NULL));
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
    free_list(lst);
}

TEST(cpl_wrong_family_entries_are_ignored)
{
    struct sockaddr_in la, ra;
    struct sockaddr_in6 a6 = cp_lo6(cp_ns(9));
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    void *sa[2]; int len[2];
    SOCKET_ADDRESS_LIST *lst;
    DWORD rl = sizeof ra;
    NEED_L();
    sa[0] = &a6; len[0] = sizeof a6;
    sa[1] = &la; len[1] = sizeof la;
    lst = mk_list(2, sa, len);
    memset(&ra, 0, sizeof ra);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(pL()(s, lst, NULL, NULL, &rl, (LPSOCKADDR)&ra, NULL, NULL));
    CHECK(cp_same_addr(&ra, &la));
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
    free_list(lst);
}

TEST(cpl_all_entries_refused_fails_and_leaves_socket_unconnected)
{
    struct sockaddr_in d1, d2;
    SOCKET h1, h2, s;
    void *sa[2]; int len[2];
    SOCKET_ADDRESS_LIST *lst;
    BOOL r;
    NEED_L();
    h1 = cp_listener(&d1, 0); h2 = cp_listener(&d2, 0);
    cp_closesocket(h1); cp_closesocket(h2);
    sa[0] = &d1; sa[1] = &d2; len[0] = len[1] = sizeof d1;
    lst = mk_list(2, sa, len);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    cp_WSASetLastError(0);
    r = pL()(s, lst, NULL, NULL, NULL, NULL, NULL, NULL);
    CP_EQ(r, FALSE);
    t_note("WSAConnectByList with every entry refused: error %d", cp_WSAGetLastError());
    CP_EQ(cp_peer_err(s), WSAENOTCONN);
    cp_closesocket(s);
    free_list(lst);
}

TEST(cpl_null_output_parameters_are_accepted)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    void *sa[1]; int len[1];
    SOCKET_ADDRESS_LIST *lst;
    NEED_L();
    sa[0] = &la; len[0] = sizeof la;
    lst = mk_list(1, sa, len);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(pL()(s, lst, NULL, NULL, NULL, NULL, NULL, NULL));
    cp_accept_one(l, &a, WAIT_MS);
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
    free_list(lst);
}

TEST(cpl_accepts_a_timeout)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    void *sa[1]; int len[1];
    SOCKET_ADDRESS_LIST *lst;
    struct timeval tv;
    NEED_L();
    sa[0] = &la; len[0] = sizeof la;
    lst = mk_list(1, sa, len);
    tv.tv_sec = 5; tv.tv_usec = 0;
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(pL()(s, lst, NULL, NULL, NULL, NULL, &tv, NULL));
    cp_accept_one(l, &a, WAIT_MS);
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
    free_list(lst);
}

TEST(cpl_connection_is_usable_for_data)
{
    struct sockaddr_in la;
    SOCKET l = cp_listener(&la, 1), s, a = INVALID_SOCKET;
    void *sa[1]; int len[1];
    SOCKET_ADDRESS_LIST *lst;
    char b[4] = {0};
    NEED_L();
    sa[0] = &la; len[0] = sizeof la;
    lst = mk_list(1, sa, len);
    s = cp_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(pL()(s, lst, NULL, NULL, NULL, NULL, NULL, NULL));
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    CP_EQ(cp_send(s, "abc", 3, 0), 3);
    CHECK(cp_wait(a, CP_R, WAIT_MS) & CP_R);
    CP_EQ(cp_recv(a, b, 3, 0), 3);
    CHECK(!memcmp(b, "abc", 3));
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
    free_list(lst);
}

TEST(cpl_v6_socket_with_v6_list)
{
    struct sockaddr_in6 la;
    SOCKET l = cp_listener6(&la, 1), s, a = INVALID_SOCKET;
    void *sa[1]; int len[1];
    SOCKET_ADDRESS_LIST *lst;
    NEED_L();
    if (l == INVALID_SOCKET) { t_skip("IPv6 loopback unavailable"); return; }
    sa[0] = &la; len[0] = sizeof la;
    lst = mk_list(1, sa, len);
    s = cp_socket(AF_INET6, SOCK_STREAM, 0);
    CHECK(pL()(s, lst, NULL, NULL, NULL, NULL, NULL, NULL));
    CHECK(cp_accept_one(l, &a, WAIT_MS));
    cp_closesocket(a); cp_closesocket(s); cp_closesocket(l);
    free_list(lst);
}

TEST(cpl_on_connected_socket_fails)
{
    SOCKET c, s;
    struct sockaddr_in a = cp_lo4(cp_ns(9));
    void *sa[1]; int len[1];
    SOCKET_ADDRESS_LIST *lst;
    BOOL r;
    NEED_L();
    CHECK(cp_pair(&c, &s));
    sa[0] = &a; len[0] = sizeof a;
    lst = mk_list(1, sa, len);
    cp_WSASetLastError(0);
    r = pL()(c, lst, NULL, NULL, NULL, NULL, NULL, NULL);
    CP_EQ(r, FALSE);
    t_note("WSAConnectByList on a connected socket: error %d", cp_WSAGetLastError());
    cp_closesocket(c); cp_closesocket(s);
    free_list(lst);
}
