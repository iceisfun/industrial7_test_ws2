/* SIO_GET_EXTENSION_FUNCTION_POINTER, the successful side: which GUIDs are served, on which socket types
 * and states, that the returned pointers are stable (across sockets, threads, repeated calls and processes),
 * distinct per function, executable, and live in the base provider's module.
 *
 * Facts relied on (base provider ioctl handler): the lookup is a table search by the 16 raw GUID bytes
 * over a fixed in-image table; the answer is the pointer itself, 8 bytes, independent of the socket the
 * question is asked on. */
#include "xf.h"

/* Module that contains an address, or NULL; refcount untouched. */
static HMODULE module_of(const void *p)
{
    HMODULE m = NULL;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)p, &m))
        return NULL;
    return m;
}

/* ---- every documented GUID, on every socket kind ---------------------------------------------------- */

static void core_on_kind(const struct xf_kind *k)
{
    unsigned i;
    SOCKET s;
    NEED_NET();
    if (k->af == AF_INET6 && !xf_ipv6_ok()) { t_skip("no IPv6"); return; }
    s = socket(k->af, k->type, k->proto);
    if (s == INVALID_SOCKET) { t_skip("cannot create %s socket", k->name); return; }
    for (i = 0; i < XF_NCORE; i++) {
        void *p = (void *)1;
        DWORD n = 0;
        int r;
        WSASetLastError(0);
        r = xf_lookup(s, &XF_GUIDS[i].g, &p, &n);
        CHECKF(r == 0, "%s on %s: r=%d err=%d", XF_GUIDS[i].name, k->name, r, WSAGetLastError());
        CHECKF(p != NULL, "%s on %s: null pointer", XF_GUIDS[i].name, k->name);
        CHECKF(n == sizeof(void *), "%s on %s: bytes %lu", XF_GUIDS[i].name, k->name, n);
        CHECKF(WSAGetLastError() == 0, "%s on %s: error %d left behind", XF_GUIDS[i].name, k->name, WSAGetLastError());
    }
    closesocket(s);
}
TEST(xf_lookup_core_guids_tcp4) { core_on_kind(&XF_KINDS[0]); }
TEST(xf_lookup_core_guids_udp4) { core_on_kind(&XF_KINDS[1]); }
TEST(xf_lookup_core_guids_tcp6) { core_on_kind(&XF_KINDS[2]); }
TEST(xf_lookup_core_guids_udp6) { core_on_kind(&XF_KINDS[3]); }

/* The eighth entry is the message-send function; it is documented for datagram sockets, so only the
 * outcome is recorded for stream sockets. */
TEST(xf_lookup_sendmsg_on_datagram_socket)
{
    SOCKET s; void *p = NULL; DWORD n = 0; int r;
    GUID g = WSAID_WSASENDMSG;
    NEED_NET();
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(s != INVALID_SOCKET);
    r = xf_lookup(s, &g, &p, &n);
    CHECKF(r == 0 && p != NULL && n == sizeof(void *), "r=%d err=%d p=%p n=%lu", r, WSAGetLastError(), p, n);
    closesocket(s);
}
TEST(xf_lookup_sendmsg_on_stream_socket)
{
    SOCKET s; void *p = NULL; DWORD n = 0; int r;
    GUID g = WSAID_WSASENDMSG;
    NEED_NET();
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    r = xf_lookup(s, &g, &p, &n);
    CHECKF(r == 0 && p, "r=%d err=%d", r, WSAGetLastError());
    closesocket(s);
}

/* ---- identity and stability of the pointers ---------------------------------------------------------- */

TEST(xf_lookup_pointers_are_pairwise_distinct)
{
    unsigned i, j; void *p[XF_NGUIDS];
    NEED_NET();
    for (i = 0; i < XF_NGUIDS; i++) p[i] = xf_fn(&XF_GUIDS[i].g);
    for (i = 0; i < XF_NCORE; i++) CHECKF(p[i] != NULL, "%s missing", XF_GUIDS[i].name);
    for (i = 0; i < XF_NGUIDS; i++)
        for (j = i + 1; j < XF_NGUIDS; j++)
            if (p[i] && p[j])
                CHECKF(p[i] != p[j], "%s and %s resolve to the same function", XF_GUIDS[i].name, XF_GUIDS[j].name);
}

TEST(xf_lookup_pointer_independent_of_socket_kind)
{
    unsigned g, k;
    NEED_NET();
    for (g = 0; g < XF_NCORE; g++) {
        void *ref = NULL;
        for (k = 0; k < XF_NKINDS; k++) {
            SOCKET s; void *p = NULL;
            if (XF_KINDS[k].af == AF_INET6 && !xf_ipv6_ok()) continue;
            s = socket(XF_KINDS[k].af, XF_KINDS[k].type, XF_KINDS[k].proto);
            if (s == INVALID_SOCKET) continue;
            if (xf_lookup(s, &XF_GUIDS[g].g, &p, NULL) == 0) {
                if (!ref) ref = p;
                CHECKF(p == ref, "%s differs on %s", XF_GUIDS[g].name, XF_KINDS[k].name);
            }
            closesocket(s);
        }
        CHECKF(ref != NULL, "%s never resolved", XF_GUIDS[g].name);
    }
}

TEST(xf_lookup_pointer_stable_across_many_sockets)
{
    unsigned g; int i;
    NEED_NET();
    for (g = 0; g < XF_NCORE; g++) {
        void *ref = xf_fn(&XF_GUIDS[g].g);
        for (i = 0; i < 40; i++) {
            void *p = xf_fn(&XF_GUIDS[g].g);
            if (p != ref) { CHECKF(0, "%s changed on socket %d", XF_GUIDS[g].name, i); break; }
        }
    }
}

TEST(xf_lookup_pointer_stable_on_one_socket)
{
    SOCKET s; unsigned g; int i;
    NEED_NET();
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    for (g = 0; g < XF_NCORE; g++) {
        void *ref = NULL, *p;
        xf_lookup(s, &XF_GUIDS[g].g, &ref, NULL);
        for (i = 0; i < 100; i++) {
            p = NULL;
            if (xf_lookup(s, &XF_GUIDS[g].g, &p, NULL) != 0 || p != ref) { CHECKF(0, "%s unstable at %d", XF_GUIDS[g].name, i); break; }
        }
    }
    closesocket(s);
}

TEST(xf_lookup_pointer_stable_after_socket_closed)
{
    SOCKET a, b; void *pa = NULL, *pb = NULL;
    GUID g = WSAID_DISCONNECTEX;
    NEED_NET();
    a = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(a != INVALID_SOCKET);
    xf_lookup(a, &g, &pa, NULL);
    closesocket(a);               /* the pointer is not owned by the socket it was asked on */
    b = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(b != INVALID_SOCKET);
    xf_lookup(b, &g, &pb, NULL);
    EXPECT_EQ(pa, pb);
    closesocket(b);
}

struct thr { const GUID *g; void *ref; int bad; };
static DWORD WINAPI lookup_thread(LPVOID arg)
{
    struct thr *t = (struct thr *)arg;
    int i;
    for (i = 0; i < 50; i++) {
        void *p = xf_fn(t->g);
        if (p != t->ref) t->bad++;
    }
    return 0;
}
TEST(xf_lookup_pointer_same_in_other_threads)
{
    struct thr t[4]; HANDLE h[4]; int i; unsigned g;
    NEED_NET();
    for (g = 0; g < XF_NCORE; g += 3) {
        void *ref = xf_fn(&XF_GUIDS[g].g);
        for (i = 0; i < 4; i++) {
            t[i].g = &XF_GUIDS[g].g; t[i].ref = ref; t[i].bad = 0;
            h[i] = CreateThread(NULL, 0, lookup_thread, &t[i], 0, NULL);
        }
        for (i = 0; i < 4; i++) {
            if (!h[i]) continue;
            CHECK(WaitForSingleObject(h[i], 20000) == WAIT_OBJECT_0);
            CloseHandle(h[i]);
            CHECKF(t[i].bad == 0, "%s: thread %d saw %d different pointers", XF_GUIDS[g].name, i, t[i].bad);
        }
    }
}

TEST(xf_lookup_pointer_survives_extra_startup_cleanup_pair)
{
    unsigned g; WSADATA d;
    NEED_NET();
    for (g = 0; g < XF_NCORE; g++) {
        void *a = xf_fn(&XF_GUIDS[g].g), *b;
        CHECK(WSAStartup(MAKEWORD(2, 2), &d) == 0);
        CHECK(WSACleanup() == 0);
        b = xf_fn(&XF_GUIDS[g].g);
        CHECKF(a == b, "%s changed over a startup/cleanup pair", XF_GUIDS[g].name);
    }
}

/* Child: fully tear Winsock down (count to zero) and up again, then report the module-relative offsets so the
 * parent can compare without depending on load addresses. */
CHILD(xf_cycle)
{
    WSADATA d;
    void *a[XF_NCORE], *b[XF_NCORE];
    unsigned i;
    int rc = 0;
    HMODULE ms;
    if (WSAStartup(MAKEWORD(2, 2), &d)) return 10;
    for (i = 0; i < XF_NCORE; i++) a[i] = xf_fn(&XF_GUIDS[i].g);
    ms = module_of(a[0]);
    if (WSACleanup()) return 11;
    if (WSAStartup(MAKEWORD(2, 2), &d)) return 12;
    for (i = 0; i < XF_NCORE; i++) b[i] = xf_fn(&XF_GUIDS[i].g);
    for (i = 0; i < XF_NCORE; i++) {
        if (!a[i] || !b[i]) return 13;
        if (module_of(a[i]) != ms) return 14;
        if (module_of(b[i]) == NULL) return 15;
        if ((char *)a[i] - (char *)ms != (char *)b[i] - (char *)module_of(b[i])) rc = 16; /* same code, wherever mapped */
    }
    WSACleanup();
    return rc;
}
TEST(xf_lookup_pointer_after_full_winsock_teardown)
{
    DWORD rc = t_run_child("xf_cycle", "", 30000);
    CHECKF(rc == 0, "child result %lu", rc);
}

/* Child: print the offsets of every pointer from the image base of the module that holds it. */
CHILD(xf_offsets)
{
    WSADATA d;
    unsigned i;
    unsigned long long sum = 0;
    if (WSAStartup(MAKEWORD(2, 2), &d)) return 1;
    for (i = 0; i < XF_NCORE; i++) {
        void *p = xf_fn(&XF_GUIDS[i].g);
        HMODULE m = p ? module_of(p) : NULL;
        if (!m) return 2;
        sum = sum * 1000003ULL + (unsigned long long)((char *)p - (char *)m);
    }
    WSACleanup();
    return (int)(sum & 0x7fffffff);
}
TEST(xf_lookup_pointer_offsets_same_in_another_process)
{
    DWORD a, b;
    unsigned i; unsigned long long sum = 0;
    NEED_NET();
    for (i = 0; i < XF_NCORE; i++) {
        void *p = xf_fn(&XF_GUIDS[i].g);
        HMODULE m = p ? module_of(p) : NULL;
        REQUIRE(m);
        sum = sum * 1000003ULL + (unsigned long long)((char *)p - (char *)m);
    }
    a = (DWORD)(sum & 0x7fffffff);
    b = t_run_child("xf_offsets", "", 30000);
    EXPECT_EQ(b, a);
    b = t_run_child("xf_offsets", "", 30000);
    EXPECT_EQ(b, a);
}

/* ---- where the pointers live ------------------------------------------------------------------------- */

TEST(xf_lookup_core_pointers_are_in_the_provider_module)
{
    unsigned i; HMODULE ms;
    NEED_NET();
    ms = t_module("mswsock.dll");
    REQUIRE(ms);
    for (i = 0; i < XF_NCORE; i++) {
        void *p = xf_fn(&XF_GUIDS[i].g);
        HMODULE m = p ? module_of(p) : NULL;
        CHECKF(m == ms, "%s does not point into the provider module", XF_GUIDS[i].name);
    }
}

TEST(xf_lookup_core_pointers_are_executable_image_code)
{
    unsigned i;
    NEED_NET();
    for (i = 0; i < XF_NCORE; i++) {
        void *p = xf_fn(&XF_GUIDS[i].g);
        MEMORY_BASIC_INFORMATION mbi;
        if (!p) { CHECKF(0, "%s missing", XF_GUIDS[i].name); continue; }
        memset(&mbi, 0, sizeof mbi);
        CHECK(VirtualQuery(p, &mbi, sizeof mbi) == sizeof mbi);
        CHECKF(mbi.Type == MEM_IMAGE, "%s: not in an image", XF_GUIDS[i].name);
        CHECKF(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY),
               "%s: page is not executable (0x%lx)", XF_GUIDS[i].name, (unsigned long)mbi.Protect);
    }
}

/* The three functions that mswsock also exports are reached through thin export thunks that perform this
 * very lookup and then call what it returns; so the looked-up pointer cannot be the export itself. */
TEST(xf_lookup_pointer_differs_from_mswsock_export_thunk)
{
    static const struct { const char *exp; int guid; } m[] = {
        {"AcceptEx", 0}, {"GetAcceptExSockaddrs", 1}, {"TransmitFile", 2}};
    unsigned i;
    NEED_NET();
    for (i = 0; i < 3; i++) {
        void *e = (void *)t_proc_in("mswsock.dll", m[i].exp);
        void *p = xf_fn(&XF_GUIDS[m[i].guid].g);
        if (!e || !p) { t_skip("missing %s", m[i].exp); return; }
        CHECKF(e != p, "%s: lookup returned the exported thunk", m[i].exp);
        CHECKF(module_of(e) == module_of(p), "%s: export and function in different modules", m[i].exp);
    }
}

/* Documentation: ConnectEx, DisconnectEx, TransmitPackets and WSARecvMsg are not exported by name from any
 * module; the lookup is the only way in. */
TEST(xf_lookup_only_functions_have_no_exports)
{
    static const char *names[] = {"ConnectEx", "DisconnectEx", "TransmitPackets", "WSARecvMsg", "WSASendMsg"};
    unsigned i; const char *mods[] = {"mswsock.dll", "ws2_32.dll"};
    int m;
    for (i = 0; i < 5; i++)
        for (m = 0; m < 2; m++) {
            FARPROC p = GetProcAddress(t_module(mods[m]), names[i]);
            if (p) t_note("%s exports %s", mods[m], names[i]);
        }
}

TEST(xf_lookup_where_wsasendmsg_lives)
{
    void *p; FARPROC e;
    GUID g = WSAID_WSASENDMSG;
    NEED_NET();
    p = xf_fn_udp(&g);
    REQUIRE(p);
    e = GetProcAddress(t_module("ws2_32.dll"), "WSASendMsg");
    CHECK(module_of(p) == t_module("mswsock.dll"));
    CHECK((FARPROC)p != e);
}

/* ---- socket states and creation variants -------------------------------------------------------------- */

static void lookup_works_on(SOCKET s, const char *what)
{
    unsigned i;
    for (i = 0; i < XF_NCORE; i++) {
        void *p = NULL; DWORD n = 0;
        int r = xf_lookup(s, &XF_GUIDS[i].g, &p, &n);
        CHECKF(r == 0 && p && n == sizeof(void *), "%s: %s r=%d err=%d", what, XF_GUIDS[i].name, r, WSAGetLastError());
    }
}

TEST(xf_lookup_on_unbound_socket_does_not_bind_it)
{
    SOCKET s; struct sockaddr_in a; int len = sizeof a;
    NEED_NET();
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    lookup_works_on(s, "unbound");
    /* still unbound: getsockname on a never-bound stream socket is WSAEINVAL */
    memset(&a, 0, sizeof a);
    CHECK(getsockname(s, (struct sockaddr *)&a, &len) == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    closesocket(s);
}
TEST(xf_lookup_on_bound_socket)
{
    SOCKET s; struct sockaddr_in a;
    NEED_NET();
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    xf_loop4(&a);
    CHECK(bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    lookup_works_on(s, "bound");
    closesocket(s);
}
TEST(xf_lookup_on_listening_socket)
{
    struct sockaddr_in a; SOCKET l;
    NEED_NET();
    l = xf_listener(&a, 2);
    REQUIRE(l != INVALID_SOCKET);
    lookup_works_on(l, "listening");
    closesocket(l);
}
TEST(xf_lookup_on_connected_and_accepted_sockets)
{
    PAIR(p);
    lookup_works_on(p.cli, "connected");
    lookup_works_on(p.srv, "accepted");
    xf_pair_close(&p);
}
TEST(xf_lookup_on_shutdown_socket)
{
    PAIR(p);
    CHECK(shutdown(p.cli, SD_BOTH) == 0);
    lookup_works_on(p.cli, "shut down");
    xf_pair_close(&p);
}
TEST(xf_lookup_after_peer_closed)
{
    PAIR(p);
    closesocket(p.srv); p.srv = INVALID_SOCKET;
    lookup_works_on(p.cli, "peer closed");
    xf_pair_close(&p);
}
TEST(xf_lookup_on_nonblocking_socket)
{
    SOCKET s; u_long one = 1;
    NEED_NET();
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    CHECK(ioctlsocket(s, FIONBIO, &one) == 0);
    lookup_works_on(s, "nonblocking");
    closesocket(s);
}
TEST(xf_lookup_on_wsasocket_flag_variants)
{
    static const DWORD flags[] = {0, WSA_FLAG_OVERLAPPED, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
                                  WSA_FLAG_NO_HANDLE_INHERIT};
    unsigned i;
    NEED_NET();
    for (i = 0; i < 4; i++) {
        SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, flags[i]);
        if (s == INVALID_SOCKET) { t_note("flags 0x%lx rejected", flags[i]); continue; }
        lookup_works_on(s, "WSASocket variant");
        closesocket(s);
    }
}
TEST(xf_lookup_on_socket_created_with_protocol_zero)
{
    SOCKET s;
    NEED_NET();
    s = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(s != INVALID_SOCKET);
    lookup_works_on(s, "protocol 0");
    closesocket(s);
    s = socket(AF_INET, SOCK_DGRAM, 0);
    REQUIRE(s != INVALID_SOCKET);
    lookup_works_on(s, "datagram protocol 0");
    closesocket(s);
}
TEST(xf_lookup_on_socket_made_with_protocol_info_by_type)
{
    /* A socket created from a type request without a protocol and one created with an explicit protocol are the
     * same provider: same answer. */
    SOCKET a, b; void *pa = NULL, *pb = NULL; GUID g = WSAID_ACCEPTEX;
    NEED_NET();
    a = socket(AF_INET, SOCK_STREAM, 0);
    b = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    REQUIRE(a != INVALID_SOCKET && b != INVALID_SOCKET);
    xf_lookup(a, &g, &pa, NULL); xf_lookup(b, &g, &pb, NULL);
    EXPECT_EQ(pa, pb);
    closesocket(a); closesocket(b);
}
TEST(xf_lookup_on_unix_domain_socket)
{
    SOCKET s; unsigned i;
    NEED_NET();
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { t_skip("AF_UNIX sockets unavailable"); return; }
    for (i = 0; i < XF_NCORE; i++) {
        void *p = NULL; DWORD n = 0;
        int r = xf_lookup(s, &XF_GUIDS[i].g, &p, &n);
        CHECKF(r == 0 && p && n == sizeof(void *), "AF_UNIX lookup of %s: r=%d err=%d", XF_GUIDS[i].name, r, WSAGetLastError());
    }
    closesocket(s);
}
TEST(xf_lookup_on_raw_socket)
{
    SOCKET s; unsigned i;
    NEED_NET();
    s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s == INVALID_SOCKET) { t_skip("raw sockets unavailable (needs elevation)"); return; }
    for (i = 0; i < XF_NCORE; i++) {
        void *p = NULL; int r = xf_lookup(s, &XF_GUIDS[i].g, &p, NULL);
        CHECKF(r == 0 && p, "raw socket lookup of %s: r=%d err=%d", XF_GUIDS[i].name, r, WSAGetLastError());
    }
    closesocket(s);
}
TEST(xf_lookup_on_registered_io_socket)
{
    SOCKET s; void *p = NULL; int r; GUID g = WSAID_ACCEPTEX;
    NEED_NET();
    s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_REGISTERED_IO);
    if (s == INVALID_SOCKET) { t_skip("registered-I/O sockets unavailable"); return; }
    r = xf_lookup(s, &g, &p, NULL);
    CHECKF(r == 0 && p, "registered-I/O socket: r=%d err=%d", r, WSAGetLastError());
    closesocket(s);
}
TEST(xf_lookup_multiple_rio_table)
{
    /* The registered-I/O function table is requested with the "multiple" variant of the control code. */
    static const GUID rio = {0x8509e081, 0x96dd, 0x4005, {0xb1, 0x65, 0x9e, 0x2e, 0xe8, 0xc7, 0x9e, 0x3f}};
    SOCKET s; BYTE tab[512]; DWORD n = 0; int r;
    NEED_NET();
    s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_REGISTERED_IO);
    if (s == INVALID_SOCKET) { t_skip("registered-I/O sockets unavailable"); return; }
    memset(tab, 0, sizeof tab);
    r = WSAIoctl(s, 0xC8000024, (LPVOID)&rio, sizeof rio, tab, sizeof tab, &n, NULL, NULL);
    CHECKF(r == 0 && n >= 8, "multiple-extension lookup: r=%d err=%d bytes=%lu", r, r ? WSAGetLastError() : 0, n);
    closesocket(s);
}

/* ---- candidate GUIDs that are not part of the core table ------------------------------------------------ */
TEST(xf_lookup_wsapoll_guid)
{
    GUID g = WSAID_WSAPOLL; void *p = NULL; int r;
    SOCKET s;
    NEED_NET();
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    REQUIRE(s != INVALID_SOCKET);
    r = xf_lookup(s, &g, &p, NULL);
    CHECK(r == SOCKET_ERROR);
    EXPECT_EQ(WSAGetLastError(), WSAEINVAL);
    closesocket(s);
}
/* The GUID table is by value: a different object holding the same 16 bytes selects the same function, and
 * trailing bytes after the GUID are ignored. */
TEST(xf_lookup_guid_matched_by_value_with_trailing_bytes)
{
    unsigned i;
    NEED_NET();
    for (i = 0; i < XF_NCORE; i++) {
        BYTE in[64]; SOCKET s; void *p = NULL, *ref = xf_fn(&XF_GUIDS[i].g); DWORD n = 0; int r;
        memset(in, 0xA5, sizeof in);
        memcpy(in, &XF_GUIDS[i].g, sizeof(GUID));
        s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        REQUIRE(s != INVALID_SOCKET);
        r = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, in, sizeof in, &p, sizeof p, &n, NULL, NULL);
        CHECKF(r == 0 && p == ref && n == sizeof p, "%s with 64-byte input: r=%d err=%d", XF_GUIDS[i].name, r, WSAGetLastError());
        closesocket(s);
    }
}
