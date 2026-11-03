/* gethostname / GetHostNameW: the buffer-length protocol.
 * Measures: what happens for every length from 0 up to "name plus terminator" and beyond, that a failing
 * call leaves the caller's buffer untouched and reports WSAEFAULT, that the terminator is counted in the
 * length, that the ANSI and wide forms agree, that a NULL buffer is WSAEFAULT whatever the length, that
 * the calls need WSAStartup first, and that wsock32's gethostname is the ws2_32 one. The relation between
 * the returned name and the lookup functions is also covered. */
#include "lns.h"

#define SENT 0x5a

/* Fetch the machine name once through a comfortably large buffer; returns its length without NUL. */
static int own_name(char *out, int cap)
{
    if (U(gethostname)(out, cap) != 0) return -1;
    return (int)strlen(out);
}

/* ---- ANSI: one test per length around the boundary ---------------------------------------------- */

/* The terminator is part of the required size: a length equal to strlen() must fail. */
#define SHORT_CASE(tag, expr) \
TEST(hostname_a_short_##tag) { \
    char name[300], buf[300]; int len, want, r; \
    LNS_NEED(gethostname); \
    len = own_name(name, sizeof name); \
    CHECK(len > 0); \
    want = (expr); \
    if (want < 0) { LNS_DONE(); t_skip("name too short for this case"); return; } \
    memset(buf, SENT, sizeof buf); LNS_SETERR(0); \
    r = U(gethostname)(buf, want); \
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(LNS_ERR(), LNS_E_FAULT); \
    { int i, dirty = 0; for (i = 0; i < (int)sizeof buf; i++) dirty += (unsigned char)buf[i] != SENT; CHECKF(dirty == 0, "%d bytes touched", dirty); } \
    LNS_DONE(); \
}
SHORT_CASE(len_zero, 0)
SHORT_CASE(len_one, 1)
SHORT_CASE(len_two, len >= 2 ? 2 : -1)
SHORT_CASE(len_half, len >= 4 ? len / 2 : -1)
SHORT_CASE(len_name_minus_one, len >= 2 ? len - 1 : -1)
SHORT_CASE(len_name, len)

/* A length of strlen()+1 is exactly enough; nothing past the terminator is written. */
TEST(hostname_a_exact_fit_writes_name_and_terminator_only)
{
    char name[300], buf[300]; int len;
    LNS_NEED(gethostname);
    len = own_name(name, sizeof name);
    CHECK(len > 0);
    memset(buf, SENT, sizeof buf);
    EXPECT_EQ(U(gethostname)(buf, len + 1), 0);
    CHECK(!strcmp(buf, name));
    CHECK((unsigned char)buf[len + 1] == SENT);
    CHECK((unsigned char)buf[len + 2] == SENT);
    LNS_DONE();
}

TEST(hostname_a_one_spare_byte_succeeds)
{
    char name[300], buf[300]; int len;
    LNS_NEED(gethostname);
    len = own_name(name, sizeof name);
    memset(buf, SENT, sizeof buf);
    EXPECT_EQ(U(gethostname)(buf, len + 2), 0);
    CHECK(!strcmp(buf, name));
    CHECK((unsigned char)buf[len + 2] == SENT);
    LNS_DONE();
}

/* Sizes that are not "just enough" all give the same name. */
TEST(hostname_a_sizes_give_identical_name)
{
    static const int sizes[] = { 16, 32, 64, 128, 256, 300 };
    char first[300], buf[300]; int i;
    LNS_NEED(gethostname);
    CHECK(own_name(first, sizeof first) > 0);
    for (i = 0; i < LNS_COUNT(sizes); i++) {
        memset(buf, SENT, sizeof buf);
        EXPECT_EQ(U(gethostname)(buf, sizes[i]), 0);
        CHECKF(!strcmp(buf, first), "size %d", sizes[i]);
    }
    LNS_DONE();
}

TEST(hostname_a_repeat_is_stable)
{
    char a[300], b[300]; int i;
    LNS_NEED(gethostname);
    CHECK(own_name(a, sizeof a) > 0);
    for (i = 0; i < 20; i++) {
        EXPECT_EQ(U(gethostname)(b, sizeof b), 0);
        CHECK(!strcmp(a, b));
    }
    LNS_DONE();
}

TEST(hostname_a_name_is_plain_text)
{
    char name[300]; int len, i, bad = 0;
    LNS_NEED(gethostname);
    len = own_name(name, sizeof name);
    CHECK(len > 0);
    /* Host names contain no blanks, control characters or dots in a NetBIOS-style single label. */
    for (i = 0; i < len; i++) if ((unsigned char)name[i] <= 0x20 || (unsigned char)name[i] >= 0x7f) bad++;
    CHECKF(bad == 0, "%d unexpected characters", bad);
    CHECK(len <= 255);
    LNS_DONE();
}

/* The machine name is also the NetBIOS or DNS host name of the computer (observation only: which one wins is
 * a configuration matter). */
TEST(hostname_a_relation_to_computer_name)
{
    char name[300], nb[300], dns[300]; DWORD n1 = sizeof nb, n2 = sizeof dns; int len, m_nb, m_dns;
    LNS_NEED(gethostname);
    len = own_name(name, sizeof name);
    CHECK(len > 0);
    CHECK(GetComputerNameExA(ComputerNameNetBIOS, nb, &n1));
    CHECK(GetComputerNameExA(ComputerNameDnsHostname, dns, &n2));
    m_nb = !_stricmp(name, nb);
    m_dns = !_stricmp(name, dns);
    CHECK(m_nb || m_dns);
    if (!m_nb) t_note("gethostname differs from the NetBIOS name");
    if (!m_dns) t_note("gethostname differs from the DNS host name");
    LNS_DONE();
}

/* ---- NULL buffer ---------------------------------------------------------------------------------- */

#define NULLBUF_CASE(tag, n) \
TEST(hostname_a_null_buffer_##tag) { \
    LNS_NEED(gethostname); \
    LNS_SETERR(0x1234); \
    EXPECT_EQ(U(gethostname)(NULL, (n)), SOCKET_ERROR); \
    EXPECT_EQ(LNS_ERR(), LNS_E_FAULT); \
    LNS_DONE(); \
}
NULLBUF_CASE(len_zero, 0)
NULLBUF_CASE(len_one, 1)
NULLBUF_CASE(len_256, 256)
NULLBUF_CASE(len_1024, 1024)

/* ---- wide form ------------------------------------------------------------------------------------ */

static int own_name_w(WCHAR *out, int cap)
{
    if (U(GetHostNameW)(out, cap) != 0) return -1;
    return lstrlenW(out);
}

#define WSHORT_CASE(tag, expr) \
TEST(hostname_w_short_##tag) { \
    WCHAR name[300], buf[300]; int len, want, r, i, dirty = 0; \
    LNS_NEED(GetHostNameW); \
    len = own_name_w(name, 300); \
    CHECK(len > 0); \
    want = (expr); \
    if (want < 0) { LNS_DONE(); t_skip("name too short for this case"); return; } \
    for (i = 0; i < 300; i++) buf[i] = 0x5a5a; \
    LNS_SETERR(0); \
    r = U(GetHostNameW)(buf, want); \
    EXPECT_EQ(r, SOCKET_ERROR); EXPECT_EQ(LNS_ERR(), LNS_E_FAULT); \
    for (i = 0; i < 300; i++) dirty += buf[i] != 0x5a5a; \
    CHECKF(dirty == 0, "%d code units touched", dirty); \
    LNS_DONE(); \
}
WSHORT_CASE(len_zero, 0)
WSHORT_CASE(len_one, 1)
WSHORT_CASE(len_two, len >= 2 ? 2 : -1)
WSHORT_CASE(len_name_minus_one, len >= 2 ? len - 1 : -1)
WSHORT_CASE(len_name, len)

/* The length counts UTF-16 code units, not bytes. */
TEST(hostname_w_exact_fit_counts_code_units)
{
    WCHAR name[300], buf[300]; int len, i;
    LNS_NEED(GetHostNameW);
    len = own_name_w(name, 300);
    CHECK(len > 0);
    for (i = 0; i < 300; i++) buf[i] = 0x5a5a;
    EXPECT_EQ(U(GetHostNameW)(buf, len + 1), 0);
    CHECK(!lstrcmpW(buf, name));
    CHECK(buf[len + 1] == 0x5a5a);
    LNS_DONE();
}

TEST(hostname_w_null_buffer_len_zero) { LNS_NEED(GetHostNameW); LNS_SETERR(0); EXPECT_EQ(U(GetHostNameW)(NULL, 0), SOCKET_ERROR); EXPECT_EQ(LNS_ERR(), LNS_E_FAULT); LNS_DONE(); }
TEST(hostname_w_null_buffer_len_256) { LNS_NEED(GetHostNameW); LNS_SETERR(0); EXPECT_EQ(U(GetHostNameW)(NULL, 256), SOCKET_ERROR); EXPECT_EQ(LNS_ERR(), LNS_E_FAULT); LNS_DONE(); }

/* The two forms describe the same name. */
TEST(hostname_aw_parity)
{
    char a[300]; WCHAR w[300]; char conv[600]; int la, lw, n;
    LNS_NEED(GetHostNameW);
    REQUIRE(U(gethostname));
    la = own_name(a, sizeof a);
    lw = own_name_w(w, 300);
    CHECK(la > 0 && lw > 0);
    EXPECT_EQ(la, lw);
    n = WideCharToMultiByte(CP_ACP, 0, w, -1, conv, sizeof conv, NULL, NULL);
    CHECK(n > 0);
    CHECK(!strcmp(a, conv));
    LNS_DONE();
}

TEST(hostname_aw_boundary_matches)
{
    char a[300]; WCHAR w[300]; int len, l;
    LNS_NEED(GetHostNameW);
    REQUIRE(U(gethostname));
    len = own_name(a, sizeof a);
    CHECK(len > 0);
    for (l = len - 1; l <= len + 1; l++) {
        int ra = U(gethostname)(a, l);
        int rw = U(GetHostNameW)(w, l);
        CHECKF(ra == rw, "length %d: ansi %d wide %d", l, ra, rw);
    }
    LNS_DONE();
}

/* ---- before WSAStartup ---------------------------------------------------------------------------- */

TEST(hostname_a_before_startup_not_initialised)
{
    char buf[64];
    REQUIRE(U(gethostname)); REQUIRE(U(WSACleanup)); REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    lns_force_down();
    LNS_SETERR(0);
    EXPECT_EQ(U(gethostname)(buf, sizeof buf), SOCKET_ERROR);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}

TEST(hostname_a_null_before_startup_is_not_initialised)
{
    REQUIRE(U(gethostname)); REQUIRE(U(WSACleanup)); REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    lns_force_down();
    LNS_SETERR(0);
    /* The initialisation check precedes the argument check. */
    EXPECT_EQ(U(gethostname)(NULL, 64), SOCKET_ERROR);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}

TEST(hostname_w_before_startup_not_initialised)
{
    WCHAR buf[64];
    REQUIRE(U(GetHostNameW)); REQUIRE(U(WSACleanup)); REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    lns_force_down();
    LNS_SETERR(0);
    EXPECT_EQ(U(GetHostNameW)(buf, 64), SOCKET_ERROR);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}

TEST(hostname_a_after_cleanup_not_initialised)
{
    char buf[64];
    LNS_NEED(gethostname);
    EXPECT_EQ(U(gethostname)(buf, sizeof buf), 0);
    LNS_DONE();
    lns_force_down();
    LNS_SETERR(0);
    EXPECT_EQ(U(gethostname)(buf, sizeof buf), SOCKET_ERROR);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}

/* Nested startups: the name is available until the last reference is dropped. */
TEST(hostname_a_needs_all_references_released)
{
    char buf[64];
    LNS_NEED(gethostname);
    CHECK(lns_up() == 0);
    lns_down();
    EXPECT_EQ(U(gethostname)(buf, sizeof buf), 0);
    lns_down();
    lns_force_down();
    LNS_SETERR(0);
    EXPECT_EQ(U(gethostname)(buf, sizeof buf), SOCKET_ERROR);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}

/* ---- wsock32 and relation to the lookups ----------------------------------------------------------- */

TEST(hostname_wsock32_forwards_to_ws2_32)
{
    FARPROC a, b;
    a = t_proc_in("ws2_32.dll", "gethostname");
    b = t_proc_in("wsock32.dll", "gethostname");
    REQUIRE(a); REQUIRE(b);
    CHECK(a == b);
}

TEST(hostname_wsock32_form_is_callable)
{
    int (WINAPI *p)(char *, int);
    char buf[300];
    LNS_NEED(gethostname);
    p = (int (WINAPI *)(char *, int))t_proc_in("wsock32.dll", "gethostname");
    REQUIRE(p);
    EXPECT_EQ(p(buf, sizeof buf), 0);
    CHECK(strlen(buf) > 0);
    EXPECT_EQ(p(buf, 0), SOCKET_ERROR);
    EXPECT_EQ(LNS_ERR(), LNS_E_FAULT);
    LNS_DONE();
}

TEST(hostname_wide_form_is_only_in_ws2_32)
{
    REQUIRE(t_proc_in("ws2_32.dll", "GetHostNameW"));
    CHECK(t_proc_in("wsock32.dll", "GetHostNameW") == NULL);
}

TEST(hostname_name_resolves_with_gethostbyname)
{
    char name[300]; struct hostent *h;
    LNS_NEED(gethostname);
    REQUIRE(U(gethostbyname));
    CHECK(own_name(name, sizeof name) > 0);
    h = U(gethostbyname)(name);
    CHECK(h != NULL);
    if (h) { CHECK(h->h_addr_list && h->h_addr_list[0]); EXPECT_EQ(h->h_addrtype, AF_INET); }
    LNS_DONE();
}

/* gethostbyname("") means "this machine": it reports the same canonical name as the name lookup of the machine name. */
TEST(hostname_empty_lookup_reports_machine_name)
{
    char name[300]; struct hostent *h;
    LNS_NEED(gethostname);
    REQUIRE(U(gethostbyname));
    CHECK(own_name(name, sizeof name) > 0);
    h = U(gethostbyname)("");
    CHECK(h != NULL);
    if (h && h->h_name) CHECKF(!_stricmp(h->h_name, name), "h_name %s", h->h_name);
    LNS_DONE();
}

TEST(hostname_success_leaves_valid_error_state)
{
    char buf[300];
    LNS_NEED(gethostname);
    LNS_SETERR(0);
    EXPECT_EQ(U(gethostname)(buf, sizeof buf), 0);
    /* Not asserted: whether a successful call resets the thread's error value. */
    t_note("error after success is %s", LNS_ERR() == 0 ? "zero" : "unchanged or set");
    LNS_DONE();
}

/* Threads: the name does not depend on the calling thread. */
static DWORD WINAPI name_thread(void *p)
{
    char *out = p;
    WSADATA d;
    out[0] = 0;
    if (U(WSAStartup)(0x202, &d)) return 1;
    if (U(gethostname)(out, 128)) { out[0] = 0; U(WSACleanup)(); return 2; }
    U(WSACleanup)();
    return 0;
}
TEST(hostname_a_other_thread_same_name)
{
    char mine[300], theirs[128]; HANDLE th; DWORD code = 99;
    LNS_NEED(gethostname);
    CHECK(own_name(mine, sizeof mine) > 0);
    th = CreateThread(NULL, 0, name_thread, theirs, 0, NULL);
    CHECK(th != NULL);
    if (th) {
        EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
        GetExitCodeThread(th, &code);
        CloseHandle(th);
        EXPECT_EQ(code, 0);
        CHECK(!strcmp(mine, theirs));
    }
    LNS_DONE();
}
