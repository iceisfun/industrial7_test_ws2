/* gethostname / GetHostNameW buffer protocols (NULL buffer, too-short buffer, exact fit) and the layout of the
 * hostent block returned by gethostbyname. Lookups are limited to "localhost" and the machine's own name. */
#include "lift03.h"

#define NEED_H() do { REQUIRE(U(gethostname)); REQUIRE(U(gethostbyname)); if (l3_up()) { t_skip("WSAStartup failed"); return; } } while (0)
#define DONE_H() l3_down()

TEST(host_gethostname_null_buffer_is_efault)
{
    NEED_H();
    SETWSERR(0x1234);
    EXPECT_EQ(U(gethostname)(NULL, 256), SOCKET_ERROR);
    EXPECT_EQ(WSERR(), WSAEFAULT);
    DONE_H();
}

TEST(host_gethostname_full_buffer_succeeds_and_resolves)
{
    NEED_H();
    char name[256];
    EXPECT_EQ(U(gethostname)(name, sizeof name), 0);
    CHECK(strlen(name) > 0);
    CHECK(U(gethostbyname)(name) != NULL);
    DONE_H();
}

/* A length equal to strlen() leaves no room for the terminator: fails with WSAEFAULT, buffer untouched. */
TEST(host_gethostname_too_short_is_efault_and_untouched)
{
    NEED_H();
    char name[256];
    EXPECT_EQ(U(gethostname)(name, sizeof name), 0);
    int len = (int)strlen(name);
    strcpy(name, "xxxxxxxx");
    SETWSERR(0x1234);
    EXPECT_EQ(U(gethostname)(name, len), SOCKET_ERROR);
    EXPECT_STR(name, "xxxxxxxx");
    EXPECT_EQ(WSERR(), WSAEFAULT);
    DONE_H();
}

TEST(host_gethostname_exact_fit_succeeds)
{
    NEED_H();
    char name[256];
    EXPECT_EQ(U(gethostname)(name, sizeof name), 0);
    int len = (int)strlen(name) + 1;
    memset(name, 'x', sizeof name);
    EXPECT_EQ(U(gethostname)(name, len), 0);
    CHECK(strlen(name) == (size_t)len - 1);
    CHECK(U(gethostbyname)(name) != NULL);
    DONE_H();
}

TEST(host_gethostnamew_null_buffer_is_efault)
{
    REQUIRE(U(GetHostNameW));
    if (l3_up()) { t_skip("WSAStartup failed"); return; }
    SETWSERR(0x1234);
    EXPECT_EQ(U(GetHostNameW)(NULL, 256), SOCKET_ERROR);
    EXPECT_EQ(WSERR(), WSAEFAULT);
    DONE_H();
}

TEST(host_gethostnamew_too_short_is_efault_and_untouched)
{
    REQUIRE(U(GetHostNameW));
    if (l3_up()) { t_skip("WSAStartup failed"); return; }
    WCHAR name[256];
    EXPECT_EQ(U(GetHostNameW)(name, (int)ARRSZ(name)), 0);
    int len = (int)lstrlenW(name);
    CHECK(len > 0);
    lstrcpyW(name, L"xxxxxxxx");
    SETWSERR(0x1234);
    EXPECT_EQ(U(GetHostNameW)(name, len), SOCKET_ERROR);
    CHECK(!lstrcmpW(name, L"xxxxxxxx"));
    EXPECT_EQ(WSERR(), WSAEFAULT);
    DONE_H();
}

TEST(host_gethostnamew_exact_fit_succeeds)
{
    REQUIRE(U(GetHostNameW));
    if (l3_up()) { t_skip("WSAStartup failed"); return; }
    WCHAR name[256];
    EXPECT_EQ(U(GetHostNameW)(name, (int)ARRSZ(name)), 0);
    int len = (int)lstrlenW(name) + 1;
    EXPECT_EQ(U(GetHostNameW)(name, len), 0);
    CHECK(lstrlenW(name) == len - 1);
    DONE_H();
}

/* gethostbyname("") means "this machine" and must succeed. */
TEST(host_gethostbyname_empty_name_succeeds)
{
    NEED_H();
    CHECK(U(gethostbyname)("") != NULL);
    DONE_H();
}

/* The hostent, its alias array, its address array and the first address live in one block in this order:
 * aliases right after the struct, address list after the (NULL-terminated) aliases, first address after the
 * (NULL-terminated) address list. */
static void check_block_layout(const char *host)
{
    struct hostent *h = U(gethostbyname)(host);
    CHECKF(h != NULL, "lookup failed");
    if (!h) return;
    char *expect = (char *)(h + 1);
    CHECK((char *)h->h_aliases == expect);
    int n = 1;
    for (char **p = h->h_aliases; *p; p++) n++;
    expect += sizeof(char *) * n;
    CHECK((char *)h->h_addr_list == expect);
    n = 1;
    for (char **p = h->h_addr_list; *p; p++) n++;
    expect += sizeof(char *) * n;
    CHECK(h->h_addr_list[0] == expect);
}

TEST(host_hostent_block_layout_localhost) { NEED_H(); check_block_layout("localhost"); DONE_H(); }
TEST(host_hostent_block_layout_own_name)
{
    NEED_H();
    char name[256];
    EXPECT_EQ(U(gethostname)(name, sizeof name), 0);
    check_block_layout(name);
    DONE_H();
}

/* localhost maps to 127.0.0.1 as the first IPv4 entry. */
TEST(host_gethostbyname_localhost_is_loopback)
{
    NEED_H();
    struct hostent *h = U(gethostbyname)("localhost");
    CHECK(h != NULL);
    if (!h) { DONE_H(); return; }
    EXPECT_EQ(h->h_addrtype, AF_INET);
    EXPECT_EQ(h->h_length, 4);
    CHECK(h->h_addr_list && h->h_addr_list[0]);
    if (h->h_length == 4 && h->h_addr_list && h->h_addr_list[0]) {
        static const unsigned char lo[4] = {127, 0, 0, 1};
        CHECK(!memcmp(h->h_addr_list[0], lo, 4));
    }
    DONE_H();
}

/* The machine's own name resolves with at least one IPv4 address even with only the loopback configured. */
TEST(host_gethostbyname_own_name_has_address)
{
    NEED_H();
    char name[256];
    EXPECT_EQ(U(gethostname)(name, sizeof name), 0);
    struct hostent *h = U(gethostbyname)(name);
    CHECK(h != NULL);
    if (h) {
        EXPECT_EQ(h->h_addrtype, AF_INET);
        CHECK(h->h_addr_list && h->h_addr_list[0]);
    }
    DONE_H();
}
