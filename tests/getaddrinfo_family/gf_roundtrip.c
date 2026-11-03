/* Round trips between the resolver and the address-to-text converter, and a few additional argument edges.
 * Measures: a numeric literal resolved and then formatted comes back as the same text; the wildcard answers
 * format as the wildcard; service ports survive both directions; flags that name no work leave buffers alone. */
#include "gf.h"

#define GR_BEGIN() \
    do { if (!U(getnameinfo) || !U(getaddrinfo) || !U(freeaddrinfo) || !U(WSAGetLastError) || !U(WSASetLastError)) { t_skip("missing export"); return; } \
         if (gf_up()) { t_skip("WSAStartup failed"); return; } } while (0)

static void rt(const char *lit, int family, const char *want_host)
{
    ADDRINFOA hint, *res = NULL;
    char host[128], serv[32];
    memset(&hint, 0, sizeof hint);
    hint.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    hint.ai_family = family;
    hint.ai_socktype = SOCK_STREAM;
    EXPECT_EQ(U(getaddrinfo)(lit, "4321", &hint, &res), 0);
    if (!res) return;
    memset(host, 0, sizeof host); memset(serv, 0, sizeof serv);
    EXPECT_EQ(U(getnameinfo)(res->ai_addr, (int)res->ai_addrlen, host, sizeof host, serv, sizeof serv,
                             NI_NUMERICHOST | NI_NUMERICSERV), 0);
    CHECK(!strcmp(host, want_host));
    CHECK(!strcmp(serv, "4321"));
    U(freeaddrinfo)(res);
}
TEST(gfr_roundtrip_v4)          { GR_BEGIN(); rt("192.0.2.9", AF_INET, "192.0.2.9"); gf_down(); }
TEST(gfr_roundtrip_v4_loop)     { GR_BEGIN(); rt("127.0.0.1", AF_UNSPEC, "127.0.0.1"); gf_down(); }
TEST(gfr_roundtrip_v6_loop)     { GR_BEGIN(); rt("::1", AF_INET6, "::1"); gf_down(); }
TEST(gfr_roundtrip_v6_doc)      { GR_BEGIN(); rt("2001:db8::5", AF_UNSPEC, "2001:db8::5"); gf_down(); }
TEST(gfr_roundtrip_v6_compress) { GR_BEGIN(); rt("2001:0db8:0000:0000:0000:0000:0000:0005", AF_INET6, "2001:db8::5"); gf_down(); }
TEST(gfr_roundtrip_v4_hex)      { GR_BEGIN(); rt("0x7f000001", AF_INET, "127.0.0.1"); gf_down(); }

static void passive(int family, const char *want)
{
    ADDRINFOA hint, *res = NULL;
    char host[128];
    memset(&hint, 0, sizeof hint);
    hint.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    hint.ai_family = family;
    hint.ai_socktype = SOCK_DGRAM;
    EXPECT_EQ(U(getaddrinfo)(NULL, "9", &hint, &res), 0);
    if (!res) return;
    CHECK(res->ai_socktype == SOCK_DGRAM);
    CHECK(res->ai_family == family);
    memset(host, 0, sizeof host);
    EXPECT_EQ(U(getnameinfo)(res->ai_addr, (int)res->ai_addrlen, host, sizeof host, NULL, 0, NI_NUMERICHOST), 0);
    CHECK(!strcmp(host, want));
    U(freeaddrinfo)(res);
}
TEST(gfr_passive_v4_formats_as_wildcard) { GR_BEGIN(); passive(AF_INET, "0.0.0.0"); gf_down(); }
TEST(gfr_passive_v6_formats_as_wildcard) { GR_BEGIN(); passive(AF_INET6, "::"); gf_down(); }

static void loopback_nonpassive(int family, const char *want)
{
    ADDRINFOA hint, *res = NULL;
    char host[128];
    memset(&hint, 0, sizeof hint);
    hint.ai_flags = AI_NUMERICSERV;
    hint.ai_family = family;
    hint.ai_socktype = SOCK_STREAM;
    EXPECT_EQ(U(getaddrinfo)(NULL, "9", &hint, &res), 0);
    if (!res) return;
    memset(host, 0, sizeof host);
    EXPECT_EQ(U(getnameinfo)(res->ai_addr, (int)res->ai_addrlen, host, sizeof host, NULL, 0, NI_NUMERICHOST), 0);
    CHECK(!strcmp(host, want));
    U(freeaddrinfo)(res);
}
TEST(gfr_nonpassive_v4_formats_as_loopback) { GR_BEGIN(); loopback_nonpassive(AF_INET, "127.0.0.1"); gf_down(); }
TEST(gfr_nonpassive_v6_formats_as_loopback) { GR_BEGIN(); loopback_nonpassive(AF_INET6, "::1"); gf_down(); }

/* a socket created from an answer accepts the answer's own triple, then is closed */
TEST(gfr_answer_triple_creates_socket)
{
    ADDRINFOA hint, *res = NULL;
    SOCKET s;
    GR_BEGIN();
    if (!U(socket) || !U(closesocket)) { t_skip("missing export"); gf_down(); return; }
    memset(&hint, 0, sizeof hint);
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_NUMERICHOST;
    EXPECT_EQ(U(getaddrinfo)("127.0.0.1", "80", &hint, &res), 0);
    if (res) {
        s = U(socket)(res->ai_family, res->ai_socktype, res->ai_protocol);
        CHECK(s != INVALID_SOCKET);
        if (s != INVALID_SOCKET) U(closesocket)(s);
        U(freeaddrinfo)(res);
    }
    gf_down();
}
