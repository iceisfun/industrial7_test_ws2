/* Text <-> address conversion with zone (scope) indexes and ports: WSAStringToAddress parsing of bracketed,
 * scoped, mapped and malformed IPv6 text under each address family; WSAAddressToString output and its buffer-size
 * protocol; getnameinfo numeric output for scoped, mapped and wildcard names; getaddrinfo numeric-host parsing
 * with zone indexes and its passive wildcard results.  Pure computation, no packets. */
#include "sm.h"

struct s2a { const char *in; int af, rc, err; const char *desc; unsigned scope; unsigned port; };
static const struct s2a S2A[] = {
    { "::1", 23, 0, 0, "v6:loop:scope0:len28", 0, 0 },
    { "::1", 2, -1, 10022, "", 0, 0 },
    { "::1", 0, -1, 10022, "", 0, 0 },
    { "[::1]", 23, 0, 0, "v6:loop:scope0:len28", 0, 0 },
    { "[::1]", 2, -1, 10022, "", 0, 0 },
    { "[::1]", 0, -1, 10022, "", 0, 0 },
    { "[::1]:80", 23, 0, 0, "v6:loop:scope0:len28", 0, 80 },
    { "[::1]:80", 2, -1, 10022, "", 0, 0 },
    { "[::1]:80", 0, -1, 10022, "", 0, 0 },
    { "::1%1", 23, 0, 0, "v6:loop:scopeloop:len28", 1, 0 },
    { "::1%1", 2, -1, 10022, "", 0, 0 },
    { "::1%1", 0, -1, 10022, "", 0, 0 },
    { "[::1%1]:80", 23, 0, 0, "v6:loop:scopeloop:len28", 1, 80 },
    { "[::1%1]:80", 2, -1, 10022, "", 0, 0 },
    { "[::1%1]:80", 0, -1, 10022, "", 0, 0 },
    { "fe80::1", 23, 0, 0, "v6:ll:scope0:len28", 0, 0 },
    { "fe80::1", 2, -1, 10022, "", 0, 0 },
    { "fe80::1", 0, -1, 10022, "", 0, 0 },
    { "fe80::1%1", 23, 0, 0, "v6:ll:scopeloop:len28", 1, 0 },
    { "fe80::1%1", 2, -1, 10022, "", 0, 0 },
    { "fe80::1%1", 0, -1, 10022, "", 0, 0 },
    { "fe80::1%0", 23, 0, 0, "v6:ll:scope0:len28", 0, 0 },
    { "fe80::1%0", 2, -1, 10022, "", 0, 0 },
    { "fe80::1%0", 0, -1, 10022, "", 0, 0 },
    { "fe80::1%4294967295", 23, 0, 0, "v6:ll:scopeother:len28", 4294967295, 0 },
    { "fe80::1%4294967295", 2, -1, 10022, "", 0, 0 },
    { "fe80::1%4294967295", 0, -1, 10022, "", 0, 0 },
    { "fe80::1%99999999999", 23, -1, 10022, "", 0, 0 },
    { "fe80::1%99999999999", 2, -1, 10022, "", 0, 0 },
    { "fe80::1%99999999999", 0, -1, 10022, "", 0, 0 },
    { "fe80::1%", 23, -1, 10022, "", 0, 0 },
    { "fe80::1%", 2, -1, 10022, "", 0, 0 },
    { "fe80::1%", 0, -1, 10022, "", 0, 0 },
    { "fe80::1%abc", 23, -1, 10022, "", 0, 0 },
    { "fe80::1%abc", 2, -1, 10022, "", 0, 0 },
    { "fe80::1%abc", 0, -1, 10022, "", 0, 0 },
    { "[fe80::1%1]", 23, 0, 0, "v6:ll:scopeloop:len28", 1, 0 },
    { "[fe80::1%1]", 2, -1, 10022, "", 0, 0 },
    { "[fe80::1%1]", 0, -1, 10022, "", 0, 0 },
    { "[fe80::1%1]:80", 23, 0, 0, "v6:ll:scopeloop:len28", 1, 80 },
    { "[fe80::1%1]:80", 2, -1, 10022, "", 0, 0 },
    { "[fe80::1%1]:80", 0, -1, 10022, "", 0, 0 },
    { "fe80::1%1:80", 23, -1, 10022, "", 0, 0 },
    { "fe80::1%1:80", 2, -1, 10022, "", 0, 0 },
    { "fe80::1%1:80", 0, -1, 10022, "", 0, 0 },
    { "::ffff:127.0.0.1", 23, 0, 0, "v6:map:loop:scope0:len28", 0, 0 },
    { "::ffff:127.0.0.1", 2, -1, 10022, "", 0, 0 },
    { "::ffff:127.0.0.1", 0, -1, 10022, "", 0, 0 },
    { "[::ffff:127.0.0.1]:81", 23, 0, 0, "v6:map:loop:scope0:len28", 0, 81 },
    { "[::ffff:127.0.0.1]:81", 2, -1, 10022, "", 0, 0 },
    { "[::ffff:127.0.0.1]:81", 0, -1, 10022, "", 0, 0 },
    { "::ffff:1.2.3.4%1", 23, 0, 0, "v6:map:other:scopeloop:len28", 1, 0 },
    { "::ffff:1.2.3.4%1", 2, -1, 10022, "", 0, 0 },
    { "::ffff:1.2.3.4%1", 0, -1, 10022, "", 0, 0 },
    { "127.0.0.1", 23, -1, 10022, "", 0, 0 },
    { "127.0.0.1", 2, 0, 0, "v4:loop:len16", 0, 0 },
    { "127.0.0.1", 0, -1, 10022, "", 0, 0 },
    { "127.0.0.1:80", 23, -1, 10022, "", 0, 0 },
    { "127.0.0.1:80", 2, 0, 0, "v4:loop:len16", 0, 80 },
    { "127.0.0.1:80", 0, -1, 10022, "", 0, 0 },
    { "127.0.0.1%1", 23, -1, 10022, "", 0, 0 },
    { "127.0.0.1%1", 2, -1, 10022, "", 0, 0 },
    { "127.0.0.1%1", 0, -1, 10022, "", 0, 0 },
    { "[127.0.0.1]:80", 23, -1, 10022, "", 0, 0 },
    { "[127.0.0.1]:80", 2, -1, 10022, "", 0, 0 },
    { "[127.0.0.1]:80", 0, -1, 10022, "", 0, 0 },
    { "::1%1%1", 23, -1, 10022, "", 0, 0 },
    { "::1%1%1", 2, -1, 10022, "", 0, 0 },
    { "::1%1%1", 0, -1, 10022, "", 0, 0 },
    { "[::1", 23, -1, 10022, "", 0, 0 },
    { "[::1", 2, -1, 10022, "", 0, 0 },
    { "[::1", 0, -1, 10022, "", 0, 0 },
    { "::1]", 23, -1, 10022, "", 0, 0 },
    { "::1]", 2, -1, 10022, "", 0, 0 },
    { "::1]", 0, -1, 10022, "", 0, 0 },
    { "[::1]80", 23, -1, 10022, "", 0, 0 },
    { "[::1]80", 2, -1, 10022, "", 0, 0 },
    { "[::1]80", 0, -1, 10022, "", 0, 0 },
    { "[::1]:", 23, 0, 0, "v6:loop:scope0:len28", 0, 0 },
    { "[::1]:", 2, -1, 10022, "", 0, 0 },
    { "[::1]:", 0, -1, 10022, "", 0, 0 },
    { "[::1]:65536", 23, -1, 10022, "", 0, 0 },
    { "[::1]:65536", 2, -1, 10022, "", 0, 0 },
    { "[::1]:65536", 0, -1, 10022, "", 0, 0 },
    { "[::1]:0", 23, 0, 0, "v6:loop:scope0:len28", 0, 0 },
    { "[::1]:0", 2, -1, 10022, "", 0, 0 },
    { "[::1]:0", 0, -1, 10022, "", 0, 0 },
    { "[::1]:99999", 23, -1, 10022, "", 0, 0 },
    { "[::1]:99999", 2, -1, 10022, "", 0, 0 },
    { "[::1]:99999", 0, -1, 10022, "", 0, 0 },
    { "fe80::1%eth0", 23, -1, 10022, "", 0, 0 },
    { "fe80::1%eth0", 2, -1, 10022, "", 0, 0 },
    { "fe80::1%eth0", 0, -1, 10022, "", 0, 0 },
    { "::", 23, 0, 0, "v6:any:scope0:len28", 0, 0 },
    { "::", 2, -1, 10022, "", 0, 0 },
    { "::", 0, -1, 10022, "", 0, 0 },
    { "[::]:0", 23, 0, 0, "v6:any:scope0:len28", 0, 0 },
    { "[::]:0", 2, -1, 10022, "", 0, 0 },
    { "[::]:0", 0, -1, 10022, "", 0, 0 },
    { "1::2::3", 23, -1, 10022, "", 0, 0 },
    { "1::2::3", 2, -1, 10022, "", 0, 0 },
    { "1::2::3", 0, -1, 10022, "", 0, 0 },
    { ":::", 23, -1, 10022, "", 0, 0 },
    { ":::", 2, -1, 10022, "", 0, 0 },
    { ":::", 0, -1, 10022, "", 0, 0 },
    { "::1 ", 23, -1, 10022, "", 0, 0 },
    { "::1 ", 2, -1, 10022, "", 0, 0 },
    { "::1 ", 0, -1, 10022, "", 0, 0 },
    { " ::1", 23, -1, 10022, "", 0, 0 },
    { " ::1", 2, -1, 10022, "", 0, 0 },
    { " ::1", 0, -1, 10022, "", 0, 0 },
    { "0:0:0:0:0:0:0:1", 23, 0, 0, "v6:loop:scope0:len28", 0, 0 },
    { "0:0:0:0:0:0:0:1", 2, -1, 10022, "", 0, 0 },
    { "0:0:0:0:0:0:0:1", 0, -1, 10022, "", 0, 0 },
    { "0:0:0:0:0:ffff:7f00:1", 23, 0, 0, "v6:map:loop:scope0:len28", 0, 0 },
    { "0:0:0:0:0:ffff:7f00:1", 2, -1, 10022, "", 0, 0 },
    { "0:0:0:0:0:ffff:7f00:1", 0, -1, 10022, "", 0, 0 },
    { "::127.0.0.1", 23, 0, 0, "v6:other:scope0:len28", 0, 0 },
    { "::127.0.0.1", 2, -1, 10022, "", 0, 0 },
    { "::127.0.0.1", 0, -1, 10022, "", 0, 0 },
    { "fe80::1%-1", 23, -1, 10022, "", 0, 0 },
    { "fe80::1%-1", 2, -1, 10022, "", 0, 0 },
    { "fe80::1%-1", 0, -1, 10022, "", 0, 0 },
    { "fe80::1%0x10", 23, -1, 10022, "", 0, 0 },
    { "fe80::1%0x10", 2, -1, 10022, "", 0, 0 },
    { "fe80::1%0x10", 0, -1, 10022, "", 0, 0 },
    { "fe80::1%010", 23, 0, 0, "v6:ll:scopeother:len28", 10, 0 },
    { "fe80::1%010", 2, -1, 10022, "", 0, 0 },
    { "fe80::1%010", 0, -1, 10022, "", 0, 0 },
};
#define NS2A ((int)(sizeof S2A / sizeof S2A[0]))

static void run_s2a(int af) {
    if (!s_up()) return;
    for (int i = 0; i < NS2A; i++) {
        struct sockaddr_in6 o; INT l = sizeof o; int rc, e = 0; char d[64];
        if (S2A[i].af != af) continue;
        memset(&o, 0xcc, sizeof o);
        rc = U(WSAStringToAddressA)((LPSTR)S2A[i].in, af, NULL, (struct sockaddr *)&o, &l);
        if (rc) e = s_err();
        CHECKF(rc == S2A[i].rc, "[%s] af=%d rc=%d want %d", S2A[i].in, af, rc, S2A[i].rc);
        if (S2A[i].rc) { CHECKF(e == S2A[i].err, "[%s] af=%d err=%d want %d", S2A[i].in, af, e, S2A[i].err); continue; }
        s_desc(&o, l, d, sizeof d);
        CHECKF(!strcmp(d, S2A[i].desc), "[%s] af=%d got %s want %s", S2A[i].in, af, d, S2A[i].desc);
        if (af == AF_INET6) {
            CHECKF(o.sin6_scope_id == S2A[i].scope, "[%s] scope %lu want %u", S2A[i].in, o.sin6_scope_id, S2A[i].scope);
            CHECKF(s_h16(o.sin6_port) == S2A[i].port, "[%s] port %u want %u", S2A[i].in, s_h16(o.sin6_port), S2A[i].port);
        } else {
            CHECKF(s_h16(((struct sockaddr_in *)&o)->sin_port) == S2A[i].port, "[%s] port want %u", S2A[i].in, S2A[i].port);
        }
    }
}
TEST(dsm_str2addr_af_inet6_table) { run_s2a(AF_INET6); }
TEST(dsm_str2addr_af_inet_table)  { run_s2a(AF_INET); }
TEST(dsm_str2addr_af_unspec_is_invalid) { run_s2a(AF_UNSPEC); }

/* a zone index is taken as plain decimal digits that fit 32 bits */
TEST(dsm_str2addr_zone_forms) {
    static const struct { const char *in; int ok; unsigned scope; } z[] = {
        { "fe80::1%1", 1, 1 }, { "fe80::1%0", 1, 0 }, { "fe80::1%010", 1, 10 }, { "fe80::1%4294967295", 1, 0xffffffffu },
        { "fe80::1%4294967296", 0, 0 }, { "fe80::1%", 0, 0 }, { "fe80::1%-1", 0, 0 }, { "fe80::1%0x10", 0, 0 }, { "fe80::1%abc", 0, 0 },
        { "::1%7", 1, 7 }, { "::ffff:1.2.3.4%9", 1, 9 }, { "::%3", 1, 3 },
    };
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof z / sizeof *z; i++) {
        struct sockaddr_in6 o; INT l = sizeof o; int rc;
        memset(&o, 0, sizeof o);
        rc = U(WSAStringToAddressA)((LPSTR)z[i].in, AF_INET6, NULL, (struct sockaddr *)&o, &l);
        CHECKF((rc == 0) == z[i].ok, "[%s] rc=%d", z[i].in, rc);
        if (rc == 0 && z[i].ok) CHECKF(o.sin6_scope_id == z[i].scope, "[%s] scope %lu", z[i].in, o.sin6_scope_id);
    }
}
TEST(dsm_str2addr_failure_error_is_einval_for_every_malformed_form) {
    static const char *const bad[] = { "[::1", "::1]", "[::1]80", "[::1]:65536", "[::1]:99999", "1::2::3", ":::", " ::1", "::1 ", "::1%1%1", "fe80::1%1:80", "fe80::1%eth0", "127.0.0.1", "" };
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        struct sockaddr_in6 o; INT l = sizeof o;
        int rc = U(WSAStringToAddressA)((LPSTR)bad[i], AF_INET6, NULL, (struct sockaddr *)&o, &l);
        CHECKF(rc != 0, "[%s] parsed", bad[i]);
        if (rc) CHECKF(s_err() == WSAEINVAL, "[%s] err %d", bad[i], s_err());
    }
}
TEST(dsm_str2addr_wide_matches_ansi_for_scoped_forms) {
    static const char *const in[] = { "fe80::1%1", "[fe80::1%5]:80", "::ffff:127.0.0.1", "[::1]:9" };
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof in / sizeof *in; i++) {
        struct sockaddr_in6 a, w; INT la = sizeof a, lw = sizeof w; WCHAR wb[64]; int k;
        for (k = 0; in[i][k]; k++) wb[k] = (WCHAR)in[i][k];
        wb[k] = 0;
        memset(&a, 0, sizeof a); memset(&w, 0, sizeof w);
        CHECK(U(WSAStringToAddressA)((LPSTR)in[i], AF_INET6, NULL, (struct sockaddr *)&a, &la) == 0);
        CHECK(U(WSAStringToAddressW)(wb, AF_INET6, NULL, (struct sockaddr *)&w, &lw) == 0);
        CHECK(la == lw && !memcmp(&a, &w, sizeof a));
    }
}

/* ---- WSAAddressToString ---- */
struct a2s { int ak; unsigned port, scope; DWORD len; const char *text; };
static const struct a2s A2S[] = {
    { AK_V6LOOP, 0, 0u, 4, "::1" },
    { AK_V6LOOP, 80, 0u, 9, "[::1]:80" },
    { AK_V6LOOP, 0, 1u, 6, "::1%1" },
    { AK_V6LOOP, 80, 1u, 11, "[::1%1]:80" },
    { AK_LL, 0, 0u, 8, "fe80::1" },
    { AK_LL, 0, 1u, 10, "fe80::1%1" },
    { AK_LL, 80, 1u, 15, "[fe80::1%1]:80" },
    { AK_LL, 0, 4294967295u, 19, "fe80::1%4294967295" },
    { AK_MAPLOOP, 0, 0u, 17, "::ffff:127.0.0.1" },
    { AK_MAPLOOP, 81, 3u, 24, "[::ffff:127.0.0.1%3]:81" },
    { AK_V6ANY, 0, 0u, 3, "::" },
    { AK_V6ANY, 0, 5u, 5, "::%5" },
    { AK_V4LOOP, 0, 0u, 10, "127.0.0.1" },
    { AK_V4LOOP, 80, 0u, 13, "127.0.0.1:80" },
};

static int fill(void *a, const struct a2s *r) {
    int len = s_mkaddr(a, r->ak, s_h16((unsigned short)r->port));
    if (len == SA6LEN) ((struct sockaddr_in6 *)a)->sin6_scope_id = r->scope;
    return len;
}
TEST(dsm_addr2str_table_text_and_length) {
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof A2S / sizeof *A2S; i++) {
        char a[32], out[128]; DWORD ol = sizeof out; int len = fill(a, &A2S[i]);
        memset(out, 0, sizeof out);
        CHECKF(U(WSAAddressToStringA)((struct sockaddr *)a, len, NULL, out, &ol) == 0, "row %u failed", i);
        CHECKF(!strcmp(out, A2S[i].text), "row %u got %s want %s", i, out, A2S[i].text);
        CHECKF(ol == A2S[i].len, "row %u length %lu want %lu", i, ol, A2S[i].len);
        CHECKF(ol == strlen(out) + 1, "row %u length counts the terminator", i);
    }
}
TEST(dsm_addr2str_one_short_buffer_reports_needed_size) {
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof A2S / sizeof *A2S; i++) {
        char a[32], out[128]; DWORD ol = A2S[i].len - 1; int len = fill(a, &A2S[i]);
        int rc = U(WSAAddressToStringA)((struct sockaddr *)a, len, NULL, out, &ol);
        CHECKF(rc != 0 && s_err() == WSAEFAULT, "row %u one-short rc=%d err=%d", i, rc, s_err());
        CHECKF(ol == A2S[i].len, "row %u needed %lu want %lu", i, ol, A2S[i].len);
    }
}
TEST(dsm_addr2str_exact_buffer_succeeds) {
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof A2S / sizeof *A2S; i++) {
        char a[32], out[128]; DWORD ol = A2S[i].len; int len = fill(a, &A2S[i]);
        CHECKF(U(WSAAddressToStringA)((struct sockaddr *)a, len, NULL, out, &ol) == 0, "row %u exact", i);
        CHECKF(ol == A2S[i].len, "row %u", i);
    }
}
TEST(dsm_addr2str_round_trips_through_str2addr) {
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof A2S / sizeof *A2S; i++) {
        char a[32], out[128]; DWORD ol = sizeof out; int len = fill(a, &A2S[i]);
        struct sockaddr_in6 b; INT bl = sizeof b; int af = len == SA6LEN ? AF_INET6 : AF_INET;
        memset(&b, 0, sizeof b);
        CHECK(U(WSAAddressToStringA)((struct sockaddr *)a, len, NULL, out, &ol) == 0);
        CHECKF(U(WSAStringToAddressA)(out, af, NULL, (struct sockaddr *)&b, &bl) == 0, "row %u [%s]", i, out);
        CHECKF(bl == len, "row %u length %d want %d", i, bl, len);
        CHECKF(!memcmp(&b, a, len), "row %u bytes differ", i);
    }
}
TEST(dsm_addr2str_address_length_rules) {
    if (!s_up()) return;
    for (int l = 0; l <= 30; l += 2) {
        char a[32], out[128]; DWORD ol = sizeof out; int rc;
        s_mkaddr(a, AK_V6LOOP, 0);
        rc = U(WSAAddressToStringA)((struct sockaddr *)a, l, NULL, out, &ol);
        if (l >= 28) CHECKF(rc == 0, "len %d", l);
        else { CHECKF(rc != 0, "len %d", l); CHECKF(s_err() == (l == 0 ? WSAEINVAL : WSAEFAULT), "len %d err %d", l, s_err()); }
    }
}

/* ---- getnameinfo ---- */
struct gni { int ak; unsigned scope; int flags; const char *host, *serv; };
static const struct gni GNI[] = {
    { AK_V6LOOP, 0u, 0xa, "::1", "8080" },
    { AK_V6LOOP, 1u, 0xa, "::1%1", "8080" },
    { AK_LL, 0u, 0xa, "fe80::1", "8080" },
    { AK_LL, 1u, 0xa, "fe80::1%1", "8080" },
    { AK_LL, 4294967295u, 0xa, "fe80::1%4294967295", "8080" },
    { AK_MAPLOOP, 0u, 0xa, "::ffff:127.0.0.1", "8080" },
    { AK_MAPLOOP, 5u, 0xa, "::ffff:127.0.0.1%5", "8080" },
    { AK_V6ANY, 0u, 0xa, "::", "8080" },
    { AK_V6ANY, 7u, 0xa, "::%7", "8080" },
    { AK_V4LOOP, 0u, 0xa, "127.0.0.1", "8080" },
};

TEST(dsm_getnameinfo_numeric_scope_table) {
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof GNI / sizeof *GNI; i++) {
        char a[32], h[80], sv[16]; int len = s_mkaddr(a, GNI[i].ak, s_h16(8080)), rc;
        if (len == SA6LEN) ((struct sockaddr_in6 *)a)->sin6_scope_id = GNI[i].scope;
        memset(h, 0, sizeof h); memset(sv, 0, sizeof sv);
        rc = U(getnameinfo)((struct sockaddr *)a, len, h, sizeof h, sv, sizeof sv, GNI[i].flags);
        CHECKF(rc == 0, "row %u rc=%d", i, rc);
        CHECKF(!strcmp(h, GNI[i].host), "row %u host %s want %s", i, h, GNI[i].host);
        CHECKF(!strcmp(sv, GNI[i].serv), "row %u serv %s want %s", i, sv, GNI[i].serv);
    }
}
TEST(dsm_getnameinfo_host_buffer_size_protocol) {
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof GNI / sizeof *GNI; i++) {
        char a[32], h[80]; int len = s_mkaddr(a, GNI[i].ak, s_h16(8080)), rc; size_t n = strlen(GNI[i].host);
        if (len == SA6LEN) ((struct sockaddr_in6 *)a)->sin6_scope_id = GNI[i].scope;
        rc = U(getnameinfo)((struct sockaddr *)a, len, h, (DWORD)n, NULL, 0, GNI[i].flags);
        CHECKF(rc == 122 && s_err() == 122, "row %u one short rc=%d err=%d", i, rc, s_err());
        rc = U(getnameinfo)((struct sockaddr *)a, len, h, (DWORD)n + 1, NULL, 0, GNI[i].flags);
        CHECKF(rc == 0, "row %u exact rc=%d", i, rc);
    }
}
TEST(dsm_getnameinfo_output_parses_back_to_the_input_name) {
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof GNI / sizeof *GNI; i++) {
        char a[32], h[80]; int len = s_mkaddr(a, GNI[i].ak, 0); struct sockaddr_in6 b; INT bl = sizeof b;
        if (len == SA6LEN) ((struct sockaddr_in6 *)a)->sin6_scope_id = GNI[i].scope;
        CHECK(U(getnameinfo)((struct sockaddr *)a, len, h, sizeof h, NULL, 0, NI_NUMERICHOST) == 0);
        memset(&b, 0, sizeof b);
        CHECK(U(WSAStringToAddressA)(h, len == SA6LEN ? AF_INET6 : AF_INET, NULL, (struct sockaddr *)&b, &bl) == 0);
        CHECKF(bl == len && !memcmp(&b, a, len), "row %u", i);
    }
}

/* ---- getaddrinfo ---- */
struct gai { const char *host; int fam, rc, count; const char *desc; unsigned scope; };
static const struct gai GAI[] = {
    { "::1", 0, 0, 1, "v6:loop:scope0:len28", 0u },
    { "::1", 23, 0, 1, "v6:loop:scope0:len28", 0u },
    { "::1", 2, 11001, 0, "", 0u },
    { "::1%1", 0, 0, 1, "v6:loop:scopeloop:len28", 1u },
    { "::1%1", 23, 0, 1, "v6:loop:scopeloop:len28", 1u },
    { "::1%1", 2, 11001, 0, "", 0u },
    { "fe80::1", 0, 0, 1, "v6:ll:scope0:len28", 0u },
    { "fe80::1", 23, 0, 1, "v6:ll:scope0:len28", 0u },
    { "fe80::1", 2, 11001, 0, "", 0u },
    { "fe80::1%1", 0, 0, 1, "v6:ll:scopeloop:len28", 1u },
    { "fe80::1%1", 23, 0, 1, "v6:ll:scopeloop:len28", 1u },
    { "fe80::1%1", 2, 11001, 0, "", 0u },
    { "fe80::1%99999", 0, 0, 1, "v6:ll:scopeother:len28", 99999u },
    { "fe80::1%99999", 23, 0, 1, "v6:ll:scopeother:len28", 99999u },
    { "fe80::1%99999", 2, 11001, 0, "", 0u },
    { "fe80::1%abc", 0, 11001, 0, "", 0u },
    { "fe80::1%abc", 23, 11001, 0, "", 0u },
    { "fe80::1%abc", 2, 11001, 0, "", 0u },
    { "::ffff:127.0.0.1", 0, 0, 1, "v6:map:loop:scope0:len28", 0u },
    { "::ffff:127.0.0.1", 23, 0, 1, "v6:map:loop:scope0:len28", 0u },
    { "::ffff:127.0.0.1", 2, 11001, 0, "", 0u },
    { "127.0.0.1", 0, 0, 1, "v4:loop:len16", 0u },
    { "127.0.0.1", 23, 11001, 0, "", 0u },
    { "127.0.0.1", 2, 0, 1, "v4:loop:len16", 0u },
    { "127.0.0.1%1", 0, 11001, 0, "", 0u },
    { "127.0.0.1%1", 23, 11001, 0, "", 0u },
    { "127.0.0.1%1", 2, 11001, 0, "", 0u },
    { "[::1]", 0, 0, 1, "v6:loop:scope0:len28", 0u },
    { "[::1]", 23, 0, 1, "v6:loop:scope0:len28", 0u },
    { "[::1]", 2, 11001, 0, "", 0u },
    { "::1%", 0, 11001, 0, "", 0u },
    { "::1%", 23, 11001, 0, "", 0u },
    { "::1%", 2, 11001, 0, "", 0u },
    { "fe80::1%4294967295", 0, 0, 1, "v6:ll:scopeother:len28", 4294967295u },
    { "fe80::1%4294967295", 23, 0, 1, "v6:ll:scopeother:len28", 4294967295u },
    { "fe80::1%4294967295", 2, 11001, 0, "", 0u },
    { "fe80::1%4294967296", 0, 11001, 0, "", 0u },
    { "fe80::1%4294967296", 23, 11001, 0, "", 0u },
    { "fe80::1%4294967296", 2, 11001, 0, "", 0u },
};

TEST(dsm_getaddrinfo_numeric_host_zone_table) {
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof GAI / sizeof *GAI; i++) {
        ADDRINFOA h, *res = NULL; int rc, n = 0; char d[64] = "";
        memset(&h, 0, sizeof h); h.ai_family = GAI[i].fam; h.ai_socktype = SOCK_STREAM; h.ai_flags = AI_NUMERICHOST;
        rc = U(getaddrinfo)(GAI[i].host, "80", &h, &res);
        CHECKF(rc == GAI[i].rc, "[%s] fam=%d rc=%d want %d", GAI[i].host, GAI[i].fam, rc, GAI[i].rc);
        if (rc == 0) {
            ADDRINFOA *p;
            for (p = res; p; p = p->ai_next) n++;
            s_desc(res->ai_addr, (int)res->ai_addrlen, d, sizeof d);
            CHECKF(n == GAI[i].count, "[%s] count %d", GAI[i].host, n);
            CHECKF(!strcmp(d, GAI[i].desc), "[%s] fam=%d got %s want %s", GAI[i].host, GAI[i].fam, d, GAI[i].desc);
            if (res->ai_family == AF_INET6) CHECKF(((struct sockaddr_in6 *)res->ai_addr)->sin6_scope_id == GAI[i].scope, "[%s] scope", GAI[i].host);
            CHECKF(s_h16(((struct sockaddr_in *)res->ai_addr)->sin_port) == 80, "[%s] port", GAI[i].host);
            U(freeaddrinfo)(res);
        }
    }
}
TEST(dsm_getaddrinfo_passive_wildcards) {
    static const struct { int fam; const char *first; int count; const char *second; } p[] = {
        { 0, "v6:any:scope0:len28", 2, "v4:any:len16" },
        { 23, "v6:any:scope0:len28", 1, "" },
        { 2, "v4:any:len16", 1, "" },
    };
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof p / sizeof *p; i++) {
        ADDRINFOA h, *res = NULL; int n = 0; char d[64];
        memset(&h, 0, sizeof h); h.ai_family = p[i].fam; h.ai_socktype = SOCK_STREAM; h.ai_flags = AI_PASSIVE;
        CHECK(U(getaddrinfo)(NULL, "80", &h, &res) == 0);
        if (!res) continue;
        for (ADDRINFOA *q = res; q; q = q->ai_next) n++;
        CHECKF(n == p[i].count, "fam=%d count %d", p[i].fam, n);
        s_desc(res->ai_addr, (int)res->ai_addrlen, d, sizeof d);
        CHECKF(!strcmp(d, p[i].first), "fam=%d first %s want %s", p[i].fam, d, p[i].first);
        if (n > 1) { s_desc(res->ai_next->ai_addr, (int)res->ai_next->ai_addrlen, d, sizeof d); CHECKF(!strcmp(d, p[i].second), "fam=%d second %s", p[i].fam, d); }
        U(freeaddrinfo)(res);
    }
}
TEST(dsm_getaddrinfo_v4mapped_flag_with_numeric_v4_host) {
    ADDRINFOA h, *res = NULL; int rc;
    if (!s_up()) return;
    memset(&h, 0, sizeof h); h.ai_family = AF_INET6; h.ai_socktype = SOCK_STREAM; h.ai_flags = AI_V4MAPPED | AI_NUMERICHOST;
    rc = U(getaddrinfo)("127.0.0.1", "80", &h, &res);
    CHECK(rc == WSAHOST_NOT_FOUND);
    if (res) U(freeaddrinfo)(res);
}
