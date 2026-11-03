/* x_error_mapping / name-service failures: the legacy gethostby*, getservby*, getprotoby* family (error in the
 * Winsock error slot, result NULL), getaddrinfo / GetAddrInfoW / getnameinfo (error returned directly and also left
 * in the slot) and the textual address converters. Only names answerable without a network (numeric forms, the
 * local host name, the services and protocols files) are used. */
#include "xe.h"

/* A row runs one call, records the primary result (call_ret: error code for the getaddrinfo family, 0/1 failure
 * flag for the legacy ones) and the Winsock error observed right after the call. */
static long long g_ret; static int g_wsa_after, g_gle_after;
#define N_CASE(n, WRET, WWSA) \
    static void nf_##n(void); \
    TEST(xename_##n) { XE_UP(); g_ret = -77; WSASetLastError(XE_BAD); nf_##n(); g_wsa_after = WSAGetLastError(); \
        if (g_ret == -77) { t_skip("scenario not available"); return; } \
        if ((WRET) == XE_UNK) { t_note("ROW name %s ret=%lld wsa=%d", #n, g_ret, g_wsa_after); return; } \
        t_check(g_ret == (WRET), "x_error_mapping", 0, #n, "ret got %lld want %lld", g_ret, (long long)(WRET)); \
        if ((WWSA) != XE_NA_) t_check(g_wsa_after == (WWSA), "x_error_mapping", 0, #n, "wsa got %d want %d", g_wsa_after, (int)(WWSA)); } \
    static void nf_##n(void)
#define XE_NA_ (-3)
#define HENT_FAIL(p) (g_ret = ((p) == NULL) ? 0 : 1)

/* ---- legacy host / service / protocol lookups ---- */
N_CASE(gethostbyname_empty, 1, 0) { HENT_FAIL(gethostbyname("")); }
N_CASE(gethostbyname_localhost, 1, 0) { HENT_FAIL(gethostbyname("localhost")); }
N_CASE(gethostbyname_numeric, 1, 0) { HENT_FAIL(gethostbyname("127.0.0.1")); }
N_CASE(gethostbyname_numeric_out_of_range, 0, 11001) { HENT_FAIL(gethostbyname("127.0.0.256")); }
N_CASE(gethostbyname_space_in_name, 0, 11001) { HENT_FAIL(gethostbyname("a b")); }
N_CASE(gethostbyname_too_long_label, 0, 11001) {
    char n[300]; memset(n, 'a', sizeof n); n[299] = 0; HENT_FAIL(gethostbyname(n)); }
N_CASE(gethostbyaddr_loopback, 1, 0) { unsigned a = 0x0100007f; HENT_FAIL(gethostbyaddr((char *)&a, 4, AF_INET)); }
N_CASE(gethostbyaddr_len3, 1, 0) { unsigned a = 0x0100007f; HENT_FAIL(gethostbyaddr((char *)&a, 3, AF_INET)); }
N_CASE(gethostbyaddr_len0, 1, 0) { unsigned a = 0x0100007f; HENT_FAIL(gethostbyaddr((char *)&a, 0, AF_INET)); }
N_CASE(gethostbyaddr_bad_type, 1, 0) { unsigned a = 0x0100007f; HENT_FAIL(gethostbyaddr((char *)&a, 4, 0x7ff0)); }
N_CASE(gethostbyaddr_inet6_len4, 0, 10022) { unsigned a = 0x0100007f; HENT_FAIL(gethostbyaddr((char *)&a, 4, AF_INET6)); }
N_CASE(gethostname_small_buffer, 0, 10014) { char b[1]; g_ret = (gethostname(b, 1) == SOCKET_ERROR) ? 0 : 1; }
N_CASE(gethostname_zero_buffer, 0, 10014) { char b[1]; g_ret = (gethostname(b, 0) == SOCKET_ERROR) ? 0 : 1; }
N_CASE(gethostname_normal, 1, 0) { char b[256]; g_ret = (gethostname(b, sizeof b) == SOCKET_ERROR) ? 0 : 1; }
N_CASE(getservbyname_http_tcp, 1, 0) { HENT_FAIL(getservbyname("http", "tcp")); }
N_CASE(getservbyname_http_any_proto, 1, 0) { HENT_FAIL(getservbyname("http", NULL)); }
N_CASE(getservbyname_unknown, 0, 11004) { HENT_FAIL(getservbyname("nosuchservice", "tcp")); }
N_CASE(getservbyname_unknown_proto, 0, 11004) { HENT_FAIL(getservbyname("http", "nosuchproto")); }
N_CASE(getservbyname_empty, 0, 11004) { HENT_FAIL(getservbyname("", "tcp")); }
N_CASE(getservbyport_80_tcp, 1, 0) { HENT_FAIL(getservbyport(XE_BE16(80), "tcp")); }
N_CASE(getservbyport_unknown, 0, 11004) { HENT_FAIL(getservbyport(XE_BE16(1), "nosuchproto")); }
N_CASE(getservbyport_unassigned, 0, 11004) { HENT_FAIL(getservbyport(XE_BE16(54321), "tcp")); }
N_CASE(getprotobyname_tcp, 1, 0) { HENT_FAIL(getprotobyname("tcp")); }
N_CASE(getprotobyname_unknown, 0, 11004) { HENT_FAIL(getprotobyname("nosuchproto")); }
N_CASE(getprotobyname_empty, 0, 11004) { HENT_FAIL(getprotobyname("")); }
N_CASE(getprotobynumber_6, 1, 0) { HENT_FAIL(getprotobynumber(6)); }
N_CASE(getprotobynumber_unknown, 0, 11004) { HENT_FAIL(getprotobynumber(250)); }
N_CASE(getprotobynumber_negative, 0, 11004) { HENT_FAIL(getprotobynumber(-1)); }

/* ---- getaddrinfo family ---- */
static int gai(const char *n, const char *s, int flags, int fam, int type, int proto) {
    ADDRINFOA h, *res = NULL; int r;
    memset(&h, 0, sizeof h); h.ai_flags = flags; h.ai_family = fam; h.ai_socktype = type; h.ai_protocol = proto;
    r = getaddrinfo(n, s, &h, &res); g_gle_after = (int)GetLastError();
    if (res) freeaddrinfo(res);
    return r;
}
#define GAI(n, WRET, WWSA, nm, sv, fl, fa, ty, pr) N_CASE(n, WRET, WWSA) { g_ret = gai(nm, sv, fl, fa, ty, pr); }
GAI(gai_null_null, 11001, 11001, NULL, NULL, 0, 0, 0, 0)
GAI(gai_passive_null_null, 11001, 11001, NULL, NULL, AI_PASSIVE, 0, 0, 0)
GAI(gai_null_name_numeric_service, 0, 0, NULL, "80", 0, AF_INET, SOCK_STREAM, 0)
GAI(gai_bad_family, 10047, 10047, "127.0.0.1", "80", 0, 0x7ff0, SOCK_STREAM, 0)
GAI(gai_bad_socktype, 10044, 10044, "127.0.0.1", "80", 0, AF_INET, 99, 0)
GAI(gai_bad_flags, 0, 0, "127.0.0.1", "80", 0x40000000, AF_INET, SOCK_STREAM, 0)
GAI(gai_unknown_service, 10109, 10109, "127.0.0.1", "nosuchservice", 0, AF_INET, SOCK_STREAM, 0)
GAI(gai_service_out_of_range, 0, 0, "127.0.0.1", "99999999", 0, AF_INET, SOCK_STREAM, 0)
GAI(gai_service_65536, 0, 0, "127.0.0.1", "65536", 0, AF_INET, SOCK_STREAM, 0)
GAI(gai_numericserv_with_name, 11001, 11001, "127.0.0.1", "http", AI_NUMERICSERV, AF_INET, SOCK_STREAM, 0)
GAI(gai_numerichost_with_name, 11001, 11001, "localhost", "80", AI_NUMERICHOST, AF_INET, SOCK_STREAM, 0)
GAI(gai_canonname_without_name, 10022, 10022, NULL, "80", AI_CANONNAME, AF_INET, SOCK_STREAM, 0)
GAI(gai_v6_literal_for_inet, 11001, 11001, "::1", "80", 0, AF_INET, SOCK_STREAM, 0)
GAI(gai_v4_literal_for_inet6, 11001, 11001, "127.0.0.1", "80", 0, AF_INET6, SOCK_STREAM, 0)
GAI(gai_stream_with_udp_proto, 0, 0, "127.0.0.1", "80", 0, AF_INET, SOCK_STREAM, IPPROTO_UDP)
GAI(gai_dgram_with_tcp_proto, 0, 0, "127.0.0.1", "80", 0, AF_INET, SOCK_DGRAM, IPPROTO_TCP)
GAI(gai_raw_socktype, 0, 0, "127.0.0.1", "80", 0, AF_INET, SOCK_RAW, 0)
GAI(gai_seqpacket_socktype, 10044, 10044, "127.0.0.1", "80", 0, AF_INET, SOCK_SEQPACKET, 0)
GAI(gai_proto_only_unknown, 0, 0, "127.0.0.1", "80", 0, AF_INET, 0, 250)
GAI(gai_empty_name, 0, 0, "", "80", 0, AF_INET, SOCK_STREAM, 0)
GAI(gai_empty_service, 0, 0, "127.0.0.1", "", 0, AF_INET, SOCK_STREAM, 0)
GAI(gai_numeric_ok, 0, 0, "127.0.0.1", "80", AI_NUMERICHOST | AI_NUMERICSERV, AF_INET, SOCK_STREAM, 0)
GAI(gai_localhost_ok, 0, 0, "localhost", "80", 0, AF_INET, SOCK_STREAM, 0)
GAI(gai_all_flags_bad_mix, 10022, 10022, "127.0.0.1", "80", AI_FQDN | AI_CANONNAME | AI_CANONNAME, AF_INET, SOCK_STREAM, 0)
N_CASE(gai_hints_addrlen_nonzero, 11003, 11003) { ADDRINFOA h, *res = NULL; memset(&h, 0, sizeof h); h.ai_family = AF_INET; h.ai_addrlen = 16; g_ret = getaddrinfo("127.0.0.1", "80", &h, &res); if (res) freeaddrinfo(res); }
N_CASE(gai_hints_next_set, 11003, 11003) { ADDRINFOA h, *res = NULL; memset(&h, 0, sizeof h); h.ai_family = AF_INET; h.ai_next = &h; g_ret = getaddrinfo("127.0.0.1", "80", &h, &res); if (res) freeaddrinfo(res); }
N_CASE(gai_hints_addr_set, 11003, 11003) { ADDRINFOA h, *res = NULL; struct sockaddr_in a = xe_lo(0); memset(&h, 0, sizeof h); h.ai_family = AF_INET; h.ai_addr = (struct sockaddr *)&a; g_ret = getaddrinfo("127.0.0.1", "80", &h, &res); if (res) freeaddrinfo(res); }
N_CASE(gai_hints_canonname_set, 11003, 11003) { ADDRINFOA h, *res = NULL; char c[2] = "x"; memset(&h, 0, sizeof h); h.ai_family = AF_INET; h.ai_canonname = c; g_ret = getaddrinfo("127.0.0.1", "80", &h, &res); if (res) freeaddrinfo(res); }
N_CASE(gai_null_hints_ok, 0, 0) { ADDRINFOA *res = NULL; g_ret = getaddrinfo("127.0.0.1", "80", NULL, &res); if (res) freeaddrinfo(res); }
N_CASE(gai_result_is_null_when_failing, 10147, 10047) {
    ADDRINFOA h, *res = (ADDRINFOA *)(ULONG_PTR)0x1; memset(&h, 0, sizeof h); h.ai_family = 0x7ff0; g_ret = getaddrinfo("127.0.0.1", "80", &h, &res); g_ret = (res == NULL) ? 100 + g_ret : 1; }

static int gaiw(const WCHAR *n, const WCHAR *s, int fam, int type, int flags) {
    ADDRINFOW h, *res = NULL; int r; memset(&h, 0, sizeof h); h.ai_family = fam; h.ai_socktype = type; h.ai_flags = flags;
    r = GetAddrInfoW(n, s, &h, &res); if (res) U(FreeAddrInfoW)(res); return r;
}
N_CASE(gaiw_bad_family, 10047, 10047) { g_ret = gaiw(L"127.0.0.1", L"80", 0x7ff0, SOCK_STREAM, 0); }
N_CASE(gaiw_bad_socktype, 10044, 10044) { g_ret = gaiw(L"127.0.0.1", L"80", AF_INET, 99, 0); }
N_CASE(gaiw_null_null, 11001, 11001) { g_ret = gaiw(NULL, NULL, 0, 0, 0); }
N_CASE(gaiw_unknown_service, 10109, 10109) { g_ret = gaiw(L"127.0.0.1", L"nosuchservice", AF_INET, SOCK_STREAM, 0); }
N_CASE(gaiw_bad_flags, 0, 0) { g_ret = gaiw(L"127.0.0.1", L"80", AF_INET, SOCK_STREAM, 0x40000000); }
N_CASE(gaiw_numerichost_name, 11001, 11001) { g_ret = gaiw(L"localhost", L"80", AF_INET, SOCK_STREAM, AI_NUMERICHOST); }

static int gni(const struct sockaddr *sa, int salen, char *h, DWORD hl, char *s, DWORD sl, int fl) { return getnameinfo(sa, salen, h, hl, s, sl, fl); }
N_CASE(gni_ok_numeric, 0, 0) { struct sockaddr_in a = xe_lo(XE_BE16(80)); char h[64], s[16]; g_ret = gni((struct sockaddr *)&a, sizeof a, h, 64, s, 16, NI_NUMERICHOST | NI_NUMERICSERV); }
N_CASE(gni_bad_flags, 0, 0) { struct sockaddr_in a = xe_lo(XE_BE16(80)); char h[64], s[16]; g_ret = gni((struct sockaddr *)&a, sizeof a, h, 64, s, 16, 0x1000); }
N_CASE(gni_bad_family, 10047, 10047) { struct sockaddr_in a = xe_lo(XE_BE16(80)); char h[64], s[16]; a.sin_family = 0x7ff0; g_ret = gni((struct sockaddr *)&a, sizeof a, h, 64, s, 16, NI_NUMERICHOST); }
N_CASE(gni_salen_short, 10014, 10014) { struct sockaddr_in a = xe_lo(XE_BE16(80)); char h[64], s[16]; g_ret = gni((struct sockaddr *)&a, 4, h, 64, s, 16, NI_NUMERICHOST); }
N_CASE(gni_salen_zero, 10014, 10014) { struct sockaddr_in a = xe_lo(XE_BE16(80)); char h[64], s[16]; g_ret = gni((struct sockaddr *)&a, 0, h, 64, s, 16, NI_NUMERICHOST); }
N_CASE(gni_no_buffers, 0, 0) { struct sockaddr_in a = xe_lo(XE_BE16(80)); g_ret = gni((struct sockaddr *)&a, sizeof a, NULL, 0, NULL, 0, NI_NUMERICHOST); }
N_CASE(gni_host_buffer_small, 122, 122) { struct sockaddr_in a = xe_lo(XE_BE16(80)); char h[4], s[16]; g_ret = gni((struct sockaddr *)&a, sizeof a, h, 4, s, 16, NI_NUMERICHOST); }
N_CASE(gni_serv_buffer_small, 122, 122) { struct sockaddr_in a = xe_lo(XE_BE16(80)); char h[64], s[1]; g_ret = gni((struct sockaddr *)&a, sizeof a, h, 64, s, 1, NI_NUMERICHOST | NI_NUMERICSERV); }
N_CASE(gni_namereqd_with_numerichost, 0, 0) { struct sockaddr_in a = xe_lo(XE_BE16(80)); char h[64], s[16]; g_ret = gni((struct sockaddr *)&a, sizeof a, h, 64, s, 16, NI_NAMEREQD | NI_NUMERICHOST); }
N_CASE(gni_unspec_family, 10047, 10047) { struct sockaddr_in a = xe_lo(XE_BE16(80)); char h[64], s[16]; a.sin_family = AF_UNSPEC; g_ret = gni((struct sockaddr *)&a, sizeof a, h, 64, s, 16, NI_NUMERICHOST); }
N_CASE(gni_v6_salen_short, 10014, 10014) { struct sockaddr_in6 a; char h[64], s[16]; memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; g_ret = gni((struct sockaddr *)&a, 16, h, 64, s, 16, NI_NUMERICHOST); }
N_CASE(gni_service_name_ok, 0, 0) { struct sockaddr_in a = xe_lo(XE_BE16(80)); char h[64], s[32]; g_ret = gni((struct sockaddr *)&a, sizeof a, h, 64, s, 32, NI_NUMERICHOST); }
N_CASE(gni_dgram_service, 0, 0) { struct sockaddr_in a = xe_lo(XE_BE16(53)); char h[64], s[32]; g_ret = gni((struct sockaddr *)&a, sizeof a, h, 64, s, 32, NI_NUMERICHOST | NI_DGRAM); }
N_CASE(gniw_bad_flags, 0, 0) { struct sockaddr_in a = xe_lo(XE_BE16(80)); WCHAR h[64], s[16]; g_ret = GetNameInfoW((struct sockaddr *)&a, sizeof a, h, 64, s, 16, 0x1000); }
N_CASE(gniw_salen_short, 10014, 10014) { struct sockaddr_in a = xe_lo(XE_BE16(80)); WCHAR h[64], s[16]; g_ret = GetNameInfoW((struct sockaddr *)&a, 4, h, 64, s, 16, NI_NUMERICHOST); }

/* ---- textual address converters ---- */
N_CASE(inet_pton_bad_family, -1, 10047) { unsigned char b[16]; g_ret = inet_pton(0x7ff0, "127.0.0.1", b); }
N_CASE(inet_pton_bad_text, 0, 57005) { unsigned char b[16]; g_ret = inet_pton(AF_INET, "127.0.0", b); }
N_CASE(inet_pton_v6_text_in_v4, 0, 57005) { unsigned char b[16]; g_ret = inet_pton(AF_INET, "::1", b); }
N_CASE(inet_pton_ok, 1, 57005) { unsigned char b[16]; g_ret = inet_pton(AF_INET, "127.0.0.1", b); }
N_CASE(inet_pton_v6_bad_text, 0, 57005) { unsigned char b[16]; g_ret = inet_pton(AF_INET6, "1::2::3", b); }
N_CASE(inetptonw_bad_family, -1, 10047) { unsigned char b[16]; g_ret = InetPtonW(0x7ff0, L"127.0.0.1", b); }
N_CASE(inet_addr_garbage, 1, 57005) { g_ret = (inet_addr("zzz") == INADDR_NONE) ? 1 : 0; }
N_CASE(inet_addr_broadcast_is_none, 1, 57005) { g_ret = (inet_addr("255.255.255.255") == INADDR_NONE) ? 1 : 0; }

/* ---- second sweep (values recorded from the first probe run are filled in below) ---- */
N_CASE(gethostbyname_trailing_dot_localhost, 1, 0) { HENT_FAIL(gethostbyname("localhost.")); }
N_CASE(gethostbyname_five_part_numeric, 0, 11001) { HENT_FAIL(gethostbyname("1.2.3.4.5")); }
N_CASE(gethostbyname_short_numeric, 0, 11001) { HENT_FAIL(gethostbyname("127.1")); }
N_CASE(gethostbyname_hex_numeric, 0, 11001) { HENT_FAIL(gethostbyname("0x7f.0.0.1")); }
N_CASE(gethostbyname_double_dot, 0, 11001) { HENT_FAIL(gethostbyname("a..b")); }
N_CASE(gethostbyname_all_ones, 1, 0) { HENT_FAIL(gethostbyname("255.255.255.255")); }
N_CASE(gethostbyname_name_256, 0, 11001) { char n[260]; memset(n, 'a', 256); n[256] = 0; HENT_FAIL(gethostbyname(n)); }
N_CASE(gethostbyaddr_len16_inet, 1, 0) { unsigned char a[16] = {127, 0, 0, 1}; HENT_FAIL(gethostbyaddr((char *)a, 16, AF_INET)); }
N_CASE(gethostbyaddr_inet6_loopback, 1, 0) { unsigned char a[16] = {0}; a[15] = 1; HENT_FAIL(gethostbyaddr((char *)a, 16, AF_INET6)); }
N_CASE(gethostbyaddr_inet6_zero_len4, 0, 10022) { unsigned char a[16] = {0}; HENT_FAIL(gethostbyaddr((char *)a, 4, AF_INET6)); }
N_CASE(getservbyname_upper_case, 1, 0) { HENT_FAIL(getservbyname("HTTP", "tcp")); }
N_CASE(getservbyname_proto_upper, 1, 0) { HENT_FAIL(getservbyname("http", "TCP")); }
N_CASE(getservbyname_udp_only_name_tcp, 1, 0) { HENT_FAIL(getservbyname("domain", "udp")); }
N_CASE(getservbyname_numeric_name, 0, 11004) { HENT_FAIL(getservbyname("80", "tcp")); }
N_CASE(getservbyport_zero, 0, 11004) { HENT_FAIL(getservbyport(0, "tcp")); }
N_CASE(getservbyport_null_proto, 1, 0) { HENT_FAIL(getservbyport(XE_BE16(80), NULL)); }
N_CASE(getservbyport_wrong_proto_for_port, 0, 11004) { HENT_FAIL(getservbyport(XE_BE16(80), "icmp")); }
N_CASE(getprotobyname_upper, 1, 0) { HENT_FAIL(getprotobyname("TCP")); }
N_CASE(getprotobyname_udp, 1, 0) { HENT_FAIL(getprotobyname("udp")); }
N_CASE(getprotobyname_icmp, 1, 0) { HENT_FAIL(getprotobyname("icmp")); }
N_CASE(getprotobyname_ip, 1, 0) { HENT_FAIL(getprotobyname("ip")); }
N_CASE(getprotobynumber_zero, 1, 0) { HENT_FAIL(getprotobynumber(0)); }
N_CASE(getprotobynumber_17, 1, 0) { HENT_FAIL(getprotobynumber(17)); }
N_CASE(getprotobynumber_big, 0, 11004) { HENT_FAIL(getprotobynumber(256)); }
N_CASE(getprotobynumber_41, 1, 0) { HENT_FAIL(getprotobynumber(41)); }
GAI(gai_service_zero, 0, 0, "127.0.0.1", "0", 0, AF_INET, SOCK_STREAM, 0)
GAI(gai_service_negative, 0, 0, "127.0.0.1", "-1", 0, AF_INET, SOCK_STREAM, 0)
GAI(gai_service_leading_space, 0, 0, "127.0.0.1", " 80", 0, AF_INET, SOCK_STREAM, 0)
GAI(gai_service_trailing_junk, 10109, 10109, "127.0.0.1", "80x", 0, AF_INET, SOCK_STREAM, 0)
GAI(gai_service_name_with_dgram_only, 0, 0, "127.0.0.1", "domain", 0, AF_INET, SOCK_STREAM, 0)
GAI(gai_service_name_any_socktype, 0, 0, "127.0.0.1", "http", 0, AF_INET, 0, 0)
GAI(gai_passive_numeric_service, 0, 0, NULL, "80", AI_PASSIVE, AF_INET, SOCK_STREAM, 0)
GAI(gai_name_256_chars, 11001, 11001, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "80", 0, AF_INET, SOCK_STREAM, 0)
GAI(gai_double_dot_name, 11001, 11001, "a..b", "80", AI_NUMERICHOST, AF_INET, SOCK_STREAM, 0)
GAI(gai_numerichost_hex_form, 0, 0, "0x7f.0.0.1", "80", AI_NUMERICHOST, AF_INET, SOCK_STREAM, 0)
GAI(gai_numerichost_short_form, 0, 0, "127.1", "80", AI_NUMERICHOST, AF_INET, SOCK_STREAM, 0)
GAI(gai_numerichost_v4_octal_looking, 0, 0, "0177.0.0.1", "80", AI_NUMERICHOST, AF_INET, SOCK_STREAM, 0)
GAI(gai_numerichost_v6_scope_garbage, 11001, 11001, "fe80::1%zz", "80", AI_NUMERICHOST, AF_INET6, SOCK_STREAM, 0)
GAI(gai_numerichost_v6_bracketed, 0, 0, "[::1]", "80", AI_NUMERICHOST, AF_INET6, SOCK_STREAM, 0)
GAI(gai_numerichost_v6_mapped_for_inet6, 0, 0, "::ffff:127.0.0.1", "80", AI_NUMERICHOST, AF_INET6, SOCK_STREAM, 0)
GAI(gai_flag_fqdn_with_numeric, 0, 0, "127.0.0.1", "80", AI_FQDN, AF_INET, SOCK_STREAM, 0)
GAI(gai_flag_canonname_and_fqdn, 10022, 10022, "localhost", "80", AI_CANONNAME | AI_FQDN, AF_INET, SOCK_STREAM, 0)
GAI(gai_flag_preferred_names_with_canonname, 0, 0, "localhost", "80", AI_RETURN_PREFERRED_NAMES | AI_CANONNAME, AF_INET, SOCK_STREAM, 0)
GAI(gai_flag_secure, 0, 0, "localhost", "80", AI_SECURE, AF_INET, SOCK_STREAM, 0)
GAI(gai_flag_all_without_v4mapped, 0, 0, "127.0.0.1", "80", AI_ALL, AF_INET, SOCK_STREAM, 0)
GAI(gai_flag_v4mapped_family_inet, 0, 0, "127.0.0.1", "80", AI_V4MAPPED, AF_INET, SOCK_STREAM, 0)
GAI(gai_flag_v4mapped_family_inet6, 0, 0, "127.0.0.1", "80", AI_V4MAPPED, AF_INET6, SOCK_STREAM, 0)
GAI(gai_family_netbios, 10047, 10047, "127.0.0.1", "80", 0, AF_NETBIOS, SOCK_STREAM, 0)
GAI(gai_family_unix, 10047, 10047, "127.0.0.1", "80", 0, AF_UNIX, SOCK_STREAM, 0)
GAI(gai_family_unspec_dgram_proto_tcp, 0, 0, "127.0.0.1", "80", 0, AF_UNSPEC, SOCK_DGRAM, IPPROTO_TCP)
GAI(gai_socktype_rdm, 10044, 10044, "127.0.0.1", "80", 0, AF_INET, SOCK_RDM, 0)
GAI(gai_proto_icmp_stream, 0, 0, "127.0.0.1", "80", 0, AF_INET, SOCK_STREAM, IPPROTO_ICMP)
GAI(gai_proto_negative, 0, 0, "127.0.0.1", "80", 0, AF_INET, 0, -1)
N_CASE(gai_flags_with_garbage_high_bits_wide, 0, 0) { g_ret = gaiw(L"127.0.0.1", L"80", AF_INET, SOCK_STREAM, (int)0x80000000); }
N_CASE(gaiw_empty_name, 0, 0) { g_ret = gaiw(L"", L"80", AF_INET, SOCK_STREAM, 0); }
N_CASE(gaiw_numerichost_bad_text, 11001, 11001) { g_ret = gaiw(L"127.0.0.300", L"80", AF_INET, SOCK_STREAM, AI_NUMERICHOST); }
N_CASE(gaiw_unicode_name_numerichost, 11001, 11001) { g_ret = gaiw(L"\x00e9.example", L"80", AF_INET, SOCK_STREAM, AI_NUMERICHOST); }
N_CASE(gniw_ok_numeric, 0, 0) { struct sockaddr_in a = xe_lo(XE_BE16(80)); WCHAR h[64], s[16]; g_ret = GetNameInfoW((struct sockaddr *)&a, sizeof a, h, 64, s, 16, NI_NUMERICHOST | NI_NUMERICSERV); }
N_CASE(gni_namereqd_loopback_numeric_only, 0, 0) { struct sockaddr_in a = xe_lo(XE_BE16(80)); char h[64], s[16]; g_ret = gni((struct sockaddr *)&a, sizeof a, h, 64, s, 16, NI_NAMEREQD | NI_NUMERICSERV); }
N_CASE(gni_nofqdn_loopback, 0, 0) { struct sockaddr_in a = xe_lo(XE_BE16(80)); char h[64], s[16]; g_ret = gni((struct sockaddr *)&a, sizeof a, h, 64, s, 16, NI_NOFQDN | NI_NUMERICSERV); }
N_CASE(gni_v6_loopback_numeric, 0, 0) { struct sockaddr_in6 a; char h[64], s[16]; memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1; a.sin6_port = XE_BE16(80); g_ret = gni((struct sockaddr *)&a, sizeof a, h, 64, s, 16, NI_NUMERICHOST | NI_NUMERICSERV); }
N_CASE(gni_v6_host_buffer_small, 122, 122) { struct sockaddr_in6 a; char h[2], s[16]; memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1; g_ret = gni((struct sockaddr *)&a, sizeof a, h, 2, s, 16, NI_NUMERICHOST | NI_NUMERICSERV); }
N_CASE(gni_hostlen_without_buffer, 0, 0) { struct sockaddr_in a = xe_lo(XE_BE16(80)); char s[16]; g_ret = gni((struct sockaddr *)&a, sizeof a, NULL, 64, s, 16, NI_NUMERICHOST | NI_NUMERICSERV); }
N_CASE(gni_servlen_without_buffer, 0, 0) { struct sockaddr_in a = xe_lo(XE_BE16(80)); char h[64]; g_ret = gni((struct sockaddr *)&a, sizeof a, h, 64, NULL, 16, NI_NUMERICHOST | NI_NUMERICSERV); }
N_CASE(gni_port_zero_service_text, 0, 0) { struct sockaddr_in a = xe_lo(0); char h[64], s[16]; g_ret = gni((struct sockaddr *)&a, sizeof a, h, 64, s, 16, NI_NUMERICHOST); }
N_CASE(inet_pton_empty, 0, 57005) { unsigned char b[16]; g_ret = inet_pton(AF_INET, "", b); }
N_CASE(inet_pton_leading_zero_octet, 0, 57005) { unsigned char b[16]; g_ret = inet_pton(AF_INET, "127.0.0.01", b); }
N_CASE(inet_pton_octal_looking, 0, 57005) { unsigned char b[16]; g_ret = inet_pton(AF_INET, "0177.0.0.1", b); }
N_CASE(inet_pton_trailing_space, 0, 57005) { unsigned char b[16]; g_ret = inet_pton(AF_INET, "127.0.0.1 ", b); }
N_CASE(inet_pton_v4_with_port, 0, 57005) { unsigned char b[16]; g_ret = inet_pton(AF_INET, "127.0.0.1:80", b); }
N_CASE(inet_pton_v6_mapped_v4_text, 1, 57005) { unsigned char b[16]; g_ret = inet_pton(AF_INET6, "::ffff:1.2.3.4", b); }
N_CASE(inet_pton_v6_brackets, 0, 57005) { unsigned char b[16]; g_ret = inet_pton(AF_INET6, "[::1]", b); }
N_CASE(inet_pton_v6_scope_text, 0, 57005) { unsigned char b[16]; g_ret = inet_pton(AF_INET6, "fe80::1%1", b); }
N_CASE(inet_pton_unspec_family, -1, 10047) { unsigned char b[16]; g_ret = inet_pton(AF_UNSPEC, "127.0.0.1", b); }
N_CASE(inetptonw_bad_text, 0, 10022) { unsigned char b[16]; g_ret = InetPtonW(AF_INET, L"1.2.3", b); }
N_CASE(inet_addr_empty, 1, 57005) { g_ret = (inet_addr("") == INADDR_NONE) ? 1 : 0; }
N_CASE(inet_addr_short_form_ok, 1, 57005) { g_ret = (inet_addr("127.1") == 0x0100007f) ? 1 : 0; }
N_CASE(inet_addr_hex_form_ok, 1, 57005) { g_ret = (inet_addr("0x7f.0.0.1") == 0x0100007f) ? 1 : 0; }
N_CASE(inet_addr_octal_form, 1, 57005) { g_ret = (inet_addr("0177.0.0.1") == 0x0100007f) ? 1 : 0; }
N_CASE(inet_addr_trailing_junk, 1, 57005) { g_ret = (inet_addr("127.0.0.1x") == INADDR_NONE) ? 1 : 0; }
N_CASE(inet_addr_five_parts, 1, 57005) { g_ret = (inet_addr("1.2.3.4.5") == INADDR_NONE) ? 1 : 0; }
