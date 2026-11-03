/* Option numbers that the IPv4 and IPv6 levels do not define: both getsockopt and setsockopt answer WSAENOPROTOOPT,
 * whatever the socket state, and the option length (even a zero length) is not looked at first for the set call.
 * The lists were taken from a sweep of option numbers 0..80 and hold the numbers that fail that way; numbers that
 * succeed or fail differently are covered by the per-option tests. Membership options (12, 13, and the source
 * filter pair) are write-only, which is why they show up in the get lists. */
#include "spl.h"

static const int udp4_unknown[] = {0, 5, 6, 7, 8, 12, 13, 15, 16, 17, 18, 20, 26, 27, 29, 30, 34, 35, 36, 37, 39, 41, 42, 43, 44, 45, 46, 48, 49, 52, 53, 54, 55, 56, 57, 58, 59, 61, 62, 63, 64, 65, 66, 67, 68, 69, 72, 74, 77, 78, 79, 80};
static const int tcp4_unknown[] = {0, 5, 6, 7, 8, 12, 13, 15, 16, 17, 18, 20, 26, 27, 29, 30, 34, 35, 36, 37, 39, 41, 42, 43, 44, 45, 46, 48, 49, 52, 53, 54, 55, 56, 57, 58, 59, 61, 62, 63, 64, 65, 66, 67, 68, 69, 72, 74, 77, 78, 79, 80};
static const int udp6_unknown[] = {0, 5, 6, 7, 8, 12, 13, 15, 16, 17, 18, 20, 26, 29, 30, 34, 35, 36, 37, 39, 41, 42, 43, 44, 45, 46, 48, 49, 52, 53, 54, 55, 56, 57, 58, 59, 61, 62, 63, 64, 65, 66, 67, 68, 69, 73, 74, 77, 78, 79, 80};
static const int tcp6_unknown[] = {0, 5, 6, 7, 8, 12, 13, 15, 16, 17, 18, 20, 26, 29, 30, 34, 35, 36, 37, 39, 41, 42, 43, 44, 45, 46, 48, 49, 52, 53, 54, 55, 56, 57, 58, 59, 61, 62, 63, 64, 65, 66, 67, 68, 69, 73, 74, 77, 78, 79, 80};

static void sweep_unknown(SOCKET s, int lv, const int *o, int n, int check_set)
{
    int i;
    for (i = 0; i < n; i++) {
        int v = 1, l = 4, e, r;
        /* 27, 72 and 73 are defined on one family's level and not the other's; the cross-level sweeps leave them out. */
        if (!check_set && (o[i] == 27 || o[i] == 72 || o[i] == 73)) continue;
        r = spl_get(s, lv, o[i], &v, &l, &e);
        t_check(r == SOCKET_ERROR && e == WSAENOPROTOOPT, __FILE__, __LINE__, "get unknown option", "lv %d opt %d: rc %d err %d", lv, o[i], r, e);
        /* Some numbers that cannot be read are real write-only options (membership 12, 13, 15..18, the interface-list
         * pair 29 and 30, and a few more in 41..46 and 74): setting those is judged by other rules, so only the get
         * call is pinned for them. */
        if (check_set && !(o[i] == 12 || o[i] == 13 || (o[i] >= 15 && o[i] <= 18) || o[i] == 29 || o[i] == 30 ||
                           (o[i] >= 41 && o[i] <= 46) || o[i] == 74)) {
            r = spl_set(s, lv, o[i], &v, 4, &e);
            t_check(r == SOCKET_ERROR && e == WSAENOPROTOOPT, __FILE__, __LINE__, "set unknown option", "lv %d opt %d: rc %d err %d", lv, o[i], r, e);
        }
    }
}
#define NUM(a) ((int)(sizeof(a) / sizeof((a)[0])))
TEST(unknown_ip_options_udp4)  { SOCKET s; if (!spl_up()) return; s = spl_udp4(); sweep_unknown(s, SPL_LVL_IP, udp4_unknown, NUM(udp4_unknown), 1); spl_close(s); }
TEST(unknown_ip_options_tcp4)  { SOCKET s; if (!spl_up()) return; s = spl_tcp4(); sweep_unknown(s, SPL_LVL_IP, tcp4_unknown, NUM(tcp4_unknown), 1); spl_close(s); }
TEST(unknown_ipv6_options_udp6) { SOCKET s; if (!spl_up()) return; s = spl_udp6(); if (s == INVALID_SOCKET) { t_skip("IPv6 unavailable"); return; } sweep_unknown(s, SPL_LVL_IPV6, udp6_unknown, NUM(udp6_unknown), 1); spl_close(s); }
TEST(unknown_ipv6_options_tcp6) { SOCKET s; if (!spl_up()) return; s = spl_tcp6(); if (s == INVALID_SOCKET) { t_skip("IPv6 unavailable"); return; } sweep_unknown(s, SPL_LVL_IPV6, tcp6_unknown, NUM(tcp6_unknown), 1); spl_close(s); }
TEST(unknown_ipv6_options_through_ip_level_on_udp6) { SOCKET s; if (!spl_up()) return; s = spl_udp6(); if (s == INVALID_SOCKET) { t_skip("IPv6 unavailable"); return; } sweep_unknown(s, SPL_LVL_IP, udp6_unknown, NUM(udp6_unknown), 0); spl_close(s); }
TEST(unknown_ip_options_through_ipv6_level_on_udp4) { SOCKET s; if (!spl_up()) return; s = spl_udp4(); sweep_unknown(s, SPL_LVL_IPV6, udp4_unknown, NUM(udp4_unknown), 0); spl_close(s); }
