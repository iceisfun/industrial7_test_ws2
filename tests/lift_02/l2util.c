/* Helpers shared by the lift_02 tests. */
#include "l2.h"

int l2_startup(void) {
    static int state; /* 0 untried, 1 ok, -1 failed */
    if (!state) {
        WSADATA d;
        int (WINAPI *start)(WORD, LPWSADATA) = (void *)UIN("ws2_32.dll", WSAStartup);
        state = (start && start(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    return state > 0;
}

int l2_have_ipv6(void) {
    SOCKET s;
    if (!l2_startup() || !U(socket) || !U(closesocket)) return 0;
    s = U(socket)(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;
    U(closesocket)(s);
    return 1;
}

void l2_unhex(const char *hex, unsigned char *out, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned v = 0; int k;
        for (k = 0; k < 2; k++) {
            char c = hex[i * 2 + k];
            v = v * 16 + (c >= 'a' ? c - 'a' + 10 : c >= 'A' ? c - 'A' + 10 : c - '0');
        }
        out[i] = (unsigned char)v;
    }
}

void l2_widen(const char *s, WCHAR *w, size_t cap) {
    size_t i = 0;
    for (; s[i] && i + 1 < cap; i++) w[i] = (unsigned char)s[i];
    w[i] = 0;
}
