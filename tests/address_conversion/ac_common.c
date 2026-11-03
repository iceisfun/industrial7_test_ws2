/* Helpers for the address_conversion area. */
#include "ac.h"

int ac_startup(void) {
    static int state; /* 0 untried, 1 ok, -1 failed */
    if (!state) {
        WSADATA d;
        int (WINAPI *start)(WORD, LPWSADATA) = (void *)t_proc_in("ws2_32.dll", "WSAStartup");
        state = (start && start(MAKEWORD(2, 2), &d) == 0) ? 1 : -1;
    }
    return state > 0;
}

void ac_unhex(const char *hex, unsigned char *out, size_t n) {
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

void ac_widen(const char *s, WCHAR *w, size_t cap) {
    size_t i = 0;
    for (; s[i] && i + 1 < cap; i++) w[i] = (unsigned char)s[i];
    w[i] = 0;
}

void ac_groups(const unsigned short g[8], unsigned char out[16]) {
    int i;
    for (i = 0; i < 8; i++) { out[2 * i] = (unsigned char)(g[i] >> 8); out[2 * i + 1] = (unsigned char)g[i]; }
}

void ac_raw_v4(unsigned char sa[16], unsigned short port, const unsigned char ip[4]) {
    memset(sa, 0, 16);
    sa[0] = AF_INET; sa[1] = 0;
    sa[2] = (unsigned char)(port >> 8); sa[3] = (unsigned char)port;
    memcpy(sa + 4, ip, 4);
}

void ac_raw_v6(unsigned char sa[28], unsigned short port, unsigned long flow, const unsigned char ip[16], unsigned long scope) {
    memset(sa, 0, 28);
    sa[0] = AF_INET6; sa[1] = 0;
    sa[2] = (unsigned char)(port >> 8); sa[3] = (unsigned char)port;
    sa[4] = (unsigned char)(flow >> 24); sa[5] = (unsigned char)(flow >> 16); sa[6] = (unsigned char)(flow >> 8); sa[7] = (unsigned char)flow;
    memcpy(sa + 8, ip, 16);
    /* scope id is stored in host order (little endian here) */
    sa[24] = (unsigned char)scope; sa[25] = (unsigned char)(scope >> 8); sa[26] = (unsigned char)(scope >> 16); sa[27] = (unsigned char)(scope >> 24);
}
