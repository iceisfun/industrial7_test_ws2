/* Shared helpers of the ancillary-provider area. */
#include "anc.h"

const anc_hinfo anc_tcp = { "wshtcpip.dll", AF_INET, "wshtcpip" };
const anc_hinfo anc_ip6 = { "wship6.dll", AF_INET6, "wship6" };
const anc_hinfo anc_bth = { "wshbth.dll", 32, "wshbth" };

int anc_begin(anc_wsh *h, const anc_hinfo *hi) {
    if (!anc_load_wsh(h, hi->dll)) { t_skip("%s is not present on this system", hi->dll); return 0; }
    return 1;
}

PVOID anc_open_ctx(const anc_wsh *h, const anc_hinfo *hi, int ty, int pr) {
    int af = hi->af, t = ty, p = pr; UNICODE_STRING us; PVOID ctx = NULL; DWORD ev = 0;
    if (!h->OpenSocket2) return NULL;
    memset(&us, 0, sizeof us);
    if (h->OpenSocket2(&af, &t, &p, 0, 0, &us, &ctx, &ev) != 0) return NULL;
    return ctx;
}

void anc_close_ctx(const anc_wsh *h, PVOID ctx) {
    if (h->Notify && ctx) h->Notify(ctx, INVALID_SOCKET, NULL, NULL, 0x80);
}

void anc_guid_str(char *o, const GUID *g) {
    sprintf(o, "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", g->Data1, g->Data2, g->Data3, g->Data4[0], g->Data4[1],
            g->Data4[2], g->Data4[3], g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
}
