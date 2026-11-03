/* Per-socket option plumbing, ioctl dispatch and multipoint join of the Winsock helper DLLs
 * (WSHGetSocketInformation, WSHSetSocketInformation, WSHIoctl, WSHJoinLeaf). Only the paths that do not reach a
 * transport are exercised: the helper-context option, unknown option levels, and argument validation with an invalid
 * socket and no transport handles. Measures: the exact error for every unsupported level/option pair, the length
 * protocol of the context option, and the context value that is stored/returned. */
#include "anc.h"

#define SOL_INTERNAL_ 0xfffe
#define SO_CONTEXT_ 1

static INT getinfo(const anc_wsh *h, PVOID ctx, INT lvl, INT opt, PCHAR buf, INT *len) {
    return h->GetSocketInformation(ctx, (SOCKET)0x1234, NULL, NULL, lvl, opt, buf, len);
}

/* The context option returns the helper's context value in eight bytes. */
static void ctx_option(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    if (hi->af == 32) return;   /* the Bluetooth helper keeps a record behind its context; covered by the rejection table */
    PVOID ctx = anc_open_ctx(&h, hi, SOCK_STREAM, 6);
    if (!ctx) { t_skip("could not open a helper context"); return; }
    BYTE buf[32]; INT len;
    for (INT l = 0; l < 8; l++) { len = l; memset(buf, ANC_FILL, sizeof buf); CHECKF(getinfo(&h, ctx, SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)buf, &len) == E_FAULT, "%s len %d", hi->tag, l); CHECKF(len == l && buf[0] == ANC_FILL, "%s len %d: touched", hi->tag, l); }
    INT lens[] = { 8, 9, 16, 32 };
    for (size_t i = 0; i < ANC_N(lens); i++) {
        len = lens[i]; memset(buf, ANC_FILL, sizeof buf);
        CHECKF(getinfo(&h, ctx, SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)buf, &len) == 0, "%s len %d", hi->tag, lens[i]);
        CHECKF(len == 8, "%s len %d: reported %d", hi->tag, lens[i], len);
        CHECKF(*(ULONG_PTR *)buf == (ULONG_PTR)ctx, "%s len %d: value %llx", hi->tag, lens[i], (unsigned long long)*(ULONG_PTR *)buf);
        CHECKF(buf[8] == ANC_FILL, "%s len %d: wrote past eight bytes", hi->tag, lens[i]);
    }
    /* the value handed back is whatever context the caller passes, not a lookup */
    PVOID fake = (PVOID)(ULONG_PTR)0x123456; len = 8;
    CHECK(getinfo(&h, fake, SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)buf, &len) == 0); CHECK(*(ULONG_PTR *)buf == 0x123456);
    /* a NULL buffer asks only for the size */
    len = 8; CHECK(getinfo(&h, ctx, SOL_INTERNAL_, SO_CONTEXT_, NULL, &len) == 0); CHECK(len == 8);
    len = 0; CHECK(getinfo(&h, ctx, SOL_INTERNAL_, SO_CONTEXT_, NULL, &len) == 0); CHECK(len == 8);
    anc_close_ctx(&h, ctx);
}
TEST(getinfo_context_option_wshtcpip) { ctx_option(&anc_tcp); }
TEST(getinfo_context_option_wship6) { ctx_option(&anc_ip6); }

/* The IP helpers accept the context option on the set side and nothing else. */
static void set_option(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    PVOID ctx = anc_open_ctx(&h, hi, SOCK_STREAM, 6);
    if (!ctx) { t_skip("could not open a helper context"); return; }
    BYTE v[16] = { 0 };
    CHECK(h.SetSocketInformation(ctx, (SOCKET)0x1234, NULL, NULL, SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)v, 8) == 0);
    CHECK(h.SetSocketInformation(ctx, (SOCKET)0x1234, NULL, NULL, SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)v, 0) == 0);
    anc_close_ctx(&h, ctx);
}
TEST(setinfo_context_option_accepted_wshtcpip) { set_option(&anc_tcp); }
TEST(setinfo_context_option_accepted_wship6) { set_option(&anc_ip6); }

/* Unsupported (level, option) pairs: reading says WSAENOPROTOOPT; writing says WSAEINVAL in the IP helpers. */
static const struct { INT lvl, opt; } unsupported[] = {
    { 0xfffe, 0 }, { 0xfffe, 2 }, { 0xfffe, 3 }, { 0xfffe, 0x1001 }, { 0xffff, 1 }, { 0xffff, 4 }, { 0xffff, 8 }, { 0xffff, 0x1001 }, { 0xffff, 0x1007 }, { 0xffff, 0x1008 }, { 0xffff, 0x2001 },
    { 0, 0 }, { 0, 1 }, { 1, 1 }, { 6, 1 }, { 6, 0x1002 }, { 11, 1 }, { 17, 1 }, { 41, 1 }, { 41, 10 }, { 41, 12 }, { 100, 1 }, { 0x100, 1 }, { 0x7fffffff, 1 }, { -1, 1 }, { 0xfffd, 1 } };

static void unsupported_get(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    PVOID ctx = anc_open_ctx(&h, hi, SOCK_STREAM, hi->af == 32 ? 3 : 6);
    if (!ctx) { t_skip("could not open a helper context"); return; }
    for (size_t i = 0; i < ANC_N(unsupported); i++) {
        INT lens[] = { 0, 4, 8, 16 };
        for (size_t j = 0; j < ANC_N(lens); j++) {
            BYTE buf[32]; INT len = lens[j]; memset(buf, ANC_FILL, sizeof buf);
            INT r = getinfo(&h, ctx, unsupported[i].lvl, unsupported[i].opt, (PCHAR)buf, &len);
            CHECKF(r == E_NOPROTOOPT, "%s level %x opt %x len %d: rc %d", hi->tag, unsupported[i].lvl, unsupported[i].opt, lens[j], r);
            CHECKF(len == lens[j] && buf[0] == ANC_FILL, "%s level %x opt %x len %d: touched", hi->tag, unsupported[i].lvl, unsupported[i].opt, lens[j]);
        }
    }
    anc_close_ctx(&h, ctx);
}
H3(getinfo_unsupported_options, unsupported_get)

static void unsupported_set(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    PVOID ctx = anc_open_ctx(&h, hi, SOCK_STREAM, hi->af == 32 ? 3 : 6);
    if (!ctx) { t_skip("could not open a helper context"); return; }
    INT want = hi->af == 32 ? E_NOPROTOOPT : E_INVAL;
    for (size_t i = 0; i < ANC_N(unsupported); i++) {
        if (unsupported[i].lvl == 0xfffe && unsupported[i].opt == SO_CONTEXT_) continue;
        BYTE v[16] = { 0 };
        INT r = h.SetSocketInformation(ctx, (SOCKET)0x1234, NULL, NULL, unsupported[i].lvl, unsupported[i].opt, (PCHAR)v, 4);
        CHECKF(r == want, "%s level %x opt %x: rc %d want %d", hi->tag, unsupported[i].lvl, unsupported[i].opt, r, want);
    }
    anc_close_ctx(&h, ctx);
}
H3(setinfo_unsupported_options, unsupported_set)

/* Bluetooth: reading the context option, and storing one with a too-small value, give WSAEFAULT. */
TEST(getinfo_context_option_wshbth_is_not_served_for_a_fake_socket) {
    anc_wsh h; if (!anc_begin(&h, &anc_bth)) return;
    PVOID ctx = anc_open_ctx(&h, &anc_bth, SOCK_STREAM, 3);
    if (!ctx) { t_skip("could not open a helper context"); return; }
    BYTE buf[32]; INT lens[] = { 0, 4, 8, 16 };
    for (size_t i = 0; i < ANC_N(lens); i++) { INT len = lens[i]; CHECKF(getinfo(&h, ctx, SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)buf, &len) == E_FAULT, "len %d", lens[i]); }
    BYTE v[16] = { 0 };
    CHECK(h.SetSocketInformation(ctx, (SOCKET)0x1234, NULL, NULL, SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)v, 4) == E_FAULT);
    CHECK(h.SetSocketInformation(ctx, (SOCKET)0x1234, NULL, NULL, SOL_INTERNAL_, SO_CONTEXT_, (PCHAR)v, 8) == 0);   /* with a full-size value the context is stored */
    anc_close_ctx(&h, ctx);
}

/* ---- WSHIoctl ---- */
static void ioctl_unknown(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    PVOID ctx = anc_open_ctx(&h, hi, SOCK_STREAM, hi->af == 32 ? 3 : 6);
    if (!ctx) { t_skip("could not open a helper context"); return; }
    static const DWORD codes[] = { 0, 1, 0x12345678, 0xffffffff };
    for (size_t i = 0; i < ANC_N(codes); i++) {
        DWORD ret = 0x77; BOOL nc = 0x55; BYTE in[16] = { 0 }, out[16] = { 0 };
        INT r;
        if (hi->af == 32) r = h.Ioctl(ctx, INVALID_SOCKET, NULL, NULL, codes[i], in, 16, out, 16, &ret, NULL, NULL, &nc);
        else r = h.Ioctl(ctx, (SOCKET)0x1234, NULL, NULL, codes[i], in, 16, out, 16, &ret, NULL, NULL, &nc);
        INT want = hi->af == 32 ? E_FAULT : E_INVAL;
        CHECKF(r == want, "%s code %lx: rc %d want %d", hi->tag, codes[i], r, want);
        CHECKF(ret == 0x77 && nc == 0x55, "%s code %lx: outputs touched", hi->tag, codes[i]);
    }
    anc_close_ctx(&h, ctx);
}
H3(ioctl_unknown_codes, ioctl_unknown)

/* ---- WSHJoinLeaf ---- */
static void joinleaf_validation(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    SOCKADDR_IN6 a6; memset(&a6, 0, sizeof a6); a6.sin6_family = AF_INET6;
    /* a NULL context is rejected by every helper */
    CHECK(h.JoinLeaf(NULL, INVALID_SOCKET, NULL, NULL, NULL, INVALID_SOCKET, (PSOCKADDR)&a6, 28, NULL, NULL, NULL, NULL, 0) == E_INVAL);
    CHECK(h.JoinLeaf(NULL, (SOCKET)0x1234, NULL, NULL, NULL, INVALID_SOCKET, (PSOCKADDR)&a6, 28, NULL, NULL, NULL, NULL, 0) == E_INVAL);
    if (hi->af == AF_INET6) {
        PVOID ctx6 = (PVOID)(ULONG_PTR)AF_INET6;
        /* each condition on its own: invalid parent socket, bad leaf, NULL/short/foreign address */
        CHECK(h.JoinLeaf(ctx6, INVALID_SOCKET, NULL, NULL, NULL, INVALID_SOCKET, (PSOCKADDR)&a6, 28, NULL, NULL, NULL, NULL, 0) == E_INVAL);
        CHECK(h.JoinLeaf(ctx6, (SOCKET)0x1234, NULL, NULL, NULL, INVALID_SOCKET, NULL, 28, NULL, NULL, NULL, NULL, 0) == E_INVAL);
        CHECK(h.JoinLeaf(ctx6, (SOCKET)0x1234, NULL, NULL, NULL, INVALID_SOCKET, (PSOCKADDR)&a6, 27, NULL, NULL, NULL, NULL, 0) == E_INVAL);
        CHECK(h.JoinLeaf(ctx6, (SOCKET)0x1234, NULL, NULL, NULL, 5, (PSOCKADDR)&a6, 28, NULL, NULL, NULL, NULL, 0) == E_INVAL);
        CHECK(h.JoinLeaf(ctx6, (SOCKET)0x1234, NULL, NULL, (PVOID)1, INVALID_SOCKET, (PSOCKADDR)&a6, 28, NULL, NULL, NULL, NULL, 0) == E_INVAL);
        SOCKADDR_IN a4; memset(&a4, 0, sizeof a4); a4.sin_family = AF_INET;
        CHECK(h.JoinLeaf(ctx6, (SOCKET)0x1234, NULL, NULL, NULL, INVALID_SOCKET, (PSOCKADDR)&a4, 28, NULL, NULL, NULL, NULL, 0) == E_INVAL);
        CHECK(h.JoinLeaf((PVOID)(ULONG_PTR)AF_INET, (SOCKET)0x1234, NULL, NULL, NULL, INVALID_SOCKET, (PSOCKADDR)&a6, 28, NULL, NULL, NULL, NULL, 0) == E_INVAL);
    }
}
H3(joinleaf_argument_validation, joinleaf_validation)
