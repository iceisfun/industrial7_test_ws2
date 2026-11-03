/* One event bit at a time against sockets in a fixed state: which single-event selections report
 * something immediately and which stay silent. Rows are the ten defined FD_* bits; columns are socket
 * states. A selection is judged by whether any message for the socket arrives in a bounded window. */
#include "asm.h"

static const struct { long ev; const char *name; } k_bits[] = {
    { FD_READ, "FD_READ" }, { FD_WRITE, "FD_WRITE" }, { FD_OOB, "FD_OOB" }, { FD_ACCEPT, "FD_ACCEPT" },
    { FD_CONNECT, "FD_CONNECT" }, { FD_CLOSE, "FD_CLOSE" }, { FD_QOS, "FD_QOS" }, { FD_GROUP_QOS, "FD_GROUP_QOS" },
    { FD_ROUTING_INTERFACE_CHANGE, "FD_ROUTING_INTERFACE_CHANGE" }, { FD_ADDRESS_LIST_CHANGE, "FD_ADDRESS_LIST_CHANGE" },
};
/* Address-list and routing notifications depend on the network, so they are recorded, never asserted. */
#define CHECKV(c, ...) do { if (k_bits[i].ev & (FD_ROUTING_INTERFACE_CHANGE | FD_ADDRESS_LIST_CHANGE)) { if (!(c)) t_note("%s: network dependent, saw %d", k_bits[i].name, n); } else CHECKF(c, __VA_ARGS__); } while (0)
#define NBITS (sizeof k_bits / sizeof k_bits[0])

/* Connected stream, no data pending, peer open: only writability exists. */
ATEST(asm_matrix_connected_idle_single_bits)
{
    size_t i;
    for (i = 0; i < NBITS; ++i) {
        SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); int n;
        NEED(w && a_pair(&c, &v));
        EQ(a_select(v, w, ASM_WM, k_bits[i].ev), 0);
        a_pump(250);
        n = a_count(v, ASM_WM);
        CHECKV(n == (k_bits[i].ev == FD_WRITE ? 1 : 0), "%s: %d messages", k_bits[i].name, n);
        a_close(c); a_close(v); a_destroy(w);
        a_log_reset();
    }
}

/* Connected stream with one byte queued: readability appears next to writability. */
ATEST(asm_matrix_connected_with_data_single_bits)
{
    size_t i;
    for (i = 0; i < NBITS; ++i) {
        SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); int n, want;
        NEED(w && a_pair(&c, &v));
        CHECK(a_send(c, 1) == 1);
        Sleep(50);
        EQ(a_select(v, w, ASM_WM, k_bits[i].ev), 0);
        a_pump(250);
        n = a_count(v, ASM_WM);
        want = (k_bits[i].ev == FD_WRITE || k_bits[i].ev == FD_READ) ? 1 : 0;
        CHECKV(n == want, "%s: %d messages, want %d", k_bits[i].name, n, want);
        a_close(c); a_close(v); a_destroy(w);
        a_log_reset();
    }
}

/* Peer already closed: the close is reported (after the empty queue), nothing else new. */
ATEST(asm_matrix_peer_closed_single_bits)
{
    size_t i;
    for (i = 0; i < NBITS; ++i) {
        SOCKET c, v; HWND w = a_win(ASM_WIN_MSGONLY); int n, want;
        NEED(w && a_pair(&c, &v));
        a_close(c);
        Sleep(100);
        EQ(a_select(v, w, ASM_WM, k_bits[i].ev), 0);
        a_pump(300);
        n = a_count(v, ASM_WM);
        want = (k_bits[i].ev == FD_CLOSE) ? 1 : 0;
        if (k_bits[i].ev == FD_READ || k_bits[i].ev == FD_WRITE) { t_note("%s after peer close: %d messages", k_bits[i].name, n); }
        else CHECKV(n == want, "%s: %d messages, want %d", k_bits[i].name, n, want);
        a_close(v); a_destroy(w);
        a_log_reset();
    }
}

ATEST(asm_matrix_unconnected_stream_single_bits)
{
    size_t i;
    for (i = 0; i < NBITS; ++i) {
        SOCKET s = a_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP); HWND w = a_win(ASM_WIN_MSGONLY); int n;
        NEED(w);
        EQ(a_select(s, w, ASM_WM, k_bits[i].ev), 0);
        a_pump(200);
        n = a_count(s, ASM_WM);
        CHECKV(n == 0, "%s: %d messages", k_bits[i].name, n);
        a_close(s); a_destroy(w);
        a_log_reset();
    }
}

ATEST(asm_matrix_idle_listener_single_bits)
{
    size_t i;
    for (i = 0; i < NBITS; ++i) {
        struct sockaddr_in a; SOCKET l = a_listener(&a, 4); HWND w = a_win(ASM_WIN_MSGONLY); int n;
        NEED(w && l != INVALID_SOCKET);
        EQ(a_select(l, w, ASM_WM, k_bits[i].ev), 0);
        a_pump(200);
        n = a_count(l, ASM_WM);
        CHECKV(n == 0, "%s: %d messages", k_bits[i].name, n);
        a_close(l); a_destroy(w);
        a_log_reset();
    }
}

/* Listener with a completed connection waiting: only FD_ACCEPT reports it. */
ATEST(asm_matrix_listener_with_pending_connection_single_bits)
{
    size_t i;
    for (i = 0; i < NBITS; ++i) {
        struct sockaddr_in a; SOCKET l = a_listener(&a, 4), c = a_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        HWND w = a_win(ASM_WIN_MSGONLY); int n;
        NEED(w && l != INVALID_SOCKET);
        EQ(U(connect)(c, (struct sockaddr *)&a, sizeof a), 0);
        EQ(a_select(l, w, ASM_WM, k_bits[i].ev), 0);
        a_pump(250);
        n = a_count(l, ASM_WM);
        CHECKV(n == (k_bits[i].ev == FD_ACCEPT ? 1 : 0), "%s: %d messages", k_bits[i].name, n);
        a_close(l); a_close(c); a_destroy(w);
        a_log_reset();
    }
}

/* Bound datagram socket, empty: nothing to read or accept; writability is recorded, not asserted. */
ATEST(asm_matrix_bound_datagram_idle_single_bits)
{
    size_t i;
    for (i = 0; i < NBITS; ++i) {
        SOCKET a, b; struct sockaddr_in aa, ba; HWND w = a_win(ASM_WIN_MSGONLY); int n;
        NEED(w && a_udp_pair(&a, &b, &aa, &ba));
        EQ(a_select(a, w, ASM_WM, k_bits[i].ev), 0);
        a_pump(200);
        n = a_count(a, ASM_WM);
        if (k_bits[i].ev == FD_WRITE) t_note("bound UDP FD_WRITE messages: %d", n);
        else CHECKV(n == 0, "%s: %d messages", k_bits[i].name, n);
        a_close(a); a_close(b); a_destroy(w);
        a_log_reset();
    }
}

ATEST(asm_matrix_bound_datagram_with_datagram_single_bits)
{
    size_t i;
    for (i = 0; i < NBITS; ++i) {
        SOCKET a, b; struct sockaddr_in aa, ba; HWND w = a_win(ASM_WIN_MSGONLY); int n;
        NEED(w && a_udp_pair(&a, &b, &aa, &ba));
        EQ(U(sendto)(b, "x", 1, 0, (struct sockaddr *)&aa, sizeof aa), 1);
        Sleep(50);
        EQ(a_select(a, w, ASM_WM, k_bits[i].ev), 0);
        a_pump(250);
        n = a_count(a, ASM_WM);
        if (k_bits[i].ev == FD_READ) CHECKV(n == 1, "FD_READ: %d messages", n);
        else if (k_bits[i].ev == FD_WRITE) t_note("bound UDP FD_WRITE messages: %d", n);
        else CHECKV(n == 0, "%s: %d messages", k_bits[i].name, n);
        a_close(a); a_close(b); a_destroy(w);
        a_log_reset();
    }
}
