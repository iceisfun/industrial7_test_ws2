/* The AFD control-code space as seen through a socket handle.
 *
 * Dispatch table of the Windows 10 22H2 driver (73 slots; the slot is bits 2..11 of the code, and the code
 * must equal the value stored in the slot). Operations in our own words, in slot order:
 *   12003 bind            12007 connect          1200b start-listen     1200c wait-for-listen   12010 accept
 *   12017 receive         1201b receive-dgram    1201f send             12023 send-dgram        12024 poll
 *   1202b partial-disc.   1202f get-address      12033 query-recv-info  12037 query-handles      1203b set-information
 *   1203f get-remote      12043 get-context      12047 set-context      1204b..12077 connect/disconnect-data and
 *   connect-option get/set (twelve codes)        1207b get-information  1207f transmit-file      12083 super-accept
 *   12087 event-select    1208b enum-events      1208c defer-accept     12090 wait-for-listen (LIFO)
 *   12094 set-qos         12098 get-qos          1209f no-op            120a0 validate-group    120a7 unaccepted-connect-data
 *   120ab routing-query   120ac routing-change   120b3 addr-list-query  120b4 addr-list-change  120bb connect (alias)
 *   120bf transport-ioctl 120c3 transmit-packets 120c7 super-connect    120cb super-disconnect  120cf receive-message
 *   120d3 send-message    120d7..120ff, 12103..1210c session-network-provider helper requests (SAN)
 *   12113 unbind-socket   12117 metrics          1211b registered-I/O   1211f/12123 socket-transfer begin/end
 * Anything else completes at once with "invalid device request".
 *
 * The driver indexes its handler table with bits 2..11 of the control code and then insists that the full
 * code equals the value registered for that slot, so a code that is merely "close" to a real one is not
 * served: the request completes at once with "invalid device request". These tests pin the exact code
 * values of the endpoint-setup requests (bind, start-listen, wait-for-listen, accept, get-address,
 * get-remote-address, defer-accept, super-accept, unbind) by showing that the real code is understood and
 * every neighbour (other transfer method, other device type, other slot content) is not.
 */
#include "abl.h"

static const struct { const char *name; ULONG code; } k_scope[] = {
    { "bind", IO_BIND }, { "start_listen", IO_START_LISTEN }, { "wait_for_listen", IO_WAIT_FOR_LISTEN },
    { "accept", IO_ACCEPT }, { "get_address", IO_GET_ADDRESS }, { "get_remote", IO_GET_REMOTE },
    { "defer_accept", IO_DEFER_ACCEPT }, { "wait_listen_lifo", IO_WAIT_LISTEN_LIFO },
    { "super_accept", IO_SUPER_ACCEPT }, { "unbind_socket", IO_UNBIND_SOCKET },
};
#define NSCOPE ((int)(sizeof k_scope / sizeof k_scope[0]))

/* Send a request carrying no data; return the final status. The status block must have been written. */
static LONG plain(SOCKET s, ULONG code, IO_STATUS_BLOCK *io) {
    return abl_ctl(s, code, NULL, 0, NULL, 0, io, NULL);
}

static void expect_not_served(SOCKET s, ULONG code, const char *what) {
    IO_STATUS_BLOCK io; LONG first;
    LONG st = abl_ctl(s, code, NULL, 0, NULL, 0, &io, &first);
    t_check((ULONG)st == NS_INVALID_DEVICE_REQUEST, __FILE__, __LINE__, what,
            "code 0x%05lx: got 0x%08lx want 0x%08lx", (unsigned long)code, (unsigned long)st, NS_INVALID_DEVICE_REQUEST);
    /* a refusal is a synchronous completion, never "pending" */
    t_check((ULONG)first == NS_INVALID_DEVICE_REQUEST, __FILE__, __LINE__, what, "code 0x%05lx: submit returned 0x%08lx",
            (unsigned long)code, (unsigned long)first);
}

TEST(ablc_scope_codes_have_afd_base) {
    /* every request code is 0x12000 | (operation << 2) | method */
    for (int i = 0; i < NSCOPE; i++) {
        CHECKF((k_scope[i].code & 0xfffff000u) == 0x12000u, "%s", k_scope[i].name);
        CHECKF(((k_scope[i].code >> 2) & 0x3ff) < ABL_SLOTS, "%s slot", k_scope[i].name);
    }
}
TEST(ablc_scope_codes_sit_in_their_table_slot) {
    for (int i = 0; i < NSCOPE; i++) {
        unsigned slot = (k_scope[i].code >> 2) & 0x3ff;
        CHECKF(abl_code_table[slot] == k_scope[i].code, "%s: slot %u holds 0x%05x", k_scope[i].name, slot, abl_code_table[slot]);
    }
}
TEST(ablc_every_table_code_shifted_past_the_table_is_refused) {
    /* shifting any registered code 256 function numbers up lands in a slot past the end of the table */
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL);
    for (int i = 0; i < ABL_SLOTS; i++) {
        ULONG c = abl_code_table[i] + 0x400u;            /* same method bits, function number + 256 */
        expect_not_served(s, c, "function number + 256");
    }
    abl_close(s);
}
TEST(ablc_method_bits_of_scope_codes) {
    /* requests that read or write the caller's own buffers use "neither" (3); the ones whose blocks the I/O
     * manager copies (wait-for-listen, accept, defer-accept) use "buffered" (0) */
    static const struct { ULONG code; ULONG method; } m[] = {
        { IO_BIND, 3 }, { IO_START_LISTEN, 3 }, { IO_WAIT_FOR_LISTEN, 0 }, { IO_ACCEPT, 0 },
        { IO_GET_ADDRESS, 3 }, { IO_GET_REMOTE, 3 }, { IO_DEFER_ACCEPT, 0 }, { IO_WAIT_LISTEN_LIFO, 0 },
        { IO_SUPER_ACCEPT, 3 }, { IO_UNBIND_SOCKET, 3 },
    };
    for (size_t i = 0; i < sizeof m / sizeof m[0]; i++)
        CHECKF((m[i].code & 3) == m[i].method, "code 0x%05lx method %lu", (unsigned long)m[i].code, (unsigned long)(m[i].code & 3));
}

/* ---- neighbours of real codes are refused ------------------------------------------------------------ */
static int is_registered(ULONG c) {
    for (int k = 0; k < ABL_SLOTS; k++) if (abl_code_table[k] == c) return 1;
    return 0;
}
static void neighbour_run(ULONG delta_xor, ULONG delta_add, const char *label) {
    SOCKET s = abl_bound(SOCK_STREAM, NULL);
    for (int i = 0; i < NSCOPE; i++) {
        ULONG c = (k_scope[i].code ^ delta_xor) + delta_add;
        if (is_registered(c)) continue;               /* the next function number is often another real request */
        expect_not_served(s, c, label);
    }
    abl_close(s);
}
TEST(ablc_flip_method_bit0_refused) { ABL_BEGIN(); neighbour_run(1, 0, "method bit 0 flipped"); }
TEST(ablc_flip_method_bit1_refused) { ABL_BEGIN(); neighbour_run(2, 0, "method bit 1 flipped"); }
TEST(ablc_method_zero_refused_for_neither_codes) { ABL_BEGIN(); neighbour_run(3, 0, "method 3 <-> 0"); }
TEST(ablc_next_function_number_refused) { ABL_BEGIN(); neighbour_run(0, 4, "function number + 1"); }
TEST(ablc_other_device_type_refused) {
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL);
    for (int i = 0; i < NSCOPE; i++) {
        expect_not_served(s, k_scope[i].code + 0x10000u, "device type + 1");
        expect_not_served(s, k_scope[i].code & 0xffffu, "device type 0");
    }
    abl_close(s);
}
TEST(ablc_slot_alias_beyond_ten_bits_refused) {
    /* function numbers 1024 apart land in the same slot but are not the registered value */
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL);
    for (int i = 0; i < NSCOPE; i++) expect_not_served(s, k_scope[i].code + 0x1000u, "slot alias (+0x1000)");
    abl_close(s);
}

/* ---- holes and the end of the table ---------------------------------------------------------------- */
TEST(ablc_slots_past_end_refused) {
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL);
    static const ULONG codes[] = { 0x12127, 0x1212b, 0x1212f, 0x12133, 0x12200, 0x12400, 0x12803, 0x12ffb, 0x12fff };
    for (size_t i = 0; i < sizeof codes / sizeof codes[0]; i++) expect_not_served(s, codes[i], "past table end");
    abl_close(s);
}
TEST(ablc_code_zero_and_small_values_refused) {
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL);
    IO_STATUS_BLOCK io;
    static const ULONG codes[] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x12000, 0x12001, 0x12002 };
    for (size_t i = 0; i < sizeof codes / sizeof codes[0]; i++) {
        LONG st = plain(s, codes[i], &io);
        t_check((ULONG)st != NS_SUCCESS && (ULONG)st != NS_PENDING, __FILE__, __LINE__, "small code refused", "code 0x%lx st 0x%08lx", (unsigned long)codes[i], (unsigned long)st);
    }
    abl_close(s);
}
TEST(ablc_holes_between_registered_codes_refused) {
    /* the codes between entries of the table (slot content differs from the code that indexes it) */
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL);
    for (int i = 0; i < ABL_SLOTS; i++) {
        ULONG c = 0x12000u | ((ULONG)i << 2) | 2u;          /* method 2 everywhere: no AFD request uses it */
        int registered = 0;
        for (int k = 0; k < ABL_SLOTS; k++) registered |= abl_code_table[k] == c;
        if (!registered) expect_not_served(s, c, "method 2 variant");
    }
    abl_close(s);
}
TEST(ablc_refusal_does_not_disturb_socket) {
    ABL_BEGIN();
    struct sockaddr_in a, b; int len = sizeof b;
    SOCKET s = abl_bound(SOCK_STREAM, &a);
    expect_not_served(s, 0x12127, "refusal");
    expect_not_served(s, IO_BIND ^ 1, "refusal");
    CHECK(W.getsockname(s, (struct sockaddr *)&b, &len) == 0);
    CHECK(!memcmp(&a, &b, sizeof a));
    CHECK(W.listen(s, 1) == 0);
    abl_close(s);
}
TEST(ablc_refusal_same_on_each_socket_kind) {
    ABL_BEGIN();
    SOCKET kinds[4]; struct sockaddr_in a;
    kinds[0] = abl_tcp();                     /* fresh */
    kinds[1] = abl_bound(SOCK_STREAM, NULL);  /* bound */
    kinds[2] = abl_listener(&a);              /* listening */
    kinds[3] = abl_udp();                     /* datagram */
    for (int i = 0; i < 4; i++) { expect_not_served(kinds[i], 0x12127, "kind refusal"); abl_close(kinds[i]); }
}
TEST(ablc_refusal_ignores_buffers) {
    ABL_BEGIN();
    SOCKET s = abl_bound(SOCK_STREAM, NULL);
    BYTE in[64] = {0}, out[64] = {0}; IO_STATUS_BLOCK io; LONG first;
    LONG st = abl_ctl(s, 0x12127, in, sizeof in, out, sizeof out, &io, &first);
    CHECK_NS(st, NS_INVALID_DEVICE_REQUEST);
    CHECK_NS(first, NS_INVALID_DEVICE_REQUEST);
    abl_close(s);
}

/* ---- every registered slot is served (does not answer "invalid device request") ----------------------- */
TEST(ablc_scope_codes_are_served) {
    ABL_BEGIN();
    for (int i = 0; i < NSCOPE; i++) {
        SOCKET s = abl_bound(SOCK_STREAM, NULL); IO_STATUS_BLOCK io;
        LONG st = plain(s, k_scope[i].code, &io);
        t_check((ULONG)st != NS_INVALID_DEVICE_REQUEST, __FILE__, __LINE__, "scope code served", "%s: 0x%08lx", k_scope[i].name, (unsigned long)st);
        abl_close(s);
    }
}
TEST(ablc_scope_codes_empty_request_status) {
    /* a request with no input and no output on a bound stream endpoint: each is refused on its parameters,
     * except get-remote-address (no connection) and super-accept, whose block pointer is dereferenced */
    ABL_BEGIN();
    static const struct { ULONG code; ULONG st; } t[] = {
        { IO_BIND, NS_INVALID_PARAMETER }, { IO_START_LISTEN, NS_INVALID_PARAMETER }, { IO_WAIT_FOR_LISTEN, NS_INVALID_PARAMETER },
        { IO_ACCEPT, NS_INVALID_PARAMETER }, { IO_GET_ADDRESS, NS_INVALID_PARAMETER }, { IO_GET_REMOTE, NS_INVALID_CONNECTION },
        { IO_DEFER_ACCEPT, NS_INVALID_PARAMETER }, { IO_WAIT_LISTEN_LIFO, NS_INVALID_PARAMETER }, { IO_UNBIND_SOCKET, NS_INVALID_PARAMETER },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        SOCKET s = abl_bound(SOCK_STREAM, NULL); IO_STATUS_BLOCK io; LONG first;
        LONG st = abl_ctl(s, t[i].code, NULL, 0, NULL, 0, &io, &first);
        t_check((ULONG)st == t[i].st && (ULONG)first == t[i].st, __FILE__, __LINE__, "empty request", "code 0x%05lx: got 0x%08lx want 0x%08lx", (unsigned long)t[i].code, (unsigned long)st, (unsigned long)t[i].st);
        abl_close(s);
    }
}
TEST(ablc_empty_request_on_fresh_endpoint_status) {
    ABL_BEGIN();
    static const struct { ULONG code; ULONG st; } t[] = {
        { IO_BIND, NS_INVALID_PARAMETER }, { IO_START_LISTEN, NS_INVALID_PARAMETER }, { IO_WAIT_FOR_LISTEN, NS_INVALID_PARAMETER },
        { IO_ACCEPT, NS_INVALID_PARAMETER }, { IO_GET_ADDRESS, NS_INVALID_PARAMETER }, { IO_GET_REMOTE, NS_INVALID_CONNECTION },
        { IO_DEFER_ACCEPT, NS_INVALID_PARAMETER }, { IO_WAIT_LISTEN_LIFO, NS_INVALID_PARAMETER },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        SOCKET s = abl_tcp(); IO_STATUS_BLOCK io;
        LONG st = abl_ctl(s, t[i].code, NULL, 0, NULL, 0, &io, NULL);
        t_check((ULONG)st == t[i].st, __FILE__, __LINE__, "empty request", "code 0x%05lx: got 0x%08lx want 0x%08lx", (unsigned long)t[i].code, (unsigned long)st, (unsigned long)t[i].st);
        abl_close(s);
    }
}
