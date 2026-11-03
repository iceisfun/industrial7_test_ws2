/* Winsock Direct ("SAN") control codes on ordinary endpoints. The SAN service is gone from current
 * systems, so no endpoint is ever a SAN switch endpoint; what is observable is how each request answers
 * a plain TCP or UDP endpoint:
 *   0x120f7 SAN_GET_PHYSICAL_ADDR   always invalid-parameter
 *   0x12103 SAN_GET_SERVICE_PID     invalid-handle (the caller is not a SAN helper endpoint)
 *   0x1210c SAN_ADDR_LIST_CHANGE    invalid-parameter, nothing pended
 *   0x120ef SAN_COMPLETE_IO         record shorter than 0x10 refused
 * The requests that can change helper registration (0x12107, 0x1210b) and those whose records carry
 * handles live in the guarded dx_gap_05 area. */
#include "g5.h"

TEST(gap5_san_get_physical_addr_always_invalid_parameter)
{
    G5_BEGIN();
    SOCKET t = g5_tcp(), u = g5_bound(SOCK_DGRAM, NULL), l = g5_listener(NULL); unsigned char r[0x40]; memset(r, 0, sizeof r);
    SOCKET all[] = { t, u, l };
    for (int i = 0; i < 3; i++) {
        IO_STATUS_BLOCK io;
        EXPECT_NTS(g5_ctl(S(all[i]), 0x120f7, NULL, 0, NULL, 0, &io, NULL), ST_INVALID_PARAMETER);
        EXPECT_EQ(io.Information, 0);
        EXPECT_NTS(g5_ctl(S(all[i]), 0x120f7, r, sizeof r, r, sizeof r, NULL, NULL), ST_INVALID_PARAMETER);
        EXPECT_NTS(g5_ctl(S(all[i]), 0x120f7, r, 4, r, 4, NULL, NULL), ST_INVALID_PARAMETER);
    }
    g5_close(t); g5_close(u); g5_close(l);
}
TEST(gap5_san_get_service_pid_on_ordinary_endpoint_invalid_handle)
{
    G5_BEGIN();
    SOCKET t = g5_tcp(), u = g5_udp(), c, p; unsigned char r[16]; memset(r, 0, sizeof r);
    g5_pair(&c, &p);
    SOCKET all[] = { t, u, c, p };
    for (int i = 0; i < 4; i++) {
        IO_STATUS_BLOCK io;
        EXPECT_NTS(g5_ctl(S(all[i]), 0x12103, NULL, 0, r, sizeof r, &io, NULL), ST_INVALID_HANDLE);
        EXPECT_EQ(io.Information, 0);
        EXPECT_NTS(g5_ctl(S(all[i]), 0x12103, NULL, 0, NULL, 0, NULL, NULL), ST_INVALID_HANDLE);
    }
    g5_close(t); g5_close(u); g5_close(c); g5_close(p);
}
TEST(gap5_san_addr_list_change_on_ordinary_endpoint_invalid_parameter)
{
    G5_BEGIN();
    SOCKET t = g5_tcp(), u = g5_udp(); USHORT fam = AF_INET; unsigned char r[0x28];
    SOCKET all[] = { t, u };
    memset(r, 0, sizeof r); *(void **)(r + 8) = &fam; *(ULONG *)(r + 0x10) = 2; *(ULONG *)(r + 0x18) = 2;
    for (int i = 0; i < 2; i++) {
        IO_STATUS_BLOCK io; LONG first = 0;
        EXPECT_NTS(g5_ctl(S(all[i]), 0x1210c, r, sizeof r, NULL, 0, &io, &first), ST_INVALID_PARAMETER);
        EXPECT_NTS(first, ST_INVALID_PARAMETER);                 /* answered at once, nothing pended */
    }
    g5_close(t); g5_close(u);
}
TEST(gap5_san_complete_io_record_shorter_than_0x10_refused)
{
    G5_BEGIN();
    static const ULONG lens[] = { 0, 1, 4, 8, 0xf };
    SOCKET t = g5_tcp(); unsigned char r[0x20]; memset(r, 0, sizeof r);
    for (int i = 0; i < 5; i++) {
        IO_STATUS_BLOCK io;
        EXPECT_NTS(g5_ctl(S(t), 0x120ef, lens[i] ? r : NULL, lens[i], NULL, 0, &io, NULL), ST_INVALID_PARAMETER);
        EXPECT_EQ(io.Information, 0);
    }
    g5_close(t);
}
TEST(gap5_san_complete_io_full_record_accepted_on_any_endpoint)
{
    G5_BEGIN();
    /* the record is a status followed by an information value; completing "success, zero bytes" involves
     * no helper state and is answered with that status */
    SOCKET t = g5_tcp(); unsigned char r[0x10]; IO_STATUS_BLOCK io;
    memset(r, 0, sizeof r);
    LONG st = g5_ctl(S(t), 0x120ef, r, sizeof r, NULL, 0, &io, NULL);
    EXPECT_NTS(st, ST_SUCCESS);
    EXPECT_EQ(io.Information, 0);
    g5_close(t);
}
