/* Additional endpoint-open checks: independence of repeated opens, duplicated handles, and close semantics.
 * Every expectation here is a plain success or a relation between two handles; no IO is issued. */
#include "aec.h"

TEST(aecz_two_opens_give_distinct_handles)
{
    ep_t e; HANDLE a, b; NEED(); ep_tcp4(&e);
    a = ep_ok(&e); b = ep_ok(&e);
    CHECK(a != NULL && b != NULL); CHECK(a != b);
    if (a) N.NtClose(a);
    if (b) N.NtClose(b);
}
TEST(aecz_close_succeeds_once)
{
    ep_t e; HANDLE h; NEED(); ep_udp4(&e);
    h = ep_ok(&e); if (!h) return;
    EXPECT_NT(N.NtClose(h), ST_SUCCESS);
}
TEST(aecz_duplicate_survives_original_close)
{
    ep_t e; HANDLE h, d = NULL; IO_STATUS_BLOCK io; ULONG m = 0; NEED(); ep_tcp4(&e);
    h = ep_ok(&e); if (!h) return;
    EXPECT_NT(N.NtDuplicateObject((HANDLE)-1, h, (HANDLE)-1, &d, 0, 0, 2 /* DUPLICATE_SAME_ACCESS */), ST_SUCCESS);
    EXPECT_NT(N.NtClose(h), ST_SUCCESS);
    if (d) {
        EXPECT_NT(N.NtQueryInformationFile(d, &io, &m, sizeof(m), FileModeInformation_), ST_SUCCESS);
        EXPECT_NT(N.NtClose(d), ST_SUCCESS);
    }
}
TEST(aecz_open_if_and_open_dispositions_same_for_packet)
{
    ep_t e; NEED(); ep_tcp4(&e);
    e.disp = 3; EXPECT_NT(ep_try(&e), ST_SUCCESS);
    e.disp = 1; EXPECT_NT(ep_try(&e), ST_SUCCESS);
}
TEST(aecz_all_stock_transports_open_in_sequence)
{
    ep_t e; NEED();
    ep_tcp4(&e); EXPECT_NT(ep_try(&e), ST_SUCCESS);
    ep_udp4(&e); EXPECT_NT(ep_try(&e), ST_SUCCESS);
    ep_tcp6(&e); EXPECT_NT(ep_try(&e), ST_SUCCESS);
    ep_udp6(&e); EXPECT_NT(ep_try(&e), ST_SUCCESS);
}
TEST(aecz_closed_handle_query_is_invalid_handle)
{
    ep_t e; HANDLE h; IO_STATUS_BLOCK io; ULONG m; NEED(); ep_tcp4(&e);
    h = ep_ok(&e); if (!h) return;
    N.NtClose(h);
    EXPECT_NT(N.NtQueryInformationFile(h, &io, &m, sizeof(m), FileModeInformation_), ST_INVALID_HANDLE);
}
