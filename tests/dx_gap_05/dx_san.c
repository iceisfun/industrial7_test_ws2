/* Guarded area: SAN helper-registration and handle-carrying control codes sent to ordinary endpoints.
 *
 * Registering a SAN service helper or announcing a provider change is a system-wide, process-lifetime
 * effect on a machine that has such a helper, so these requests are only sent from an elevated process and
 * only to endpoints that are not helper endpoints; every one of them is expected to be refused, and the
 * tests then check that nothing changed (the service-pid query still answers invalid-handle, a normal
 * listen/accept cycle still works). Nothing outside the test's own sockets is touched.
 *   0x12107 SAN_SET_SERVICE_PROCESS   0x1210b SAN_PROVIDER_CHANGE
 *   0x120d7 SAN_CEMENT_ENDPOINT       0x120db SAN_SET_EVENTS      0x120df SAN_RESET_EVENTS
 *   0x120e2 SAN_CONNECT               0x120e7 SAN_COMPLETE_ACCEPT 0x120eb SAN_COMPLETE_REQUEST
 *   0x120f3 SAN_REFRESH_ENDPOINT      0x120fb SAN_ACQUIRE_CONTEXT 0x120ff SAN_TRANSFER_CONTEXT */
#include "g5.h"   /* identical copy of the helpers in the gap_05 area */

static int elevated(void)
{
    HANDLE tok; TOKEN_ELEVATION e; DWORD n = 0; int r = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &e, sizeof e, &n)) r = e.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}
#define DX_BEGIN() do { G5_BEGIN(); if (!elevated()) { t_skip("needs an elevated token"); return; } } while (0)

TEST(gap5dx_san_set_service_process_refused_for_ordinary_endpoint)
{
    DX_BEGIN();
    SOCKET t = g5_tcp(), u = g5_udp(); unsigned char r[16]; memset(r, 0, sizeof r);
    EXPECT_NTS(g5_ctl(S(t), 0x12107, NULL, 0, NULL, 0, NULL, NULL), ST_INVALID_HANDLE);
    EXPECT_NTS(g5_ctl(S(u), 0x12107, r, sizeof r, r, sizeof r, NULL, NULL), ST_INVALID_HANDLE);
    EXPECT_NTS(g5_ctl(S(t), 0x12103, NULL, 0, r, sizeof r, NULL, NULL), ST_INVALID_HANDLE);   /* still no helper registered */
    g5_close(t); g5_close(u);
}
TEST(gap5dx_san_provider_change_refused_for_ordinary_endpoint)
{
    DX_BEGIN();
    SOCKET t = g5_tcp(); unsigned char r[16]; memset(r, 0, sizeof r);
    EXPECT_NTS(g5_ctl(S(t), 0x1210b, NULL, 0, NULL, 0, NULL, NULL), ST_INVALID_HANDLE);
    EXPECT_NTS(g5_ctl(S(t), 0x1210b, r, sizeof r, NULL, 0, NULL, NULL), ST_INVALID_HANDLE);
    g5_close(t);
}
TEST(gap5dx_san_requests_leave_normal_traffic_working)
{
    DX_BEGIN();
    SOCKET c, p, x = g5_tcp(); char b[4];
    EXPECT_NTS(g5_ctl(S(x), 0x12107, NULL, 0, NULL, 0, NULL, NULL), ST_INVALID_HANDLE);
    EXPECT_NTS(g5_ctl(S(x), 0x1210b, NULL, 0, NULL, 0, NULL, NULL), ST_INVALID_HANDLE);
    g5_close(x);
    g5_pair(&c, &p);
    int sent = W.send(c, "xyz", 3, 0), got;
    EXPECT_EQ(sent, 3);
    got = W.recv(p, b, sizeof b, 0);
    EXPECT_EQ(got, 3);
    g5_close(c); g5_close(p);
}

/* Records of adequate size filled with zeros: no helper, no handles, so each request is refused on a plain
 * endpoint. The statuses are recorded (and must be failures); they are properties of the SAN code path. */
static const struct { const char *name; ULONG code; ULONG len; } k_probe[] = {
    { "set_events", 0x120db, 0x18 }, { "reset_events", 0x120df, 0x18 }, { "complete_accept", 0x120e7, 0x20 },
    { "complete_request", 0x120eb, 0x20 }, { "refresh_endpoint", 0x120f3, 0x20 }, { "transfer_context", 0x120ff, 0x30 },
    { "connect", 0x120e2, 0x40 }, { "acquire_context", 0x120fb, 0x30 },
};
TEST(gap5dx_san_handle_requests_with_zero_records_fail)
{
    DX_BEGIN();
    for (int i = 0; i < 8; i++) {
        SOCKET t = g5_tcp(); unsigned char r[0x80], o[0x40]; IO_STATUS_BLOCK io;
        memset(r, 0, sizeof r); memset(o, 0, sizeof o);
        LONG st = g5_ctl(S(t), k_probe[i].code, r, k_probe[i].len, o, sizeof o, &io, NULL);
        t_note("%s with a zero record: failed=%d", k_probe[i].name, st < 0);
        t_check(st < 0, __FILE__, __LINE__, "refused", "%s: 0x%08lx", k_probe[i].name, (unsigned long)st);
        g5_close(t);
    }
}
TEST(gap5dx_san_cement_endpoint_needs_target_pointer)
{
    DX_BEGIN();
    /* a record whose second field is zero is refused as invalid-parameter; shorter than 0x10 as well */
    SOCKET t = g5_tcp(); unsigned char r[0x20]; memset(r, 0, sizeof r);
    EXPECT_NTS(g5_ctl(S(t), 0x120d7, r, sizeof r, NULL, 0, NULL, NULL), ST_INVALID_PARAMETER);
    EXPECT_NTS(g5_ctl(S(t), 0x120d7, r, 8, NULL, 0, NULL, NULL), ST_INVALID_PARAMETER);
    g5_close(t);
}
TEST(gap5dx_san_short_records_are_refused_not_fatal)
{
    DX_BEGIN();
    /* records shorter than the minimum raise an invalid-parameter status inside the driver; the request
     * must come back as that status and the system must carry on */
    for (int i = 0; i < 8; i++) {
        SOCKET t = g5_tcp(); unsigned char r[0x10]; memset(r, 0, sizeof r);
        LONG st = g5_ctl(S(t), k_probe[i].code, r, 4, NULL, 0, NULL, NULL);
        t_check(st == ST_INVALID_PARAMETER, __FILE__, __LINE__, "short record", "%s: 0x%08lx", k_probe[i].name, (unsigned long)st);
        g5_close(t);
    }
}
