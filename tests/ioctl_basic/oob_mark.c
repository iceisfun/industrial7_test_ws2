/* Measures SIOCATMARK and FIONREAD while TCP urgent data is pending on a loopback stream pair: the mark
 * flag is reported as FALSE exactly while urgent data waits to be read (not inline), the byte count covers
 * ordinary data only, and the flag returns to TRUE once the urgent byte has been consumed.  With
 * SO_OOBINLINE the urgent byte becomes part of the byte count.  All waits are bounded polls. */
#include "ib.h"

static u_long ib_atmark(SOCKET s)
{
    u_long v = IB_UNSET;
    U(ioctlsocket)(s, SIOCATMARK, &v);
    return v;
}
static u_long ib_avail(SOCKET s)
{
    u_long v = IB_UNSET;
    U(ioctlsocket)(s, FIONREAD, &v);
    return v;
}
/* Poll (at most about 3 s) until the mark flag equals want. */
static int ib_wait_mark(SOCKET s, u_long want)
{
    int i;
    for (i = 0; i < 150; ++i) {
        if (ib_atmark(s) == want) return 1;
        Sleep(20);
    }
    return 0;
}
static int ib_wait_avail(SOCKET s, u_long want)
{
    int i;
    for (i = 0; i < 150; ++i) {
        if (ib_avail(s) == want) return 1;
        Sleep(20);
    }
    return 0;
}

IBTEST(ib_oob_pending_urgent_byte_clears_mark_flag)
{
    IB_PAIR(c, s);
    char b[8];
    CHECK(U(send)(s, "hello", 5, 0) == 5);
    CHECK(ib_wait_avail(c, 5));
    CHECKF(ib_atmark(c) == 1, "mark before urgent data: %lu", ib_atmark(c));
    CHECK(U(send)(s, "!", 1, MSG_OOB) == 1);
    CHECKF(ib_wait_mark(c, 0), "mark flag never dropped: %lu", ib_atmark(c));
    CHECKF(ib_avail(c) == 5, "avail with urgent byte pending: %lu", ib_avail(c));
    ib_close(c); ib_close(s);
    (void)b;
}

IBTEST(ib_oob_mark_returns_after_urgent_byte_is_read)
{
    IB_PAIR(c, s);
    char b[8];
    CHECK(U(send)(s, "a", 1, MSG_OOB) == 1);
    CHECK(ib_wait_mark(c, 0));
    CHECKF(ib_avail(c) == 0, "avail: %lu", ib_avail(c));
    CHECK(U(recv)(c, b, 1, MSG_OOB) == 1);
    CHECK(b[0] == 'a');
    CHECKF(ib_atmark(c) == 1, "mark after read: %lu", ib_atmark(c));
    CHECKF(ib_avail(c) == 0, "avail after read: %lu", ib_avail(c));
    ib_close(c); ib_close(s);
}

IBTEST(ib_oob_inline_urgent_byte_counts_as_data)
{
    IB_PAIR(c, s);
    char b[4];
    int one = 1;
    CHECK(U(send)(s, "a", 1, MSG_OOB) == 1);
    CHECK(ib_wait_mark(c, 0));
    CHECK(U(setsockopt)(c, SOL_SOCKET, SO_OOBINLINE, (char *)&one, sizeof one) == 0);
    CHECKF(ib_wait_avail(c, 1), "avail: %lu", ib_avail(c));
    CHECKF(ib_atmark(c) == 0, "mark with inline urgent byte unread: %lu", ib_atmark(c));
    CHECK(U(recv)(c, b, 1, 0) == 1);
    CHECK(b[0] == 'a');
    CHECKF(ib_atmark(c) == 1, "mark after inline read: %lu", ib_atmark(c));
    CHECKF(ib_avail(c) == 0, "avail after inline read: %lu", ib_avail(c));
    ib_close(c); ib_close(s);
}

IBTEST(ib_oob_wsaioctl_reports_mark_with_four_byte_output)
{
    IB_PAIR(c, s);
    DWORD v = IB_UNSET, n = IB_UNSET;
    int r;
    CHECK(U(send)(s, "a", 1, MSG_OOB) == 1);
    CHECK(ib_wait_mark(c, 0));
    ib_seterr(0);
    r = U(WSAIoctl)(c, IB_SIOCATMARK, NULL, 0, &v, 4, &n, NULL, NULL);
    CHECKF(r == 0 && v == 0 && n == 4, "r=%d v=%lu n=%lu", r, v, n);
    ib_close(c); ib_close(s);
}
