/* WSAIoctl forms of the classic socket controls on AF_UNIX, plus extension-function lookup and the
 * overlapped/completion-routine forms of an ioctl. The classic commands behave the same through ioctlsocket and
 * WSAIoctl; the extension-function table is the stack-wide one. */
#include "xud.h"

TEST(xud_ioctl_wsaioctl_fionread_counts_pending)
{
    u_long n = 99;
    DWORD ret = 0;
    TRIO(t, "io1.sock");
    XEQ(U(send)(t.cli, "12345", 5, 0), 5);
    CHECK(x_readable(t.srv, 3000));
    XEQ(U(WSAIoctl)(t.srv, FIONREAD, NULL, 0, &n, sizeof n, &ret, NULL, NULL), 0);
    XEQ(n, 5);
    XEQ(ret, 4);
    x_trio_close(&t);
}
TEST(xud_ioctl_wsaioctl_fionbio_switches_mode)
{
    u_long on = 1, off = 0;
    DWORD ret = 0;
    char b[4];
    TRIO(t, "io2.sock");
    XEQ(U(WSAIoctl)(t.srv, FIONBIO, &on, sizeof on, NULL, 0, &ret, NULL, NULL), 0);
    XEQ(U(recv)(t.srv, b, sizeof b, 0), -1);
    XEQ(x_err(), WSAEWOULDBLOCK);
    XEQ(U(WSAIoctl)(t.srv, FIONBIO, &off, sizeof off, NULL, 0, &ret, NULL, NULL), 0);
    x_rcvtimeo(t.srv, 150);
    XEQ(U(recv)(t.srv, b, sizeof b, 0), -1);
    XEQ(x_err(), WSAETIMEDOUT);                              /* blocking again: the timeout, not WOULDBLOCK */
    x_trio_close(&t);
}
TEST(xud_ioctl_wsaioctl_siocatmark_true)
{
    u_long v = 5;
    DWORD ret = 0;
    TRIO(t, "io3.sock");
    XEQ(U(WSAIoctl)(t.srv, SIOCATMARK, NULL, 0, &v, sizeof v, &ret, NULL, NULL), 0);
    XEQ(v, 1);
    x_trio_close(&t);
}
TEST(xud_ioctl_wsaioctl_unknown_code_is_notsupp)
{
    DWORD ret = 0;
    char out[16];
    TRIO(t, "io4.sock");
    XEQ(U(WSAIoctl)(t.cli, 0x98765432, NULL, 0, out, sizeof out, &ret, NULL, NULL), -1);
    XEQ(x_err(), WSAEOPNOTSUPP);
    x_trio_close(&t);
}
TEST(xud_ioctl_wsaioctl_null_bytes_returned_is_fault)
{
    u_long n;
    TRIO(t, "io5.sock");
    XEQ(U(WSAIoctl)(t.srv, FIONREAD, NULL, 0, &n, sizeof n, NULL, NULL, NULL), -1);
    XEQ(x_err(), WSAEFAULT);
    x_trio_close(&t);
}
TEST(xud_ioctl_wsaioctl_after_close_is_notsock)
{
    u_long n;
    DWORD ret;
    TRIO(t, "io6.sock");
    U(closesocket)(t.cli);
    XEQ(U(WSAIoctl)(t.cli, FIONREAD, NULL, 0, &n, sizeof n, &ret, NULL, NULL), -1);
    XEQ(x_err(), WSAENOTSOCK);
    t.cli = INVALID_SOCKET;
    x_trio_close(&t);
}
TEST(xud_ioctl_extension_lookup_is_identical_across_families)
{
    SOCKET u, i;
    void *fu = NULL, *fi = NULL;
    GUID g = WSAID_CONNECTEX;
    DWORD n = 0;
    UP();
    u = x_sock();
    i = U(WSASocketW)(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (u == INVALID_SOCKET || i == INVALID_SOCKET) { t_skip("sockets unavailable"); if (u != INVALID_SOCKET) U(closesocket)(u); if (i != INVALID_SOCKET) U(closesocket)(i); return; }
    XEQ(U(WSAIoctl)(u, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &fu, sizeof fu, &n, NULL, NULL), 0);
    XEQ(n, sizeof fu);
    XEQ(U(WSAIoctl)(i, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &fi, sizeof fi, &n, NULL, NULL), 0);
    CHECK(fu != NULL && fu == fi);
    U(closesocket)(u); U(closesocket)(i);
}
TEST(xud_ioctl_extension_lookup_small_output_is_fault)
{
    GUID g = WSAID_ACCEPTEX;
    char small[2];
    DWORD n = 0;
    TRIO(t, "io7.sock");
    XEQ(U(WSAIoctl)(t.lis, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, small, sizeof small, &n, NULL, NULL), -1);
    XEQ(x_err(), WSAEFAULT);
    x_trio_close(&t);
}
TEST(xud_ioctl_extension_lookup_unknown_guid_is_inval)
{
    GUID g = { 0x12345678, 0x1234, 0x1234, { 1, 2, 3, 4, 5, 6, 7, 8 } };
    void *fn = (void *)1;
    DWORD n = 0;
    TRIO(t, "io8.sock");
    XEQ(U(WSAIoctl)(t.lis, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &fn, sizeof fn, &n, NULL, NULL), -1);
    XEQ(x_err(), WSAEINVAL);
    x_trio_close(&t);
}
TEST(xud_ioctl_overlapped_fionread_with_event)
{
    u_long n = 99;
    DWORD ret = 0, tr = 0, fl = 0;
    WSAOVERLAPPED ov;
    int r;
    TRIO(t, "io9.sock");
    XEQ(U(send)(t.cli, "abc", 3, 0), 3);
    CHECK(x_readable(t.srv, 3000));
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    r = U(WSAIoctl)(t.srv, FIONREAD, NULL, 0, &n, sizeof n, &ret, &ov, NULL);
    CHECK(r == 0 || x_err() == WSA_IO_PENDING);
    CHECK(U(WSAGetOverlappedResult)(t.srv, &ov, &tr, TRUE, &fl));
    XEQ(n, 3);
    CloseHandle(ov.hEvent);
    x_trio_close(&t);
}
