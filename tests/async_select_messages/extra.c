/* A few further WSAAsyncSelect edge cases: sockets created without the overlapped flag, repeated
 * cancel calls and cancel on a datagram socket, all checked through the posted-message log. */
#include "asm.h"

ATEST(asm_extra_non_overlapped_wsasocket_accepts_selection)
{
    HWND w = a_win(ASM_WIN_MSGONLY);
    SOCKET s;
    NEED(w && U(WSASocketW));
    s = U(WSASocketW)(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    NEED(s != INVALID_SOCKET);
    EQ(a_select(s, w, ASM_WM, FD_READ | FD_CLOSE), 0);
    EQ(a_select(s, w, 0, 0), 0);
    U(closesocket)(s);
}

ATEST(asm_extra_cancel_twice_succeeds_both_times)
{
    HWND w = a_win(ASM_WIN_MSGONLY);
    SOCKET s = a_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    NEED(w && s != INVALID_SOCKET);
    EQ(a_select(s, w, ASM_WM, FD_READ), 0);
    EQ(a_select(s, w, 0, 0), 0);
    EQ(a_select(s, w, 0, 0), 0);
}

ATEST(asm_extra_datagram_cancel_silences_arrival)
{
    HWND w = a_win(ASM_WIN_MSGONLY);
    SOCKET a, b; struct sockaddr_in aa, ba;
    NEED(w && a_udp_pair(&a, &b, &aa, &ba));
    EQ(a_select(b, w, ASM_WM, FD_READ), 0);
    EQ(a_select(b, w, 0, 0), 0);
    a_log_reset();
    EQ(U(sendto)(a, "x", 1, 0, (struct sockaddr *)&ba, sizeof ba), 1);
    EQ(a_quiet_for(b, ASM_WM, 300), 0);
}
