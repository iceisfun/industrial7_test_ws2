/* Overlapped I/O matrix: every operation that can be issued with an OVERLAPPED on a socket, crossed with the
 * completion styles (event, event with the low bit set, completion routine, completion port, completion port
 * with FILE_SKIP_COMPLETION_PORT_ON_SUCCESS and/or FILE_SKIP_SET_EVENT_ON_HANDLE), the socket's overlapped
 * attribute, request already satisfiable versus pending, and the way a pending request ends (data/peer action,
 * CancelIoEx, closesocket). Each case is reduced to a line of observations (see xom.h) compared with expect.inc. */
#include "xom.h"

#define R2(name, OP) \
    TEST(name##_ready_ovl)          { xom_grid(OP, 1, FIN_COMPLETE, 1); } \
    TEST(name##_ready_plain)        { xom_grid(OP, 1, FIN_COMPLETE, 0); } \
    TEST(name##_fails_at_once)      { xom_grid(OP, 2, FIN_COMPLETE, 1); }
#define P2(name, OP) \
    TEST(name##_pending_cancelex)   { xom_grid(OP, 0, FIN_CANCEL, 1); } \
    TEST(name##_pending_closesock)  { xom_grid(OP, 0, FIN_CLOSE, 1); }
#define P3(name, OP) \
    TEST(name##_pending_completes)  { xom_grid(OP, 0, FIN_COMPLETE, 1); } \
    P2(name, OP)

R2(send, OP_SEND)               P3(send, OP_SEND)
R2(recv, OP_RECV)               P3(recv, OP_RECV)
R2(sendto, OP_SENDTO)
R2(recvfrom, OP_RECVFROM)       P3(recvfrom, OP_RECVFROM)
R2(sendmsg, OP_SENDMSG)
R2(recvmsg, OP_RECVMSG)         P3(recvmsg, OP_RECVMSG)
P2(ioctl_addrchange, OP_ALC)
R2(ioctl_extptr, OP_EXT)
R2(ioctl_addrquery, OP_ALQ)
R2(acceptex, OP_ACCEPTEX)       P3(acceptex, OP_ACCEPTEX)
R2(connectex, OP_CONNECTEX)     P2(connectex, OP_CONNECTEX)
R2(disconnectex, OP_DISCONNECTEX)
R2(transmitfile, OP_TRANSMIT)
R2(readfile, OP_READFILE)       P3(readfile, OP_READFILE)
R2(writefile, OP_WRITEFILE)     P3(writefile, OP_WRITEFILE)
R2(readfileex, OP_READFILEEX)   P3(readfileex, OP_READFILEEX)
R2(writefileex, OP_WRITEFILEEX) P3(writefileex, OP_WRITEFILEEX)
