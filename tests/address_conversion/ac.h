/* Shared helpers for the address_conversion area (text <-> binary address conversion and byte order).
 * Everything in ws2_32 is reached through U()/t_proc_in(); nothing here links the library under test. */
#ifndef AC_H
#define AC_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2bth.h>
#include <wchar.h>

#define AC_COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define AC_NONE 0xffffffffUL
/* Four octets as inet_addr returns them: memory order a,b,c,d, i.e. network byte order in a ULONG. */
#define AC_RAW(a, b, c, d) ((unsigned long)((a) | ((b) << 8) | ((c) << 16) | ((unsigned long)(d) << 24)))

/* Error numbers spelled out so a table row reads the same as the documented value. */
#define AC_EFAULT   10014
#define AC_EINVAL   10022
#define AC_ENOTSOCK 10038
#define AC_EAFNOSUPPORT 10047
#define AC_NOTINIT  10093

typedef INT (WSAAPI *ac_pton_a_fn)(INT, PCSTR, PVOID);
typedef INT (WSAAPI *ac_pton_w_fn)(INT, PCWSTR, PVOID);
typedef PCSTR  (WSAAPI *ac_ntop_a_fn)(INT, const VOID *, PSTR, size_t);
typedef PCWSTR (WSAAPI *ac_ntop_w_fn)(INT, const VOID *, PWSTR, size_t);
typedef INT (WSAAPI *ac_s2a_a_fn)(LPSTR, INT, LPWSAPROTOCOL_INFOA, LPSOCKADDR, LPINT);
typedef INT (WSAAPI *ac_s2a_w_fn)(LPWSTR, INT, LPWSAPROTOCOL_INFOW, LPSOCKADDR, LPINT);
typedef INT (WSAAPI *ac_a2s_a_fn)(LPSOCKADDR, DWORD, LPWSAPROTOCOL_INFOA, LPSTR, LPDWORD);
typedef INT (WSAAPI *ac_a2s_w_fn)(LPSOCKADDR, DWORD, LPWSAPROTOCOL_INFOW, LPWSTR, LPDWORD);

#define AC_PTON_A ((ac_pton_a_fn)t_proc_in("ws2_32.dll", "inet_pton"))
#define AC_PTON_W ((ac_pton_w_fn)t_proc_in("ws2_32.dll", "InetPtonW"))
#define AC_NTOP_A ((ac_ntop_a_fn)t_proc_in("ws2_32.dll", "inet_ntop"))
#define AC_NTOP_W ((ac_ntop_w_fn)t_proc_in("ws2_32.dll", "InetNtopW"))
#define AC_S2A_A  ((ac_s2a_a_fn)t_proc_in("ws2_32.dll", "WSAStringToAddressA"))
#define AC_S2A_W  ((ac_s2a_w_fn)t_proc_in("ws2_32.dll", "WSAStringToAddressW"))
#define AC_A2S_A  ((ac_a2s_a_fn)t_proc_in("ws2_32.dll", "WSAAddressToStringA"))
#define AC_A2S_W  ((ac_a2s_w_fn)t_proc_in("ws2_32.dll", "WSAAddressToStringW"))

/* WSAStartup(2.2) once per process; nonzero when the library is usable. */
int ac_startup(void);
/* Decode 2*n hex digits into out[n]. */
void ac_unhex(const char *hex, unsigned char *out, size_t n);
/* Widen plain ASCII. */
void ac_widen(const char *s, WCHAR *w, size_t cap);
/* Eight IPv6 groups given as the numbers written in the text form -> 16 network-order bytes. */
void ac_groups(const unsigned short g[8], unsigned char out[16]);
/* Raw sockaddr builders (layout written out byte by byte, not through the SDK structs). */
void ac_raw_v4(unsigned char sa[16], unsigned short port_host, const unsigned char ip[4]);
void ac_raw_v6(unsigned char sa[28], unsigned short port_host, unsigned long flow_host,
               const unsigned char ip[16], unsigned long scope_host);

#define AC_NEED_WSA() do { if (!ac_startup()) { t_skip("WSAStartup failed"); return; } } while (0)
#endif
