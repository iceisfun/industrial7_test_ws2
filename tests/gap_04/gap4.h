/* Shared declarations for gap_04: the non-public exports of mswsock.dll (message lookup, setup migration, the
 * WSD proxy service pair and the embedded TCP/IP transport helper entry points Tcpip4_WSH* / Tcpip6_WSH*).
 * mswsock.dll is never linked: every entry point is reached with LoadLibrary -> GetProcAddress and called through
 * a pointer typed by the declarations below. ws2_32.dll is loaded dynamically too, only for sockets and startup. */
#ifndef GAP4_H
#define GAP4_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wchar.h>

#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { ULONG_PTR a_ = (ULONG_PTR)(a), b_ = (ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", (unsigned long long)a_, (unsigned long long)b_); } while (0)
#define G4N(a) (sizeof(a) / sizeof((a)[0]))

/* Winsock error numbers spelled numerically. */
#define G4_FAULT    10014
#define G4_INVAL    10022
#define G4_NOTSOCK  10038
#define G4_NOPROTOOPT 10042

static __inline FARPROC g4_ms(const char *name) { return t_proc_in("mswsock.dll", name); }
static __inline unsigned short g4_sw16(unsigned short v) { return (unsigned short)((v >> 8) | (v << 8)); }

/* Starts the stack once per process (dynamic); returns 1 when the stack is up. */
static __inline int g4_wsa_up(void)
{
    static int st;
    if (!st) {
        WSADATA d;
        typedef int (WSAAPI *su_fn)(WORD, LPWSADATA);
        su_fn f = (su_fn)t_proc_in("ws2_32.dll", "WSAStartup");
        st = (f && f(0x202, &d) == 0) ? 1 : -1;
    }
    return st > 0;
}

typedef INT (WINAPI *g4_open2_fn)(LPINT, LPINT, LPINT, GROUP, DWORD, PUNICODE_STRING, PVOID *, LPDWORD);
typedef INT (WINAPI *g4_open_fn)(LPINT, LPINT, LPINT, PUNICODE_STRING, PVOID *, LPDWORD);
typedef INT (WINAPI *g4_notify_fn)(PVOID, SOCKET, HANDLE, HANDLE, DWORD);
typedef INT (WINAPI *g4_getinfo_fn)(PVOID, SOCKET, HANDLE, HANDLE, INT, INT, PCHAR, LPINT);
typedef INT (WINAPI *g4_setinfo_fn)(PVOID, SOCKET, HANDLE, HANDLE, INT, INT, PCHAR, INT);
typedef INT (WINAPI *g4_join_fn)(PVOID, SOCKET, HANDLE, HANDLE, PVOID, SOCKET, PSOCKADDR, DWORD, LPWSABUF, LPWSABUF, PVOID, PVOID, DWORD);
typedef INT (WINAPI *g4_ioctl_fn)(PVOID, SOCKET, HANDLE, HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPVOID, LPVOID, LPBOOL);
typedef INT (WINAPI *g4_protoinfo_fn)(LPWSTR, WSAPROTOCOL_INFOW **, LPDWORD);
typedef INT (WINAPI *g4_a2s_fn)(LPSOCKADDR, INT, LPWSAPROTOCOL_INFOW, LPWSTR, LPDWORD);
typedef INT (WINAPI *g4_s2a_fn)(LPWSTR, DWORD, LPWSAPROTOCOL_INFOW, LPSOCKADDR, LPDWORD);
typedef INT (WINAPI *g4_enum_fn)(LPINT, LPWSTR, LPVOID, LPDWORD);

/* Per-family description of the embedded helper. */
typedef struct { const char *tag; const char *prefix; int af; const WCHAR *tdi_stream, *tdi_dgram; } g4_fam;
extern const g4_fam g4_v4, g4_v6;
void *g4_fn(const g4_fam *f, const char *suffix);   /* Tcpip<N>_WSH<suffix> from mswsock.dll, or NULL */
#endif
