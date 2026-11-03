/* Shared declarations for the ancillary-provider area: Winsock helper DLLs (wshtcpip, wship6, wshbth),
 * name-space providers (winrnr, napinsp, pnrpnsp, nlaapi) and the autodial helper (rasadhlp).
 * None of these libraries is linked: every entry point is reached with LoadLibrary -> GetProcAddress
 * and called through a pointer typed by the declarations below. */
#ifndef ANC_H
#define ANC_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2spi.h>
#include <wchar.h>

#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { ULONG_PTR a_ = (ULONG_PTR)(a), b_ = (ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", (unsigned long long)a_, (unsigned long long)b_); } while (0)

#undef htons
#undef htonl
#define htons(x) ((USHORT)((((x) & 0xff) << 8) | (((x) >> 8) & 0xff)))
#undef WSAGetLastError
#undef WSASetLastError
#define WSAGetLastError() ((int)GetLastError())
#define WSASetLastError(e) SetLastError((DWORD)(e))
#define ANC_N(a) (sizeof(a) / sizeof((a)[0]))

/* Winsock error numbers spelled numerically. */
#define E_FAULT      10014
#define E_INVAL      10022
#define E_NOPROTOOPT 10042
#define E_AFNOSUPPORT 10047
#define E_NOBUFS     10055
#define E_NOTINIT    10093
#define E_BADPROCTABLE 10104
#define E_BADPROVIDER 10105
#define E_NSP_NOTFOUND 10108
#define E_BADPROVIDERID 10108

typedef struct { DWORD AddressInfo; DWORD EndpointInfo; } anc_sockaddr_info;   /* SOCKADDR_INFO */
#define ADDR_NORMAL 0
#define ADDR_WILDCARD 1
#define ADDR_BROADCAST 2
#define ADDR_LOOPBACK 3
#define PORT_NORMAL 0
#define PORT_WILDCARD 1
#define PORT_RESERVED 2

typedef INT (WINAPI *pWSHGetSockaddrType)(PSOCKADDR, DWORD, anc_sockaddr_info *);
typedef INT (WINAPI *pWSHGetWildcardSockaddr)(PVOID, PSOCKADDR, LPINT);
typedef INT (WINAPI *pWSHGetBroadcastSockaddr)(PVOID, PSOCKADDR, LPINT);
typedef INT (WINAPI *pWSHOpenSocket2)(LPINT, LPINT, LPINT, GROUP, DWORD, PUNICODE_STRING, PVOID *, LPDWORD);
typedef INT (WINAPI *pWSHOpenSocket)(LPINT, LPINT, LPINT, PUNICODE_STRING, PVOID *, LPDWORD);
typedef DWORD (WINAPI *pWSHGetWinsockMapping)(PVOID, DWORD);
typedef INT (WINAPI *pWSHEnumProtocols)(LPINT, LPWSTR, LPVOID, LPDWORD);
typedef INT (WINAPI *pWSHGetProviderGuid)(LPWSTR, LPGUID);
typedef INT (WINAPI *pWSHAddressToString)(LPSOCKADDR, INT, LPWSAPROTOCOL_INFOW, LPWSTR, LPDWORD);
typedef INT (WINAPI *pWSHStringToAddress)(LPWSTR, DWORD, LPWSAPROTOCOL_INFOW, LPSOCKADDR, LPDWORD);
typedef INT (WINAPI *pWSHGetSocketInformation)(PVOID, SOCKET, HANDLE, HANDLE, INT, INT, PCHAR, LPINT);
typedef INT (WINAPI *pWSHSetSocketInformation)(PVOID, SOCKET, HANDLE, HANDLE, INT, INT, PCHAR, INT);
typedef INT (WINAPI *pWSHNotify)(PVOID, SOCKET, HANDLE, HANDLE, DWORD);
typedef INT (WINAPI *pWSHIoctl)(PVOID, SOCKET, HANDLE, HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE, LPBOOL);
typedef INT (WINAPI *pWSHGetWSAProtocolInfo)(LPWSTR, WSAPROTOCOL_INFOW **, LPDWORD);
typedef INT (WINAPI *pWSHJoinLeaf)(PVOID, SOCKET, HANDLE, HANDLE, PVOID, SOCKET, PSOCKADDR, DWORD, LPWSABUF, LPWSABUF, LPQOS, LPQOS, DWORD);

typedef struct {
    pWSHGetSockaddrType      GetSockaddrType;
    pWSHGetWildcardSockaddr  GetWildcardSockaddr;
    pWSHGetBroadcastSockaddr GetBroadcastSockaddr;
    pWSHOpenSocket2          OpenSocket2;
    pWSHOpenSocket           OpenSocket;
    pWSHGetWinsockMapping    GetWinsockMapping;
    pWSHEnumProtocols        EnumProtocols;
    pWSHGetProviderGuid      GetProviderGuid;
    pWSHAddressToString      AddressToString;
    pWSHStringToAddress      StringToAddress;
    pWSHGetSocketInformation GetSocketInformation;
    pWSHSetSocketInformation SetSocketInformation;
    pWSHNotify               Notify;
    pWSHIoctl                Ioctl;
    pWSHGetWSAProtocolInfo   GetWSAProtocolInfo;
    pWSHJoinLeaf             JoinLeaf;
    HMODULE mod;
} anc_wsh;

static inline FARPROC anc_proc(const char *dll, const char *name) { return t_proc_in(dll, name); }
/* Resolve the whole helper-DLL contract from one module; returns 0 when the module is absent. */
static inline int anc_load_wsh(anc_wsh *h, const char *dll) {
    memset(h, 0, sizeof *h);
    h->mod = t_module(dll);
    if (!h->mod) return 0;
#define R_(f) h->f = (pWSH##f)GetProcAddress(h->mod, "WSH" #f)
    R_(GetSockaddrType); R_(GetWildcardSockaddr); R_(GetBroadcastSockaddr); R_(OpenSocket2); R_(OpenSocket);
    R_(GetWinsockMapping); R_(EnumProtocols); R_(GetProviderGuid); R_(AddressToString); R_(StringToAddress);
    R_(GetSocketInformation); R_(SetSocketInformation); R_(Notify); R_(Ioctl); R_(GetWSAProtocolInfo); R_(JoinLeaf);
#undef R_
    return 1;
}

/* ---- per-helper description and shared helpers (anc_common.c) ---- */
typedef struct { const char *dll; int af; const char *tag; } anc_hinfo;
extern const anc_hinfo anc_tcp, anc_ip6, anc_bth;   /* wshtcpip.dll (IPv4), wship6.dll (IPv6), wshbth.dll (Bluetooth) */
/* Load the helper and resolve its exports; skips the running test (returns 0) when the module is absent. */
int anc_begin(anc_wsh *h, const anc_hinfo *hi);
PVOID anc_open_ctx(const anc_wsh *h, const anc_hinfo *hi, int ty, int pr);   /* WSHOpenSocket2 with defaults; NULL on failure */
void anc_close_ctx(const anc_wsh *h, PVOID ctx);                             /* WSHNotify(close) */
void anc_guid_str(char *out, const GUID *g);                                 /* upper-case braces form */
#define ANC_SENT 0xA5A5A5A5u
#define ANC_FILL 0xCC

/* Run the same body once per helper DLL. */
#define H3(name, fn) \
    TEST(name##_wshtcpip) { fn(&anc_tcp); } \
    TEST(name##_wship6)   { fn(&anc_ip6); } \
    TEST(name##_wshbth)   { fn(&anc_bth); }

#pragma pack(push, 1)
typedef struct { USHORT family; ULONGLONG bt_addr; GUID service; ULONG port; } anc_sockaddr_bth;   /* 30 bytes */
#pragma pack(pop)
typedef struct { DWORD service_flags; INT af; INT max_sockaddr; INT min_sockaddr; INT type; INT proto; DWORD message_size; WCHAR *name; } anc_protocol_info;   /* PROTOCOL_INFOW, 40 bytes */
#endif
