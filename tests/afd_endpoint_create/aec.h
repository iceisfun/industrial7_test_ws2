/* Shared helpers for the AFD endpoint create/open tests.
 *
 * Nothing here links ntdll or ws2_32: NtCreateFile and the other Nt* calls are resolved with
 * GetProcAddress and invoked through pointers (the harness' UN() does the lookup).
 *
 * The contract measured by this area is the open-packet protocol between the Winsock helper layer
 * and the AFD driver: NtCreateFile on \Device\Afd\Endpoint carrying one extended attribute named
 * "AfdOpenPacketXX" whose value is { Flags, GroupID, AddressFamily, SocketType, Protocol,
 * TransportDeviceNameLength, TransportDeviceName[] }.
 */
#ifndef AEC_H
#define AEC_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

/* ---- NTSTATUS values the expectations use ---------------------------------- */
#define ST_SUCCESS                 ((LONG)0x00000000)
#define ST_PENDING                 ((LONG)0x00000103)
#define ST_EA_LIST_INCONSISTENT    ((LONG)0x80000014)
#define ST_INVALID_HANDLE          ((LONG)0xC0000008)
#define ST_INVALID_PARAMETER       ((LONG)0xC000000D)
#define ST_NO_SUCH_DEVICE          ((LONG)0xC000000E)
#define ST_NO_SUCH_FILE            ((LONG)0xC000000F)
#define ST_INVALID_DEVICE_REQUEST  ((LONG)0xC0000010)
#define ST_ACCESS_VIOLATION        ((LONG)0xC0000005)
#define ST_INFO_LENGTH_MISMATCH    ((LONG)0xC0000004)
#define ST_OBJECT_NAME_INVALID     ((LONG)0xC0000033)
#define ST_OBJECT_NAME_NOT_FOUND   ((LONG)0xC0000034)
#define ST_OBJECT_PATH_NOT_FOUND   ((LONG)0xC000003A)
#define ST_NOT_SUPPORTED           ((LONG)0xC00000BB)
#define ST_INVALID_PARAM_MIX       ((LONG)0xC0000030)
#define ST_ACCESS_DENIED           ((LONG)0xC0000022)
#define ST_INVALID_EA_NAME         ((LONG)0x80000013)
#define ST_NOT_IMPLEMENTED         ((LONG)0xC0000002)
#define ST_INVALID_INFO_CLASS      ((LONG)0xC0000003)
#define ST_PATH_SYNTAX_BAD         ((LONG)0xC000003B)
#define ST_AFD_UNSERVED            ((LONG)0xC000A013)   /* no transport serves the requested address family */

/* ---- AFD open packet ---------------------------------------------------------- */
#define AOP_CONNECTIONLESS  0x00000001u   /* datagram style endpoint */
#define AOP_MSG_ORIENTED    0x00000010u
#define AOP_RAW             0x00000100u
#define AOP_MULTIPOINT      0x00001000u
#define AOP_C_ROOT          0x00010000u
#define AOP_D_ROOT          0x00100000u
#define AOP_NO_FILTER       0x01000000u
#define AOP_RIO             0x10000000u

typedef struct {
    ULONG Flags, GroupID, Family, Type, Protocol, TdnLen;
    WCHAR Name[48];
} aop_t;

#define AOP_HDR  24                 /* bytes before TransportDeviceName */

/* How an open is described. Zero-initialise, then fill what matters; ep_defaults() fills the rest. */
typedef struct {
    ACCESS_MASK access;
    ULONG share, disp, options, attrs;
    const wchar_t *path;            /* NULL: \Device\Afd\Endpoint */
    HANDLE root;
    const char *ea_name;            /* NULL: AfdOpenPacketXX */
    int ea_name_len;                /* -1: strlen(ea_name) */
    aop_t pkt;
    int value_len;                  /* -1: derived from the packet (header + tdnl rounded + NUL) */
    int no_ea;                      /* 1: pass NULL/0 */
    int ea_total_adjust;            /* added to EaLength */
} ep_t;

typedef LONG (NTAPI *pNtCreateFile)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *, IO_STATUS_BLOCK *, LARGE_INTEGER *,
                                    ULONG, ULONG, ULONG, ULONG, void *, ULONG);
typedef LONG (NTAPI *pNtClose)(HANDLE);
typedef LONG (NTAPI *pNtQueryObject)(HANDLE, int, void *, ULONG, ULONG *);
typedef LONG (NTAPI *pNtQueryInformationFile)(HANDLE, IO_STATUS_BLOCK *, void *, ULONG, int);
typedef LONG (NTAPI *pNtSetInformationFile)(HANDLE, IO_STATUS_BLOCK *, void *, ULONG, int);
typedef LONG (NTAPI *pNtQueryVolumeInformationFile)(HANDLE, IO_STATUS_BLOCK *, void *, ULONG, int);
typedef LONG (NTAPI *pNtDeviceIoControlFile)(HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, ULONG, void *, ULONG, void *, ULONG);
typedef LONG (NTAPI *pNtFsControlFile)(HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, ULONG, void *, ULONG, void *, ULONG);
typedef LONG (NTAPI *pNtReadFile)(HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, void *, ULONG, LARGE_INTEGER *, ULONG *);
typedef LONG (NTAPI *pNtWriteFile)(HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, void *, ULONG, LARGE_INTEGER *, ULONG *);
typedef LONG (NTAPI *pNtDuplicateObject)(HANDLE, HANDLE, HANDLE, HANDLE *, ACCESS_MASK, ULONG, ULONG);
typedef LONG (NTAPI *pNtWaitForSingleObject)(HANDLE, BOOLEAN, LARGE_INTEGER *);
typedef LONG (NTAPI *pNtCancelIoFile)(HANDLE, IO_STATUS_BLOCK *);
typedef LONG (NTAPI *pNtOpenFile)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *, IO_STATUS_BLOCK *, ULONG, ULONG);

typedef struct {
    pNtCreateFile NtCreateFile; pNtClose NtClose; pNtQueryObject NtQueryObject;
    pNtQueryInformationFile NtQueryInformationFile; pNtSetInformationFile NtSetInformationFile;
    pNtQueryVolumeInformationFile NtQueryVolumeInformationFile;
    pNtDeviceIoControlFile NtDeviceIoControlFile; pNtFsControlFile NtFsControlFile;
    pNtReadFile NtReadFile; pNtWriteFile NtWriteFile;
    pNtDuplicateObject NtDuplicateObject; pNtWaitForSingleObject NtWaitForSingleObject;
    pNtCancelIoFile NtCancelIoFile; pNtOpenFile NtOpenFile;
    __typeof__(&WSAStartup) WSAStartup; __typeof__(&WSACleanup) WSACleanup;
    __typeof__(&WSAGetLastError) WSAGetLastError;
    __typeof__(&socket) socket; __typeof__(&WSASocketW) WSASocketW; __typeof__(&closesocket) closesocket;
    __typeof__(&bind) bind; __typeof__(&listen) listen; __typeof__(&connect) connect;
    __typeof__(&getsockname) getsockname; __typeof__(&setsockopt) setsockopt; __typeof__(&getsockopt) getsockopt;
    __typeof__(&ioctlsocket) ioctlsocket; __typeof__(&WSAIoctl) WSAIoctl;
} aec_fns;
extern aec_fns N;

int aec_ready(void);               /* resolve everything and start Winsock once; 0 if something is missing */
#define NEED() do { if (!aec_ready()) { t_skip("entry points unavailable"); return; } } while (0)

/* Fill pkt from the usual meaning (as the Winsock helper layer would for this family/type/proto). */
void ep_init(ep_t *e, ULONG family, ULONG type, ULONG proto, const wchar_t *tdname, ULONG flags);
/* TCP/UDP/raw over IPv4/IPv6 with the stock transport names and flags. */
void ep_tcp4(ep_t *e); void ep_udp4(ep_t *e); void ep_raw4(ep_t *e, ULONG proto);   /* name \Device\RawIp\<proto>, as the helper layer builds it */
void ep_raw4_bare(ep_t *e, ULONG proto); void ep_raw6_bare(ep_t *e, ULONG proto);  /* bare \Device\RawIp[6] */
void ep_tcp6(ep_t *e); void ep_udp6(ep_t *e); void ep_raw6(ep_t *e, ULONG proto);
/* Perform the open. *h is NULL on failure. io receives the status block. */
LONG ep_open(const ep_t *e, HANDLE *h, IO_STATUS_BLOCK *io);
/* Same with the result handle closed straight away; returns the status only. */
LONG ep_try(const ep_t *e);
/* Open then close; CHECK success and release. */
HANDLE ep_ok(const ep_t *e);

/* Create a raw EA buffer: one entry. Returns total length. cap is the buffer size. */
ULONG ea_one(unsigned char *buf, size_t cap, const char *name, int name_len, const void *val, int val_len);

#define EXPECT_NT(call, want) do { LONG st_ = (LONG)(call); \
    CHECKF(st_ == (LONG)(want), "got %#lx want %#lx", (unsigned long)st_, (unsigned long)(LONG)(want)); } while (0)

/* Mode information: FileModeInformation (16) -> ULONG Mode, access (8), position (14) */
#define FileBasicInformation_   4
#define FileStandardInformation_ 5
#define FileInternalInformation_ 6
#define FileEaInformation_       7
#define FileAccessInformation_   8
#define FileNameInformation_     9
#define FilePositionInformation_ 14
#define FileModeInformation_     16
#define FileAlignmentInformation_ 17
#define FileAllInformation_      18
#define FileNetworkOpenInformation_ 34
#define FileAttributeTagInformation_ 35

#define FSDEVICE_INFO 4

/* Handle of a freshly created socket through the real ws2_32 path with explicit flags. */
SOCKET ws_sock(int af, int type, int proto, DWORD flags);
#endif

/* One-row test: build a baseline packet, apply a mutation, expect an exact NTSTATUS from the open.
 *   EP_ROW(test_name, base_call, mutation_statement, expected_status)
 * The handle is closed again when the open unexpectedly succeeds. */
#define EP_ROW(tname, base, mut, want) \
    TEST(tname) { ep_t e; NEED(); base; mut; EXPECT_NT(ep_try(&e), want); }

/* An unelevated token is refused (access denied) where an elevated one succeeds: raw protocols other than
   ICMP/ICMPv6, and the device root without a leaf. */
int aec_is_elevated(void);
#define EP_ROW_ADMIN(tname, base, mut) \
    TEST(tname) { ep_t e; NEED(); base; mut; EXPECT_NT(ep_try(&e), aec_is_elevated() ? ST_SUCCESS : ST_ACCESS_DENIED); }

/* Server/workstation: the SKU-dependent rows only assert on client SKUs. */
int aec_is_client_sku(void);

/* Symbolic name for a status in the notes (deterministic text only). */
const char *st_name(LONG st);
/* OBJECT_BASIC_INFORMATION: NtQueryObject(class 0) insists on exactly this size (0x38 bytes). */
typedef struct { ULONG Attributes; ACCESS_MASK GrantedAccess; ULONG HandleCount, PointerCount;
    ULONG PagedPoolCharge, NonPagedPoolCharge, Reserved[3]; ULONG NameInfoSize, TypeInfoSize, SecuritySize;
    LARGE_INTEGER CreationTime; } objbasic_t;
