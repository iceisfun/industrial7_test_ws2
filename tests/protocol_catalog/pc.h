/* Shared helpers for the protocol_catalog area (Winsock protocol and namespace catalogs).
 * ws2_32 is never linked: every service is reached through U()/UIN()/UN() function pointers. */
#ifndef PC_H
#define PC_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2spi.h>

#define PC_N(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* Layout facts the corpus relies on (the structures are ABI, not preference). */
#define PC_INFOW_SIZE 628
#define PC_INFOA_SIZE 372

/* Well-known provider ids of the stock IPv4 / IPv6 base providers. */
extern const GUID pc_guid_tcpip4, pc_guid_tcpip6;
/* Well-known namespace provider id of the DNS namespace. */
extern const GUID pc_guid_ns_dns;

/* Throwaway ids that no catalog contains. */
extern const GUID pc_guid_unknown_a, pc_guid_unknown_b;

/* WSAStartup(2.2) once for the process. Nonzero when sockets are usable; never torn down. */
int pc_up(void);
#define PC_NEED_WSA() do { if (!pc_up()) { t_skip("WSAStartup failed"); return; } } while (0)

typedef struct { WSAPROTOCOL_INFOW *e; int n; DWORD bytes; } pc_list;

/* Enumerate through the named exports (NULL filter = everything). Return the entry count, -1 on failure.
 * The caller releases with pc_free(). which: 0 WSAEnumProtocolsW, 1 WSCEnumProtocols, 2 WSCEnumProtocols32. */
int pc_enum_w(int which, INT *filter, pc_list *out);
/* ANSI catalog through WSAEnumProtocolsA; out->e is an array of WSAPROTOCOL_INFOA. */
int pc_enum_a(INT *filter, WSAPROTOCOL_INFOA **out);
void pc_free(pc_list *l);

int pc_guid_eq(const GUID *a, const GUID *b);
/* First entry matching family/type/proto with the given chain length (any when chain < 0); NULL when none. */
const WSAPROTOCOL_INFOW *pc_find(const pc_list *l, int af, int type, int proto, int chain);
/* Catalog id lookup. */
const WSAPROTOCOL_INFOW *pc_by_id(const pc_list *l, DWORD id);
/* The protocol-number filter predicate shared by both enumeration families. */
int pc_in_range(const WSAPROTOCOL_INFOW *e, int proto);
/* Raw wide-string equality ignoring case. */
int pc_wieq(const WCHAR *a, const WCHAR *b);
#endif
