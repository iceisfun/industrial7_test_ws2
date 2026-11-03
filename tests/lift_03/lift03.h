/* Shared helpers for the name-resolution / startup / provider-query tests in this area.
 * ws2_32 is never linked: every service is reached through U()/UN() function pointers. */
#ifndef LIFT03_H
#define LIFT03_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

#define ARRSZ(a) (sizeof(a) / sizeof((a)[0]))

/* services not declared (or declared differently) in the SDK headers */
UDECL(int, WSCGetApplicationCategory, (LPCWSTR path, DWORD pathlen, LPCWSTR extra, DWORD extralen, DWORD *category, LPINT err));
UDECL(int, WSCGetProviderInfo, (const GUID *provider, int infotype, BYTE *info, size_t *infosize, DWORD flags, LPINT err));
UDECL(int, GetAddrInfoExOverlappedResult, (LPOVERLAPPED ov));
UDECL(int, WSCGetProviderPath, (GUID *provider, WCHAR *path, LPINT pathlen, LPINT err));
UDECL(const char *, inet_ntop, (int af, const void *addr, char *buf, size_t len));

/* A WSAStartup(2.2) / WSACleanup() bracket so each test leaves the process reference count where it found it. */
static int l3_up(void)
{
    WSADATA d;
    if (!U(WSAStartup)) return -1;
    return U(WSAStartup)(0x202, &d);
}
static void l3_down(void) { if (U(WSACleanup)) U(WSACleanup)(); }
#define WSERR()    (U(WSAGetLastError)())
#define SETWSERR(e) (U(WSASetLastError)(e))

/* Compare two ASCII / wide address-info chains field by field; returns the number of mismatching fields. */
static int l3_cmp_ai_a(const ADDRINFOA *a, const ADDRINFOA *b)
{
    int bad = 0;
    for (; a && b; a = a->ai_next, b = b->ai_next) {
        bad += a->ai_flags != b->ai_flags;
        bad += a->ai_family != b->ai_family;
        bad += a->ai_socktype != b->ai_socktype;
        bad += a->ai_protocol != b->ai_protocol;
        bad += a->ai_addrlen != b->ai_addrlen;
        if (a->ai_addrlen == b->ai_addrlen && a->ai_addr && b->ai_addr)
            bad += memcmp(a->ai_addr, b->ai_addr, a->ai_addrlen) != 0;
        if (a->ai_canonname && b->ai_canonname) bad += strcmp(a->ai_canonname, b->ai_canonname) != 0;
        else bad += (a->ai_canonname != NULL) != (b->ai_canonname != NULL);
    }
    bad += (a != NULL) != (b != NULL);
    return bad;
}
static int l3_cmp_ai_w(const ADDRINFOW *a, const ADDRINFOW *b)
{
    int bad = 0;
    for (; a && b; a = a->ai_next, b = b->ai_next) {
        bad += a->ai_flags != b->ai_flags;
        bad += a->ai_family != b->ai_family;
        bad += a->ai_socktype != b->ai_socktype;
        bad += a->ai_protocol != b->ai_protocol;
        bad += a->ai_addrlen != b->ai_addrlen;
        if (a->ai_addrlen == b->ai_addrlen && a->ai_addr && b->ai_addr)
            bad += memcmp(a->ai_addr, b->ai_addr, a->ai_addrlen) != 0;
        if (a->ai_canonname && b->ai_canonname) bad += lstrcmpW(a->ai_canonname, b->ai_canonname) != 0;
        else bad += (a->ai_canonname != NULL) != (b->ai_canonname != NULL);
    }
    bad += (a != NULL) != (b != NULL);
    return bad;
}

/* getaddrinfo hint combinations: for each, the result code and (on success) the family/type/protocol every
 * returned entry must carry. */
struct l3_hint { int family, socktype, protocol; DWORD error; };
static const struct l3_hint l3_hints[] = {
    {AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, 0},  {AF_UNSPEC, SOCK_STREAM, IPPROTO_UDP, 0},
    {AF_UNSPEC, SOCK_STREAM, IPPROTO_IPV6, 0}, {AF_UNSPEC, SOCK_DGRAM, IPPROTO_TCP, 0},
    {AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, 0},   {AF_UNSPEC, SOCK_DGRAM, IPPROTO_IPV6, 0},
    {AF_INET, SOCK_STREAM, IPPROTO_TCP, 0},    {AF_INET, SOCK_STREAM, IPPROTO_UDP, 0},
    {AF_INET, SOCK_STREAM, IPPROTO_IPV6, 0},   {AF_INET, SOCK_DGRAM, IPPROTO_TCP, 0},
    {AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0},     {AF_INET, SOCK_DGRAM, IPPROTO_IPV6, 0},
    {AF_UNSPEC, 0, IPPROTO_TCP, 0},            {AF_UNSPEC, 0, IPPROTO_UDP, 0},
    {AF_UNSPEC, 0, IPPROTO_IPV6, 0},           {AF_UNSPEC, SOCK_STREAM, 0, 0},
    {AF_UNSPEC, SOCK_DGRAM, 0, 0},             {AF_INET, 0, IPPROTO_TCP, 0},
    {AF_INET, 0, IPPROTO_UDP, 0},              {AF_INET, 0, IPPROTO_IPV6, 0},
    {AF_INET, SOCK_STREAM, 0, 0},              {AF_INET, SOCK_DGRAM, 0, 0},
    {AF_UNSPEC, 999, IPPROTO_TCP, WSAESOCKTNOSUPPORT},  {AF_UNSPEC, 999, IPPROTO_UDP, WSAESOCKTNOSUPPORT},
    {AF_UNSPEC, 999, IPPROTO_IPV6, WSAESOCKTNOSUPPORT}, {AF_INET, 999, IPPROTO_TCP, WSAESOCKTNOSUPPORT},
    {AF_INET, 999, IPPROTO_UDP, WSAESOCKTNOSUPPORT},    {AF_INET, 999, IPPROTO_IPV6, WSAESOCKTNOSUPPORT},
    {AF_UNSPEC, SOCK_STREAM, 999, 0},          {AF_INET, SOCK_DGRAM, 999, 0},
};
#endif
