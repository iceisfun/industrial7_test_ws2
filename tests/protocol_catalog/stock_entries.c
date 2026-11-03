/* Contents of the stock transport catalog: the six base MSAFD entries (TCP, UDP, RAW over IPv4 and IPv6).
 * Measures, per entry and per property, the values every Windows 10 installation carries: provider id,
 * address sizes, version, byte order, security scheme, protocol range, service flags, provider flags and
 * chain length. The same table is run against the native catalog (WSCEnumProtocols) and the 32-bit
 * catalog (WSCEnumProtocols32). Display names are locale dependent and only recorded as notes. */
#include "pc.h"
#include <stdlib.h>

typedef struct {
    const char *tag;
    int af, type, proto;
    const GUID *id;
    int addr;          /* iMaxSockAddr == iMinSockAddr */
    int maxoff;        /* iProtocolMaxOffset */
    DWORD svc;         /* dwServiceFlags1 without the QOS bit */
    DWORD pflags;      /* required bits of dwProviderFlags */
    DWORD pflags_forbidden;
    int raw;
} row;

#define TCPF (XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER | XP1_GRACEFUL_CLOSE | XP1_EXPEDITED_DATA | XP1_IFS_HANDLES)
#define DGF  (XP1_CONNECTIONLESS | XP1_MESSAGE_ORIENTED | XP1_SUPPORT_BROADCAST | XP1_SUPPORT_MULTIPOINT | XP1_IFS_HANDLES)

static const row R[] = {
    { "tcp4", AF_INET,  SOCK_STREAM, IPPROTO_TCP, &pc_guid_tcpip4, 16, 0,   TCPF, PFL_MATCHES_PROTOCOL_ZERO, PFL_HIDDEN, 0 },
    { "udp4", AF_INET,  SOCK_DGRAM,  IPPROTO_UDP, &pc_guid_tcpip4, 16, 0,   DGF,  PFL_MATCHES_PROTOCOL_ZERO, PFL_HIDDEN, 0 },
    { "raw4", AF_INET,  SOCK_RAW,    0,           &pc_guid_tcpip4, 16, 255, DGF,  PFL_MATCHES_PROTOCOL_ZERO | PFL_HIDDEN, 0, 1 },
    { "tcp6", AF_INET6, SOCK_STREAM, IPPROTO_TCP, &pc_guid_tcpip6, 28, 0,   TCPF, PFL_MATCHES_PROTOCOL_ZERO, PFL_HIDDEN, 0 },
    { "udp6", AF_INET6, SOCK_DGRAM,  IPPROTO_UDP, &pc_guid_tcpip6, 28, 0,   DGF,  PFL_MATCHES_PROTOCOL_ZERO, PFL_HIDDEN, 0 },
    { "raw6", AF_INET6, SOCK_RAW,    0,           &pc_guid_tcpip6, 28, 255, DGF,  PFL_MATCHES_PROTOCOL_ZERO, 0, 1 },
};

static int load(int which, pc_list *l)
{
    int n = pc_enum_w(which, NULL, l);
    return n;
}

/* Run fn over every row of catalog `which`; the entry is found with chain length 1 (a base provider). */
typedef void (*row_fn)(const row *r, const WSAPROTOCOL_INFOW *e);
static void each_row(int which, row_fn fn)
{
    pc_list l; int i;
    if (load(which, &l) < 0) { t_skip("catalog enumeration failed"); return; }
    for (i = 0; i < PC_N(R); i++) {
        const WSAPROTOCOL_INFOW *e = pc_find(&l, R[i].af, R[i].type, R[i].proto, 1);
        CHECKF(e != NULL, "%s: base entry missing", R[i].tag);
        if (e) fn(&R[i], e);
    }
    pc_free(&l);
}

static void f_present(const row *r, const WSAPROTOCOL_INFOW *e) { (void)r; (void)e; }
static void f_id(const row *r, const WSAPROTOCOL_INFOW *e) { CHECKF(pc_guid_eq(&e->ProviderId, r->id), "%s: provider id", r->tag); }
static void f_addr(const row *r, const WSAPROTOCOL_INFOW *e)
{
    CHECKF(e->iMaxSockAddr == r->addr, "%s: iMaxSockAddr %d want %d", r->tag, e->iMaxSockAddr, r->addr);
    CHECKF(e->iMinSockAddr == r->addr, "%s: iMinSockAddr %d want %d", r->tag, e->iMinSockAddr, r->addr);
}
static void f_version(const row *r, const WSAPROTOCOL_INFOW *e) { CHECKF(e->iVersion == 2, "%s: iVersion %d", r->tag, e->iVersion); }
static void f_order(const row *r, const WSAPROTOCOL_INFOW *e) { CHECKF(e->iNetworkByteOrder == BIGENDIAN, "%s: byte order %d", r->tag, e->iNetworkByteOrder); }
static void f_security(const row *r, const WSAPROTOCOL_INFOW *e) { CHECKF(e->iSecurityScheme == SECURITY_PROTOCOL_NONE, "%s: security scheme %d", r->tag, e->iSecurityScheme); }
static void f_maxoff(const row *r, const WSAPROTOCOL_INFOW *e) { CHECKF(e->iProtocolMaxOffset == r->maxoff, "%s: max offset %d", r->tag, e->iProtocolMaxOffset); }
static void f_svc(const row *r, const WSAPROTOCOL_INFOW *e) { CHECKF((e->dwServiceFlags1 & ~XP1_QOS_SUPPORTED) == r->svc, "%s: service flags %lx want %lx", r->tag, e->dwServiceFlags1, r->svc); }
static void f_pflags(const row *r, const WSAPROTOCOL_INFOW *e)
{
    CHECKF((e->dwProviderFlags & r->pflags) == r->pflags, "%s: provider flags %lx lack %lx", r->tag, e->dwProviderFlags, r->pflags);
    CHECKF((e->dwProviderFlags & r->pflags_forbidden) == 0, "%s: provider flags %lx carry %lx", r->tag, e->dwProviderFlags, r->pflags_forbidden);
}
static void f_chain(const row *r, const WSAPROTOCOL_INFOW *e) { CHECKF(e->ProtocolChain.ChainLen == BASE_PROTOCOL, "%s: chain len %d", r->tag, e->ProtocolChain.ChainLen); }
static void f_reserved(const row *r, const WSAPROTOCOL_INFOW *e) { CHECKF(e->dwProviderReserved == 0, "%s: provider reserved %lx", r->tag, e->dwProviderReserved); }
static void f_family(const row *r, const WSAPROTOCOL_INFOW *e)
{
    CHECKF(e->iAddressFamily == r->af && e->iSocketType == r->type && e->iProtocol == r->proto, "%s: tuple", r->tag);
}
static void f_name(const row *r, const WSAPROTOCOL_INFOW *e)
{
    int i, term = 0;
    for (i = 0; i < WSAPROTOCOL_LEN + 1; i++) if (!e->szProtocol[i]) { term = 1; break; }
    CHECKF(term, "%s: name not terminated", r->tag);
    CHECKF(e->szProtocol[0] != 0, "%s: name empty", r->tag);
    t_note("%s display name: %ls", r->tag, e->szProtocol);
}
static void f_msgsize(const row *r, const WSAPROTOCOL_INFOW *e)
{
    if (r->type == SOCK_STREAM) CHECKF(e->dwMessageSize == 0, "%s: stream message size %lu", r->tag, e->dwMessageSize);
    else if (r->type == SOCK_DGRAM) CHECKF(e->dwMessageSize == 65527, "%s: datagram message size %lu", r->tag, e->dwMessageSize);
    else CHECKF(e->dwMessageSize == 32768, "%s: raw message size %lu", r->tag, e->dwMessageSize);
}
static void f_unique_id(const row *r, const WSAPROTOCOL_INFOW *e) { CHECKF(e->dwCatalogEntryId != 0, "%s: catalog id 0", r->tag); }

#define PROP(prop, ...) \
    TEST(stock_native_##prop) { PC_NEED_WSA(); each_row(1, f_##prop); } \
    TEST(stock_wow_##prop) { PC_NEED_WSA(); each_row(2, f_##prop); }

PROP(present) PROP(id) PROP(addr) PROP(version) PROP(order) PROP(security) PROP(maxoff) PROP(svc) PROP(pflags)
PROP(chain) PROP(reserved) PROP(family) PROP(name) PROP(msgsize) PROP(unique_id)

/* ---- cross-catalog relations ------------------------------------------------------------------ */
TEST(stock_wow_matches_native_for_base_entries)
{
    pc_list a, b; int i;
    PC_NEED_WSA();
    if (pc_enum_w(1, NULL, &a) < 0 || pc_enum_w(2, NULL, &b) < 0) { t_skip("enumeration failed"); return; }
    for (i = 0; i < PC_N(R); i++) {
        const WSAPROTOCOL_INFOW *x = pc_find(&a, R[i].af, R[i].type, R[i].proto, 1), *y = pc_find(&b, R[i].af, R[i].type, R[i].proto, 1);
        if (!x || !y) { CHECKF(0, "%s missing", R[i].tag); continue; }
        CHECKF(x->dwServiceFlags1 == y->dwServiceFlags1, "%s: service flags differ", R[i].tag);
        CHECKF(x->dwProviderFlags == y->dwProviderFlags, "%s: provider flags differ", R[i].tag);
        CHECKF(pc_guid_eq(&x->ProviderId, &y->ProviderId), "%s: provider id differs", R[i].tag);
        CHECKF(x->dwMessageSize == y->dwMessageSize, "%s: message size differs", R[i].tag);
    }
    pc_free(&a); pc_free(&b);
}

TEST(stock_v4_and_v6_share_one_provider_id_each)
{
    pc_list l; const WSAPROTOCOL_INFOW *t4, *u4, *t6, *u6;
    PC_NEED_WSA();
    if (pc_enum_w(1, NULL, &l) < 0) { t_skip("enumeration failed"); return; }
    t4 = pc_find(&l, AF_INET, SOCK_STREAM, 6, 1); u4 = pc_find(&l, AF_INET, SOCK_DGRAM, 17, 1);
    t6 = pc_find(&l, AF_INET6, SOCK_STREAM, 6, 1); u6 = pc_find(&l, AF_INET6, SOCK_DGRAM, 17, 1);
    if (t4 && u4 && t6 && u6) {
        CHECK(pc_guid_eq(&t4->ProviderId, &u4->ProviderId));
        CHECK(pc_guid_eq(&t6->ProviderId, &u6->ProviderId));
        CHECK(!pc_guid_eq(&t4->ProviderId, &t6->ProviderId));
    } else CHECK(0);
    pc_free(&l);
}

TEST(stock_base_entries_have_distinct_ids)
{
    pc_list l; int i, j;
    PC_NEED_WSA();
    if (pc_enum_w(1, NULL, &l) < 0) { t_skip("enumeration failed"); return; }
    for (i = 0; i < PC_N(R); i++) {
        const WSAPROTOCOL_INFOW *x = pc_find(&l, R[i].af, R[i].type, R[i].proto, 1);
        for (j = i + 1; j < PC_N(R) && x; j++) {
            const WSAPROTOCOL_INFOW *y = pc_find(&l, R[j].af, R[j].type, R[j].proto, 1);
            if (y) CHECKF(x->dwCatalogEntryId != y->dwCatalogEntryId, "%s and %s share a catalog id", R[i].tag, R[j].tag);
        }
    }
    pc_free(&l);
}

/* ---- whole-catalog invariants ----------------------------------------------------------------- */
TEST(stock_all_entries_ids_unique_and_nonzero)
{
    pc_list l; int i, j;
    PC_NEED_WSA();
    if (pc_enum_w(1, NULL, &l) < 0) { t_skip("enumeration failed"); return; }
    for (i = 0; i < l.n; i++) {
        CHECKF(l.e[i].dwCatalogEntryId != 0, "entry %d id 0", i);
        for (j = i + 1; j < l.n; j++) CHECKF(l.e[i].dwCatalogEntryId != l.e[j].dwCatalogEntryId, "entries %d/%d share id", i, j);
    }
    pc_free(&l);
}

TEST(stock_all_entries_have_provider_id)
{
    pc_list l; int i; GUID zero = {0};
    PC_NEED_WSA();
    if (pc_enum_w(1, NULL, &l) < 0) { t_skip("enumeration failed"); return; }
    for (i = 0; i < l.n; i++) CHECKF(!pc_guid_eq(&l.e[i].ProviderId, &zero), "entry %d has a null provider id", i);
    pc_free(&l);
}

TEST(stock_all_entries_chain_len_within_array)
{
    pc_list l; int i;
    PC_NEED_WSA();
    if (pc_enum_w(1, NULL, &l) < 0) { t_skip("enumeration failed"); return; }
    for (i = 0; i < l.n; i++) CHECKF(l.e[i].ProtocolChain.ChainLen >= 0 && l.e[i].ProtocolChain.ChainLen <= MAX_PROTOCOL_CHAIN, "entry %d chain len %d", i, l.e[i].ProtocolChain.ChainLen);
    pc_free(&l);
}

TEST(stock_chain_entries_refer_to_catalog_ids)
{
    pc_list l; int i, k, checked = 0;
    PC_NEED_WSA();
    if (pc_enum_w(1, NULL, &l) < 0) { t_skip("enumeration failed"); return; }
    for (i = 0; i < l.n; i++) {
        if (l.e[i].ProtocolChain.ChainLen <= 1) continue;
        for (k = 0; k < l.e[i].ProtocolChain.ChainLen; k++) {
            CHECKF(pc_by_id(&l, l.e[i].ProtocolChain.ChainEntries[k]) != NULL, "entry %d chain slot %d id %lu unknown", i, k, l.e[i].ProtocolChain.ChainEntries[k]);
            checked++;
        }
    }
    if (!checked) t_note("no multi-entry chains in this catalog");
    pc_free(&l);
}

TEST(stock_all_entries_named)
{
    pc_list l; int i;
    PC_NEED_WSA();
    if (pc_enum_w(1, NULL, &l) < 0) { t_skip("enumeration failed"); return; }
    for (i = 0; i < l.n; i++) CHECKF(l.e[i].szProtocol[0] != 0, "entry %d (id %lu) has no name", i, l.e[i].dwCatalogEntryId);
    pc_free(&l);
}

TEST(stock_provider_flag_bits_are_defined)
{
    pc_list l; int i;
    PC_NEED_WSA();
    if (pc_enum_w(1, NULL, &l) < 0) { t_skip("enumeration failed"); return; }
    for (i = 0; i < l.n; i++)
        if (l.e[i].dwProviderFlags & ~0x1fUL) t_note("entry %lu carries undocumented provider flag bits %lx", l.e[i].dwCatalogEntryId, l.e[i].dwProviderFlags);
    pc_free(&l);
}

/* Which families the catalog covers, recorded as information. */
TEST(stock_catalog_families_note)
{
    pc_list l; int i, fam[64] = {0};
    PC_NEED_WSA();
    if (pc_enum_w(1, NULL, &l) < 0) { t_skip("enumeration failed"); return; }
    for (i = 0; i < l.n; i++) if (l.e[i].iAddressFamily >= 0 && l.e[i].iAddressFamily < 64) fam[l.e[i].iAddressFamily]++;
    for (i = 0; i < 64; i++) if (fam[i]) t_note("family %d: %d entries", i, fam[i]);
    pc_free(&l);
}

/* Entries outside the IP families (local, Bluetooth, Hyper-V sockets and friends), recorded field by field. */
TEST(stock_non_ip_entries_note)
{
    pc_list l; int i;
    PC_NEED_WSA();
    if (pc_enum_w(1, NULL, &l) < 0) { t_skip("enumeration failed"); return; }
    for (i = 0; i < l.n; i++) {
        const WSAPROTOCOL_INFOW *e = &l.e[i];
        if (e->iAddressFamily == AF_INET || e->iAddressFamily == AF_INET6) continue;
        t_note("family %d type %d proto %d off %d addr %d/%d chain %d svc %lx pflags %lx msg %lu ver %d order %d sec %d",
               e->iAddressFamily, e->iSocketType, e->iProtocol, e->iProtocolMaxOffset, e->iMaxSockAddr, e->iMinSockAddr,
               e->ProtocolChain.ChainLen, e->dwServiceFlags1, e->dwProviderFlags, e->dwMessageSize, e->iVersion, e->iNetworkByteOrder, e->iSecurityScheme);
    }
    pc_free(&l);
}

/* IP-family entries beyond the six base ones, recorded the same way. */
TEST(stock_extra_ip_entries_note)
{
    pc_list l; int i, j;
    PC_NEED_WSA();
    if (pc_enum_w(1, NULL, &l) < 0) { t_skip("enumeration failed"); return; }
    for (i = 0; i < l.n; i++) {
        const WSAPROTOCOL_INFOW *e = &l.e[i];
        int base = 0;
        if (e->iAddressFamily != AF_INET && e->iAddressFamily != AF_INET6) continue;
        for (j = 0; j < PC_N(R); j++) if (e == pc_find(&l, R[j].af, R[j].type, R[j].proto, 1)) base = 1;
        if (base) continue;
        t_note("extra ip entry: family %d type %d proto %d off %d chain %d svc %lx pflags %lx msg %lu name %ls",
               e->iAddressFamily, e->iSocketType, e->iProtocol, e->iProtocolMaxOffset, e->ProtocolChain.ChainLen, e->dwServiceFlags1, e->dwProviderFlags, e->dwMessageSize, e->szProtocol);
    }
    pc_free(&l);
}
