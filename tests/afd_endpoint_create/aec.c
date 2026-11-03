/* Implementation of the helpers declared in aec.h. */
#include "aec.h"

aec_fns N;
static int g_ready = -1;

int aec_ready(void)
{
    if (g_ready >= 0) return g_ready;
    g_ready = 0;
    HMODULE nt = t_module("ntdll.dll"), ws = t_module("ws2_32.dll");
    if (!nt || !ws) return 0;
#define NT(n) do { N.n = (p##n)GetProcAddress(nt, #n); if (!N.n) return 0; } while (0)
    NT(NtCreateFile); NT(NtClose); NT(NtQueryObject); NT(NtQueryInformationFile); NT(NtSetInformationFile);
    NT(NtQueryVolumeInformationFile); NT(NtDeviceIoControlFile); NT(NtFsControlFile); NT(NtReadFile);
    NT(NtWriteFile); NT(NtDuplicateObject); NT(NtWaitForSingleObject); NT(NtCancelIoFile); NT(NtOpenFile);
#undef NT
#define WS(n) do { N.n = (__typeof__(N.n))GetProcAddress(ws, #n); if (!N.n) return 0; } while (0)
    WS(WSAStartup); WS(WSACleanup); WS(WSAGetLastError);
    WS(socket); WS(closesocket); WS(bind); WS(listen); WS(connect);
    WS(getsockname); WS(setsockopt); WS(getsockopt); WS(ioctlsocket); WS(WSAIoctl);
#undef WS
    N.WSASocketW = (__typeof__(N.WSASocketW))GetProcAddress(ws, "WSASocketW");
    if (!N.WSASocketW) return 0;
    WSADATA d;
    if (N.WSAStartup(MAKEWORD(2, 2), &d) != 0) return 0;
    g_ready = 1;
    return 1;
}

void ep_init(ep_t *e, ULONG family, ULONG type, ULONG proto, const wchar_t *tdname, ULONG flags)
{
    memset(e, 0, sizeof(*e));
    e->access = 0xC0140000u;       /* GENERIC_READ|GENERIC_WRITE|WRITE_DAC|SYNCHRONIZE as the helper layer asks */
    e->share = 3;                  /* FILE_SHARE_READ|FILE_SHARE_WRITE */
    e->disp = 3;                   /* FILE_OPEN_IF */
    e->options = 0;                /* overlapped style */
    e->attrs = OBJ_CASE_INSENSITIVE | OBJ_INHERIT;
    e->ea_name_len = -1;
    e->value_len = -1;
    e->pkt.Flags = flags; e->pkt.Family = family; e->pkt.Type = type; e->pkt.Protocol = proto;
    if (tdname) {
        size_t n = wcslen(tdname);
        wcscpy(e->pkt.Name, tdname);
        e->pkt.TdnLen = (ULONG)(n * 2);
    }
}
void ep_tcp4(ep_t *e) { ep_init(e, 2, 1, 6, L"\\Device\\Tcp", 0); }
void ep_udp4(ep_t *e) { ep_init(e, 2, 2, 17, L"\\Device\\Udp", AOP_CONNECTIONLESS | AOP_MSG_ORIENTED); }
static void raw_named(ep_t *e, ULONG fam, ULONG proto, const wchar_t *base, int bare)
{
    wchar_t nm[48];
    if (bare) wcscpy(nm, base); else swprintf(nm, 48, L"%ls\\%lu", base, proto);
    ep_init(e, fam, 3, proto, nm, AOP_CONNECTIONLESS | AOP_MSG_ORIENTED | AOP_RAW);
}
void ep_raw4(ep_t *e, ULONG proto) { raw_named(e, 2, proto, L"\\Device\\RawIp", 0); }
void ep_raw4_bare(ep_t *e, ULONG proto) { raw_named(e, 2, proto, L"\\Device\\RawIp", 1); }
void ep_raw6_bare(ep_t *e, ULONG proto) { raw_named(e, 23, proto, L"\\Device\\RawIp6", 1); }
void ep_tcp6(ep_t *e) { ep_init(e, 23, 1, 6, L"\\Device\\Tcp6", 0); }
void ep_udp6(ep_t *e) { ep_init(e, 23, 2, 17, L"\\Device\\Udp6", AOP_CONNECTIONLESS | AOP_MSG_ORIENTED); }
void ep_raw6(ep_t *e, ULONG proto) { raw_named(e, 23, proto, L"\\Device\\RawIp6", 0); }

ULONG ea_one(unsigned char *buf, size_t cap, const char *name, int name_len, const void *val, int val_len)
{
    size_t nl = name_len < 0 ? strlen(name) : (size_t)name_len;
    size_t total = 8 + nl + 1 + (size_t)val_len;
    if (total > cap) return 0;
    memset(buf, 0, total);
    *(ULONG *)buf = 0;                       /* NextEntryOffset */
    buf[4] = 0;                              /* Flags */
    buf[5] = (unsigned char)nl;
    *(USHORT *)(buf + 6) = (USHORT)val_len;
    memcpy(buf + 8, name, nl);
    buf[8 + nl] = 0;
    if (val_len > 0 && val) memcpy(buf + 8 + nl + 1, val, (size_t)val_len);
    return (ULONG)total;
}

LONG ep_open(const ep_t *e, HANDLE *h, IO_STATUS_BLOCK *io)
{
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    unsigned char buf[512];
    ULONG ealen = 0;
    const wchar_t *path = e->path ? e->path : L"\\Device\\Afd\\Endpoint";
    *h = NULL;
    memset(io, 0xAB, sizeof(*io));
    us.Buffer = (PWSTR)path; us.Length = (USHORT)(wcslen(path) * 2); us.MaximumLength = us.Length + 2;
    InitializeObjectAttributes(&oa, &us, e->attrs, e->root, NULL);
    if (!e->no_ea) {
        int vl = e->value_len;
        if (vl < 0) {
            /* derived length: the packet header plus the name rounded up to an even size plus a terminator
             * slot, never below the 28-byte minimum the driver insists on; huge declared names clamp */
            unsigned long long need = (unsigned long long)AOP_HDR + (((unsigned long long)e->pkt.TdnLen + 2) & ~1ull);
            vl = need > 120 ? 120 : (int)need;
            if (vl < 28) vl = 28;
        }
        if (vl > (int)sizeof(e->pkt)) vl = (int)sizeof(e->pkt);  /* never read past the struct */
        const char *nm = e->ea_name ? e->ea_name : "AfdOpenPacketXX";
        /* the declared value length may exceed what the struct holds: pad with zero */
        unsigned char val[sizeof(aop_t) + 64];
        memset(val, 0, sizeof(val));
        memcpy(val, &e->pkt, sizeof(e->pkt));
        int declared = e->value_len < 0 ? vl : e->value_len;
        if (declared > (int)sizeof(val)) declared = (int)sizeof(val);
        ealen = ea_one(buf, sizeof(buf), nm, e->ea_name_len, val, declared);
        ealen = (ULONG)((int)ealen + e->ea_total_adjust);
    }
    HANDLE hh = NULL;
    LONG st = N.NtCreateFile(&hh, e->access, &oa, io, NULL, 0, e->share, e->disp, e->options,
                             e->no_ea ? NULL : buf, e->no_ea ? 0 : ealen);
    if (st >= 0) *h = hh;
    return st;
}

LONG ep_try(const ep_t *e)
{
    HANDLE h; IO_STATUS_BLOCK io;
    LONG st = ep_open(e, &h, &io);
    if (h) N.NtClose(h);
    return st;
}

HANDLE ep_ok(const ep_t *e)
{
    HANDLE h; IO_STATUS_BLOCK io;
    LONG st = ep_open(e, &h, &io);
    CHECKF(st >= 0 && h, "open failed %#lx", (unsigned long)st);
    return h;
}

SOCKET ws_sock(int af, int type, int proto, DWORD flags)
{
    return N.WSASocketW(af, type, proto, NULL, 0, flags);
}

typedef struct { ULONG sz, maj, min, build, plat; WCHAR csd[128]; USHORT spmaj, spmin, suite; UCHAR ptype, res; } osvi_t;
int aec_is_client_sku(void)
{
    HMODULE nt = t_module("ntdll.dll");
    LONG (NTAPI *rgv)(osvi_t *) = nt ? (LONG (NTAPI *)(osvi_t *))GetProcAddress(nt, "RtlGetVersion") : NULL;
    osvi_t v;
    if (!rgv) return 0;
    memset(&v, 0, sizeof(v)); v.sz = sizeof(v);
    if (rgv(&v) < 0) return 0;
    return v.ptype == 1;      /* VER_NT_WORKSTATION */
}

int aec_is_elevated(void)
{
    HANDLE tok = NULL; DWORD elev = 0, n = 0; int r = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    if (GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)20 /* TokenElevation */, &elev, sizeof(elev), &n)) r = elev != 0;
    CloseHandle(tok);
    return r;
}

const char *st_name(LONG st)
{
    static char buf[4][24]; static int k;
    switch (st) {
    case 0: return "SUCCESS";
    case ST_PENDING: return "PENDING";
    case ST_INVALID_PARAMETER: return "INVALID_PARAMETER";
    case ST_INVALID_DEVICE_REQUEST: return "INVALID_DEVICE_REQUEST";
    case ST_ACCESS_VIOLATION: return "ACCESS_VIOLATION";
    case ST_NO_SUCH_FILE: return "NO_SUCH_FILE";
    case ST_NOT_SUPPORTED: return "NOT_SUPPORTED";
    case ST_INFO_LENGTH_MISMATCH: return "INFO_LENGTH_MISMATCH";
    case ST_INVALID_HANDLE: return "INVALID_HANDLE";
    case ST_OBJECT_NAME_NOT_FOUND: return "OBJECT_NAME_NOT_FOUND";
    case ST_OBJECT_PATH_NOT_FOUND: return "OBJECT_PATH_NOT_FOUND";
    case ST_NO_SUCH_DEVICE: return "NO_SUCH_DEVICE";
    case ST_ACCESS_DENIED: return "ACCESS_DENIED";
    case ST_NOT_IMPLEMENTED: return "NOT_IMPLEMENTED";
    case ST_INVALID_INFO_CLASS: return "INVALID_INFO_CLASS";
    case ST_OBJECT_NAME_INVALID: return "OBJECT_NAME_INVALID";
    case ST_PATH_SYNTAX_BAD: return "OBJECT_PATH_SYNTAX_BAD";
    case ST_AFD_UNSERVED: return "0xC000A013";
    default: k = (k + 1) & 3; snprintf(buf[k], sizeof(buf[k]), "0x%08lX", (unsigned long)st); return buf[k];
    }
}
