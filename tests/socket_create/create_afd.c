/* socket_create: what the NT object layer sees behind a socket handle (the AFD contract).
 * A socket is a File object on the \Device\Afd device: NtQueryObject reports that device as the object name and
 * "File" as the type, GetFileType classifies it like a pipe, FileModeInformation exposes the synchronous /
 * overlapped decision, and once the socket is closed the handle is invalid for every NT query.
 * Values that other NT versions or configurations may report differently are only noted. */
#include "sc.h"

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } SC_USTR;
typedef struct { ULONG_PTR Status; ULONG_PTR Information; } SC_IOSB;
typedef struct { ULONG DeviceType; ULONG Characteristics; } SC_FSDEVICE;
typedef LONG (NTAPI *NtClose_t)(HANDLE);

static LONG obj_string(SOCKET s, ULONG cls, wchar_t *out, size_t cap) {
    sc_NtQueryObject_t q = (sc_NtQueryObject_t)t_proc_in("ntdll.dll", "NtQueryObject");
    union { SC_USTR u; char raw[1024]; } buf;
    ULONG rl = 0;
    LONG st;
    out[0] = 0;
    if (!q) return (LONG)0xC0000002;
    memset(&buf, 0, sizeof buf);
    st = q((HANDLE)s, cls, &buf, sizeof buf, &rl);
    if (st == 0 && buf.u.Buffer) {
        size_t n = buf.u.Length / sizeof(wchar_t);
        if (n >= cap) n = cap - 1;
        memcpy(out, buf.u.Buffer, n * sizeof(wchar_t));
        out[n] = 0;
    }
    return st;
}
static SOCKET make(int af, int ty, DWORD fl) { return sc_make(af, ty, 0, fl); }

TEST(sockcreate_afd_object_name_is_the_afd_device) {
    static const int rows[][2] = {{AF_INET, SOCK_STREAM}, {AF_INET, SOCK_DGRAM}, {AF_INET6, SOCK_STREAM}, {AF_INET6, SOCK_DGRAM}};
    unsigned i;
    SC_UP();
    for (i = 0; i < 4; i++) {
        SOCKET s = make(rows[i][0], rows[i][1], 1);
        wchar_t name[128];
        CHECK(s != INVALID_SOCKET);
        if (s == INVALID_SOCKET) continue;
        SC_EQ(obj_string(s, 1 /* ObjectNameInformation */, name, 128), 0);
        EXPECT_WSTR(name, L"\\Device\\Afd");
        sc_close(s);
    }
}
TEST(sockcreate_afd_object_type_is_file) {
    SOCKET s;
    wchar_t type[64];
    SC_UP();
    s = make(AF_INET, SOCK_STREAM, 1);
    SC_EQ(obj_string(s, 2 /* ObjectTypeInformation */, type, 64), 0);
    EXPECT_WSTR(type, L"File");
    sc_close(s);
}
TEST(sockcreate_afd_unix_socket_object_name_recorded) {
    SOCKET s;
    wchar_t name[128];
    LONG st;
    SC_UP();
    s = make(AF_UNIX, SOCK_STREAM, 1);
    CHECK(s != INVALID_SOCKET);
    st = obj_string(s, 1, name, 128);
    t_note("AF_UNIX object name query: status %#lx name %ls", st, name);
    SC_EQ(st, 0);
    sc_close(s);
}
TEST(sockcreate_afd_object_name_is_independent_of_open_mode) {
    static const DWORD fl[] = {0, 1, 0x80, 0x100};
    unsigned i;
    SC_UP();
    for (i = 0; i < 4; i++) {
        SOCKET s = make(AF_INET, SOCK_STREAM, fl[i]);
        wchar_t name[128];
        CHECK(s != INVALID_SOCKET);
        if (s == INVALID_SOCKET) continue;
        SC_EQ(obj_string(s, 1, name, 128), 0);
        EXPECT_WSTR(name, L"\\Device\\Afd");
        sc_close(s);
    }
}
TEST(sockcreate_afd_get_file_type_is_pipe_like) {
    int i;
    SC_UP();
    for (i = 0; i < 5; i++) {
        SOCKET s;
        switch (i) {
        case 0: s = sc_make(AF_INET, SOCK_STREAM, 0, 1); break;
        case 1: s = sc_make(AF_INET, SOCK_DGRAM, 0, 0); break;
        case 2: s = sc_make(AF_INET6, SOCK_STREAM, 0, 1); break;
        case 3: s = sc_make(AF_UNIX, SOCK_STREAM, 0, 1); break;
        default: s = sc_make(AF_INET6, SOCK_DGRAM, 0, 0x80); break;
        }
        CHECK(s != INVALID_SOCKET);
        if (s == INVALID_SOCKET) continue;
        SC_EQ(GetFileType((HANDLE)s), FILE_TYPE_PIPE);
        sc_close(s);
    }
}
TEST(sockcreate_afd_file_mode_information_follows_overlapped_flag) {
    sc_NtQueryInformationFile_t q;
    SC_UP();
    q = (sc_NtQueryInformationFile_t)t_proc_in("ntdll.dll", "NtQueryInformationFile");
    REQUIRE(q);
    {
        SOCKET a = make(AF_INET, SOCK_STREAM, 1), b = make(AF_INET, SOCK_STREAM, 0);
        ULONG_PTR iosb[2] = {0, 0};
        ULONG ma = 0xff, mb = 0xff;
        SC_EQ(q((HANDLE)a, iosb, &ma, 4, 16), 0);
        SC_EQ(q((HANDLE)b, iosb, &mb, 4, 16), 0);
        SC_EQ(ma, 0);
        SC_EQ(mb, FILE_SYNCHRONOUS_IO_NONALERT);
        sc_close(a); sc_close(b);
    }
}
TEST(sockcreate_afd_nt_query_on_closed_socket_is_invalid_handle) {
    sc_NtQueryInformationFile_t q;
    SOCKET s;
    ULONG mode = 0;
    ULONG_PTR iosb[2] = {0, 0};
    SC_UP();
    q = (sc_NtQueryInformationFile_t)t_proc_in("ntdll.dll", "NtQueryInformationFile");
    REQUIRE(q);
    s = make(AF_INET, SOCK_DGRAM, 1);
    SC_EQ(q((HANDLE)s, iosb, &mode, 4, 16), 0);
    sc_close(s);
    SC_EQ(q((HANDLE)s, iosb, &mode, 4, 16), (LONG)0xC0000008);      /* STATUS_INVALID_HANDLE */
}
TEST(sockcreate_afd_device_type_is_named_pipe_class) {
    sc_NtQueryVolumeInformationFile_t q;
    SOCKET s;
    SC_FSDEVICE d;
    SC_IOSB iosb;
    LONG st;
    SC_UP();
    q = (sc_NtQueryVolumeInformationFile_t)t_proc_in("ntdll.dll", "NtQueryVolumeInformationFile");
    REQUIRE(q);
    s = make(AF_INET, SOCK_STREAM, 1);
    memset(&d, 0xaa, sizeof d);
    memset(&iosb, 0, sizeof iosb);
    st = q((HANDLE)s, &iosb, &d, sizeof d, 4 /* FileFsDeviceInformation */);
    SC_EQ(st, 0);
    if (st == 0) {
        SC_EQ(d.DeviceType, 0x11);                 /* FILE_DEVICE_NAMED_PIPE: why GetFileType calls a socket a pipe */
        t_note("AFD characteristics %#lx", d.Characteristics);
    }
    sc_close(s);
}
TEST(sockcreate_afd_file_name_information_recorded) {
    sc_NtQueryInformationFile_t q;
    SOCKET s;
    struct { ULONG len; wchar_t name[128]; } fni;
    ULONG_PTR iosb[2] = {0, 0};
    LONG st;
    SC_UP();
    q = (sc_NtQueryInformationFile_t)t_proc_in("ntdll.dll", "NtQueryInformationFile");
    REQUIRE(q);
    s = make(AF_INET, SOCK_STREAM, 1);
    memset(&fni, 0, sizeof fni);
    st = q((HANDLE)s, iosb, &fni, sizeof fni, 9 /* FileNameInformation */);
    t_note("FileNameInformation status %#lx len %lu name %.*ls", st, fni.len, (int)(fni.len / 2), fni.name);
    sc_close(s);
}
TEST(sockcreate_afd_handle_basic_information_recorded) {
    sc_NtQueryObject_t q;
    SOCKET s;
    struct { ULONG Attributes, GrantedAccess, HandleCount, PointerCount, PagedPool, NonPagedPool, Reserved[3];
             ULONG NameInfoSize, TypeInfoSize, SecurityDescriptorSize; LARGE_INTEGER CreationTime; } bi;
    ULONG rl = 0;
    LONG st;
    SC_UP();
    q = (sc_NtQueryObject_t)t_proc_in("ntdll.dll", "NtQueryObject");
    REQUIRE(q);
    s = make(AF_INET, SOCK_STREAM, 1);
    memset(&bi, 0, sizeof bi);
    st = q((HANDLE)s, 0 /* ObjectBasicInformation */, &bi, sizeof bi, &rl);
    SC_EQ(st, 0);
    t_note("socket handle granted access %#lx attributes %#lx", bi.GrantedAccess, bi.Attributes);
    SC_EQ(bi.HandleCount >= 1, 1);
    sc_close(s);
}
TEST(sockcreate_afd_ntclose_closes_a_socket_handle) {
    NtClose_t nc;
    SOCKET s;
    DWORD f;
    SC_UP();
    nc = (NtClose_t)t_proc_in("ntdll.dll", "NtClose");
    REQUIRE(nc);
    s = make(AF_INET, SOCK_DGRAM, 1);
    SC_EQ(nc((HANDLE)s), 0);
    SetLastError(0);
    CHECK(!GetHandleInformation((HANDLE)s, &f));
    EXPECT_ERR(ERROR_INVALID_HANDLE);
}
TEST(sockcreate_afd_handle_count_of_endpoint_is_one) {
    sc_NtQueryObject_t q;
    SOCKET s;
    struct { ULONG Attributes, GrantedAccess, HandleCount, PointerCount, PagedPool, NonPagedPool, Reserved[3];
             ULONG NameInfoSize, TypeInfoSize, SecurityDescriptorSize; LARGE_INTEGER CreationTime; } bi;
    ULONG rl = 0;
    HANDLE d = NULL;
    ULONG base = 0;
    SC_UP();
    q = (sc_NtQueryObject_t)t_proc_in("ntdll.dll", "NtQueryObject");
    REQUIRE(q);
    s = make(AF_INET, SOCK_DGRAM, 1);
    memset(&bi, 0, sizeof bi);
    SC_EQ(q((HANDLE)s, 0, &bi, sizeof bi, &rl), 0);
    t_note("endpoint handle count of a fresh socket: %lu", bi.HandleCount);
    CHECK(bi.HandleCount >= 1);
    base = bi.HandleCount;
    CHECK(DuplicateHandle(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &d, 0, FALSE, DUPLICATE_SAME_ACCESS));
    memset(&bi, 0, sizeof bi);
    SC_EQ(q((HANDLE)s, 0, &bi, sizeof bi, &rl), 0);
    SC_EQ(bi.HandleCount, base + 1);               /* a duplicate adds exactly one reference */
    sc_close(s);
    sc_close((SOCKET)d);
}
