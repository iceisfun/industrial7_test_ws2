/* socket_handle_semantics / nt: what the object manager and the I/O manager say about a socket handle.
 * NtQueryObject classes and length protocol, NtQueryInformationFile / NtSetInformationFile /
 * NtQueryVolumeInformationFile classes that a socket answers or refuses, SetFileCompletionNotificationModes
 * (and its read-back), completion-port association rules, and CancelIo / CancelIoEx / NtCancelIoFile. */
#include "sh.h"

static sh_NtQueryObject_t            QO;
static sh_NtQueryInformationFile_t   QF;
static sh_NtSetInformationFile_t     SF;
static sh_NtQueryVolumeInformationFile_t QV;
static int nt_init(void)
{
    QO = NTFN(sh_NtQueryObject_t, "NtQueryObject");
    QF = NTFN(sh_NtQueryInformationFile_t, "NtQueryInformationFile");
    SF = NTFN(sh_NtSetInformationFile_t, "NtSetInformationFile");
    QV = NTFN(sh_NtQueryVolumeInformationFile_t, "NtQueryVolumeInformationFile");
    return QO && QF && SF && QV;
}
#define NT() do { UP(); if (!nt_init()) { t_skip("ntdll entry points missing"); return; } } while (0)

/* ---------------- NtQueryObject ---------------- */

/* Object type name: every kind of socket handle is a File object. */
static void type_name_for(int type, int flags)
{
    SOCKET s; char name[32];
    NT(); s = sh_make(type, flags);
    CHECK(s != INVALID_SOCKET);
    EQ(sh_type_name((HANDLE)s, name, sizeof name), 0);
    EXPECT_STR(name, "File");
    sh_closes(s);
}
TEST(shs_obj_type_tcp)            { type_name_for(SOCK_STREAM, PLAIN); }
TEST(shs_obj_type_tcp_sync)       { type_name_for(SOCK_STREAM, SYNC); }
TEST(shs_obj_type_udp)            { type_name_for(SOCK_DGRAM, PLAIN); }
TEST(shs_obj_type_noinherit)      { type_name_for(SOCK_STREAM, WSA_FLAG_NO_HANDLE_INHERIT); }

TEST(shs_obj_type_accepted_and_listener)
{
    SOCKET c, s, l; char name[32];
    NT(); PAIR(c, s, PLAIN);
    EQ(sh_type_name((HANDLE)s, name, sizeof name), 0);
    EXPECT_STR(name, "File");
    sh_closes(c); sh_closes(s);
    l = sh_listener(PLAIN, NULL);
    EQ(sh_type_name((HANDLE)l, name, sizeof name), 0);
    EXPECT_STR(name, "File");
    sh_closes(l);
}

/* The type of a non-socket handle for contrast. */
TEST(shs_obj_type_names_of_other_objects)
{
    char name[32]; HANDLE ev;
    NT(); ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    EQ(sh_type_name(ev, name, sizeof name), 0);
    EXPECT_STR(name, "Event");
    EQ(sh_type_name(GetCurrentProcess(), name, sizeof name), 0);
    EXPECT_STR(name, "Process");
    CloseHandle(ev);
}

/* ObjectNameInformation (class 1): the file object of a socket is named after the device. */
static LONG name_info(HANDLE h, char *out, size_t cap, ULONG *ret)
{
    union { char raw[512]; struct { USHORT Length, Max; PWSTR Buf; } u; } b;
    LONG st;
    ULONG r = 0;
    memset(&b, 0, sizeof b);
    out[0] = 0;
    st = QO(h, 1, &b, sizeof b, &r);
    if (ret) *ret = r;
    if (st == 0) {
        size_t i, n = b.u.Length / 2;
        for (i = 0; i < n && i + 1 < cap; i++) out[i] = (char)b.u.Buf[i];
        out[i] = 0;
    }
    return st;
}
TEST(shs_obj_name_is_afd_device)
{
    SOCKET s; char name[64];
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    EQ(name_info((HANDLE)s, name, sizeof name, NULL), 0);
    EXPECT_STR(name, "\\Device\\Afd");
    sh_closes(s);
}
TEST(shs_obj_name_same_for_all_kinds)
{
    SOCKET c, s, u; char n1[64], n2[64], n3[64];
    NT(); PAIR(c, s, SYNC); u = sh_make(SOCK_DGRAM, PLAIN);
    EQ(name_info((HANDLE)c, n1, sizeof n1, NULL), 0);
    EQ(name_info((HANDLE)s, n2, sizeof n2, NULL), 0);
    EQ(name_info((HANDLE)u, n3, sizeof n3, NULL), 0);
    EXPECT_STR(n1, "\\Device\\Afd"); EXPECT_STR(n2, "\\Device\\Afd"); EXPECT_STR(n3, "\\Device\\Afd");
    sh_closes(c); sh_closes(s); sh_closes(u);
}
/* The returned length covers the UNICODE_STRING header, the characters and a terminator. */
TEST(shs_obj_name_length_protocol)
{
    SOCKET s; char b[256]; ULONG ret = 0; LONG st;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    st = QO((HANDLE)s, 1, b, sizeof b, &ret);
    EQ(st, 0);
    EQ(ret, sizeof(UNICODE_STRING) + 24);
    EQ32(QO((HANDLE)s, 1, b, 0, &ret), ST_INFO_LENGTH_MISMATCH);
    EQ(ret, sizeof(UNICODE_STRING) + 24);
    EQ32(QO((HANDLE)s, 1, b, 8, &ret), ST_INFO_LENGTH_MISMATCH);
    /* header fits, the name does not: STATUS_BUFFER_OVERFLOW, required size reported */
    ret = 0;
    EQ32(QO((HANDLE)s, 1, b, sizeof(UNICODE_STRING), &ret), (LONG)0x80000005);
    EQ(ret, sizeof(UNICODE_STRING) + 24);
    sh_closes(s);
}

/* ObjectBasicInformation (class 0) demands exactly its own size. */
TEST(shs_obj_basic_length_protocol)
{
    SOCKET s; char b[256]; ULONG ret;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    memset(b, 0, sizeof b);
    EQ32(QO((HANDLE)s, 0, b, sizeof(sh_objbasic), NULL), 0);
    EQ32(QO((HANDLE)s, 0, b, sizeof(sh_objbasic) - 1, NULL), ST_INFO_LENGTH_MISMATCH);
    EQ32(QO((HANDLE)s, 0, b, sizeof(sh_objbasic) + 1, NULL), ST_INFO_LENGTH_MISMATCH);
    EQ32(QO((HANDLE)s, 0, b, 0, NULL), ST_INFO_LENGTH_MISMATCH);
    EQ32(QO((HANDLE)s, 0, b, sizeof b, NULL), ST_INFO_LENGTH_MISMATCH);
    ret = 0xdead;
    QO((HANDLE)s, 0, b, 4, &ret);
    t_note("ObjectBasicInformation short buffer: returned length %lu", ret);
    sh_closes(s);
}

/* Handle count: one socket handle is one reference; every duplicate adds one, closing one removes one. */
TEST(shs_obj_handle_count_tracks_duplicates)
{
    SOCKET s; sh_objbasic ob; HANDLE d1, d2; ULONG base;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    memset(&ob, 0, sizeof ob);
    EQ32(QO((HANDLE)s, 0, &ob, sizeof ob, NULL), 0);
    base = ob.HandleCount;
    t_note("fresh socket handle count: %lu", base);
    CHECK(base >= 1);
    d1 = sh_dup((HANDLE)s, 0, FALSE, DUPLICATE_SAME_ACCESS);
    QO((HANDLE)s, 0, &ob, sizeof ob, NULL); EQ32(ob.HandleCount, base + 1);
    d2 = sh_dup((HANDLE)s, 0, FALSE, DUPLICATE_SAME_ACCESS);
    QO((HANDLE)s, 0, &ob, sizeof ob, NULL); EQ32(ob.HandleCount, base + 2);
    CloseHandle(d1);
    QO((HANDLE)s, 0, &ob, sizeof ob, NULL); EQ32(ob.HandleCount, base + 1);
    CloseHandle(d2);
    QO((HANDLE)s, 0, &ob, sizeof ob, NULL); EQ32(ob.HandleCount, base);
    sh_closes(s);
}
TEST(shs_obj_handle_count_fresh_socket_is_one)
{
    SOCKET s; sh_objbasic ob;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    memset(&ob, 0, sizeof ob);
    EQ32(QO((HANDLE)s, 0, &ob, sizeof ob, NULL), 0);
    EQ(ob.HandleCount, 1);
    sh_closes(s);
}
TEST(shs_obj_handle_count_accepted_socket_is_one)
{
    SOCKET c, s; sh_objbasic ob;
    NT(); PAIR(c, s, PLAIN);
    memset(&ob, 0, sizeof ob);
    EQ32(QO((HANDLE)s, 0, &ob, sizeof ob, NULL), 0);
    EQ(ob.HandleCount, 1);
    EQ32(QO((HANDLE)c, 0, &ob, sizeof ob, NULL), 0);
    EQ(ob.HandleCount, 1);
    sh_closes(c); sh_closes(s);
}

/* Attributes and granted access for kinds the basic socket test does not cover. */
static void basic_for(int type, int flags, ULONG attr)
{
    SOCKET s; sh_objbasic ob;
    NT(); s = sh_make(type, flags);
    memset(&ob, 0, sizeof ob);
    EQ32(QO((HANDLE)s, 0, &ob, sizeof ob, NULL), 0);
    EQ(ob.Attributes, attr);
    EQ(ob.GrantedAccess, FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC);
    sh_closes(s);
}
TEST(shs_obj_basic_udp)               { basic_for(SOCK_DGRAM, PLAIN, OBJ_INHERIT); }
TEST(shs_obj_basic_tcp_sync)          { basic_for(SOCK_STREAM, SYNC, OBJ_INHERIT); }
TEST(shs_obj_basic_noinherit)         { basic_for(SOCK_STREAM, WSA_FLAG_NO_HANDLE_INHERIT, 0); }
TEST(shs_obj_basic_noinherit_ovl)     { basic_for(SOCK_STREAM, OVLD | WSA_FLAG_NO_HANDLE_INHERIT, 0); }
TEST(shs_obj_basic_accepted)
{
    SOCKET c, s; sh_objbasic ob;
    NT(); PAIR(c, s, PLAIN);
    memset(&ob, 0, sizeof ob);
    EQ32(QO((HANDLE)s, 0, &ob, sizeof ob, NULL), 0);
    EQ(ob.Attributes, OBJ_INHERIT);
    EQ(ob.GrantedAccess, FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC);
    sh_closes(c); sh_closes(s);
}
/* A duplicate made without inheritance has no OBJ_INHERIT attribute. */
TEST(shs_obj_basic_duplicate_attributes)
{
    SOCKET s; sh_objbasic ob; HANDLE d;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    d = sh_dup((HANDLE)s, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d);
    memset(&ob, 0, sizeof ob);
    EQ32(QO(d, 0, &ob, sizeof ob, NULL), 0);
    EQ(ob.Attributes, 0);
    CloseHandle(d); sh_closes(s);
}

/* ObjectHandleFlagInformation (class 4): two BOOLEANs {inherit, protect}. */
TEST(shs_obj_handle_flags_class)
{
    SOCKET s; unsigned char f[2]; ULONG ret = 0;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    memset(f, 0xee, sizeof f);
    EQ32(QO((HANDLE)s, 4, f, sizeof f, &ret), 0);
    EQ(ret, 2);
    EQ(f[0], 1);
    EQ(f[1], 0);
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
    EQ32(QO((HANDLE)s, 4, f, sizeof f, &ret), 0);
    EQ(f[0], 0);
    EQ(f[1], 1);
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0);
    sh_closes(s);
}
TEST(shs_obj_handle_flags_length_protocol)
{
    SOCKET s; unsigned char f[16]; ULONG ret = 0xdead;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    EQ32(QO((HANDLE)s, 4, f, 0, &ret), ST_INFO_LENGTH_MISMATCH);
    EQ(ret, 2);
    EQ32(QO((HANDLE)s, 4, f, 1, &ret), ST_INFO_LENGTH_MISMATCH);
    EQ32(QO((HANDLE)s, 4, f, 2, &ret), 0);
    sh_closes(s);
}
/* Setting the flags with the object-level call is the same state GetHandleInformation reads. */
TEST(shs_obj_set_handle_flags)
{
    SOCKET s; unsigned char f[2]; sh_NtSetInformationObject_t so; DWORD hf = 0;
    NT(); so = NTFN(sh_NtSetInformationObject_t, "NtSetInformationObject");
    REQUIRE(so);
    s = sh_make(SOCK_STREAM, PLAIN);
    f[0] = 0; f[1] = 0;
    EQ32(so((HANDLE)s, 4, f, 2), 0);
    GetHandleInformation((HANDLE)s, &hf);
    EQ(hf, 0);
    f[0] = 1;
    EQ32(so((HANDLE)s, 4, f, 2), 0);
    GetHandleInformation((HANDLE)s, &hf);
    EQ(hf, HANDLE_FLAG_INHERIT);
    sh_closes(s);
}

/* Type information: size protocol only (contents vary with the build). */
TEST(shs_obj_type_info_length_protocol)
{
    SOCKET s; char b[1024]; ULONG ret = 0;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    EQ32(QO((HANDLE)s, 2, NULL, 0, &ret), ST_INFO_LENGTH_MISMATCH);
    CHECK(ret > 16 && ret < sizeof b);
    EQ32(QO((HANDLE)s, 2, b, 16, NULL), ST_INFO_LENGTH_MISMATCH);
    EQ32(QO((HANDLE)s, 2, b, ret, NULL), 0);
    sh_closes(s);
}

/* Unknown classes and invalid handles. */
TEST(shs_obj_unknown_classes)
{
    static const ULONG cls[] = { 5, 6, 7, 8, 9, 10, 11, 12, 0x7fff, 0x10000 };
    SOCKET s; char b[256]; int i;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    for (i = 0; i < (int)(sizeof cls / sizeof cls[0]); i++)
        EQ32(QO((HANDLE)s, cls[i], b, sizeof b, NULL), ST_INVALID_INFO_CLASS);
    sh_closes(s);
}
TEST(shs_obj_invalid_handles)
{
    static const ULONG_PTR bad[] = { 0, 0x7ffffffc, 0x4444 };
    char b[256]; int i;
    NT();
    for (i = 0; i < 3; i++) {
        EQ32(QO((HANDLE)bad[i], 0, b, sizeof(sh_objbasic), NULL), ST_INVALID_HANDLE);
        EQ32(QO((HANDLE)bad[i], 2, b, sizeof b, NULL), ST_INVALID_HANDLE);
    }
}
TEST(shs_obj_query_closed_socket)
{
    SOCKET s; char b[256];
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    sh_closes(s);
    EQ32(QO((HANDLE)s, 0, b, sizeof(sh_objbasic), NULL), ST_INVALID_HANDLE);
}

/* ---------------- NtQueryInformationFile ---------------- */

typedef union { ULONG u[16]; unsigned char c[64]; } qbuf;

/* The classes a socket handle answers. */
TEST(shs_fi_access_information_matches_granted_access)
{
    SOCKET s; sh_iosb io; ULONG v = 0; sh_objbasic ob;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    memset(&io, 0, sizeof io); memset(&ob, 0, sizeof ob);
    EQ32(QF((HANDLE)s, &io, &v, sizeof v, 8), 0);
    EQ(io.Information, 4);
    EQ32(QO((HANDLE)s, 0, &ob, sizeof ob, NULL), 0);
    EQ(v, ob.GrantedAccess);
    sh_closes(s);
}
TEST(shs_fi_access_information_reduced_duplicate)
{
    SOCKET s; sh_iosb io; ULONG v = 0; HANDLE d;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    d = sh_dup((HANDLE)s, FILE_READ_DATA | SYNCHRONIZE, FALSE, 0);
    REQUIRE(d);
    EQ32(QF(d, &io, &v, sizeof v, 8), 0);
    EQ(v, FILE_READ_DATA | SYNCHRONIZE);
    CloseHandle(d); sh_closes(s);
}
TEST(shs_fi_access_information_length_protocol)
{
    SOCKET s; sh_iosb io; char b[16];
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    EQ32(QF((HANDLE)s, &io, b, 3, 8), ST_INFO_LENGTH_MISMATCH);
    EQ32(QF((HANDLE)s, &io, b, 0, 8), ST_INFO_LENGTH_MISMATCH);
    EQ32(QF((HANDLE)s, &io, b, 4, 8), 0);
    EQ32(QF((HANDLE)s, &io, b, 16, 8), 0);          /* a larger buffer is fine */
    EQ(io.Information, 4);
    sh_closes(s);
}

/* FileModeInformation: the synchronous-IO bits show whether the handle is overlapped. */
#define FILE_SYNC_NONALERT 0x20
#define FILE_SYNC_ALERT    0x10
static ULONG mode_of(SOCKET s)
{
    sh_iosb io; ULONG v = 0xdead;
    if (QF((HANDLE)s, &io, &v, sizeof v, 16) != 0) return 0xbad;
    return v;
}
TEST(shs_fi_mode_overlapped_has_no_sync_bits)
{
    SOCKET s;
    NT();
    s = sh_make(SOCK_STREAM, PLAIN);       EQ(mode_of(s), 0); sh_closes(s);
    s = sh_make(SOCK_STREAM, OVLD);        EQ(mode_of(s), 0); sh_closes(s);
    s = sh_make(SOCK_DGRAM, OVLD);         EQ(mode_of(s), 0); sh_closes(s);
}
TEST(shs_fi_mode_sync_is_nonalert)
{
    SOCKET s;
    NT();
    s = sh_make(SOCK_STREAM, SYNC);        EQ(mode_of(s), FILE_SYNC_NONALERT); sh_closes(s);
    s = sh_make(SOCK_DGRAM, SYNC);         EQ(mode_of(s), FILE_SYNC_NONALERT); sh_closes(s);
    s = sh_make(SOCK_STREAM, WSA_FLAG_NO_HANDLE_INHERIT); EQ(mode_of(s), FILE_SYNC_NONALERT); sh_closes(s);
}
TEST(shs_fi_mode_noinherit_overlapped)
{
    SOCKET s;
    NT(); s = sh_make(SOCK_STREAM, OVLD | WSA_FLAG_NO_HANDLE_INHERIT);
    EQ(mode_of(s), 0);
    sh_closes(s);
}
TEST(shs_fi_mode_accepted_follows_listener)
{
    SOCKET c, s;
    NT(); PAIR(c, s, SYNC);
    EQ(mode_of(c), FILE_SYNC_NONALERT);
    EQ(mode_of(s), FILE_SYNC_NONALERT);
    sh_closes(c); sh_closes(s);
    PAIR(c, s, PLAIN);
    EQ(mode_of(c), 0);
    EQ(mode_of(s), 0);
    sh_closes(c); sh_closes(s);
}
TEST(shs_fi_mode_duplicate_shares_file_object)
{
    SOCKET s; HANDLE d; sh_iosb io; ULONG v = 0xdead;
    NT(); s = sh_make(SOCK_STREAM, SYNC);
    d = sh_dup((HANDLE)s, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d);
    EQ32(QF(d, &io, &v, sizeof v, 16), 0);
    EQ(v, FILE_SYNC_NONALERT);
    CloseHandle(d); sh_closes(s);
}
/* Mode matches what the file API layer does: a synchronous handle takes a NULL OVERLAPPED. */
TEST(shs_fi_mode_agrees_with_writefile_rule)
{
    SOCKET c, s; DWORD n = 0;
    NT(); PAIR(c, s, SYNC);
    EQ(mode_of(c) & (FILE_SYNC_ALERT | FILE_SYNC_NONALERT), FILE_SYNC_NONALERT);
    CHECK(sh_wf((HANDLE)c, "q", 1, &n, NULL));
    sh_closes(c); sh_closes(s);
}

/* The remaining classes that succeed. */
TEST(shs_fi_alignment_information)
{
    SOCKET s; sh_iosb io; ULONG v = 0xdead;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    EQ32(QF((HANDLE)s, &io, &v, sizeof v, 17), 0);
    EQ(v, 0);
    EQ(io.Information, 4);
    sh_closes(s);
}
TEST(shs_fi_io_priority_hint_normal)
{
    SOCKET s; sh_iosb io; ULONGLONG v = 0xdead;      /* 8-byte aligned: the class checks alignment */
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    EQ32(QF((HANDLE)s, &io, &v, 4, 43), 0);
    EQ(v & 0xffffffff, 2);                      /* IoPriorityNormal */
    sh_closes(s);
}
TEST(shs_fi_remote_device_flag_clear)
{
    SOCKET s; sh_iosb io; unsigned char v = 0xee;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    EQ32(QF((HANDLE)s, &io, &v, 1, 51), 0);
    EQ(v, 0);
    EQ(io.Information, 1);
    sh_closes(s);
}
TEST(shs_fi_volume_name_is_device_name)
{
    SOCKET s; sh_iosb io; struct { ULONG len; WCHAR name[64]; } b;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    memset(&b, 0, sizeof b);
    EQ32(QF((HANDLE)s, &io, &b, sizeof b, 58), 0);
    EQ(b.len, 22);                  /* "\Device\Afd" */
    EQ(io.Information, 4 + 22);
    sh_closes(s);
}
TEST(shs_fi_processes_using_file_empty_list)
{
    SOCKET s; sh_iosb io; ULONG b[8];
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    memset(b, 0xee, sizeof b);
    EQ32(QF((HANDLE)s, &io, b, sizeof b, 47), 0);
    EQ(b[0], 0);
    sh_closes(s);
}
TEST(shs_fi_completion_notification_default_clear)
{
    SOCKET s; sh_iosb io; ULONG v = 0xdead;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    EQ32(QF((HANDLE)s, &io, &v, sizeof v, 41), 0);
    EQ(v, 0);
    sh_closes(s);
}

/* Classes that AFD does not implement: STATUS_NOT_IMPLEMENTED, whichever socket it is. */
static void fi_not_implemented(ULONG cls)
{
    SOCKET s[3]; sh_iosb io; char b[256]; int i;
    NT();
    s[0] = sh_make(SOCK_STREAM, PLAIN); s[1] = sh_make(SOCK_DGRAM, SYNC);
    { SOCKET c, a; PAIR(c, a, PLAIN); s[2] = c; sh_closes(a); }
    for (i = 0; i < 3; i++) { memset(b, 0, sizeof b); EQ32(QF((HANDLE)s[i], &io, b, sizeof b, cls), 0xC0000002); sh_closes(s[i]); }
}
TEST(shs_fi_basic_not_implemented)       { fi_not_implemented(4); }
TEST(shs_fi_standard_not_implemented)    { fi_not_implemented(5); }
TEST(shs_fi_internal_not_implemented)    { fi_not_implemented(6); }
TEST(shs_fi_ea_not_implemented)          { fi_not_implemented(7); }
TEST(shs_fi_name_not_implemented)        { fi_not_implemented(9); }
/* Position is kept by the I/O manager for synchronous handles; an overlapped socket has none. */
TEST(shs_fi_position_overlapped_not_implemented)
{
    SOCKET s; sh_iosb io; char b[64];
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    EQ32(QF((HANDLE)s, &io, b, sizeof b, 14), 0xC0000002);
    sh_closes(s);
}
TEST(shs_fi_position_sync_answered)
{
    SOCKET s; sh_iosb io; LONGLONG pos = 0x77;
    NT(); s = sh_make(SOCK_STREAM, SYNC);
    EQ32(QF((HANDLE)s, &io, &pos, sizeof pos, 14), 0);
    EQ(pos, 0);
    sh_closes(s);
}
TEST(shs_fi_all_not_implemented)         { fi_not_implemented(18); }
TEST(shs_fi_networkopen_not_implemented) { fi_not_implemented(34); }

/* Directory-style classes and out-of-range numbers are not information classes of a plain file object. */
TEST(shs_fi_invalid_classes)
{
    static const ULONG cls[] = { 0, 1, 2, 3, 10, 11, 12, 13, 15, 19, 20, 0x1000 };
    SOCKET s; sh_iosb io; char b[256]; int i;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    for (i = 0; i < (int)(sizeof cls / sizeof cls[0]); i++) {
        memset(b, 0, sizeof b);
        EQ32(QF((HANDLE)s, &io, b, sizeof b, cls[i]), ST_INVALID_INFO_CLASS);
    }
    sh_closes(s);
}
TEST(shs_fi_invalid_handle)
{
    sh_iosb io; ULONG v;
    NT();
    EQ32(QF((HANDLE)(ULONG_PTR)0x7ffffffc, &io, &v, sizeof v, 8), ST_INVALID_HANDLE);
    EQ32(QF(NULL, &io, &v, sizeof v, 8), ST_INVALID_HANDLE);
}
TEST(shs_fi_non_file_handle)
{
    HANDLE ev; sh_iosb io; ULONG v;
    NT(); ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    EQ32(QF(ev, &io, &v, sizeof v, 8), ST_OBJECT_TYPE_MISMATCH);
    CloseHandle(ev);
}

/* ---------------- NtSetInformationFile ---------------- */

TEST(shs_si_basic_not_implemented)
{
    SOCKET s; sh_iosb io; char b[64] = {0};
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    EQ32(SF((HANDLE)s, &io, b, sizeof b, 4), 0xC0000002);
    sh_closes(s);
}
TEST(shs_si_invalid_classes)
{
    static const ULONG cls[] = { 0, 1, 2, 3, 5, 6, 7, 8, 9, 12, 15, 17, 18 };
    SOCKET s; sh_iosb io; char b[64]; int i;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    for (i = 0; i < (int)(sizeof cls / sizeof cls[0]); i++) { memset(b, 0, sizeof b); EQ32(SF((HANDLE)s, &io, b, sizeof b, cls[i]), ST_INVALID_INFO_CLASS); }
    sh_closes(s);
}
TEST(shs_si_mode_zero_accepted)
{
    SOCKET s; sh_iosb io; ULONG v = 0;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    EQ32(SF((HANDLE)s, &io, &v, sizeof v, 16), 0);
    sh_closes(s);
}
TEST(shs_si_invalid_handle)
{
    sh_iosb io; ULONG v = 0;
    NT();
    EQ32(SF((HANDLE)(ULONG_PTR)0x7ffffffc, &io, &v, sizeof v, 16), ST_INVALID_HANDLE);
}

/* ---------------- NtQueryVolumeInformationFile ---------------- */

typedef struct { ULONG DeviceType; ULONG Characteristics; } fsdev;
TEST(shs_vol_device_information)
{
    SOCKET s; sh_iosb io; fsdev d;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    memset(&d, 0xee, sizeof d);
    EQ32(QV((HANDLE)s, &io, &d, sizeof d, 4), 0);
    EQ(io.Information, 8);
    EQ(d.DeviceType, 0x11);                      /* FILE_DEVICE_NAMED_PIPE */
    t_note("AFD device characteristics: 0x%lx", d.Characteristics);
    sh_closes(s);
}
TEST(shs_vol_device_type_same_for_all_kinds)
{
    SOCKET c, s, u; sh_iosb io; fsdev d;
    NT(); PAIR(c, s, SYNC); u = sh_make(SOCK_DGRAM, PLAIN);
    EQ32(QV((HANDLE)c, &io, &d, sizeof d, 4), 0); EQ32(d.DeviceType, 0x11);
    EQ32(QV((HANDLE)s, &io, &d, sizeof d, 4), 0); EQ32(d.DeviceType, 0x11);
    EQ32(QV((HANDLE)u, &io, &d, sizeof d, 4), 0); EQ32(d.DeviceType, 0x11);
    sh_closes(c); sh_closes(s); sh_closes(u);
}
/* GetFileType is derived from this device type. */
TEST(shs_vol_device_type_explains_filetype)
{
    SOCKET s; sh_iosb io; fsdev d;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    EQ32(QV((HANDLE)s, &io, &d, sizeof d, 4), 0);
    CHECK(d.DeviceType == 0x11 && GetFileType((HANDLE)s) == FILE_TYPE_PIPE);
    sh_closes(s);
}
TEST(shs_vol_other_classes_not_implemented)
{
    static const ULONG cls[] = { 1, 3, 5, 6, 7, 8, 10, 11 };
    SOCKET s; sh_iosb io; char b[256]; int i;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    for (i = 0; i < (int)(sizeof cls / sizeof cls[0]); i++) { memset(b, 0, sizeof b); EQ32(QV((HANDLE)s, &io, b, sizeof b, cls[i]), 0xC0000002); }
    sh_closes(s);
}
TEST(shs_vol_attribute_class_invalid)
{
    SOCKET s; sh_iosb io; char b[256];
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    EQ32(QV((HANDLE)s, &io, b, sizeof b, 0), ST_INVALID_INFO_CLASS);
    EQ32(QV((HANDLE)s, &io, b, sizeof b, 2), ST_INVALID_INFO_CLASS);
    EQ32(QV((HANDLE)s, &io, b, sizeof b, 0x1000), ST_INVALID_INFO_CLASS);
    sh_closes(s);
}
TEST(shs_vol_device_information_short_buffer)
{
    SOCKET s; sh_iosb io; char b[16];
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    EQ32(QV((HANDLE)s, &io, b, 4, 4), ST_INFO_LENGTH_MISMATCH);
    sh_closes(s);
}
TEST(shs_vol_invalid_handle)
{
    sh_iosb io; fsdev d;
    NT();
    EQ32(QV((HANDLE)(ULONG_PTR)0x7ffffffc, &io, &d, sizeof d, 4), ST_INVALID_HANDLE);
}

/* ---------------- SetFileCompletionNotificationModes ---------------- */

static ULONG notif_flags(SOCKET s)
{
    sh_iosb io; ULONG v = 0xdead;
    if (QF((HANDLE)s, &io, &v, sizeof v, 41) != 0) return 0xbad;
    return v;
}
/* Accepted values are the two documented flags in any combination; anything else is a parameter error. */
TEST(shs_notif_valid_modes_on_overlapped_socket)
{
    static const UCHAR ok[] = { 0, 1, 2, 3 };
    int i;
    NT();
    for (i = 0; i < 4; i++) {
        SOCKET s = sh_make(SOCK_STREAM, PLAIN);
        SET_ERR(0);
        CHECK(SetFileCompletionNotificationModes((HANDLE)s, ok[i]));
        sh_closes(s);
    }
}
TEST(shs_notif_invalid_modes_on_overlapped_socket)
{
    static const UCHAR bad[] = { 4, 5, 7, 8, 0x10, 0x80, 0xff };
    int i;
    NT();
    for (i = 0; i < 7; i++) {
        SOCKET s = sh_make(SOCK_STREAM, PLAIN);
        SET_ERR(0);
        CHECK(!SetFileCompletionNotificationModes((HANDLE)s, bad[i]));
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        sh_closes(s);
    }
}
/* A synchronous handle never completes through a port or event, so only "no modes" is acceptable. */
TEST(shs_notif_sync_socket_accepts_only_zero)
{
    int m;
    NT();
    for (m = 0; m < 5; m++) {
        SOCKET s = sh_make(SOCK_STREAM, SYNC);
        SET_ERR(0);
        BOOL r = SetFileCompletionNotificationModes((HANDLE)s, (UCHAR)m);
        if (m == 0) CHECK(r);
        else { CHECK(!r); EXPECT_ERR(ERROR_INVALID_PARAMETER); }
        sh_closes(s);
    }
}
TEST(shs_notif_udp_overlapped_valid)
{
    SOCKET s;
    NT(); s = sh_make(SOCK_DGRAM, PLAIN);
    CHECK(SetFileCompletionNotificationModes((HANDLE)s, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS));
    sh_closes(s);
}
TEST(shs_notif_accepted_socket)
{
    SOCKET c, s;
    NT(); PAIR(c, s, PLAIN);
    CHECK(SetFileCompletionNotificationModes((HANDLE)s, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE));
    EQ(notif_flags(s), 3);
    EQ(notif_flags(c), 0);
    sh_closes(c); sh_closes(s);
}
TEST(shs_notif_listener)
{
    SOCKET l;
    NT(); l = sh_listener(PLAIN, NULL);
    CHECK(SetFileCompletionNotificationModes((HANDLE)l, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS));
    sh_closes(l);
}
TEST(shs_notif_invalid_handle_kinds)
{
    HANDLE ev;
    NT(); ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    SET_ERR(0); CHECK(!SetFileCompletionNotificationModes(INVALID_HANDLE_VALUE, 1)); EXPECT_ERR(ERROR_INVALID_HANDLE);
    SET_ERR(0); CHECK(!SetFileCompletionNotificationModes((HANDLE)(ULONG_PTR)0x7ffffffc, 1)); EXPECT_ERR(ERROR_INVALID_HANDLE);
    SET_ERR(0); CHECK(!SetFileCompletionNotificationModes(ev, 1)); EXPECT_ERR(ERROR_INVALID_HANDLE);
    CloseHandle(ev);
}
TEST(shs_notif_closed_socket)
{
    SOCKET s;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    sh_closes(s);
    SET_ERR(0);
    CHECK(!SetFileCompletionNotificationModes((HANDLE)s, 1));
    EXPECT_ERR(ERROR_INVALID_HANDLE);
}

/* The modes are readable through the file information class and only ever accumulate. */
TEST(shs_notif_readback_each_flag)
{
    SOCKET s;
    NT();
    s = sh_make(SOCK_STREAM, PLAIN);
    CHECK(SetFileCompletionNotificationModes((HANDLE)s, 1)); EQ(notif_flags(s), 1);
    sh_closes(s);
    s = sh_make(SOCK_STREAM, PLAIN);
    CHECK(SetFileCompletionNotificationModes((HANDLE)s, 2)); EQ(notif_flags(s), 2);
    sh_closes(s);
    s = sh_make(SOCK_STREAM, PLAIN);
    CHECK(SetFileCompletionNotificationModes((HANDLE)s, 3)); EQ(notif_flags(s), 3);
    sh_closes(s);
}
TEST(shs_notif_flags_accumulate_and_cannot_be_cleared)
{
    SOCKET s;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    SetFileCompletionNotificationModes((HANDLE)s, 1);
    SetFileCompletionNotificationModes((HANDLE)s, 0);
    EQ(notif_flags(s), 1);
    SetFileCompletionNotificationModes((HANDLE)s, 2);
    EQ(notif_flags(s), 3);
    SetFileCompletionNotificationModes((HANDLE)s, 1);
    EQ(notif_flags(s), 3);
    sh_closes(s);
}
/* The setting lives on the file object, so a duplicate handle sees it. */
TEST(shs_notif_visible_through_duplicate)
{
    SOCKET s; HANDLE d; sh_iosb io; ULONG v = 0xdead;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    d = sh_dup((HANDLE)s, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d);
    SetFileCompletionNotificationModes(d, 1);
    EQ(notif_flags(s), 1);
    EQ32(QF(d, &io, &v, sizeof v, 41), 0);
    EQ(v, 1);
    CloseHandle(d); sh_closes(s);
}
/* Direct class-41 set: length rules. */
TEST(shs_notif_nt_set_length_protocol)
{
    SOCKET s; sh_iosb io; ULONG v = 1;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    EQ32(SF((HANDLE)s, &io, &v, 3, 41), ST_INFO_LENGTH_MISMATCH);
    EQ32(SF((HANDLE)s, &io, &v, 0, 41), ST_INFO_LENGTH_MISMATCH);
    EQ32(SF((HANDLE)s, &io, &v, 4, 41), 0);
    EQ(notif_flags(s), 1);
    sh_closes(s);
}

/* Association with a completion port: once only, and only for asynchronous handles. */
TEST(shs_iocp_associate_once)
{
    SOCKET s; HANDLE p1, p2, r;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    p1 = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    p2 = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    REQUIRE(p1 && p2);
    r = CreateIoCompletionPort((HANDLE)s, p1, 7, 0);
    CHECK(r == p1);
    SET_ERR(0);
    r = CreateIoCompletionPort((HANDLE)s, p1, 8, 0);
    CHECK(r == NULL);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    r = CreateIoCompletionPort((HANDLE)s, p2, 8, 0);
    CHECK(r == NULL);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    sh_closes(s); CloseHandle(p1); CloseHandle(p2);
}
TEST(shs_iocp_sync_socket_refused)
{
    SOCKET s; HANDLE p, r;
    NT(); s = sh_make(SOCK_STREAM, SYNC);
    p = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    REQUIRE(p);
    SET_ERR(0);
    r = CreateIoCompletionPort((HANDLE)s, p, 1, 0);
    CHECK(r == NULL);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    sh_closes(s); CloseHandle(p);
}
/* The association belongs to the file object: a duplicate handle cannot be associated again. */
TEST(shs_iocp_duplicate_cannot_reassociate)
{
    SOCKET s; HANDLE p, d, r;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    p = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    d = sh_dup((HANDLE)s, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(p && d);
    CHECK(CreateIoCompletionPort((HANDLE)s, p, 1, 0) == p);
    SET_ERR(0);
    r = CreateIoCompletionPort(d, p, 2, 0);
    CHECK(r == NULL);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CloseHandle(d); sh_closes(s); CloseHandle(p);
}
/* An inline WriteFile on an associated socket still posts a completion packet unless skip-on-success is set. */
static int port_packet(HANDLE p, ULONG_PTR *key, DWORD ms)
{
    DWORD n; LPOVERLAPPED o;
    return GetQueuedCompletionStatus(p, &n, key, &o, ms) && o != NULL;
}
TEST(shs_iocp_inline_write_posts_packet)
{
    SOCKET c, s; HANDLE p; OVERLAPPED o; DWORD n; ULONG_PTR key = 0;
    NT(); PAIR(c, s, PLAIN);
    p = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CHECK(CreateIoCompletionPort((HANDLE)c, p, 5, 0) == p);
    sh_ovl(&o, NULL);
    CHECK(sh_wf((HANDLE)c, "pkt", 3, &n, &o));
    CHECK(port_packet(p, &key, SH_WAIT));
    EQ(key, 5);
    sh_closes(c); sh_closes(s); CloseHandle(p);
}
TEST(shs_iocp_skip_on_success_suppresses_packet)
{
    SOCKET c, s; HANDLE p; OVERLAPPED o; DWORD n; ULONG_PTR key = 0;
    NT(); PAIR(c, s, PLAIN);
    p = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CHECK(CreateIoCompletionPort((HANDLE)c, p, 5, 0) == p);
    CHECK(SetFileCompletionNotificationModes((HANDLE)c, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS));
    sh_ovl(&o, NULL);
    CHECK(sh_wf((HANDLE)c, "pkt", 3, &n, &o));
    EQ(n, 3);
    CHECK(!port_packet(p, &key, 500));
    sh_closes(c); sh_closes(s); CloseHandle(p);
}
/* A request that pends still completes through the port with the skip flag set. */
TEST(shs_iocp_skip_on_success_pending_request_still_posts)
{
    SOCKET c, s; HANDLE p; OVERLAPPED o; DWORD n; ULONG_PTR key = 0; char b[8];
    NT(); PAIR(c, s, PLAIN);
    p = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CHECK(CreateIoCompletionPort((HANDLE)s, p, 9, 0) == p);
    CHECK(SetFileCompletionNotificationModes((HANDLE)s, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS));
    sh_ovl(&o, NULL);
    CHECK(!sh_rf((HANDLE)s, b, sizeof b, &n, &o));
    EXPECT_ERR(ERROR_IO_PENDING);
    sh_send(c, "x", 1);
    CHECK(port_packet(p, &key, SH_WAIT));
    EQ(key, 9);
    sh_closes(c); sh_closes(s); CloseHandle(p);
}
/* The low bit of hEvent suppresses the packet for that one request. */
TEST(shs_iocp_event_low_bit_suppresses_packet)
{
    SOCKET c, s; HANDLE p, ev; OVERLAPPED o; DWORD n; ULONG_PTR key = 0;
    NT(); PAIR(c, s, PLAIN);
    ev = sh_event();
    p = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CHECK(CreateIoCompletionPort((HANDLE)c, p, 5, 0) == p);
    sh_ovl(&o, (HANDLE)((ULONG_PTR)ev | 1));
    CHECK(sh_wf((HANDLE)c, "pkt", 3, &n, &o));
    CHECK(!port_packet(p, &key, 500));
    CloseHandle(ev); sh_closes(c); sh_closes(s); CloseHandle(p);
}

/* ---------------- cancellation ---------------- */

static BOOL post_read(SOCKET s, char *b, DWORD n, OVERLAPPED *o)
{
    DWORD got = 0;
    SET_ERR(0);
    return !sh_rf((HANDLE)s, b, n, &got, o) && GetLastError() == ERROR_IO_PENDING;
}
TEST(shs_cancel_cancelio_cancels_pending_read)
{
    SOCKET c, s; OVERLAPPED o; HANDLE ev = sh_event(); char b[8]; DWORD n;
    UP(); PAIR(c, s, PLAIN);
    sh_ovl(&o, ev);
    CHECK(post_read(s, b, sizeof b, &o));
    SET_ERR(0);
    CHECK(CancelIo((HANDLE)s));
    EQ(sh_wait(ev), WAIT_OBJECT_0);
    EQ32(o.Internal, 0xC0000120);
    SET_ERR(0);
    CHECK(!GetOverlappedResult((HANDLE)s, &o, &n, FALSE));
    EXPECT_ERR(ERROR_OPERATION_ABORTED);
    CloseHandle(ev); sh_closes(c); sh_closes(s);
}
TEST(shs_cancel_cancelio_nothing_pending_succeeds)
{
    SOCKET s;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    SET_ERR(0);
    CHECK(CancelIo((HANDLE)s));
    sh_closes(s);
}
TEST(shs_cancel_ex_nothing_pending_not_found)
{
    SOCKET s;
    UP(); s = sh_make(SOCK_STREAM, PLAIN);
    SET_ERR(0);
    CHECK(!CancelIoEx((HANDLE)s, NULL));
    EXPECT_ERR(ERROR_NOT_FOUND);
    sh_closes(s);
}
/* The request is found through any handle of the same file object. */
TEST(shs_cancel_ex_through_duplicate_handle)
{
    SOCKET c, s; OVERLAPPED o; HANDLE ev = sh_event(), d; char b[8]; DWORD n;
    UP(); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)s, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d);
    sh_ovl(&o, ev);
    CHECK(post_read(s, b, sizeof b, &o));
    SET_ERR(0);
    CHECK(CancelIoEx(d, &o));
    EQ(sh_wait(ev), WAIT_OBJECT_0);
    CHECK(!GetOverlappedResult((HANDLE)s, &o, &n, FALSE));
    EXPECT_ERR(ERROR_OPERATION_ABORTED);
    CloseHandle(d); CloseHandle(ev); sh_closes(c); sh_closes(s);
}
TEST(shs_cancel_ex_all_requests_of_one_socket_only)
{
    SOCKET c1, s1, c2, s2; OVERLAPPED o1, o2; HANDLE e1 = sh_event(), e2 = sh_event(); char b1[8], b2[8];
    UP(); PAIR(c1, s1, PLAIN); PAIR(c2, s2, PLAIN);
    sh_ovl(&o1, e1); sh_ovl(&o2, e2);
    CHECK(post_read(s1, b1, sizeof b1, &o1));
    CHECK(post_read(s2, b2, sizeof b2, &o2));
    CHECK(CancelIoEx((HANDLE)s1, NULL));
    EQ(sh_wait(e1), WAIT_OBJECT_0);
    EQ(WaitForSingleObject(e2, 200), WAIT_TIMEOUT);       /* the other socket's request is untouched */
    CHECK(CancelIoEx((HANDLE)s2, NULL));
    EQ(sh_wait(e2), WAIT_OBJECT_0);
    CloseHandle(e1); CloseHandle(e2); sh_closes(c1); sh_closes(s1); sh_closes(c2); sh_closes(s2);
}
TEST(shs_cancel_ntcancel_nothing_pending_is_success)
{
    SOCKET s; sh_iosb io;
    NT(); s = sh_make(SOCK_STREAM, PLAIN);
    sh_NtCancelIoFile_t nc = NTFN(sh_NtCancelIoFile_t, "NtCancelIoFile");
    REQUIRE(nc);
    EQ32(nc((HANDLE)s, &io), 0);
    sh_closes(s);
}
TEST(shs_cancel_ntcancel_cancels_pending)
{
    SOCKET c, s; sh_iosb io; OVERLAPPED o; HANDLE ev = sh_event(); char b[8];
    NT(); PAIR(c, s, PLAIN);
    sh_NtCancelIoFile_t nc = NTFN(sh_NtCancelIoFile_t, "NtCancelIoFile");
    REQUIRE(nc);
    sh_ovl(&o, ev);
    CHECK(post_read(s, b, sizeof b, &o));
    EQ32(nc((HANDLE)s, &io), 0);
    EQ(sh_wait(ev), WAIT_OBJECT_0);
    EQ32(o.Internal, 0xC0000120);
    CloseHandle(ev); sh_closes(c); sh_closes(s);
}
TEST(shs_cancel_ntcancel_invalid_handle)
{
    sh_iosb io; sh_NtCancelIoFile_t nc = NTFN(sh_NtCancelIoFile_t, "NtCancelIoFile");
    NT(); REQUIRE(nc);
    EQ32(nc((HANDLE)(ULONG_PTR)0x7ffffffc, &io), ST_INVALID_HANDLE);
}

/* A blocked synchronous ReadFile is interrupted by CancelSynchronousIo and by CancelIoEx(NULL), reporting
 * ERROR_OPERATION_ABORTED. */
typedef struct { HANDLE h; char buf[8]; BOOL ret; DWORD err, got; } syncjob;
static DWORD WINAPI sync_reader(LPVOID p)
{
    syncjob *j = (syncjob *)p;
    j->ret = ReadFile(j->h, j->buf, sizeof j->buf, &j->got, NULL);
    j->err = GetLastError();
    return 0;
}
TEST(shs_cancel_synchronous_io_interrupts_blocked_read)
{
    SOCKET c, s; syncjob j; HANDLE t; BOOL r;
    UP(); PAIR(c, s, SYNC);
    memset(&j, 0, sizeof j); j.h = (HANDLE)s;
    t = CreateThread(NULL, 0, sync_reader, &j, 0, NULL);
    Sleep(300);
    SET_ERR(0);
    r = CancelSynchronousIo(t);
    CHECK(r);
    if (WaitForSingleObject(t, SH_WAIT) != WAIT_OBJECT_0) { sh_closes(c); WaitForSingleObject(t, SH_WAIT); }
    CHECK(!j.ret);
    EQ(j.err, ERROR_OPERATION_ABORTED);
    CloseHandle(t); sh_closes(c); sh_closes(s);
}
TEST(shs_cancel_ex_null_interrupts_blocked_sync_read)
{
    SOCKET c, s; syncjob j; HANDLE t;
    UP(); PAIR(c, s, SYNC);
    memset(&j, 0, sizeof j); j.h = (HANDLE)s;
    t = CreateThread(NULL, 0, sync_reader, &j, 0, NULL);
    Sleep(300);
    SET_ERR(0);
    CHECK(CancelIoEx((HANDLE)s, NULL));
    if (WaitForSingleObject(t, SH_WAIT) != WAIT_OBJECT_0) { sh_closes(c); WaitForSingleObject(t, SH_WAIT); }
    CHECK(!j.ret);
    EQ(j.err, ERROR_OPERATION_ABORTED);
    CloseHandle(t); sh_closes(c); sh_closes(s);
}
TEST(shs_cancel_synchronous_io_no_io_in_progress)
{
    SOCKET c, s; syncjob j; HANDLE t;
    UP(); PAIR(c, s, SYNC);
    memset(&j, 0, sizeof j); j.h = (HANDLE)s;
    sh_send(c, "x", 1);
    t = CreateThread(NULL, 0, sync_reader, &j, 0, NULL);
    WaitForSingleObject(t, SH_WAIT);
    SET_ERR(0);
    CHECK(!CancelSynchronousIo(t));
    EXPECT_ERR(ERROR_NOT_FOUND);
    CloseHandle(t); sh_closes(c); sh_closes(s);
}
/* Closing a socket with a pending overlapped read aborts it. */
TEST(shs_cancel_close_aborts_pending_read)
{
    SOCKET c, s; OVERLAPPED o; HANDLE ev = sh_event(); char b[8]; DWORD n;
    UP(); PAIR(c, s, PLAIN);
    sh_ovl(&o, ev);
    CHECK(post_read(s, b, sizeof b, &o));
    sh_closes(s);
    EQ(sh_wait(ev), WAIT_OBJECT_0);
    t_note("pending ReadFile completion status when the socket is closed: 0x%08lx", (unsigned long)o.Internal);
    CHECK(o.Internal != 0 && o.Internal != 0x103);
    CloseHandle(ev); sh_closes(c);
}
/* ...but only when the last handle goes: a pending read survives closing the original while a duplicate is open. */
TEST(shs_cancel_close_with_live_duplicate_keeps_request)
{
    SOCKET c, s; OVERLAPPED o; HANDLE ev = sh_event(), d; char b[8]; DWORD n = 0;
    UP(); PAIR(c, s, PLAIN);
    d = sh_dup((HANDLE)s, 0, FALSE, DUPLICATE_SAME_ACCESS);
    REQUIRE(d);
    sh_ovl(&o, ev);
    CHECK(post_read(s, b, sizeof b, &o));
    sh_closes(s);
    CHECK(WaitForSingleObject(ev, 300) == WAIT_TIMEOUT);       /* still pending: the file object lives on */
    sh_send(c, "k", 1);
    CHECK(WaitForSingleObject(ev, SH_WAIT) == WAIT_OBJECT_0);
    CHECK(GetOverlappedResult(d, &o, &n, FALSE));
    EQ(n, 1);
    CloseHandle(d); CloseHandle(ev); sh_closes(c);
}
