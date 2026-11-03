/* TransmitFile extension function (fetched through SIO_GET_EXTENSION_FUNCTION_POINTER): invalid arguments,
 * header/trailer buffers, file contents, the overlapped path with and without a start offset, and the
 * datagram-socket rejection. Data is verified byte for byte on the receiving socket. */
#include "h9.h"

typedef BOOL (WINAPI *transmitfile_fn)(SOCKET, HANDLE, DWORD, DWORD, LPOVERLAPPED, LPTRANSMIT_FILE_BUFFERS, DWORD);

#define FILE_LEN 3000

static const char HEAD[] = "hello world";
static const char TAIL[] = "goodbye!!!";

struct fx {
    transmitfile_fn tf;
    SOCKET lst, cli, dst;
    HANDLE file;
    char data[FILE_LEN];
    char path[MAX_PATH];
};

static int fx_open(struct fx *f)
{
    GUID g = WSAID_TRANSMITFILE;
    struct sockaddr_in a;
    DWORD n;
    memset(f, 0, sizeof *f);
    f->file = INVALID_HANDLE_VALUE;
    f->cli = f->dst = INVALID_SOCKET;
    f->lst = h9_listener(&a, 1, SOCK_STREAM);
    f->cli = socket(AF_INET, SOCK_STREAM, 0);
    if (f->lst == INVALID_SOCKET || f->cli == INVALID_SOCKET) return 0;
    f->tf = (transmitfile_fn)h9_ext(f->cli, g);
    if (!f->tf) return 0;
    for (int i = 0; i < FILE_LEN; i++) f->data[i] = (char)('A' + (i * 7 + i / 251) % 26);
    t_tmpfile(f->path, sizeof f->path, "tf_payload.bin");
    f->file = CreateFileA(f->path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (f->file == INVALID_HANDLE_VALUE) return 0;
    if (!WriteFile(f->file, f->data, FILE_LEN, &n, NULL) || n != FILE_LEN) return 0;
    SetFilePointer(f->file, 0, NULL, FILE_BEGIN);
    if (connect(f->cli, (struct sockaddr *)&a, sizeof a)) return 0;
    f->dst = h9_accept(f->lst);
    return f->dst != INVALID_SOCKET;
}

static void fx_close(struct fx *f)
{
    if (f->file != INVALID_HANDLE_VALUE) CloseHandle(f->file);
    if (f->cli != INVALID_SOCKET) closesocket(f->cli);
    if (f->dst != INVALID_SOCKET) closesocket(f->dst);
    if (f->lst != INVALID_SOCKET) closesocket(f->lst);
    DeleteFileA(f->path);
}

#define FX(f) struct fx f; do { NEED_NET(); if (!fx_open(&f)) { fx_close(&f); t_skip("TransmitFile fixture unavailable"); return; } } while (0)

/* The next `len` bytes on the destination must equal `want`. */
static void expect_stream(SOCKET s, const void *want, int len)
{
    char buf[FILE_LEN + 64];
    int got;
    memset(buf, 0, sizeof buf);
    got = h9_recv_all(s, buf, len);
    EXPECT_EQ(got, len);
    CHECK(got == len && !memcmp(buf, want, len));
}

static void rewind_file(struct fx *f) { SetFilePointer(f->file, 0, NULL, FILE_BEGIN); }

static void fill_buffers(TRANSMIT_FILE_BUFFERS *b)
{
    b->Head = (PVOID)HEAD;
    b->HeadLength = sizeof HEAD;
    b->Tail = (PVOID)TAIL;
    b->TailLength = sizeof TAIL;
}

/* Overlapped transmit; returns the byte count reported through WSAGetOverlappedResult. */
static DWORD overlapped_transmit(struct fx *f, DWORD offset, TRANSMIT_FILE_BUFFERS *b)
{
    OVERLAPPED ov;
    DWORD sent = POISON, flags = 0;
    int e;
    BOOL r;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    ov.Offset = offset;
    rewind_file(f);
    SetLastError(0);
    r = f->tf(f->cli, f->file, 0, 0, &ov, b, 0);
    e = WSAGetLastError();
    CHECK(!r);
    EXPECT_EQ(e, ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(ov.hEvent, 4000), WAIT_OBJECT_0);
    CHECK(WSAGetOverlappedResult(f->cli, (LPWSAOVERLAPPED)&ov, &sent, FALSE, &flags));
    CloseHandle(ov.hEvent);
    return sent;
}

TEST(transmitfile_invalid_socket_is_notsock)
{
    FX(f);
    WSASetLastError(POISON);
    CHECK(!f.tf(INVALID_SOCKET, f.file, 0, 0, NULL, NULL, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTSOCK);
    fx_close(&f);
}

TEST(transmitfile_unconnected_socket_is_notconn)
{
    FX(f);
    SOCKET u = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(u != INVALID_SOCKET);
    WSASetLastError(POISON);
    CHECK(!f.tf(u, NULL, 0, 0, NULL, NULL, TF_REUSE_SOCKET));
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(u);
    fx_close(&f);
}

TEST(transmitfile_nothing_to_send_succeeds_and_sends_nothing)
{
    FX(f);
    char b[16];
    h9_nonblock(f.dst, 1);
    CHECK(f.tf(f.cli, NULL, 0, 0, NULL, NULL, 0));
    WSASetLastError(POISON);
    CHECK(recv(f.dst, b, sizeof b, 0) == -1);
    EXPECT_EQ(WSAGetLastError(), WSAEWOULDBLOCK);
    fx_close(&f);
}

TEST(transmitfile_buffers_only_arrive_in_order)
{
    FX(f);
    TRANSMIT_FILE_BUFFERS tb;
    char want[sizeof HEAD + sizeof TAIL];
    fill_buffers(&tb);
    memcpy(want, HEAD, sizeof HEAD);
    memcpy(want + sizeof HEAD, TAIL, sizeof TAIL);
    CHECK(f.tf(f.cli, NULL, 0, 0, NULL, &tb, 0));
    expect_stream(f.dst, want, sizeof want);
    fx_close(&f);
}

TEST(transmitfile_file_only_sends_whole_file)
{
    FX(f);
    rewind_file(&f);
    CHECK(f.tf(f.cli, f.file, 0, 0, NULL, NULL, 0));
    expect_stream(f.dst, f.data, FILE_LEN);
    fx_close(&f);
}

TEST(transmitfile_file_with_head_and_tail)
{
    FX(f);
    TRANSMIT_FILE_BUFFERS tb;
    fill_buffers(&tb);
    rewind_file(&f);
    CHECK(f.tf(f.cli, f.file, 0, 0, NULL, &tb, 0));
    expect_stream(f.dst, HEAD, sizeof HEAD);
    expect_stream(f.dst, f.data, FILE_LEN);
    expect_stream(f.dst, TAIL, sizeof TAIL);
    fx_close(&f);
}

TEST(transmitfile_explicit_byte_count)
{
    FX(f);
    rewind_file(&f);
    CHECK(f.tf(f.cli, f.file, 1000, 0, NULL, NULL, 0));
    expect_stream(f.dst, f.data, 1000);
    CHECK(!h9_readable(f.dst, 200));   /* nothing beyond the requested count */
    fx_close(&f);
}

TEST(transmitfile_overlapped_file_reports_file_size)
{
    FX(f);
    DWORD sent = overlapped_transmit(&f, 0, NULL);
    EXPECT_EQ(sent, FILE_LEN);
    expect_stream(f.dst, f.data, FILE_LEN);
    fx_close(&f);
}

TEST(transmitfile_overlapped_start_offset)
{
    FX(f);
    DWORD sent = overlapped_transmit(&f, 10, NULL);
    EXPECT_EQ(sent, FILE_LEN - 10);
    expect_stream(f.dst, f.data + 10, FILE_LEN - 10);
    fx_close(&f);
}

TEST(transmitfile_overlapped_file_with_head_and_tail)
{
    FX(f);
    TRANSMIT_FILE_BUFFERS tb;
    DWORD sent;
    fill_buffers(&tb);
    sent = overlapped_transmit(&f, 0, &tb);
    EXPECT_EQ(sent, FILE_LEN + sizeof HEAD + sizeof TAIL);
    expect_stream(f.dst, HEAD, sizeof HEAD);
    expect_stream(f.dst, f.data, FILE_LEN);
    expect_stream(f.dst, TAIL, sizeof TAIL);
    fx_close(&f);
}

TEST(transmitfile_datagram_socket_is_notconn)
{
    FX(f);
    SOCKET u = socket(AF_INET, SOCK_DGRAM, 0);
    REQUIRE(u != INVALID_SOCKET);
    WSASetLastError(POISON);
    CHECK(!f.tf(u, NULL, 0, 0, NULL, NULL, 0));
    EXPECT_EQ(WSAGetLastError(), WSAENOTCONN);
    closesocket(u);
    fx_close(&f);
}
