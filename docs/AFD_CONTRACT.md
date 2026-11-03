# The AFD device contract on Windows 10 22H2 x64

This document describes the behavior of the AFD driver (the `\Device\Afd` device that backs every Winsock socket) as
established by the tests in this repository, measured on Windows 10 22H2 (build 19045). It is written for someone
re-implementing the device: it gives the control codes, request layouts (64-bit), the endpoint state machine, the
validation order and the status codes. All layouts are described in prose and tables, not copied from any source.

Where a statement carries an area name in brackets it is asserted by that test area; `COVERAGE.md` has the exact
status sweep over every control code. Anything this document does not state is not covered.

Conventions: offsets are bytes; "pends" means the request returns `STATUS_PENDING` and completes later;
"in-place" means the request completes in the submitting call. Status names are the usual NT names with their values.

## 1. Opening an endpoint

An endpoint is a file object created with `NtCreateFile` on the device path `\Device\Afd\Endpoint`.
The open carries exactly one extended attribute (EA) whose name selects the kind of open [afd_endpoint_create]:

| EA name | Purpose | Value |
|---|---|---|
| `AfdOpenPacketXX` | create a socket endpoint | open packet (below) |
| `AfdRioRDOpenPacket` | registered-I/O registration domain | ignored (any length, even none); opens |
| `AfdSwOpenPacket` | software helper endpoint | server SKUs only; client SKUs answer `STATUS_NOT_SUPPORTED` (0xC00000BB) before looking at the value |

Only the first EA entry is considered; later entries are ignored whether or not they are valid packets.

**Open packet** (the EA value):

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | Flags |
| 4 | 4 | GroupID |
| 8 | 4 | AddressFamily |
| 12 | 4 | SocketType |
| 16 | 4 | Protocol |
| 20 | 4 | TransportDeviceNameLength (bytes) |
| 24 | n | TransportDeviceName, UTF-16, not necessarily terminated |

Flags: 0x00000001 connectionless (datagram), 0x00000010 message oriented, 0x00000100 raw, 0x00001000 multipoint,
0x00010000 multipoint control root, 0x00100000 multipoint data root, 0x01000000 no filtering, 0x10000000 registered
I/O. Bits outside these are rejected with `STATUS_INVALID_PARAMETER` (0xC000000D). An unknown address family with an
unknown group reports the group error.

Validation order, first failing step wins: EA name, then the value length (a value shorter than the fixed header plus
the transport name that the name-length field declares is `STATUS_ACCESS_VIOLATION` 0xC0000005, as is a declared name length that runs past
the value or is huge (0xFFFD and up); an odd name length within the value is `STATUS_INVALID_PARAMETER`), then flags (invalid parameter), then group, then the family/transport lookup.
With no transport name, a family no transport serves is 0xC000A013, and a known family with an unserved type or protocol
(type 0, 9, 0xFFFF; protocol 0xFFFF) is `STATUS_NO_SUCH_FILE` (0xC000000F); type or protocol values with high bits set are
`STATUS_INVALID_PARAMETER`. A message-oriented flag without the connectionless flag is invalid parameter. Group ids 0
(none), 1 (new unconstrained group) and 2 (new constrained group) open; other values that are not existing groups
(0x7ffffff0, 0xffffffff, 0x80000000, ...) are rejected with `STATUS_INVALID_PARAMETER`; the group check precedes the family
check and follows the flags check.

The granted access is the request with generic rights mapped to file rights (generic-all and maximum-allowed give
0x001F01FF); an empty desired-access mask is denied (`STATUS_ACCESS_DENIED`). Opening can be synchronous or
overlapped; a handle opened overlapped completes requests asynchronously through its status block, event, APC or
I/O completion port.

A freshly created, never-bound endpoint answers file-information queries as follows [afd_endpoint_create]:
FileAccess, FileMode, FileAlignment, FileIoCompletionNotification and FileIoPriorityHint succeed (these belong to the
I/O manager); the classes a file system would implement (basic, standard, internal, name, position, network-open,
...) return `STATUS_NOT_IMPLEMENTED` (0xC0000002); classes the system does not define return
`STATUS_INVALID_INFO_CLASS` (0xC0000003); a buffer too short for the class returns `STATUS_INFO_LENGTH_MISMATCH`
(0xC0000004). The full per-class tables are in `afd_endpoint_create` and `afd_close_cleanup`.
`NtReadFile`/`NtWriteFile` on an endpoint are valid only on a connected endpoint; without a byte offset a read is
`STATUS_INVALID_PARAMETER`.

## 2. Issuing requests

Every request is `NtDeviceIoControlFile(endpoint, event, apc, apc_context, iosb, code, in, in_len, out, out_len)`.
Control codes have device type 0x12 (the AFD device); bits 2..11 are the function number; the low two bits are the
transfer method.

- The table has exactly **73 slots**, function numbers 0x12003 .. 0x12123 (see `COVERAGE.md`). Codes are strictly
  increasing in the table.
- Anything else is refused: a function number past the table, a registered code with its method bits changed, with
  another device type, shifted by a multiple of 256 or 1024 function numbers (slot alias), or a slot hole.
  The refusal is `STATUS_INVALID_DEVICE_REQUEST` (0xC0000010) and leaves the endpoint untouched, identically on
  every endpoint kind and state [afd_bind_listen_accept `ablc_*`, afd_info_options `aio_sweep_*`].
- Method "neither" (3) codes read and write the caller's buffers directly; wait-for-listen, accept and defer-accept
  use method "buffered" (0) [afd_bind_listen_accept].
- A request that pends and has no event, APC or port still completes into its status block; requests on a
  synchronous handle block the caller until done.
- Cancelling (`NtCancelIoFile`, `NtCancelIoFileEx`) completes a pending request with `STATUS_CANCELLED` (0xC0000120);
  the classic cancel is per calling thread, the extended one covers every request by that handle or status block;
  cancelling a status block that names nothing is `STATUS_NOT_FOUND` (0xC0000225).
- Requests are copied at submission: the input buffer may be reused immediately [afd_poll_events].

## 3. Endpoint state machine

Stream (TCP) endpoint:

    created --BIND--> bound --START_LISTEN--> listening
       |                 |
       |                 +--CONNECT--> connecting --> connected --PARTIAL_DISCONNECT--> half-closed
       |                                                |
       +--CONNECT (autobind) ---------------------------+      (reset / abort / peer close are flags on connected)

Datagram (UDP) endpoint: created --BIND--> bound; CONNECT sets a default peer (bound-and-connected);
PARTIAL_DISCONNECT with the unconnect flag returns to bound. Raw endpoints behave as datagram for state purposes.

Key rules [afd_bind_listen_accept, afd_connect_send_recv]:

- The driver keeps its own state; the user-mode Winsock layer keeps a separate record (bound, listening, connected
  names). Raw requests update only the driver state, so `getsockname`, `SO_ACCEPTCONN` and `listen()` do not see an
  endpoint driven through raw requests (a Winsock `listen` after a raw listen fails `WSAEINVAL`, and the reverse).
- GET_REMOTE_ADDRESS returns the peer name the Winsock layer stored in the endpoint context when it connected the
  socket; an endpoint Winsock did not connect has none and answers `STATUS_INVALID_CONNECTION` (0xC0000140).
- Closing the last handle to an endpoint ends it: pending requests complete (receive/send with
  `STATUS_CANCELLED`, or `STATUS_CONNECTION_ABORTED` 0xC0000241 as seen through overlapped results), poll waiters are
  woken with the close event, and an unread-data close resets the peer. Duplicated handles (`NtDuplicateObject`,
  inheritance) keep the endpoint alive; only the final close tears it down, including when the final handle belongs
  to another process that exits [afd_close_cleanup].
- Port reuse: a bound port is held until the endpoint closes, then is free again.

## 4. Control codes

Grouped by function; sizes in bytes. "refused" for a state means the stated status; see `COVERAGE.md` for every
code on every endpoint kind and request shape.

### 4.1 Bind, listen, accept (afd_bind_listen_accept)

| Code | Name | Input | Output | Behavior |
|---|---|---|---|---|
| 0x12003 | BIND | share word (4) then a socket address | socket address (the bound name) | binds; wildcard port 0 picks an ephemeral port |
| 0x1200b | START_LISTEN | 12: use-SAN byte, pad(3), backlog (4), delayed-accept word (4) | none (ignored) | stream endpoints only |
| 0x1200c | WAIT_FOR_LISTEN | none | 4-byte sequence number + peer address | oldest queued connection |
| 0x12090 | WAIT_FOR_LISTEN_LIFO | none | same | newest queued connection |
| 0x12010 | ACCEPT | 16: use-SAN byte, pad(3), sequence (4), accept handle (8) | none | attaches the connection to the target endpoint |
| 0x1208c | DEFER_ACCEPT | 8: sequence (4), flag (4) | none | flag clear: back to the waiting list; set: refuse the connection |
| 0x12083 | SUPER_ACCEPT | AcceptEx block | | judges listener state before buffer lengths |
| 0x12113 | UNBIND | 8 bytes | none | only for stream endpoints that bound by themselves |
| 0x1202f | GET_ADDRESS | none | local socket address | bound endpoint required |
| 0x1203f | GET_REMOTE_ADDRESS | none | the stored peer record | see state rules |

BIND: share word 0 default, 1 allow reuse by others that also asked, 2 and 3 other modes; the word is not validated.
A second endpoint binding a taken address and port gets `STATUS_SHARING_VIOLATION` (0xC0000043), except that a bind
asking for reuse against a holder that did not is `STATUS_ACCESS_DENIED` (0xC0000022) and two binds that both asked
for reuse succeed. A second bind on an already bound endpoint (stream, datagram, listening or connected) is
`STATUS_ADDRESS_ALREADY_ASSOCIATED` (0xC0000238) and leaves the first name in place. Address errors: family 0 is
`STATUS_INVALID_ADDRESS_COMPONENT` (0xC0000207); a family other than the endpoint's is `STATUS_INVALID_ADDRESS`
(0xC0000141); input longer than the address is accepted; the output buffer must cover the input address length;
IPv6 flow info is accepted and not echoed; a scope id on a loopback IPv6 address is refused; the unused tail of an
IPv4 address (`sin_zero`) is ignored. Specific and wildcard binds coexist on one port; distinct loopback addresses do
not conflict; TCP and UDP port spaces are independent.

GET_ADDRESS: unbound endpoint is always `STATUS_INVALID_PARAMETER`; the output must hold the family's whole address
(16 bytes IPv4, 28 IPv6), less than 2 bytes is invalid parameter, in between is `STATUS_BUFFER_TOO_SMALL`
(0xC0000023).

START_LISTEN: unbound endpoint is `STATUS_INVALID_PARAMETER`; datagram endpoints and connected clients are refused;
a second listen is refused; input shorter than 12 bytes leaves the endpoint bound; backlog and delayed-accept values
are all accepted; the SAN flag without a helper is accepted. A connect with no listener ends with
`STATUS_CONNECTION_REFUSED` (0xC0000236), and the endpoint stays bound and listenable.

WAIT_FOR_LISTEN has three output zones: below 12 bytes `STATUS_INVALID_PARAMETER`; from 12 to one byte short of the
full answer `STATUS_BUFFER_TOO_SMALL` without consuming the connection; at the full answer (4 + 16 for IPv4, 4 + 28 for
IPv6, reported as 20 and 32) success. It pends if nothing is queued.

ACCEPT: the endpoint must be listening; a short input block, an unknown sequence number, a sequence number that did
not come from wait-for-listen, a closed or non-endpoint handle (`STATUS_INVALID_HANDLE` 0xC0000008) are refused; the
sequence is single-use; the target endpoint must be fresh (a target already bound is refused) and is consumed; IOSB
information is 0; data sent before accept is delivered; the accepted endpoint reports the listener's local name and
the client sees the listener as its peer.

### 4.2 Connect, data transfer (afd_connect_send_recv)

| Code | Name | Request |
|---|---|---|
| 0x12007 / 0x120bb | CONNECT / CONNECT_EX | 0x18-byte header (use-SAN byte, root handle, reserved word) then the raw socket address |
| 0x12017 | RECEIVE | 24: buffer list pointer (8), count (4), AFD flags (4), TDI flags (4), pad (4) |
| 0x1201f | SEND | same 24-byte block |
| 0x1201b | RECEIVE_DATAGRAM | 40: the 24-byte block + address buffer pointer (+0x18) + address length pointer (+0x20) |
| 0x12023 | SEND_DATAGRAM | 104: buffers, count, AFD flags, ..., destination length at +0x58, destination pointer at +0x60 |
| 0x1202b | PARTIAL_DISCONNECT | 16: flags (4) at 0, timeout (LARGE_INTEGER) at 8 |

TDI flags on receive: 0x0020 normal data, 0x0040 expedited (urgent), 0x0080 peek, 0x4000 wait-all. AFD flag 0x0002
forces asynchronous completion. Disconnect flags: 1 send, 2 receive, 4 abortive, 8 unconnect datagram.

CONNECT: a block shorter than the header is `STATUS_INVALID_PARAMETER`, completing in-place. The address is validated
before any network activity: a family above the largest known, or fewer bytes than the family's address, is
`STATUS_INVALID_ADDRESS` (or invalid parameter on the legacy endpoint flavor; both are accepted and the observed one
is recorded). A good stream connect pends or completes with success and zero bytes; a closed port ends with
`STATUS_CONNECTION_REFUSED`. On a datagram endpoint the request sets the default peer.

RECEIVE validation order: connected state (stream not connected: `STATUS_INVALID_CONNECTION`; datagram:
`STATUS_INVALID_PARAMETER`), the 24-byte block, exactly one of the normal/urgent selectors, a non-empty buffer list with
a non-NULL array. Wait-all is accepted only with the normal selector and nothing else. Graceful peer close completes
a pending receive with success and zero bytes; reset completes it with `STATUS_CONNECTION_RESET` (0xC000020D); the
graceful-disconnect status is 0xC0000237 where an interface reports it.

SEND validation order: connected state (`STATUS_INVALID_CONNECTION`), per-direction shutdown flags
(`STATUS_PIPE_DISCONNECTED` 0xC00000B0, or `STATUS_LOCAL_DISCONNECT` 0xC000013B after a local abort) and the reset
flag, then the block, then the buffer list (non-empty, non-NULL array, at most 0x0fffffff entries). Large sends pend
and can be cancelled.

Datagram requests, in order: the endpoint must be a datagram endpoint (invalid parameter otherwise); the receive or
send shutdown flag (`STATUS_PIPE_DISCONNECTED`); the endpoint must be bound or connected; the block must be complete;
then buffers and address are examined. Datagram boundaries are preserved, zero-length datagrams are delivered, and a
truncated receive is `STATUS_BUFFER_OVERFLOW` (0x80000005).

PARTIAL_DISCONNECT: a block under 16 bytes is invalid parameter before anything else. A stream endpoint must be
connected; flags then apply independently and idempotently, unknown bits are ignored, an empty flag word succeeds and
does nothing. A datagram endpoint accepts it in any state, records the send/receive shutdown bits for its own sends and
receives; the unconnect bit returns a connected datagram endpoint to bound.

TRANSMIT_FILE (0x1207f) and TRANSMIT_PACKETS (0x120c3): validated first on endpoint state (`STATUS_INVALID_CONNECTION`
when not connected), then on the block; a good request completes after the transport accepted the bytes and reports
head + file range + tail in Information; the disconnect flag disconnects after sending.

### 4.3 Poll and event select (afd_poll_events)

POLL (0x12024) input: a 16-byte header { timeout (8, 100 ns units, negative = relative, 0x7fffffffffffffff = infinite),
count (4), exclusive byte, pad (3) } followed by `count` entries of 16 bytes { handle value (8), event mask (4),
status (4) }. Output has the same shape; only the reported prefix is written.

Event bits: 0x0001 receive, 0x0002 expedited, 0x0004 send, 0x0008 disconnect, 0x0010 abort, 0x0020 close, 0x0040
connect, 0x0080 accept, 0x0100 connect failed, 0x0200 QoS, 0x0400 group QoS, 0x0800 routing, 0x1000 address list.

- State bits are level-triggered; polling consumes nothing; the mask only filters what is reported, except that the
  local-close indication ignores the mask. Reserved, QoS and route bits are never reported by a poll.
- A refused connect reports the failed bit with the refusal status in that entry's status field; statuses are
  per entry. A listener reports only the accept bit; its close ends a poll with the close bit.
- Closing one handle of a duplicated endpoint is not a local close. Closing an unrelated socket leaves a poll alone.
- Timeout: zero is an immediate snapshot; a relative or absolute future deadline ends on event or time; the
  exclusive flag is a single byte and demands the infinite timeout, any other timeout (relative, absolute, zero, just
  below infinite, any non-zero byte in the deadline) is refused before anything is queued; an exclusive infinite poll
  pends until cancelled.
- Size protocol: the count is checked before the handles; entries whose handle is not a socket endpoint fail the
  whole request (wrong object type `STATUS_OBJECT_TYPE_MISMATCH` 0xC0000024, closed handle `STATUS_INVALID_HANDLE`,
  non-AFD file `STATUS_INVALID_HANDLE`); the request may be sent through any endpoint handle as carrier, but an event
  handle as carrier is a type mismatch and a closed one an invalid handle. Ready entries keep submission order;
  a duplicated handle value is reported for each occurrence.
- Cancel: completes with `STATUS_CANCELLED`; a sibling poll on the same handle keeps waiting.

EVENT_SELECT (0x12087): input 16 bytes { event handle, mask }, method neither. GET_EVENTS (0x1208b): the input
pointer (length 0) is an optional event handle to reset; the 0x38-byte output is { pending mask (4), status[13] (4
each, per event bit) }. The selected mask gates both signalling and the pending bits (bits outside the mask stay
pending); GET_EVENTS resets the event handle it is given even when nothing is pending; a failed call consumes nothing;
the poll and the event-select bookkeeping are independent.

### 4.4 Information, context, options (afd_info_options)

GET_INFORMATION (0x1207b) and SET_INFORMATION (0x1203b) use a 16-byte record { class (4), pad (4), value (8) }.
GET reports 16 bytes on success; the length is checked before the class (`STATUS_BUFFER_TOO_SMALL` for output under
16, `STATUS_INVALID_PARAMETER` for bad input shape); GET of classes 0, 1, 2, 9, 11, 12 and 13 and SET of any class outside the defined set (18, 19, 31, 64, 255, 0x10000, 0x7fffffff, 0x80000000, 0xffffffff, ...) are `STATUS_INVALID_PARAMETER`; the output
buffer on SET is ignored and Information is 0.

| Class | Meaning | Observed values |
|---:|---|---|
| 1 | inline (urgent data in stream) mode | set-only (GET is invalid parameter); boolean; mirrors SO_OOBINLINE |
| 2 | non-blocking | set-only (GET is invalid parameter) |
| 3 | maximum send size | stream 0xffffffff; UDP 65507; raw 65515 |
| 4 | sends pending | 0 on idle endpoints and after completed sends |
| 5 | maximum path send size | equals class 3 |
| 6 | receive window | default non-zero, uniform across kinds |
| 7 | send window | default non-zero; settable on connected streams, uses the low 32 bits, round-trips; independent per endpoint |
| 8 | connect time | all ones when not connected; seconds since connect when connected (accepted endpoints too) |
| 9 | circular queue | set-only (GET is invalid parameter) |
| 10 | group id and type | zero for ungrouped |
| 11 | report unreachable | set-only (GET is invalid parameter) |
| 14 | delivery status | unbound endpoints refused; bound UDP and connected TCP answer |

CONTEXT (afd_info_options `context.c`): every provider-created endpoint carries an opaque caller-defined blob
(SET_CONTEXT 0x12047 replaces it, any length; GET_CONTEXT 0x12043 copies up to the output size and reports the full
stored size in Information, completing `STATUS_BUFFER_OVERFLOW` when it did not all fit; an endpoint with no blob
answers GET with `STATUS_INVALID_PARAMETER`). QUERY_HANDLES (0x12037) returns the handle record of the endpoint.

Connect/disconnect data and options (0x1204b .. 0x12077): stream transports do not carry setup data, so requests are
validated and dropped. SET_x (0x1204b, 0x1204f, 0x12053, 0x12057) with data in the output buffer succeeds on stream
endpoints and is invalid parameter on datagram and raw ones; GET_x (0x1205b, 0x1205f, 0x12063, 0x12067) always succeeds
with Information 0; SIZE_x (0x1206b, 0x1206f, 0x12073, 0x12077) succeeds on stream endpoints and is invalid
parameter elsewhere. Quality of service (0x12094 SET, 0x12098 GET) is a fixed 0x58-byte exchange: SET validates the
length and stores nothing; GET returns the 0x50-byte default structure.

Others: NO_OPERATION (0x1209f) succeeds on every endpoint in every shape; with an input record of at least 16 bytes
{ status (4), pad (4), information (8) } it completes with that status and information. VALIDATE_GROUP (0x120a0),
GET_UNACCEPTED_CONNECT_DATA (0x120a7), routing interface query/change (0x120ab/0x120ac), address-list query/change
(0x120b3/0x120b4: query answers success on UDP/raw and some shapes, see the sweep), SQM (0x12117: success or
invalid-device-request depending on build), RIO (0x1211b: 0xC00000F0 when no input block is given,
`STATUS_INVALID_DEVICE_REQUEST` otherwise), SOCKET_TRANSFER_BEGIN/END (0x1211f/0x12123: success).
SAN codes 0x120d7 .. 0x1210c are validated and refused as invalid parameter (or `STATUS_INVALID_HANDLE` for the
service-process codes 0x12103, 0x12107, 0x1210b) when no SAN helper is registered.

## 5. Status code summary

| NTSTATUS | Value | Typical meaning here |
|---|---|---|
| STATUS_SUCCESS | 0x00000000 | |
| STATUS_TIMEOUT | 0x00000102 | poll deadline reached |
| STATUS_PENDING | 0x00000103 | request queued |
| STATUS_BUFFER_OVERFLOW | 0x80000005 | output did not fit; partial data written |
| STATUS_ACCESS_VIOLATION | 0xC0000005 | EA value / NULL inner pointer |
| STATUS_INVALID_HANDLE | 0xC0000008 | closed or non-socket handle in a request |
| STATUS_INVALID_PARAMETER | 0xC000000D | wrong state, short block, bad shape |
| STATUS_INVALID_DEVICE_REQUEST | 0xC0000010 | unregistered control code |
| STATUS_BUFFER_TOO_SMALL | 0xC0000023 | output below the answer size, request not consumed |
| STATUS_OBJECT_TYPE_MISMATCH | 0xC0000024 | handle of the wrong object type |
| STATUS_SHARING_VIOLATION | 0xC0000043 | address in use |
| STATUS_PIPE_DISCONNECTED | 0xC00000B0 | data direction shut down |
| STATUS_NOT_SUPPORTED | 0xC00000BB | helper endpoint on client SKU, unbind on datagram |
| STATUS_CANCELLED | 0xC0000120 | request cancelled / endpoint closed |
| STATUS_LOCAL_DISCONNECT | 0xC000013B | send after local abort |
| STATUS_INVALID_CONNECTION | 0xC0000140 | stream request on an unconnected endpoint |
| STATUS_INVALID_ADDRESS | 0xC0000141 | address too short or wrong family |
| STATUS_INVALID_ADDRESS_COMPONENT | 0xC0000207 | family 0 / bad part of an address |
| STATUS_CONNECTION_RESET | 0xC000020D | peer reset |
| STATUS_CONNECTION_REFUSED | 0xC0000236 | no listener |
| STATUS_GRACEFUL_DISCONNECT | 0xC0000237 | orderly peer close where reported |
| STATUS_ADDRESS_ALREADY_ASSOCIATED | 0xC0000238 | endpoint already bound |
| STATUS_CONNECTION_ABORTED | 0xC0000241 | closed with requests outstanding |
| STATUS_NOT_FOUND | 0xC0000225 | cancel target not found |
| 0xC000A013 | | no transport serves the family |

## 6. Where to look

| Question | Area |
|---|---|
| open packet, EA rules, handle behavior | `afd_endpoint_create` |
| bind / listen / accept / defer / unbind | `afd_bind_listen_accept` |
| connect, send, receive, datagrams, partial disconnect, completion delivery | `afd_connect_send_recv` |
| poll, event select, enum events | `afd_poll_events` |
| information classes, context, connect data, QoS, full control-code sweep | `afd_info_options` |
| close, duplicate, cancel, completion ports, peer effects | `afd_close_cleanup` |
| SAN, connect/disconnect data per literal code | `gap_05`, `dx_gap_05` |
