(** Concrete binary reader: stateful cursor over an immutable Bytes buffer. *)

type t = {
  buf: bytes;
  mutable pos: int;
}

let of_bytes buf = { buf; pos = 0 }

let pos t = t.pos
let length t = Bytes.length t.buf
let remaining t = Bytes.length t.buf - t.pos

let bounds_check t n =
  if t.pos + n > Bytes.length t.buf then
    Error (Error.Unexpected_eof {
      offset = t.pos;
      needed = n;
      available = remaining t;
    })
  else Ok ()

let seek t off =
  if off < 0 || off > Bytes.length t.buf then
    Error (Error.Offset_out_of_bounds { offset = off; size = Bytes.length t.buf })
  else begin
    t.pos <- off;
    Ok ()
  end

let skip t n =
  match bounds_check t n with
  | Error e -> Error e
  | Ok () -> t.pos <- t.pos + n; Ok ()

let read_u8 t =
  match bounds_check t 1 with
  | Error e -> Error e
  | Ok () ->
    let v = Bytes.get_uint8 t.buf t.pos in
    t.pos <- t.pos + 1;
    Ok v

let read_u16_le t =
  match bounds_check t 2 with
  | Error e -> Error e
  | Ok () ->
    let v = Bytes.get_uint16_le t.buf t.pos in
    t.pos <- t.pos + 2;
    Ok v

let read_i16_le t =
  match bounds_check t 2 with
  | Error e -> Error e
  | Ok () ->
    let v = Bytes.get_int16_le t.buf t.pos in
    t.pos <- t.pos + 2;
    Ok v

let read_u32_le t =
  match bounds_check t 4 with
  | Error e -> Error e
  | Ok () ->
    let v = Bytes.get_int32_le t.buf t.pos in
    t.pos <- t.pos + 4;
    Ok v

let read_i32_le t = read_u32_le t

let read_u64_le t =
  match bounds_check t 8 with
  | Error e -> Error e
  | Ok () ->
    let v = Bytes.get_int64_le t.buf t.pos in
    t.pos <- t.pos + 8;
    Ok v

let read_u32_be t =
  match bounds_check t 4 with
  | Error e -> Error e
  | Ok () ->
    let v = Bytes.get_int32_be t.buf t.pos in
    t.pos <- t.pos + 4;
    Ok v

let read_bytes t n =
  match bounds_check t n with
  | Error e -> Error e
  | Ok () ->
    let result = Bytes.sub t.buf t.pos n in
    t.pos <- t.pos + n;
    Ok result

let read_string t n =
  match read_bytes t n with
  | Error e -> Error e
  | Ok b -> Ok (Bytes.to_string b)

let read_cstring t ?(max_len = 4096) () =
  let start = t.pos in
  let limit = min (Bytes.length t.buf) (start + max_len) in
  let rec find_null p =
    if p >= limit then Error (Error.String_not_terminated { offset = start })
    else if Bytes.get_uint8 t.buf p = 0 then Ok p
    else find_null (p + 1)
  in
  match find_null start with
  | Error e -> Error e
  | Ok null_pos ->
    let s = Bytes.sub_string t.buf start (null_pos - start) in
    t.pos <- null_pos + 1;
    Ok s

let peek_bytes t n =
  match bounds_check t n with
  | Error e -> Error e
  | Ok () -> Ok (Bytes.sub t.buf t.pos n)

let at_offset t off f =
  let saved = t.pos in
  match seek t off with
  | Error e -> Error e
  | Ok () ->
    let result = f t in
    t.pos <- saved;
    result
