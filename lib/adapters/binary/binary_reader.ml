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
    (* Sign-extend 16-bit value *)
    let v = Bytes.get_uint16_le t.buf t.pos in
    t.pos <- t.pos + 2;
    let signed = if v land 0x8000 <> 0 then v lor (lnot 0xffff) else v in
    Ok signed

let read_u32_le t =
  match bounds_check t 4 with
  | Error e -> Error e
  | Ok () ->
    let v = Bytes.get_int32_le t.buf t.pos in
    t.pos <- t.pos + 4;
    Ok v

let read_i32_le t = read_u32_le t  (* int32 is already signed *)

let read_u64_le t =
  match bounds_check t 8 with
  | Error e -> Error e
  | Ok () ->
    let lo = Int64.of_int32 (Bytes.get_int32_le t.buf t.pos) in
    let hi = Int64.of_int32 (Bytes.get_int32_le t.buf (t.pos + 4)) in
    t.pos <- t.pos + 8;
    (* Combine: lo (low 32 bits, treated as unsigned) | hi << 32 *)
    let lo_u = Int64.logand lo 0xffffffffL in
    let hi_s = Int64.shift_left hi 32 in
    Ok (Int64.logor hi_s lo_u)

let read_u32_be t =
  match bounds_check t 4 with
  | Error e -> Error e
  | Ok () ->
    let b0 = Bytes.get_uint8 t.buf t.pos in
    let b1 = Bytes.get_uint8 t.buf (t.pos+1) in
    let b2 = Bytes.get_uint8 t.buf (t.pos+2) in
    let b3 = Bytes.get_uint8 t.buf (t.pos+3) in
    t.pos <- t.pos + 4;
    let v = Int32.of_int ((b0 lsl 24) lor (b1 lsl 16) lor (b2 lsl 8) lor b3) in
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
  let pos = ref start in
  while !pos < limit && Bytes.get_uint8 t.buf !pos <> 0 do
    incr pos
  done;
  if !pos >= limit then
    Error (Error.String_not_terminated { offset = start })
  else begin
    let s = Bytes.sub_string t.buf start (!pos - start) in
    t.pos <- !pos + 1;  (* skip null terminator *)
    Ok s
  end

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
