(** Concrete binary writer backed by Buffer.t. *)

type t = { buf: Buffer.t }

let create ?(initial_size = 4096) () =
  { buf = Buffer.create initial_size }

let pos t = Buffer.length t.buf
let to_bytes t = Buffer.to_bytes t.buf

let write_u8 t v =
  Buffer.add_uint8 t.buf (v land 0xff)

let write_u16_le t v =
  Buffer.add_uint8 t.buf (v land 0xff);
  Buffer.add_uint8 t.buf ((v lsr 8) land 0xff)

let write_i16_le t v = write_u16_le t (v land 0xffff)

let write_u32_le t v =
  let v = Int32.to_int v in
  Buffer.add_uint8 t.buf (v land 0xff);
  Buffer.add_uint8 t.buf ((v lsr 8) land 0xff);
  Buffer.add_uint8 t.buf ((v lsr 16) land 0xff);
  Buffer.add_uint8 t.buf ((v lsr 24) land 0xff)

let write_i32_le t v = write_u32_le t v

let write_u64_le t v =
  let lo = Int64.to_int32 v in
  let hi = Int64.to_int32 (Int64.shift_right_logical v 32) in
  write_u32_le t lo;
  write_u32_le t hi

let write_bytes t b =
  Buffer.add_bytes t.buf b

let write_string t s =
  Buffer.add_string t.buf s

let write_zero_pad t n =
  for _ = 1 to n do
    Buffer.add_uint8 t.buf 0
  done

let write_align t alignment =
  let p = pos t in
  let rem = p mod alignment in
  if rem <> 0 then write_zero_pad t (alignment - rem)
