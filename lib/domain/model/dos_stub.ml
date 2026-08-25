(** MS-DOS stub preceding the PE signature in image files. *)

type t = {
  raw: bytes;
  (** The raw bytes of the MS-DOS stub, including the MZ header. *)
  pe_offset: int;
  (** File offset to the PE signature, found at offset 0x3c in the stub. *)
}

(** Byte offset within the DOS header where the PE signature offset is stored. *)
let pe_offset_location = 0x3c

(** Construct a DOS stub value from its raw bytes and the resolved PE offset. *)
let make raw pe_offset = { raw; pe_offset }

let raw t = t.raw
let pe_offset t = t.pe_offset

let mz_magic = Bytes.of_string "MZ"

(** Return [true] if the stub's first two bytes are the MZ signature (0x4d 0x5a). *)
let is_valid t =
  Bytes.length t.raw >= 2 &&
  Bytes.get_uint8 t.raw 0 = Bytes.get_uint8 mz_magic 0 &&
  Bytes.get_uint8 t.raw 1 = Bytes.get_uint8 mz_magic 1

let pp fmt t =
  Format.fprintf fmt "<DOS stub: %d bytes, PE offset=0x%x>"
    (Bytes.length t.raw) t.pe_offset
