(** COFF symbol name: either inline (up to 8 bytes) or a string-table reference.

    The PE/COFF specification encodes symbol names in the first 8 bytes of a
    symbol table record:

    - If the first four bytes are all zero, bytes 4–7 contain a 32-bit
      little-endian offset into the COFF string table.
    - Otherwise, the 8 bytes directly encode the name (null-padded, not
      null-terminated if exactly 8 bytes long).

    Use {!resolve} to obtain the final string regardless of which variant
    is stored. *)

(** A COFF symbol name, before string-table resolution. *)
type t =
  | Inline of string
  (** The name is encoded directly in the symbol record (at most 8 bytes). *)
  | Reference of int
  (** Byte offset into the COFF string table where the null-terminated name
      begins.  The string table itself begins with a 4-byte size field;
      offsets are relative to that size field (i.e. valid offsets start at 4). *)

(** Parse a symbol name from [buf] at byte [offset].

    Reads exactly 8 bytes.  If the first 4 bytes are zero the name is a
    {!Reference}; otherwise it is an {!Inline} string with trailing null
    bytes stripped. *)
let of_bytes buf offset =
  (* First four bytes being zero signals a string-table reference. *)
  if Bytes.get_uint8 buf  offset      = 0 &&
     Bytes.get_uint8 buf (offset + 1) = 0 &&
     Bytes.get_uint8 buf (offset + 2) = 0 &&
     Bytes.get_uint8 buf (offset + 3) = 0
  then
    let off = Bytes.get_int32_le buf (offset + 4) in
    Reference (Int32.to_int off)
  else begin
    (* Up to 8 bytes; trim trailing nulls. *)
    let len = ref 8 in
    while !len > 0 && Bytes.get_uint8 buf (offset + !len - 1) = 0 do
      decr len
    done;
    Inline (Bytes.sub_string buf offset !len)
  end

(** Return the resolved symbol name string.

    @param string_table  The raw content of the COFF string table, {b not}
                         including the leading 4-byte size field; i.e. the
                         bytes starting from file offset
                         [pointer_to_symbol_table + number_of_symbols * 18 + 4].
    For an {!Inline} name the string is returned directly.
    For a {!Reference}, the null-terminated string at [off - 4] within
    [string_table] is returned (adjusted because the spec offsets include the
    size field).  Returns [""] for out-of-bounds references. *)
let resolve t ~string_table =
  match t with
  | Inline s -> s
  | Reference off ->
    (* The offset in the symbol record is relative to the start of the
       string table including its 4-byte size header.  We receive the
       table without that header, so subtract 4. *)
    let adjusted = off - 4 in
    let len = String.length string_table in
    if adjusted < 0 || adjusted >= len then ""
    else begin
      let end_off = ref adjusted in
      while !end_off < len && string_table.[!end_off] <> '\x00' do
        incr end_off
      done;
      String.sub string_table adjusted (!end_off - adjusted)
    end

let pp fmt = function
  | Inline s      -> Format.fprintf fmt "\"%s\"" s
  | Reference off -> Format.fprintf fmt "@strtab+%d" off
