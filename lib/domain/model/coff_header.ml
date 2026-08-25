(** Standard COFF file header (IMAGE_FILE_HEADER), 20 bytes.

    Layout per the PE/COFF specification (all fields little-endian):
    {v
    Offset | Size | Field
    -------+------+-------------------------------
      0    |  2   | Machine
      2    |  2   | NumberOfSections
      4    |  4   | TimeDateStamp
      8    |  4   | PointerToSymbolTable
     12    |  4   | NumberOfSymbols
     16    |  2   | SizeOfOptionalHeader
     18    |  2   | Characteristics
    v}
    Total: 20 bytes. *)

(** Size of the COFF file header on disk, in bytes. *)
let size_bytes = 20

(** The COFF file header record. *)
type t = {
  machine: int;
  (** Target machine architecture (raw uint16). See IMAGE_FILE_MACHINE_* constants. *)
  number_of_sections: int;
  (** Number of section headers immediately following the optional header. *)
  time_date_stamp: int32;
  (** Low 32 bits of the Unix timestamp recording when the file was created. *)
  pointer_to_symbol_table: int32;
  (** File offset of the COFF symbol table, or 0 if absent.
      Deprecated in image files; use debug information instead. *)
  number_of_symbols: int32;
  (** Number of entries in the symbol table. Each entry is 18 bytes.
      Also controls the implicit start of the string table immediately
      following the symbol table. *)
  size_of_optional_header: int;
  (** Size in bytes of the optional header that follows this header.
      Zero for COFF object files. *)
  characteristics: int;
  (** Bit flags describing attributes of the file (IMAGE_FILE_* ). *)
}

(** Construct a COFF file header record. *)
let make ~machine ~number_of_sections ~time_date_stamp
         ~pointer_to_symbol_table ~number_of_symbols
         ~size_of_optional_header ~characteristics =
  { machine; number_of_sections; time_date_stamp;
    pointer_to_symbol_table; number_of_symbols;
    size_of_optional_header; characteristics }

let machine t = t.machine
let number_of_sections t = t.number_of_sections
let time_date_stamp t = t.time_date_stamp
let pointer_to_symbol_table t = t.pointer_to_symbol_table
let number_of_symbols t = t.number_of_symbols
let size_of_optional_header t = t.size_of_optional_header
let characteristics t = t.characteristics

(** Return [true] when an optional header is present ([size_of_optional_header > 0]). *)
let has_optional_header t = t.size_of_optional_header > 0

(** File offset of the COFF symbol table.  Alias for [pointer_to_symbol_table]. *)
let symbol_table_offset t = t.pointer_to_symbol_table

(** File offset of the COFF string table.

    The string table begins immediately after the symbol table.  Each symbol
    record is 18 bytes, so:
    {v string_table_offset = pointer_to_symbol_table + number_of_symbols * 18 v}

    Returns [0L] when [pointer_to_symbol_table] is zero (no symbol table). *)
let string_table_offset t =
  if Int32.compare t.pointer_to_symbol_table 0l = 0 then 0L
  else
    let sym_base = Int64.of_int32 t.pointer_to_symbol_table in
    let sym_count = Int64.of_int32 t.number_of_symbols in
    Int64.add sym_base (Int64.mul sym_count 18L)

let pp fmt t =
  Format.fprintf fmt
    "<COFF header: machine=0x%04x sections=%d symtab=0x%lx nsyms=%ld opthdrsz=%d chars=0x%04x>"
    t.machine t.number_of_sections t.pointer_to_symbol_table
    t.number_of_symbols t.size_of_optional_header t.characteristics
