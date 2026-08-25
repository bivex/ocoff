(** COFF symbol table record, 18 bytes per entry.

    Each primary symbol record may be followed by zero or more auxiliary
    records (each also 18 bytes).  The number of auxiliary records is given
    by a field in the primary record.  The [aux_records] field of {!t}
    aggregates them after parsing.

    Primary record layout:
    {v
    Offset | Size | Field
    -------+------+-------------------------------
      0    |  8   | Name (see Symbol_name)
      8    |  4   | Value
     12    |  2   | SectionNumber (signed)
     14    |  2   | Type
     16    |  1   | StorageClass
     17    |  1   | NumberOfAuxSymbols
    v}
    Total: 18 bytes. *)

(** Size of one symbol table record (primary or auxiliary) on disk, in bytes. *)
let size_bytes = 18

(** COFF symbol type encoding. *)
type symbol_type = {
  raw: int;
  (** Raw 16-bit type field. *)
  base_type: int;
  (** Base (scalar) type code (bits 0..3). Significant values:
      0 = no type, 2 = char, 3 = short, 4 = int, … *)
  derived_type: int;
  (** Derived type modifier (bits 4..7):
      0 = none, 1 = pointer, 2 = function (0x20), 3 = array. *)
}

(** An 18-byte auxiliary record attached to a symbol entry. *)
type auxiliary_record =
  | FunctionDef of {
      tag_index: int32;
      total_size: int32;
      pointer_to_linenumber: int32;
      pointer_to_next_function: int32;
    }
  | BfEfSymbol of {
      linenumber: int;
      pointer_to_next_function: int32;
    }
  | WeakExternal of {
      tag_index: int32;
      characteristics: int32;
    }
  | File of string
  | SectionDef of {
      length: int32;
      number_of_relocations: int;
      number_of_linenumbers: int;
      checksum: int32;
      number: int;
      selection: int;
    }
  | ClrToken of {
      aux_type: int;
      symbol_table_index: int32;
    }
  | Raw of bytes

(** A COFF symbol table entry together with all of its auxiliary records. *)
type t = {
  name: Symbol_name.t;
  value: int32;
  section_number: int;
  sym_type: symbol_type;
  storage_class: int;
  aux_records: auxiliary_record list;
}

let make ~name ~value ~section_number ~sym_type ~storage_class ~aux_records =
  { name; value; section_number; sym_type; storage_class; aux_records }

let name t = t.name
let value t = t.value
let section_number t = t.section_number
let sym_type t = t.sym_type
let storage_class t = t.storage_class
let aux_records t = t.aux_records

(** Return [true] when the symbol represents a function
    (IMAGE_SYM_DTYPE_FUNCTION = 2, Type = 0x20). *)
let is_function t =
  t.sym_type.derived_type = 2 || t.sym_type.raw = 0x20 || (t.sym_type.raw land 0x20 <> 0)

(** Return [true] when the symbol has external linkage
    (IMAGE_SYM_CLASS_EXTERNAL = 2). *)
let is_external t = t.storage_class = 2

(** Return [true] when the symbol has static storage class
    (IMAGE_SYM_CLASS_STATIC = 3). *)
let is_static t = t.storage_class = 3

(** Return [true] when [section_number] is IMAGE_SYM_UNDEFINED (0). *)
let is_undefined t = t.section_number = 0

let pp fmt t =
  Format.fprintf fmt "sym: %a val=0x%lx sec=%d sc=%d"
    Symbol_name.pp t.name t.value t.section_number t.storage_class
