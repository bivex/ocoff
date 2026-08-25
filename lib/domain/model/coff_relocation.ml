(** COFF relocation entry, 10 bytes (object files only).

    Relocation entries appear after the raw section data and describe
    address fixups the linker must apply.  Each entry references a symbol
    in the COFF symbol table.  The meaning of [reloc_type] depends on the
    target machine architecture (see the PE/COFF spec, section 4).

    Layout:
    {v
    Offset | Size | Field
    -------+------+-------------------------------
      0    |  4   | VirtualAddress  (section-relative offset of the fixup)
      4    |  4   | SymbolTableIndex
      8    |  2   | Type
    v}
    Total: 10 bytes. *)

(** Size of a COFF relocation entry on disk, in bytes. *)
let size_bytes = 10

(** A single relocation entry. *)
type t = {
  virtual_address: int32;
  (** Offset within the section at which the fixup is applied.
      When extended relocations are used ([IMAGE_SCN_LNK_NRELOC_OVFL]), the
      first entry in the section's relocation array has this field set to the
      actual relocation count. *)
  symbol_table_index: int32;
  (** Zero-based index into the COFF symbol table for the symbol whose
      address is used in the fixup. *)
  reloc_type: int;
  (** Machine-specific relocation type (raw uint16). *)
}

(** Construct a relocation entry. *)
let make ~virtual_address ~symbol_table_index ~reloc_type =
  { virtual_address; symbol_table_index; reloc_type }

let virtual_address t = t.virtual_address
let symbol_table_index t = t.symbol_table_index
let reloc_type t = t.reloc_type

let pp fmt t =
  Format.fprintf fmt "reloc: va=0x%lx sym=%ld type=0x%x"
    t.virtual_address t.symbol_table_index t.reloc_type
