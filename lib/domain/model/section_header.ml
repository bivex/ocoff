(** Section table entry (IMAGE_SECTION_HEADER), 40 bytes.

    Layout per the PE/COFF specification:
    {v
    Offset | Size | Field
    -------+------+-------------------------------
      0    |  8   | Name (null-padded UTF-8)
      8    |  4   | VirtualSize (or PhysicalAddress in object files)
     12    |  4   | VirtualAddress
     16    |  4   | SizeOfRawData
     20    |  4   | PointerToRawData
     24    |  4   | PointerToRelocations
     28    |  4   | PointerToLinenumbers
     32    |  2   | NumberOfRelocations
     34    |  2   | NumberOfLinenumbers
     36    |  4   | Characteristics
    v}
    Total: 40 bytes. *)

(** Size of a section header on disk, in bytes. *)
let size_bytes = 40

(** Characteristics bit flag: section has extended relocations
    (IMAGE_SCN_LNK_NRELOC_OVFL). *)
let scn_lnk_nreloc_ovfl = 0x01000000l

(** A single section header record. *)
type t = {
  name: string;
  (** Raw 8-byte null-padded section name, stored as an OCaml string of length
      exactly 8.  Use {!name_string} to obtain a trimmed, printable name. *)
  virtual_size: int32;
  (** Total size of the section when loaded into memory.  In object files this
      is the physical (file) size. *)
  virtual_address: int32;
  (** RVA of the section in memory when the image is loaded.  Zero in object
      files. *)
  size_of_raw_data: int32;
  (** Size of the initialised data on disk, rounded up to [file_alignment].
      May be zero for BSS sections. *)
  pointer_to_raw_data: int32;
  (** File offset of the first page of the section's raw data.
      Zero for sections with no on-disk content (e.g. BSS). *)
  pointer_to_relocations: int32;
  (** File offset of the relocation entries for this section (object files).
      Zero in image files. *)
  pointer_to_linenumbers: int32;
  (** File offset of COFF line-number entries for this section.
      Zero if none, or deprecated. *)
  number_of_relocations: int;
  (** Count of relocation entries for this section.  If
      [IMAGE_SCN_LNK_NRELOC_OVFL] is set and this field is 0xFFFF, the actual
      count is stored in the first relocation entry. *)
  number_of_linenumbers: int;
  (** Count of COFF line-number entries for this section. *)
  characteristics: int32;
  (** Bit flags describing the section's attributes (IMAGE_SCN_* ). *)
}

(** Construct a section header record. *)
let make ~name ~virtual_size ~virtual_address ~size_of_raw_data
         ~pointer_to_raw_data ~pointer_to_relocations ~pointer_to_linenumbers
         ~number_of_relocations ~number_of_linenumbers ~characteristics =
  { name; virtual_size; virtual_address; size_of_raw_data;
    pointer_to_raw_data; pointer_to_relocations; pointer_to_linenumbers;
    number_of_relocations; number_of_linenumbers; characteristics }

let name t = t.name
let virtual_size t = t.virtual_size
let virtual_address t = t.virtual_address
let size_of_raw_data t = t.size_of_raw_data
let pointer_to_raw_data t = t.pointer_to_raw_data
let pointer_to_relocations t = t.pointer_to_relocations
let pointer_to_linenumbers t = t.pointer_to_linenumbers
let number_of_relocations t = t.number_of_relocations
let number_of_linenumbers t = t.number_of_linenumbers
let characteristics t = t.characteristics

(** Return the section name as a trimmed OCaml string, removing any trailing
    null bytes from the raw 8-byte field.  Long names in COFF object files
    (beginning with [/]) refer to the string table and are returned as-is. *)
let name_string t =
  let s = t.name in
  let len = String.length s in
  let i = ref (len - 1) in
  while !i >= 0 && s.[!i] = '\x00' do decr i done;
  if !i < 0 then "" else String.sub s 0 (!i + 1)

(** Return [true] when the section uses the extended-relocation mechanism:
    the [IMAGE_SCN_LNK_NRELOC_OVFL] flag is set and
    [number_of_relocations = 0xFFFF]. *)
let has_extended_relocations t =
  Int32.logand t.characteristics scn_lnk_nreloc_ovfl <> 0l &&
  t.number_of_relocations = 0xFFFF

let pp fmt t =
  Format.fprintf fmt
    "<Section %S: va=0x%lx vsize=0x%lx rawsz=0x%lx rawoff=0x%lx chars=0x%lx>"
    (name_string t)
    t.virtual_address t.virtual_size
    t.size_of_raw_data t.pointer_to_raw_data
    t.characteristics
