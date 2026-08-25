(** Top-level PE image and COFF object file aggregate root. *)

type t = {
  dos_stub: Dos_stub.t option;
  (** MS-DOS stub, present in image files, absent in raw COFF object files. *)
  coff_header: Coff_header.t;
  (** The mandatory COFF file header. *)
  optional_header: Optional_header.t option;
  (** Optional header, required for image files. *)
  sections: Section_header.t list;
  (** Section headers, in order. *)
  symbol_table: Coff_symbol.t list;
  (** COFF symbol table entries (deprecated in images). *)
  string_table: string;
  (** COFF string table raw content (begins after 4-byte size field). *)
  raw_data: bytes;
  (** The complete raw file bytes for section data access. *)
}

let make ~dos_stub ~coff_header ~optional_header ~sections
         ~symbol_table ~string_table ~raw_data =
  { dos_stub; coff_header; optional_header; sections;
    symbol_table; string_table; raw_data }

let dos_stub t = t.dos_stub
let coff_header t = t.coff_header
let optional_header t = t.optional_header
let sections t = t.sections
let symbol_table t = t.symbol_table
let string_table t = t.string_table
let raw_data t = t.raw_data

let is_image t = t.optional_header <> None
let is_object t = t.optional_header = None

let find_section_by_name t name =
  List.find_opt (fun s -> Section_header.name_string s = name) t.sections

let find_section_by_rva t rva =
  List.find_opt (fun s ->
    let va = Int32.to_int s.Section_header.virtual_address in
    let sz = Int32.to_int s.Section_header.virtual_size in
    rva >= va && rva < va + sz
  ) t.sections

let section_data t (section : Section_header.t) =
  let offset = Int32.to_int section.pointer_to_raw_data in
  let size = Int32.to_int section.size_of_raw_data in
  if offset = 0 || size = 0 then Bytes.empty
  else if offset + size > Bytes.length t.raw_data then Bytes.empty
  else Bytes.sub t.raw_data offset size

let pp fmt t =
  let kind = if is_image t then "image" else "object" in
  Format.fprintf fmt "<PE/COFF %s: %d sections, %d symbols>"
    kind (List.length t.sections) (List.length t.symbol_table)
