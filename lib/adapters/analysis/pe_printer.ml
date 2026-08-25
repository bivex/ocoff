(** Analysis adapter: pretty-print PE/COFF structures to a formatter. *)

let pp_hex_dump fmt (buf : bytes) ~(max_bytes : int) =
  let len = min max_bytes (Bytes.length buf) in
  for i = 0 to len - 1 do
    if i mod 16 = 0 then Format.fprintf fmt "  %04x: " i;
    Format.fprintf fmt "%02x " (Bytes.get_uint8 buf i);
    if (i + 1) mod 16 = 0 then Format.fprintf fmt "\n"
  done;
  if len mod 16 <> 0 then Format.fprintf fmt "\n"

let pp_machine fmt machine_raw =
  match Machine_type.of_uint16 machine_raw with
  | Ok m -> Machine_type.pp fmt m
  | Error (`Unknown_machine n) -> Format.fprintf fmt "Unknown (0x%04x)" n

let pp_characteristics fmt raw =
  let flags = Characteristics.of_uint16 raw in
  Format.fprintf fmt "0x%04x [%a]" raw Characteristics.pp flags

let pp_coff_header fmt (h : Coff_header.t) =
  Format.fprintf fmt "=== COFF File Header ===\n";
  Format.fprintf fmt "  Machine:              %a\n" pp_machine h.machine;
  Format.fprintf fmt "  NumberOfSections:     %d\n" h.number_of_sections;
  Format.fprintf fmt "  TimeDateStamp:        0x%08lx\n" h.time_date_stamp;
  Format.fprintf fmt "  PointerToSymbolTable: 0x%08lx\n" h.pointer_to_symbol_table;
  Format.fprintf fmt "  NumberOfSymbols:      %ld\n" h.number_of_symbols;
  Format.fprintf fmt "  SizeOfOptionalHeader: %d\n" h.size_of_optional_header;
  Format.fprintf fmt "  Characteristics:      %a\n" pp_characteristics h.characteristics

let pp_subsystem fmt v =
  match Subsystem.of_uint16 v with
  | Ok s -> Subsystem.pp fmt s
  | Error (`Unknown_subsystem n) -> Format.fprintf fmt "Unknown (%d)" n

let pp_optional_header fmt (oh : Optional_header.t) =
  Format.fprintf fmt "=== Optional Header ===\n";
  let fmt_str = match oh.format with
    | Optional_header.Pe32 -> "PE32 (0x10b)"
    | Optional_header.Pe32plus -> "PE32+ (0x20b)"
  in
  Format.fprintf fmt "  Magic:                    %s\n" fmt_str;
  Format.fprintf fmt "  AddressOfEntryPoint:      0x%08lx\n" oh.standard.address_of_entry_point;
  Format.fprintf fmt "  BaseOfCode:               0x%08lx\n" oh.standard.base_of_code;
  (match oh.standard.base_of_data with
   | Some v -> Format.fprintf fmt "  BaseOfData:               0x%08lx\n" v
   | None -> ());
  Format.fprintf fmt "  ImageBase:                0x%016Lx\n" oh.windows.image_base;
  Format.fprintf fmt "  SectionAlignment:         0x%08lx\n" oh.windows.section_alignment;
  Format.fprintf fmt "  FileAlignment:            0x%08lx\n" oh.windows.file_alignment;
  Format.fprintf fmt "  SizeOfImage:              0x%08lx\n" oh.windows.size_of_image;
  Format.fprintf fmt "  SizeOfHeaders:            0x%08lx\n" oh.windows.size_of_headers;
  Format.fprintf fmt "  CheckSum:                 0x%08lx\n" oh.windows.checksum;
  Format.fprintf fmt "  Subsystem:                %a\n" pp_subsystem oh.windows.subsystem;
  Format.fprintf fmt "  NumberOfRvaAndSizes:      %ld\n" oh.windows.number_of_rva_and_sizes;
  Format.fprintf fmt "  --- Data Directories ---\n";
  Array.iter (fun dir ->
    if Data_directory.is_present dir then
      Format.fprintf fmt "    %-26s va=0x%08lx size=0x%08lx\n"
        (Data_directory.kind_to_string dir.Data_directory.kind)
        dir.Data_directory.virtual_address
        dir.Data_directory.size
  ) oh.data_directories

let pp_section_flags fmt raw =
  let flags = Section_flags.of_uint32 raw in
  Format.fprintf fmt "0x%08lx [%a]" raw Section_flags.pp flags

let pp_section fmt (s : Section_header.t) =
  Format.fprintf fmt "  %-8s va=0x%08lx vsize=0x%08lx raw=0x%08lx rawsize=0x%08lx flags=%a\n"
    (Section_header.name_string s)
    s.virtual_address
    s.virtual_size
    s.pointer_to_raw_data
    s.size_of_raw_data
    pp_section_flags s.characteristics

let pp_pe_file fmt (f : Pe_file.t) =
  (match f.dos_stub with
   | Some stub ->
     Format.fprintf fmt "=== MS-DOS Stub ===\n";
     Format.fprintf fmt "  PE offset: 0x%x\n" (Dos_stub.pe_offset stub)
   | None -> ());
  pp_coff_header fmt f.coff_header;
  (match f.optional_header with
   | Some oh -> pp_optional_header fmt oh
   | None -> Format.fprintf fmt "(no optional header)\n");
  Format.fprintf fmt "=== Section Headers (%d) ===\n" (List.length f.sections);
  List.iter (pp_section fmt) f.sections;
  if f.symbol_table <> [] then begin
    Format.fprintf fmt "=== Symbol Table (%d entries) ===\n"
      (List.length f.symbol_table);
    List.iteri (fun i sym ->
      let name = Symbol_name.resolve (Coff_symbol.name sym)
        ~string_table:f.string_table in
      Format.fprintf fmt "  [%4d] %-30s val=0x%08lx sec=%d sc=%d\n"
        i name
        (Coff_symbol.value sym)
        (Coff_symbol.section_number sym)
        (Coff_symbol.storage_class sym)
    ) f.symbol_table
  end
