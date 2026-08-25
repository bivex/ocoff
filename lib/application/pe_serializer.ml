(** PE/COFF serializer application service.
    Implements Pe_serializer_port.S using Binary_writer. *)

let serialize_coff_header w (h : Coff_header.t) =
  Binary_writer.write_u16_le w h.machine;
  Binary_writer.write_u16_le w h.number_of_sections;
  Binary_writer.write_u32_le w h.time_date_stamp;
  Binary_writer.write_u32_le w h.pointer_to_symbol_table;
  Binary_writer.write_u32_le w h.number_of_symbols;
  Binary_writer.write_u16_le w h.size_of_optional_header;
  Binary_writer.write_u16_le w h.characteristics

let serialize_optional_header w (oh : Optional_header.t) =
  Binary_writer.write_u16_le w oh.standard.magic;
  Binary_writer.write_u8 w oh.standard.major_linker_version;
  Binary_writer.write_u8 w oh.standard.minor_linker_version;
  Binary_writer.write_u32_le w oh.standard.size_of_code;
  Binary_writer.write_u32_le w oh.standard.size_of_initialized_data;
  Binary_writer.write_u32_le w oh.standard.size_of_uninitialized_data;
  Binary_writer.write_u32_le w oh.standard.address_of_entry_point;
  Binary_writer.write_u32_le w oh.standard.base_of_code;
  (match oh.standard.base_of_data with
   | Some v -> Binary_writer.write_u32_le w v
   | None -> ());
  (match oh.format with
   | Optional_header.Pe32 ->
     Binary_writer.write_u32_le w (Int64.to_int32 oh.windows.image_base)
   | Optional_header.Pe32plus ->
     Binary_writer.write_u64_le w oh.windows.image_base);
  Binary_writer.write_u32_le w oh.windows.section_alignment;
  Binary_writer.write_u32_le w oh.windows.file_alignment;
  Binary_writer.write_u16_le w oh.windows.major_os_version;
  Binary_writer.write_u16_le w oh.windows.minor_os_version;
  Binary_writer.write_u16_le w oh.windows.major_image_version;
  Binary_writer.write_u16_le w oh.windows.minor_image_version;
  Binary_writer.write_u16_le w oh.windows.major_subsystem_version;
  Binary_writer.write_u16_le w oh.windows.minor_subsystem_version;
  Binary_writer.write_u32_le w oh.windows.win32_version_value;
  Binary_writer.write_u32_le w oh.windows.size_of_image;
  Binary_writer.write_u32_le w oh.windows.size_of_headers;
  Binary_writer.write_u32_le w oh.windows.checksum;
  Binary_writer.write_u16_le w oh.windows.subsystem;
  Binary_writer.write_u16_le w oh.windows.dll_characteristics;
  (match oh.format with
   | Optional_header.Pe32 ->
     Binary_writer.write_u32_le w (Int64.to_int32 oh.windows.size_of_stack_reserve);
     Binary_writer.write_u32_le w (Int64.to_int32 oh.windows.size_of_stack_commit);
     Binary_writer.write_u32_le w (Int64.to_int32 oh.windows.size_of_heap_reserve);
     Binary_writer.write_u32_le w (Int64.to_int32 oh.windows.size_of_heap_commit)
   | Optional_header.Pe32plus ->
     Binary_writer.write_u64_le w oh.windows.size_of_stack_reserve;
     Binary_writer.write_u64_le w oh.windows.size_of_stack_commit;
     Binary_writer.write_u64_le w oh.windows.size_of_heap_reserve;
     Binary_writer.write_u64_le w oh.windows.size_of_heap_commit);
  Binary_writer.write_u32_le w oh.windows.loader_flags;
  Binary_writer.write_u32_le w oh.windows.number_of_rva_and_sizes;
  Array.iter (fun (dir : Data_directory.t) ->
    Binary_writer.write_u32_le w dir.virtual_address;
    Binary_writer.write_u32_le w dir.size
  ) oh.data_directories

let serialize_section_header w (s : Section_header.t) =
  let name_bytes = Bytes.make 8 '\x00' in
  let name_len = min 8 (String.length s.name) in
  Bytes.blit_string s.name 0 name_bytes 0 name_len;
  Binary_writer.write_bytes w name_bytes;
  Binary_writer.write_u32_le w s.virtual_size;
  Binary_writer.write_u32_le w s.virtual_address;
  Binary_writer.write_u32_le w s.size_of_raw_data;
  Binary_writer.write_u32_le w s.pointer_to_raw_data;
  Binary_writer.write_u32_le w s.pointer_to_relocations;
  Binary_writer.write_u32_le w s.pointer_to_linenumbers;
  Binary_writer.write_u16_le w s.number_of_relocations;
  Binary_writer.write_u16_le w s.number_of_linenumbers;
  Binary_writer.write_u32_le w s.characteristics

let serialize_aux_record w = function
  | Coff_symbol.FunctionDef { tag_index; total_size; pointer_to_linenumber; pointer_to_next_function } ->
    Binary_writer.write_u32_le w tag_index;
    Binary_writer.write_u32_le w total_size;
    Binary_writer.write_u32_le w pointer_to_linenumber;
    Binary_writer.write_u32_le w pointer_to_next_function;
    Binary_writer.write_u16_le w 0
  | Coff_symbol.BfEfSymbol { linenumber; pointer_to_next_function } ->
    Binary_writer.write_u32_le w 0l;
    Binary_writer.write_u16_le w linenumber;
    Binary_writer.write_zero_pad w 6;
    Binary_writer.write_u32_le w pointer_to_next_function;
    Binary_writer.write_u16_le w 0
  | Coff_symbol.WeakExternal { tag_index; characteristics } ->
    Binary_writer.write_u32_le w tag_index;
    Binary_writer.write_u32_le w characteristics;
    Binary_writer.write_zero_pad w 10
  | Coff_symbol.File name ->
    let buf = Bytes.make 18 '\x00' in
    let len = min 18 (String.length name) in
    Bytes.blit_string name 0 buf 0 len;
    Binary_writer.write_bytes w buf
  | Coff_symbol.SectionDef { length; number_of_relocations; number_of_linenumbers; checksum; number; selection } ->
    Binary_writer.write_u32_le w length;
    Binary_writer.write_u16_le w number_of_relocations;
    Binary_writer.write_u16_le w number_of_linenumbers;
    Binary_writer.write_u32_le w checksum;
    Binary_writer.write_u16_le w number;
    Binary_writer.write_u8 w selection;
    Binary_writer.write_zero_pad w 3
  | Coff_symbol.ClrToken { aux_type; symbol_table_index } ->
    Binary_writer.write_u8 w aux_type;
    Binary_writer.write_u8 w 0;
    Binary_writer.write_u32_le w symbol_table_index;
    Binary_writer.write_zero_pad w 12
  | Coff_symbol.Raw b ->
    if Bytes.length b = 18 then Binary_writer.write_bytes w b
    else Binary_writer.write_zero_pad w 18

let serialize_symbol w (sym : Coff_symbol.t) =
  (match sym.name with
   | Symbol_name.Inline s ->
     let buf = Bytes.make 8 '\x00' in
     let len = min 8 (String.length s) in
     Bytes.blit_string s 0 buf 0 len;
     Binary_writer.write_bytes w buf
   | Symbol_name.Reference off ->
     Binary_writer.write_u32_le w 0l;
     Binary_writer.write_u32_le w (Int32.of_int off));
  Binary_writer.write_u32_le w sym.value;
  Binary_writer.write_i16_le w sym.section_number;
  let type_val =
    if sym.sym_type.raw <> 0 then sym.sym_type.raw
    else sym.sym_type.base_type lor (sym.sym_type.derived_type lsl 4)
  in
  Binary_writer.write_u16_le w type_val;
  Binary_writer.write_u8 w sym.storage_class;
  Binary_writer.write_u8 w (List.length sym.aux_records);
  List.iter (serialize_aux_record w) sym.aux_records

let serialize_pe_file (pf : Pe_file.t) : (bytes, Error.t) result =
  let w = Binary_writer.create () in
  (match pf.dos_stub with
   | Some stub ->
     Binary_writer.write_bytes w (Dos_stub.raw stub);
     let pe_off = Dos_stub.pe_offset stub in
     let cur = Binary_writer.pos w in
     if cur < pe_off then Binary_writer.write_zero_pad w (pe_off - cur)
   | None -> ());
  Binary_writer.write_string w "PE\x00\x00";
  serialize_coff_header w pf.coff_header;
  (match pf.optional_header with
   | Some oh -> serialize_optional_header w oh
   | None -> ());
  List.iter (serialize_section_header w) pf.sections;

  (* Symbol Table *)
  let sym_off = Int32.to_int pf.coff_header.pointer_to_symbol_table in
  if sym_off > 0 then begin
    let cur = Binary_writer.pos w in
    if cur < sym_off then Binary_writer.write_zero_pad w (sym_off - cur);
    List.iter (serialize_symbol w) pf.symbol_table;
    (* String Table *)
    let strtab_len = String.length pf.string_table in
    if strtab_len > 0 then begin
      Binary_writer.write_u32_le w (Int32.of_int (strtab_len + 4));
      Binary_writer.write_string w pf.string_table
    end else if pf.coff_header.number_of_symbols > 0l then begin
      Binary_writer.write_u32_le w 4l
    end
  end;

  (* Section Data *)
  List.iter (fun (sec : Section_header.t) ->
    let raw_off = Int32.to_int sec.pointer_to_raw_data in
    let raw_sz = Int32.to_int sec.size_of_raw_data in
    if raw_off > 0 && raw_sz > 0 then begin
      let cur = Binary_writer.pos w in
      if cur < raw_off then Binary_writer.write_zero_pad w (raw_off - cur);
      let data = Pe_file.section_data pf sec in
      if Bytes.length data > 0 then Binary_writer.write_bytes w data
      else Binary_writer.write_zero_pad w raw_sz
    end
  ) pf.sections;

  Ok (Binary_writer.to_bytes w)

let serialize_coff_object (pf : Pe_file.t) : (bytes, Error.t) result =
  let w = Binary_writer.create () in
  serialize_coff_header w pf.coff_header;
  (match pf.optional_header with
   | Some oh -> serialize_optional_header w oh
   | None -> ());
  List.iter (serialize_section_header w) pf.sections;

  (* Symbol Table *)
  let sym_off = Int32.to_int pf.coff_header.pointer_to_symbol_table in
  if sym_off > 0 then begin
    let cur = Binary_writer.pos w in
    if cur < sym_off then Binary_writer.write_zero_pad w (sym_off - cur);
    List.iter (serialize_symbol w) pf.symbol_table;
    (* String Table *)
    let strtab_len = String.length pf.string_table in
    if strtab_len > 0 then begin
      Binary_writer.write_u32_le w (Int32.of_int (strtab_len + 4));
      Binary_writer.write_string w pf.string_table
    end else if pf.coff_header.number_of_symbols > 0l then begin
      Binary_writer.write_u32_le w 4l
    end
  end;

  (* Section Data *)
  List.iter (fun (sec : Section_header.t) ->
    let raw_off = Int32.to_int sec.pointer_to_raw_data in
    let raw_sz = Int32.to_int sec.size_of_raw_data in
    if raw_off > 0 && raw_sz > 0 then begin
      let cur = Binary_writer.pos w in
      if cur < raw_off then Binary_writer.write_zero_pad w (raw_off - cur);
      let data = Pe_file.section_data pf sec in
      if Bytes.length data > 0 then Binary_writer.write_bytes w data
      else Binary_writer.write_zero_pad w raw_sz
    end
  ) pf.sections;

  Ok (Binary_writer.to_bytes w)
