(** PE/COFF parser application service.
    Implements Pe_parser_port.S using Binary_reader. *)

let ( let* ) = Result.bind

(* ---- COFF Header parsing ---- *)

let parse_coff_header r =
  let* machine = Binary_reader.read_u16_le r in
  let* number_of_sections = Binary_reader.read_u16_le r in
  let* time_date_stamp = Binary_reader.read_u32_le r in
  let* pointer_to_symbol_table = Binary_reader.read_u32_le r in
  let* number_of_symbols = Binary_reader.read_u32_le r in
  let* size_of_optional_header = Binary_reader.read_u16_le r in
  let* characteristics = Binary_reader.read_u16_le r in
  Ok {
    Coff_header.machine;
    number_of_sections;
    time_date_stamp;
    pointer_to_symbol_table;
    number_of_symbols;
    size_of_optional_header;
    characteristics;
  }

(* ---- Data Directory parsing ---- *)

let parse_data_directory r idx =
  let kind = Data_directory.kind_of_index idx in
  let* virtual_address = Binary_reader.read_u32_le r in
  let* size = Binary_reader.read_u32_le r in
  Ok (Data_directory.make ~kind ~virtual_address ~size)

let parse_data_directories r count =
  let dirs = Array.make 16 (Data_directory.make
    ~kind:Data_directory.Reserved
    ~virtual_address:0l ~size:0l) in
  let safe_count = max 0 (min count 16) in
  let rec loop i =
    if i >= safe_count then Ok ()
    else
      let* dir = parse_data_directory r i in
      dirs.(i) <- dir;
      loop (i + 1)
  in
  let* () = loop 0 in
  Ok dirs

(* ---- Optional Header parsing ---- *)

let parse_optional_header r size_of_opt_hdr =
  if size_of_opt_hdr = 0 then Ok None
  else begin
    let start_pos = Binary_reader.pos r in
    let* magic = Binary_reader.read_u16_le r in
    let format = match magic with
      | 0x10b -> Optional_header.Pe32
      | 0x20b -> Optional_header.Pe32plus
      | _ -> Optional_header.Pe32
    in
    let* major_linker_version = Binary_reader.read_u8 r in
    let* minor_linker_version = Binary_reader.read_u8 r in
    let* size_of_code = Binary_reader.read_u32_le r in
    let* size_of_initialized_data = Binary_reader.read_u32_le r in
    let* size_of_uninitialized_data = Binary_reader.read_u32_le r in
    let* address_of_entry_point = Binary_reader.read_u32_le r in
    let* base_of_code = Binary_reader.read_u32_le r in
    let* base_of_data =
      if format = Optional_header.Pe32 then
        let* v = Binary_reader.read_u32_le r in Ok (Some v)
      else Ok None
    in
    let standard = {
      Optional_header.magic;
      major_linker_version;
      minor_linker_version;
      size_of_code;
      size_of_initialized_data;
      size_of_uninitialized_data;
      address_of_entry_point;
      base_of_code;
      base_of_data;
    } in
    let* image_base =
      if format = Optional_header.Pe32 then
        let* v = Binary_reader.read_u32_le r in
        Ok (Int64.logand (Int64.of_int32 v) 0xFFFFFFFFL)
      else Binary_reader.read_u64_le r
    in
    let* section_alignment = Binary_reader.read_u32_le r in
    let* file_alignment = Binary_reader.read_u32_le r in
    let* major_os_version = Binary_reader.read_u16_le r in
    let* minor_os_version = Binary_reader.read_u16_le r in
    let* major_image_version = Binary_reader.read_u16_le r in
    let* minor_image_version = Binary_reader.read_u16_le r in
    let* major_subsystem_version = Binary_reader.read_u16_le r in
    let* minor_subsystem_version = Binary_reader.read_u16_le r in
    let* win32_version_value = Binary_reader.read_u32_le r in
    let* size_of_image = Binary_reader.read_u32_le r in
    let* size_of_headers = Binary_reader.read_u32_le r in
    let* checksum = Binary_reader.read_u32_le r in
    let* subsystem = Binary_reader.read_u16_le r in
    let* dll_characteristics = Binary_reader.read_u16_le r in
    let* size_of_stack_reserve =
      if format = Optional_header.Pe32 then
        let* v = Binary_reader.read_u32_le r in
        Ok (Int64.logand (Int64.of_int32 v) 0xFFFFFFFFL)
      else Binary_reader.read_u64_le r
    in
    let* size_of_stack_commit =
      if format = Optional_header.Pe32 then
        let* v = Binary_reader.read_u32_le r in
        Ok (Int64.logand (Int64.of_int32 v) 0xFFFFFFFFL)
      else Binary_reader.read_u64_le r
    in
    let* size_of_heap_reserve =
      if format = Optional_header.Pe32 then
        let* v = Binary_reader.read_u32_le r in
        Ok (Int64.logand (Int64.of_int32 v) 0xFFFFFFFFL)
      else Binary_reader.read_u64_le r
    in
    let* size_of_heap_commit =
      if format = Optional_header.Pe32 then
        let* v = Binary_reader.read_u32_le r in
        Ok (Int64.logand (Int64.of_int32 v) 0xFFFFFFFFL)
      else Binary_reader.read_u64_le r
    in
    let* loader_flags = Binary_reader.read_u32_le r in
    let* number_of_rva_and_sizes = Binary_reader.read_u32_le r in
    let windows = {
      Optional_header.image_base;
      section_alignment;
      file_alignment;
      major_os_version;
      minor_os_version;
      major_image_version;
      minor_image_version;
      major_subsystem_version;
      minor_subsystem_version;
      win32_version_value;
      size_of_image;
      size_of_headers;
      checksum;
      subsystem;
      dll_characteristics;
      size_of_stack_reserve;
      size_of_stack_commit;
      size_of_heap_reserve;
      size_of_heap_commit;
      loader_flags;
      number_of_rva_and_sizes;
    } in
    let num_dirs = max 0 (min (Int32.to_int number_of_rva_and_sizes) 16) in
    let* data_directories = parse_data_directories r num_dirs in
    let end_pos = start_pos + size_of_opt_hdr in
    let* () = Binary_reader.seek r end_pos in
    Ok (Some { Optional_header.format; standard; windows; data_directories })
  end

(* ---- Section Header parsing ---- *)

let parse_section_header r =
  let* name = Binary_reader.read_string r 8 in
  let* virtual_size = Binary_reader.read_u32_le r in
  let* virtual_address = Binary_reader.read_u32_le r in
  let* size_of_raw_data = Binary_reader.read_u32_le r in
  let* pointer_to_raw_data = Binary_reader.read_u32_le r in
  let* pointer_to_relocations = Binary_reader.read_u32_le r in
  let* pointer_to_linenumbers = Binary_reader.read_u32_le r in
  let* number_of_relocations = Binary_reader.read_u16_le r in
  let* number_of_linenumbers = Binary_reader.read_u16_le r in
  let* characteristics = Binary_reader.read_u32_le r in
  Ok {
    Section_header.name;
    virtual_size;
    virtual_address;
    size_of_raw_data;
    pointer_to_raw_data;
    pointer_to_relocations;
    pointer_to_linenumbers;
    number_of_relocations;
    number_of_linenumbers;
    characteristics;
  }

let parse_section_headers r count =
  let rec loop acc i =
    if i = 0 then Ok (List.rev acc)
    else
      let* hdr = parse_section_header r in
      loop (hdr :: acc) (i - 1)
  in
  loop [] count

(* ---- Symbol Table parsing ---- *)

let parse_aux_function_def r =
  let* tag_index = Binary_reader.read_u32_le r in
  let* total_size = Binary_reader.read_u32_le r in
  let* pointer_to_linenumber = Binary_reader.read_u32_le r in
  let* pointer_to_next_function = Binary_reader.read_u32_le r in
  let* _ = Binary_reader.read_u16_le r in
  Ok (Coff_symbol.FunctionDef {
    tag_index; total_size;
    pointer_to_linenumber;
    pointer_to_next_function;
  })

let parse_aux_bf_ef r =
  let* _ = Binary_reader.read_u32_le r in
  let* linenumber = Binary_reader.read_u16_le r in
  let* _ = Binary_reader.read_bytes r 6 in
  let* pointer_to_next_function = Binary_reader.read_u32_le r in
  let* _ = Binary_reader.read_u16_le r in
  Ok (Coff_symbol.BfEfSymbol { linenumber; pointer_to_next_function })

let parse_aux_weak_external r =
  let* tag_index = Binary_reader.read_u32_le r in
  let* characteristics = Binary_reader.read_u32_le r in
  let* _ = Binary_reader.read_bytes r 10 in
  Ok (Coff_symbol.WeakExternal { tag_index; characteristics })

let parse_aux_file r =
  let* name_bytes = Binary_reader.read_bytes r 18 in
  let rec find_len l =
    if l <= 0 || Bytes.get_uint8 name_bytes (l - 1) <> 0 then l
    else find_len (l - 1)
  in
  let len = find_len 18 in
  Ok (Coff_symbol.File (Bytes.sub_string name_bytes 0 len))

let parse_aux_section_def r =
  let* length = Binary_reader.read_u32_le r in
  let* number_of_relocations = Binary_reader.read_u16_le r in
  let* number_of_linenumbers = Binary_reader.read_u16_le r in
  let* checksum = Binary_reader.read_u32_le r in
  let* number = Binary_reader.read_u16_le r in
  let* selection = Binary_reader.read_u8 r in
  let* _ = Binary_reader.read_bytes r 3 in
  Ok (Coff_symbol.SectionDef {
    length; number_of_relocations; number_of_linenumbers;
    checksum; number; selection;
  })

let parse_aux_clr_token r =
  let* aux_type = Binary_reader.read_u8 r in
  let* _ = Binary_reader.read_u8 r in
  let* symbol_table_index = Binary_reader.read_u32_le r in
  let* _ = Binary_reader.read_bytes r 12 in
  Ok (Coff_symbol.ClrToken { aux_type; symbol_table_index })

let parse_aux_record r storage_class name_str =
  let start = Binary_reader.pos r in
  let result = match storage_class with
    | 2 -> parse_aux_function_def r
    | 101 when name_str = ".bf" || name_str = ".ef" ->
      parse_aux_bf_ef r
    | 105 -> parse_aux_weak_external r
    | 103 -> parse_aux_file r
    | 3 -> parse_aux_section_def r
    | 107 -> parse_aux_clr_token r
    | _ ->
      let* raw = Binary_reader.read_bytes r 18 in
      Ok (Coff_symbol.Raw raw)
  in
  let consumed = Binary_reader.pos r - start in
  if consumed < 18 then begin
    match Binary_reader.skip r (18 - consumed) with
    | _ -> ()
  end;
  result

let parse_symbol r =
  let* name_bytes = Binary_reader.peek_bytes r 8 in
  let name = Symbol_name.of_bytes name_bytes 0 in
  let* _ = Binary_reader.skip r 8 in
  let* value = Binary_reader.read_u32_le r in
  let* section_number = Binary_reader.read_i16_le r in
  let* type_raw = Binary_reader.read_u16_le r in
  let sym_type = {
    Coff_symbol.raw = type_raw;
    base_type = type_raw land 0x0f;
    derived_type =
      let hi = (type_raw lsr 8) land 0xff in
      if hi <> 0 then hi else (type_raw lsr 4) land 0x0f;
  } in
  let* storage_class = Binary_reader.read_u8 r in
  let* num_aux = Binary_reader.read_u8 r in
  let name_str = match name with
    | Symbol_name.Inline s -> s
    | Symbol_name.Reference _ -> ""
  in
  let rec parse_aux_list acc n =
    if n = 0 then Ok (List.rev acc)
    else
      let* aux = parse_aux_record r storage_class name_str in
      parse_aux_list (aux :: acc) (n - 1)
  in
  let* aux_records = parse_aux_list [] num_aux in
  Ok (
    Coff_symbol.make ~name ~value ~section_number
      ~sym_type ~storage_class ~aux_records,
    num_aux
  )

let parse_symbol_table r offset count =
  if Int32.compare offset 0l = 0 || count <= 0 then Ok []
  else
    Binary_reader.at_offset r (Int32.to_int offset) (fun r ->
      let rec loop acc remaining_slots =
        if remaining_slots <= 0 then Ok (List.rev acc)
        else
          let* (sym, num_aux) = parse_symbol r in
          loop (sym :: acc) (remaining_slots - 1 - num_aux)
      in
      loop [] count
    )

(* ---- String Table parsing ---- *)

let parse_string_table r symtab_offset symtab_count =
  if Int32.compare symtab_offset 0l = 0 || symtab_count <= 0 then Ok ""
  else
    let offset = Int32.add symtab_offset (Int32.mul (Int32.of_int symtab_count) 18l) in
    Binary_reader.at_offset r (Int32.to_int offset) (fun r ->
      let* size_i32 = Binary_reader.read_u32_le r in
      let size = Int32.to_int size_i32 in
      if size <= 4 then Ok ""
      else
        let* content = Binary_reader.read_string r (size - 4) in
        Ok content
    )

(* ---- PE Image parsing ---- *)

let pe_signature = "PE\x00\x00"

let parse_pe_file buf =
  let r = Binary_reader.of_bytes buf in
  let* mz = Binary_reader.read_bytes r 2 in
  if Bytes.get_uint8 mz 0 <> 0x4d || Bytes.get_uint8 mz 1 <> 0x5a then
    Error (Error.Invalid_signature {
      offset = 0;
      expected = Bytes.of_string "MZ";
      got = mz;
    })
  else begin
    let* () = Binary_reader.seek r 0x3c in
    let* pe_offset_i32 = Binary_reader.read_u32_le r in
    let pe_offset = Int32.to_int pe_offset_i32 in
    let dos_stub_bytes =
      match Binary_reader.at_offset r 0 (fun r ->
        Binary_reader.read_bytes r pe_offset
      ) with
      | Ok b -> b
      | Error _ -> Bytes.sub buf 0 (min pe_offset (Bytes.length buf))
    in
    let dos_stub = Some (Dos_stub.make dos_stub_bytes pe_offset) in
    let* () = Binary_reader.seek r pe_offset in
    let* sig_bytes = Binary_reader.read_bytes r 4 in
    if Bytes.to_string sig_bytes <> pe_signature then
      Error (Error.Invalid_signature {
        offset = pe_offset;
        expected = Bytes.of_string pe_signature;
        got = sig_bytes;
      })
    else begin
      let* coff_hdr = parse_coff_header r in
      let* optional_hdr = parse_optional_header r coff_hdr.size_of_optional_header in
      let* sections = parse_section_headers r coff_hdr.number_of_sections in
      let sym_count = Int32.to_int coff_hdr.number_of_symbols in
      let* symbol_table =
        parse_symbol_table r
          coff_hdr.pointer_to_symbol_table
          sym_count
      in
      let* string_table =
        parse_string_table r
          coff_hdr.pointer_to_symbol_table
          sym_count
      in
      Ok (Pe_file.make
        ~dos_stub
        ~coff_header:coff_hdr
        ~optional_header:optional_hdr
        ~sections
        ~symbol_table
        ~string_table
        ~raw_data:buf)
    end
  end

let parse_coff_object buf =
  let r = Binary_reader.of_bytes buf in
  let* coff_hdr = parse_coff_header r in
  let* optional_hdr = parse_optional_header r coff_hdr.size_of_optional_header in
  let* sections = parse_section_headers r coff_hdr.number_of_sections in
  let sym_count = Int32.to_int coff_hdr.number_of_symbols in
  let* symbol_table =
    parse_symbol_table r
      coff_hdr.pointer_to_symbol_table
      sym_count
  in
  let* string_table =
    parse_string_table r
      coff_hdr.pointer_to_symbol_table
      sym_count
  in
  Ok (Pe_file.make
    ~dos_stub:None
    ~coff_header:coff_hdr
    ~optional_header:optional_hdr
    ~sections
    ~symbol_table
    ~string_table
    ~raw_data:buf)

(* ---- Archive parsing ---- *)

let archive_signature = "!<arch>\n"

let parse_archive_member_header r =
  let* name_raw = Binary_reader.read_string r 16 in
  let* date_raw = Binary_reader.read_string r 12 in
  let* user_id_raw = Binary_reader.read_string r 6 in
  let* group_id_raw = Binary_reader.read_string r 6 in
  let* mode_raw = Binary_reader.read_string r 8 in
  let* size_raw = Binary_reader.read_string r 10 in
  let* end_marker = Binary_reader.read_bytes r 2 in
  if Bytes.get_uint8 end_marker 0 <> 0x60 || Bytes.get_uint8 end_marker 1 <> 0x0a then
    Error (Error.Invalid_signature {
      offset = Binary_reader.pos r - 2;
      expected = Bytes.of_string "`\n";
      got = end_marker;
    })
  else begin
    let trim s = String.trim s in
    let name = trim name_raw in
    let date = Option.value ~default:0L (Int64.of_string_opt (trim date_raw)) in
    let user_id = trim user_id_raw in
    let group_id = trim group_id_raw in
    let mode = Option.value ~default:0 (int_of_string_opt ("0o" ^ trim mode_raw)) in
    let size = Option.value ~default:0 (int_of_string_opt (trim size_raw)) in
    Ok { Archive.name; date; user_id; group_id; mode; size }
  end

let parse_archive buf =
  let r = Binary_reader.of_bytes buf in
  let* sig_bytes = Binary_reader.read_string r 8 in
  if sig_bytes <> archive_signature then
    Error (Error.Invalid_signature {
      offset = 0;
      expected = Bytes.of_string archive_signature;
      got = Bytes.of_string sig_bytes;
    })
  else begin
    let rec read_members acc =
      if Binary_reader.remaining r < 60 then Ok (Archive.make (List.rev acc))
      else
        match parse_archive_member_header r with
        | Error _ -> Ok (Archive.make (List.rev acc))
        | Ok hdr ->
          let member_start = Binary_reader.pos r in
          let data = match Binary_reader.read_bytes r hdr.Archive.size with
            | Ok b -> b
            | Error _ -> Bytes.empty
          in
          let consumed = Binary_reader.pos r - member_start in
          if consumed mod 2 = 1 then
            (match Binary_reader.skip r 1 with _ -> ());
          let content = match hdr.Archive.name with
            | "/" ->
              let member_r = Binary_reader.of_bytes data in
              (match Binary_reader.read_u32_be member_r with
               | Error _ -> Archive.Raw data
               | Ok num_syms ->
                 let n = Int32.to_int num_syms in
                 let rec read_offsets oacc count =
                   if count <= 0 then Ok (List.rev oacc)
                   else
                     match Binary_reader.read_u32_be member_r with
                     | Ok o -> read_offsets (o :: oacc) (count - 1)
                     | Error _ -> Error ()
                 in
                 match read_offsets [] n with
                 | Error () -> Archive.Raw data
                 | Ok offsets ->
                   let rec read_symbols sacc =
                     if Binary_reader.remaining member_r <= 0 then List.rev sacc
                     else
                       match Binary_reader.read_cstring member_r () with
                       | Ok s -> read_symbols (s :: sacc)
                       | Error _ -> List.rev sacc
                   in
                   let symbols = read_symbols [] in
                   Archive.LinkerMember1 { offsets; symbols })
            | "//" ->
              let s = Bytes.to_string data in
              let len = String.length s in
              let rec split_names nacc start i =
                if i >= len then List.rev nacc
                else if s.[i] = '\x00' then
                  split_names (String.sub s start (i - start) :: nacc) (i + 1) (i + 1)
                else
                  split_names nacc start (i + 1)
              in
              Archive.LongnamesMember (split_names [] 0 0)
            | _ ->
              (match parse_coff_object data with
               | Ok pf -> Archive.Object pf
               | Error _ -> Archive.Raw data)
          in
          read_members ({ Archive.header = hdr; content } :: acc)
    in
    read_members []
  end

let parse_any buf =
  if Bytes.length buf >= 2 &&
     Bytes.get_uint8 buf 0 = 0x4d && Bytes.get_uint8 buf 1 = 0x5a
  then
    Result.map (fun f -> `Pe f) (parse_pe_file buf)
  else if Bytes.length buf >= 8 &&
          Bytes.sub_string buf 0 8 = archive_signature
  then
    Result.map (fun a -> `Archive a) (parse_archive buf)
  else
    Result.map (fun f -> `Coff f) (parse_coff_object buf)
