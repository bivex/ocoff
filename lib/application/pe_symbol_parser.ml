(** COFF Symbol and String Table parser application service. *)

let ( let* ) = Result.bind

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
