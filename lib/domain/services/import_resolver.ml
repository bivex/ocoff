(** Domain service: parse PE imports from PE file or .idata section. *)

type import_by =
  | ByOrdinal of int
  | ByName of { hint: int; name: string }

type import_entry = {
  dll_name: string;
  entries: import_by list;
}

let ( let* ) = Result.bind

let rva_to_offset_in_pe (pf : Pe_file.t) (rva : int32) : int option =
  let rva_int = Int32.to_int rva in
  match Pe_file.find_section_by_rva pf rva_int with
  | None -> None
  | Some sec ->
    let sec_va = Int32.to_int sec.virtual_address in
    let sec_raw = Int32.to_int sec.pointer_to_raw_data in
    let offset_in_sec = rva_int - sec_va in
    let file_off = sec_raw + offset_in_sec in
    if file_off >= 0 && file_off < Bytes.length pf.raw_data then Some file_off
    else None

let read_cstring_at_file_offset (raw : bytes) (offset : int) : string option =
  if offset < 0 || offset >= Bytes.length raw then None
  else
    let end_off = ref offset in
    let len = Bytes.length raw in
    while !end_off < len && Bytes.get_uint8 raw !end_off <> 0 do
      incr end_off
    done;
    Some (Bytes.sub_string raw offset (!end_off - offset))

(** Parse all imports directly from a PE file using its Data Directories. *)
let parse_pe_imports (pf : Pe_file.t) : (import_entry list, Error.t) result =
  match pf.optional_header with
  | None -> Ok []
  | Some oh ->
    match Optional_header.data_directory oh Data_directory.ImportTable with
    | None -> Ok []
    | Some dir when not (Data_directory.is_present dir) -> Ok []
    | Some dir ->
      match rva_to_offset_in_pe pf dir.virtual_address with
      | None -> Ok []
      | Some import_dir_file_off ->
        let r = Binary_reader.of_bytes pf.raw_data in
        let* () = Binary_reader.seek r import_dir_file_off in
        let is_64 = Optional_header.is_64bit oh in
        let entries = ref [] in
        let continue_loop = ref true in
        while !continue_loop && Binary_reader.remaining r >= 20 do
          match
            let* ilt_rva = Binary_reader.read_u32_le r in
            let* _timestamp = Binary_reader.read_u32_le r in
            let* _forwarder_chain = Binary_reader.read_u32_le r in
            let* name_rva = Binary_reader.read_u32_le r in
            let* iat_rva = Binary_reader.read_u32_le r in
            if Int32.compare ilt_rva 0l = 0 && Int32.compare name_rva 0l = 0 && Int32.compare iat_rva 0l = 0 then begin
              continue_loop := false;
              Ok None
            end else begin
              let dll_name =
                match rva_to_offset_in_pe pf name_rva with
                | Some off -> Option.value ~default:"" (read_cstring_at_file_offset pf.raw_data off)
                | None -> ""
              in
              (* Use ILT if available, otherwise fall back to IAT (bound imports) *)
              let lookup_rva = if Int32.compare ilt_rva 0l <> 0 then ilt_rva else iat_rva in
              match rva_to_offset_in_pe pf lookup_rva with
              | None -> Ok (Some { dll_name; entries = [] })
              | Some lookup_file_off ->
                let lookup_r = Binary_reader.of_bytes pf.raw_data in
                let* () = Binary_reader.seek lookup_r lookup_file_off in
                let imports = ref [] in
                let lookup_done = ref false in
                while not !lookup_done do
                  if is_64 then begin
                    if Binary_reader.remaining lookup_r < 8 then lookup_done := true
                    else
                      match Binary_reader.read_u64_le lookup_r with
                      | Error _ -> lookup_done := true
                      | Ok entry ->
                        if entry = 0L then lookup_done := true
                        else if Int64.logand entry 0x8000000000000000L <> 0L then
                          let ordinal = Int64.to_int (Int64.logand entry 0xffffL) in
                          imports := ByOrdinal ordinal :: !imports
                        else
                          let hint_name_rva = Int64.to_int32 (Int64.logand entry 0x7fffffffL) in
                          match rva_to_offset_in_pe pf hint_name_rva with
                          | None -> ()
                          | Some hno ->
                            let hint =
                              if hno + 1 < Bytes.length pf.raw_data
                              then Bytes.get_uint16_le pf.raw_data hno
                              else 0
                            in
                            let name = Option.value ~default:"" (read_cstring_at_file_offset pf.raw_data (hno + 2)) in
                            imports := ByName { hint; name } :: !imports
                  end else begin
                    if Binary_reader.remaining lookup_r < 4 then lookup_done := true
                    else
                      match Binary_reader.read_u32_le lookup_r with
                      | Error _ -> lookup_done := true
                      | Ok entry ->
                        if Int32.compare entry 0l = 0 then lookup_done := true
                        else if Int32.logand entry 0x80000000l <> 0l then
                          let ordinal = Int32.to_int (Int32.logand entry 0xffffl) in
                          imports := ByOrdinal ordinal :: !imports
                        else
                          let hint_name_rva = Int32.logand entry 0x7fffffffl in
                          match rva_to_offset_in_pe pf hint_name_rva with
                          | None -> ()
                          | Some hno ->
                            let hint =
                              if hno + 1 < Bytes.length pf.raw_data
                              then Bytes.get_uint16_le pf.raw_data hno
                              else 0
                            in
                            let name = Option.value ~default:"" (read_cstring_at_file_offset pf.raw_data (hno + 2)) in
                            imports := ByName { hint; name } :: !imports
                  end
                done;
                Ok (Some { dll_name; entries = List.rev !imports })
            end
          with
          | Error _ -> continue_loop := false
          | Ok None -> ()
          | Ok (Some entry) -> entries := entry :: !entries
        done;
        Ok (List.rev !entries)

(** Parse all imports from raw .idata section bytes given the section's RVA. *)
let parse_imports
    ~(idata_bytes : bytes)
    ~(idata_rva : int32)
    : (import_entry list, Error.t) result =
  let r = Binary_reader.of_bytes idata_bytes in
  let rva_to_offset rva =
    let off = Int32.to_int (Int32.sub rva idata_rva) in
    if off < 0 || off >= Bytes.length idata_bytes then
      Error (Error.Offset_out_of_bounds { offset = off; size = Bytes.length idata_bytes })
    else Ok off
  in
  let read_cstring_at rva =
    match rva_to_offset rva with
    | Error _ -> None
    | Ok off ->
      let end_off = ref off in
      while !end_off < Bytes.length idata_bytes &&
            Bytes.get_uint8 idata_bytes !end_off <> 0 do
        incr end_off
      done;
      Some (Bytes.sub_string idata_bytes off (!end_off - off))
  in
  let entries = ref [] in
  let continue_loop = ref true in
  while !continue_loop && Binary_reader.remaining r >= 20 do
    match
      let* ilt_rva = Binary_reader.read_u32_le r in
      let* _timestamp = Binary_reader.read_u32_le r in
      let* _forwarder_chain = Binary_reader.read_u32_le r in
      let* name_rva = Binary_reader.read_u32_le r in
      let* _iat_rva = Binary_reader.read_u32_le r in
      if Int32.compare ilt_rva 0l = 0 && Int32.compare name_rva 0l = 0 then begin
        continue_loop := false;
        Ok None
      end else begin
        let dll_name = Option.value ~default:"" (read_cstring_at name_rva) in
        match rva_to_offset ilt_rva with
        | Error _ -> Ok (Some { dll_name; entries = [] })
        | Ok ilt_off ->
          let ilt_r = Binary_reader.of_bytes idata_bytes in
          let* () = Binary_reader.seek ilt_r ilt_off in
          let imports = ref [] in
          let ilt_done = ref false in
          while not !ilt_done && Binary_reader.remaining ilt_r >= 4 do
            match Binary_reader.read_u32_le ilt_r with
            | Error _ -> ilt_done := true
            | Ok entry ->
              if Int32.compare entry 0l = 0 then
                ilt_done := true
              else if Int32.logand entry 0x80000000l <> 0l then begin
                let ordinal = Int32.to_int (Int32.logand entry 0xffffl) in
                imports := ByOrdinal ordinal :: !imports
              end else begin
                let hint_name_rva = Int32.logand entry 0x7fffffffl in
                match rva_to_offset hint_name_rva with
                | Error _ -> ()
                | Ok hno ->
                  let hint =
                    if hno + 1 < Bytes.length idata_bytes
                    then Bytes.get_uint16_le idata_bytes hno
                    else 0
                  in
                  let name_off = hno + 2 in
                  let end_off = ref name_off in
                  while !end_off < Bytes.length idata_bytes &&
                        Bytes.get_uint8 idata_bytes !end_off <> 0 do
                    incr end_off
                  done;
                  let name = Bytes.sub_string idata_bytes name_off (!end_off - name_off) in
                  imports := ByName { hint; name } :: !imports
              end
          done;
          Ok (Some { dll_name; entries = List.rev !imports })
      end
    with
    | Error _ -> continue_loop := false
    | Ok None -> ()
    | Ok (Some entry) -> entries := entry :: !entries
  done;
  Ok (List.rev !entries)

let pp_entry fmt (entry : import_entry) =
  Format.fprintf fmt "DLL: %s (%d functions)\n" entry.dll_name (List.length entry.entries);
  List.iter (fun imp ->
    match imp with
    | ByOrdinal n -> Format.fprintf fmt "    [ordinal %d]\n" n
    | ByName { hint; name } -> Format.fprintf fmt "    [hint %4d] %s\n" hint name
  ) entry.entries
