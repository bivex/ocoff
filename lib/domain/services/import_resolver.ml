(** Domain service: parse PE imports from PE file or .idata section. *)

type import_by =
  | ByOrdinal of int
  | ByName of { hint: int; name: string }

type import_entry = {
  dll_name: string;
  entries: import_by list;
}

let ( let* ) = Result.bind

(** Parse lookup table entries (ILT or IAT) for a single DLL in a 64-bit PE file *)
let read_pe_lookups_64 (pf : Pe_file.t) (lookup_r : Binary_reader.t) =
  let rec loop acc =
    if Binary_reader.remaining lookup_r < 8 then List.rev acc
    else
      match Binary_reader.read_u64_le lookup_r with
      | Error _ | Ok 0L -> List.rev acc
      | Ok entry ->
        if Int64.logand entry 0x8000000000000000L <> 0L then
          let ordinal = Int64.to_int (Int64.logand entry 0xffffL) in
          loop (ByOrdinal ordinal :: acc)
        else
          let hint_name_rva = Int64.to_int32 (Int64.logand entry 0x7fffffffL) in
          match Pe_file.rva_to_offset pf hint_name_rva with
          | None -> loop acc
          | Some hno ->
            let hint =
              if hno + 1 < Bytes.length pf.raw_data
              then Bytes.get_uint16_le pf.raw_data hno
              else 0
            in
            let name = Option.value ~default:"" (Pe_file.read_cstring_at_offset pf.raw_data (hno + 2)) in
            loop (ByName { hint; name } :: acc)
  in
  loop []

(** Parse lookup table entries (ILT or IAT) for a single DLL in a 32-bit PE file *)
let read_pe_lookups_32 (pf : Pe_file.t) (lookup_r : Binary_reader.t) =
  let rec loop acc =
    if Binary_reader.remaining lookup_r < 4 then List.rev acc
    else
      match Binary_reader.read_u32_le lookup_r with
      | Error _ | Ok 0l -> List.rev acc
      | Ok entry ->
        if Int32.logand entry 0x80000000l <> 0l then
          let ordinal = Int32.to_int (Int32.logand entry 0xffffl) in
          loop (ByOrdinal ordinal :: acc)
        else
          let hint_name_rva = Int32.logand entry 0x7fffffffl in
          match Pe_file.rva_to_offset pf hint_name_rva with
          | None -> loop acc
          | Some hno ->
            let hint =
              if hno + 1 < Bytes.length pf.raw_data
              then Bytes.get_uint16_le pf.raw_data hno
              else 0
            in
            let name = Option.value ~default:"" (Pe_file.read_cstring_at_offset pf.raw_data (hno + 2)) in
            loop (ByName { hint; name } :: acc)
  in
  loop []

(** Parse all imports directly from a PE file using its Data Directories. *)
let parse_pe_imports (pf : Pe_file.t) : (import_entry list, Error.t) result =
  match pf.optional_header with
  | None -> Ok []
  | Some oh ->
    match Optional_header.data_directory oh Data_directory.ImportTable with
    | None -> Ok []
    | Some dir when not (Data_directory.is_present dir) -> Ok []
    | Some dir ->
      match Pe_file.rva_to_offset pf dir.virtual_address with
      | None -> Ok []
      | Some import_dir_file_off ->
        let r = Binary_reader.of_bytes pf.raw_data in
        let* () = Binary_reader.seek r import_dir_file_off in
        let is_64 = Optional_header.is_64bit oh in
        let rec read_descriptors acc =
          if Binary_reader.remaining r < 20 then Ok (List.rev acc)
          else
            match
              let* ilt_rva = Binary_reader.read_u32_le r in
              let* _timestamp = Binary_reader.read_u32_le r in
              let* _forwarder_chain = Binary_reader.read_u32_le r in
              let* name_rva = Binary_reader.read_u32_le r in
              let* iat_rva = Binary_reader.read_u32_le r in
              Ok (ilt_rva, name_rva, iat_rva)
            with
            | Error _ -> Ok (List.rev acc)
            | Ok (0l, 0l, 0l) -> Ok (List.rev acc)
            | Ok (ilt_rva, name_rva, iat_rva) ->
              let dll_name = Option.value ~default:"" (Pe_file.read_cstring_at_rva pf name_rva) in
              let lookup_rva = if Int32.compare ilt_rva 0l <> 0 then ilt_rva else iat_rva in
              let entries =
                match Pe_file.rva_to_offset pf lookup_rva with
                | None -> []
                | Some lookup_file_off ->
                  let lookup_r = Binary_reader.of_bytes pf.raw_data in
                  (match Binary_reader.seek lookup_r lookup_file_off with
                   | Error _ -> []
                   | Ok () ->
                     if is_64 then read_pe_lookups_64 pf lookup_r
                     else read_pe_lookups_32 pf lookup_r)
              in
              read_descriptors ({ dll_name; entries } :: acc)
        in
        read_descriptors []

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
    | Ok off -> Pe_file.read_cstring_at_offset idata_bytes off
  in
  let rec read_descriptors acc =
    if Binary_reader.remaining r < 20 then Ok (List.rev acc)
    else
      match
        let* ilt_rva = Binary_reader.read_u32_le r in
        let* _timestamp = Binary_reader.read_u32_le r in
        let* _forwarder_chain = Binary_reader.read_u32_le r in
        let* name_rva = Binary_reader.read_u32_le r in
        let* _iat_rva = Binary_reader.read_u32_le r in
        Ok (ilt_rva, name_rva)
      with
      | Error _ -> Ok (List.rev acc)
      | Ok (0l, 0l) -> Ok (List.rev acc)
      | Ok (ilt_rva, name_rva) ->
        let dll_name = Option.value ~default:"" (read_cstring_at name_rva) in
        let entries =
          match rva_to_offset ilt_rva with
          | Error _ -> []
          | Ok ilt_off ->
            let ilt_r = Binary_reader.of_bytes idata_bytes in
            (match Binary_reader.seek ilt_r ilt_off with
             | Error _ -> []
             | Ok () ->
               let rec read_ilt iacc =
                 if Binary_reader.remaining ilt_r < 4 then List.rev iacc
                 else
                   match Binary_reader.read_u32_le ilt_r with
                   | Error _ | Ok 0l -> List.rev iacc
                   | Ok entry ->
                     if Int32.logand entry 0x80000000l <> 0l then
                       let ordinal = Int32.to_int (Int32.logand entry 0xffffl) in
                       read_ilt (ByOrdinal ordinal :: iacc)
                     else
                       let hint_name_rva = Int32.logand entry 0x7fffffffl in
                       match rva_to_offset hint_name_rva with
                       | Error _ -> read_ilt iacc
                       | Ok hno ->
                         let hint =
                           if hno + 1 < Bytes.length idata_bytes
                           then Bytes.get_uint16_le idata_bytes hno
                           else 0
                         in
                         let name = Option.value ~default:"" (Pe_file.read_cstring_at_offset idata_bytes (hno + 2)) in
                         read_ilt (ByName { hint; name } :: iacc)
               in
               read_ilt [])
        in
        read_descriptors ({ dll_name; entries } :: acc)
  in
  read_descriptors []

let pp_entry fmt (entry : import_entry) =
  Format.fprintf fmt "DLL: %s (%d functions)\n" entry.dll_name (List.length entry.entries);
  List.iter (fun imp ->
    match imp with
    | ByOrdinal n -> Format.fprintf fmt "    [ordinal %d]\n" n
    | ByName { hint; name } -> Format.fprintf fmt "    [hint %4d] %s\n" hint name
  ) entry.entries
