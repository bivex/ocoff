(** Domain service: parse PE imports from PE file or .idata section. *)

type import_by =
  | ByOrdinal of int
  | ByName of { hint: int; name: string }

type import_entry = {
  dll_name: string;
  entries: import_by list;
}

let ( let* ) = Result.bind

let read_hint_name bytes hno =
  let hint =
    if hno + 1 < Bytes.length bytes
    then Bytes.get_uint16_le bytes hno
    else 0
  in
  let name = Option.value ~default:"" (Pe_file.read_cstring_at_offset bytes (hno + 2)) in
  ByName { hint; name }

let parse_lookup_entry_64 pf entry =
  if Int64.logand entry 0x8000000000000000L <> 0L then
    Some (ByOrdinal (Int64.to_int (Int64.logand entry 0xffffL)))
  else
    let hint_name_rva = Int64.to_int32 (Int64.logand entry 0x7fffffffL) in
    match Pe_file.rva_to_offset pf hint_name_rva with
    | None -> None
    | Some hno -> Some (read_hint_name pf.raw_data hno)

(** Parse lookup table entries (ILT or IAT) for a single DLL in a 64-bit PE file *)
let read_pe_lookups_64 (pf : Pe_file.t) (lookup_r : Binary_reader.t) =
  let rec loop acc =
    if Binary_reader.remaining lookup_r < 8 then List.rev acc
    else
      match Binary_reader.read_u64_le lookup_r with
      | Error _ | Ok 0L -> List.rev acc
      | Ok entry ->
        let acc' = match parse_lookup_entry_64 pf entry with
          | Some item -> item :: acc
          | None -> acc
        in
        loop acc'
  in
  loop []

let parse_lookup_entry_32 rva_to_offset_fn raw_data entry =
  if Int32.logand entry 0x80000000l <> 0l then
    Some (ByOrdinal (Int32.to_int (Int32.logand entry 0xffffl)))
  else
    let hint_name_rva = Int32.logand entry 0x7fffffffl in
    match rva_to_offset_fn hint_name_rva with
    | None -> None
    | Some hno -> Some (read_hint_name raw_data hno)

let read_lookups_32 ~rva_to_offset ~raw_data r =
  let rec loop acc =
    if Binary_reader.remaining r < 4 then List.rev acc
    else
      match Binary_reader.read_u32_le r with
      | Error _ | Ok 0l -> List.rev acc
      | Ok entry ->
        let acc' = match parse_lookup_entry_32 rva_to_offset raw_data entry with
          | Some item -> item :: acc
          | None -> acc
        in
        loop acc'
  in
  loop []

(** Parse lookup table entries (ILT or IAT) for a single DLL in a 32-bit PE file *)
let read_pe_lookups_32 (pf : Pe_file.t) (lookup_r : Binary_reader.t) =
  read_lookups_32 ~rva_to_offset:(Pe_file.rva_to_offset pf) ~raw_data:pf.raw_data lookup_r

let read_import_descriptor r =
  let* ilt_rva = Binary_reader.read_u32_le r in
  let* _timestamp = Binary_reader.read_u32_le r in
  let* _forwarder_chain = Binary_reader.read_u32_le r in
  let* name_rva = Binary_reader.read_u32_le r in
  let* iat_rva = Binary_reader.read_u32_le r in
  Ok (ilt_rva, name_rva, iat_rva)

let is_null_descriptor (ilt, name, iat) =
  ilt = 0l && name = 0l && iat = 0l

let read_dll_entries pf ~is_64 lookup_rva =
  match Pe_file.rva_to_offset pf lookup_rva with
  | None -> []
  | Some lookup_file_off ->
    let lookup_r = Binary_reader.of_bytes pf.raw_data in
    match Binary_reader.seek lookup_r lookup_file_off with
    | Error _ -> []
    | Ok () ->
      if is_64 then read_pe_lookups_64 pf lookup_r
      else read_pe_lookups_32 pf lookup_r

let find_import_dir (pf : Pe_file.t) =
  match pf.optional_header with
  | None -> None
  | Some oh ->
    match Optional_header.data_directory oh Data_directory.ImportTable with
    | Some dir when Data_directory.is_present dir ->
      Option.map (fun off -> (oh, off)) (Pe_file.rva_to_offset pf dir.virtual_address)
    | _ -> None

(** Parse all imports directly from a PE file using its Data Directories. *)
let parse_pe_imports (pf : Pe_file.t) : (import_entry list, Error.t) result =
  match find_import_dir pf with
  | None -> Ok []
  | Some (oh, import_dir_file_off) ->
    let r = Binary_reader.of_bytes pf.raw_data in
    let* () = Binary_reader.seek r import_dir_file_off in
    let is_64 = Optional_header.is_64bit oh in
    let rec read_descriptors acc =
      if Binary_reader.remaining r < 20 then Ok (List.rev acc)
      else
        match read_import_descriptor r with
        | Error _ -> Ok (List.rev acc)
        | Ok desc when is_null_descriptor desc -> Ok (List.rev acc)
        | Ok (ilt_rva, name_rva, iat_rva) ->
          let dll_name = Option.value ~default:"" (Pe_file.read_cstring_at_rva pf name_rva) in
          let lookup_rva = if Int32.compare ilt_rva 0l <> 0 then ilt_rva else iat_rva in
          let entries = read_dll_entries pf ~is_64 lookup_rva in
          read_descriptors ({ dll_name; entries } :: acc)
    in
    read_descriptors []

let read_ilt_entries_from_bytes idata_bytes rva_to_offset ilt_rva =
  match rva_to_offset ilt_rva with
  | None -> []
  | Some ilt_off ->
    let ilt_r = Binary_reader.of_bytes idata_bytes in
    match Binary_reader.seek ilt_r ilt_off with
    | Error _ -> []
    | Ok () -> read_lookups_32 ~rva_to_offset ~raw_data:idata_bytes ilt_r

let make_idata_offset_resolver ~idata_bytes ~idata_rva =
  let rva_to_offset rva =
    let off = Int32.to_int (Int32.sub rva idata_rva) in
    if off < 0 || off >= Bytes.length idata_bytes then None
    else Some off
  in
  let read_cstring_at rva =
    match rva_to_offset rva with
    | None -> None
    | Some off -> Pe_file.read_cstring_at_offset idata_bytes off
  in
  (rva_to_offset, read_cstring_at)

(** Parse all imports from raw .idata section bytes given the section's RVA. *)
let parse_imports
    ~(idata_bytes : bytes)
    ~(idata_rva : int32)
    : (import_entry list, Error.t) result =
  let r = Binary_reader.of_bytes idata_bytes in
  let rva_to_offset, read_cstring_at = make_idata_offset_resolver ~idata_bytes ~idata_rva in
  let rec read_descriptors acc =
    if Binary_reader.remaining r < 20 then Ok (List.rev acc)
    else
      match read_import_descriptor r with
      | Error _ | Ok (0l, 0l, _) -> Ok (List.rev acc)
      | Ok (ilt_rva, name_rva, _) ->
        let dll_name = Option.value ~default:"" (read_cstring_at name_rva) in
        let entries = read_ilt_entries_from_bytes idata_bytes rva_to_offset ilt_rva in
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
