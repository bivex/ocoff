(** Domain service: resolve PE exports from PE file or .edata section. *)

type export_entry = {
  ordinal: int;              (** Biased ordinal (as seen by caller) *)
  rva: int32;                (** Export RVA, or 0 if forwarder *)
  name: string option;       (** Optional public name *)
  forwarder: string option;  (** Forwarder string (e.g. "NTDLL.RtlAllocateHeap") *)
}

let ( let* ) = Result.bind

type export_header = {
  ordinal_base: int32;
  addr_table_entries: int32;
  num_name_ptrs: int32;
  eat_rva: int32;
  name_ptr_rva: int32;
  ordinal_table_rva: int32;
}

let read_export_header r =
  let* _flags = Binary_reader.read_u32_le r in
  let* _timestamp = Binary_reader.read_u32_le r in
  let* _major_ver = Binary_reader.read_u16_le r in
  let* _minor_ver = Binary_reader.read_u16_le r in
  let* _name_rva = Binary_reader.read_u32_le r in
  let* ordinal_base = Binary_reader.read_u32_le r in
  let* addr_table_entries = Binary_reader.read_u32_le r in
  let* num_name_ptrs = Binary_reader.read_u32_le r in
  let* eat_rva = Binary_reader.read_u32_le r in
  let* name_ptr_rva = Binary_reader.read_u32_le r in
  let* ordinal_table_rva = Binary_reader.read_u32_le r in
  Ok { ordinal_base; addr_table_entries; num_name_ptrs; eat_rva; name_ptr_rva; ordinal_table_rva }

let read_u32_array r base_off count =
  let arr = Array.make count 0l in
  let rec loop i =
    if i >= count then Ok arr
    else
      match Binary_reader.at_offset r (base_off + i * 4) Binary_reader.read_u32_le with
      | Error e -> Error e
      | Ok v -> arr.(i) <- v; loop (i + 1)
  in
  loop 0

let read_u16_array r base_off count =
  let arr = Array.make count 0 in
  let rec loop i =
    if i >= count then Ok arr
    else
      match Binary_reader.at_offset r (base_off + i * 2) Binary_reader.read_u16_le with
      | Error e -> Error e
      | Ok v -> arr.(i) <- v; loop (i + 1)
  in
  loop 0

let read_u32_table r off_opt count =
  match off_opt with
  | None -> Ok (Array.make count 0l)
  | Some off -> read_u32_array r off count

let read_u16_table r off_opt count =
  match off_opt with
  | None -> Ok (Array.make count 0)
  | Some off -> read_u16_array r off count

let build_names_table ~count ~ordinal_indexes ~name_rvas ~resolve_name =
  let table = Hashtbl.create count in
  for i = 0 to count - 1 do
    let eat_idx = ordinal_indexes.(i) in
    match resolve_name name_rvas.(i) with
    | Some name -> Hashtbl.replace table eat_idx name
    | None -> ()
  done;
  table

let build_export_entries ~count ~ordinal_base ~export_rvas ~names_tbl ~is_forwarder ~resolve_forwarder =
  let entries = Array.init count (fun i ->
    let rva = export_rvas.(i) in
    let name = Hashtbl.find_opt names_tbl i in
    let biased_ordinal = i + Int32.to_int ordinal_base in
    let forwarder = if is_forwarder rva then resolve_forwarder rva else None in
    let actual_rva = if forwarder <> None then 0l else rva in
    { ordinal = biased_ordinal; rva = actual_rva; name; forwarder }
  ) in
  Array.to_list entries

let find_export_dir (pf : Pe_file.t) =
  match pf.optional_header with
  | None -> None
  | Some oh ->
    match Optional_header.data_directory oh Data_directory.ExportTable with
    | Some dir when Data_directory.is_present dir ->
      Option.map (fun off -> (dir, off)) (Pe_file.rva_to_offset pf dir.virtual_address)
    | _ -> None

(** Parse exports directly from a PE file using its Data Directories. *)
let parse_pe_exports (pf : Pe_file.t) : (export_entry list, Error.t) result =
  match find_export_dir pf with
  | None -> Ok []
  | Some (dir, export_dir_file_off) ->
    let r = Binary_reader.of_bytes pf.raw_data in
    let* () = Binary_reader.seek r export_dir_file_off in
    let* h = read_export_header r in
    let n_exports = max 0 (min (Int32.to_int h.addr_table_entries) 65536) in
    let* export_rvas = read_u32_table r (Pe_file.rva_to_offset pf h.eat_rva) n_exports in
    let n_names = max 0 (min (Int32.to_int h.num_name_ptrs) n_exports) in
    let* name_rvas = read_u32_table r (Pe_file.rva_to_offset pf h.name_ptr_rva) n_names in
    let* ordinal_indexes = read_u16_table r (Pe_file.rva_to_offset pf h.ordinal_table_rva) n_names in
    let names_tbl = build_names_table ~count:n_names ~ordinal_indexes ~name_rvas
      ~resolve_name:(Pe_file.read_cstring_at_rva pf) in
    let dir_start = Int32.to_int dir.virtual_address in
    let dir_end = dir_start + Int32.to_int dir.size in
    let is_forwarder rva =
      let v = Int32.to_int rva in
      v >= dir_start && v < dir_end
    in
    Ok (build_export_entries ~count:n_exports ~ordinal_base:h.ordinal_base
          ~export_rvas ~names_tbl ~is_forwarder
          ~resolve_forwarder:(Pe_file.read_cstring_at_rva pf))

let make_edata_rva_resolver edata_bytes edata_rva =
  let edata_start = Int32.to_int edata_rva in
  let edata_end = edata_start + Bytes.length edata_bytes in
  let rva_to_offset rva =
    let off = Int32.to_int (Int32.sub rva edata_rva) in
    if off < 0 || off >= Bytes.length edata_bytes then
      Error (Error.Offset_out_of_bounds { offset = off; size = Bytes.length edata_bytes })
    else Ok off
  in
  let is_forwarder rva =
    let v = Int32.to_int rva in
    v >= edata_start && v < edata_end
  in
  let resolve_cstring rva =
    match rva_to_offset rva with
    | Error _ -> None
    | Ok off -> Pe_file.read_cstring_at_offset edata_bytes off
  in
  (rva_to_offset, is_forwarder, resolve_cstring)

(** Parse the export directory from raw .edata section bytes. *)
let parse_exports (edata_bytes : bytes) (edata_rva : int32) : (export_entry list, Error.t) result =
  let r = Binary_reader.of_bytes edata_bytes in
  let* h = read_export_header r in
  let rva_to_offset, is_forwarder, resolve_cstring = make_edata_rva_resolver edata_bytes edata_rva in
  let* eat_off = rva_to_offset h.eat_rva in
  let n_exports = Int32.to_int h.addr_table_entries in
  let* export_rvas = read_u32_array r eat_off n_exports in
  let n_names = Int32.to_int h.num_name_ptrs in
  let* name_rvas = read_u32_table r (Result.to_option (rva_to_offset h.name_ptr_rva)) n_names in
  let* ordinal_indexes = read_u16_table r (Result.to_option (rva_to_offset h.ordinal_table_rva)) n_names in
  let names_tbl = build_names_table ~count:n_names ~ordinal_indexes ~name_rvas ~resolve_name:resolve_cstring in
  Ok (build_export_entries ~count:n_exports ~ordinal_base:h.ordinal_base
        ~export_rvas ~names_tbl ~is_forwarder ~resolve_forwarder:resolve_cstring)

let find_by_name entries name =
  List.find_opt (fun e -> e.name = Some name) entries

let find_by_ordinal entries ordinal =
  List.find_opt (fun e -> e.ordinal = ordinal) entries

let pp_entry fmt e =
  Format.fprintf fmt "[%4d] rva=0x%08lx name=%s%s\n"
    e.ordinal e.rva
    (Option.value ~default:"<noname>" e.name)
    (match e.forwarder with
     | None -> ""
     | Some f -> Printf.sprintf " -> %s" f)
