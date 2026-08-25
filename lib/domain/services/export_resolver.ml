(** Domain service: resolve PE exports from PE file or .edata section. *)

type export_entry = {
  ordinal: int;              (** Biased ordinal (as seen by caller) *)
  rva: int32;                (** Export RVA, or 0 if forwarder *)
  name: string option;       (** Optional public name *)
  forwarder: string option;  (** Forwarder string (e.g. "NTDLL.RtlAllocateHeap") *)
}

let ( let* ) = Result.bind

(** Parse exports directly from a PE file using its Data Directories. *)
let parse_pe_exports (pf : Pe_file.t) : (export_entry list, Error.t) result =
  match pf.optional_header with
  | None -> Ok []
  | Some oh ->
    match Optional_header.data_directory oh Data_directory.ExportTable with
    | None -> Ok []
    | Some dir when not (Data_directory.is_present dir) -> Ok []
    | Some dir ->
      match Pe_file.rva_to_offset pf dir.virtual_address with
      | None -> Ok []
      | Some export_dir_file_off ->
        let r = Binary_reader.of_bytes pf.raw_data in
        let* () = Binary_reader.seek r export_dir_file_off in
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

        let n_exports = max 0 (min (Int32.to_int addr_table_entries) 65536) in
        let export_rvas = Array.make n_exports 0l in
        let* () =
          match Pe_file.rva_to_offset pf eat_rva with
          | None -> Ok ()
          | Some eat_off ->
            let rec loop i =
              if i >= n_exports then Ok ()
              else
                match Binary_reader.at_offset r (eat_off + i * 4) (fun r -> Binary_reader.read_u32_le r) with
                | Error e -> Error e
                | Ok v -> export_rvas.(i) <- v; loop (i + 1)
            in
            loop 0
        in

        let n_names = max 0 (min (Int32.to_int num_name_ptrs) n_exports) in
        let name_rvas = Array.make n_names 0l in
        let* () =
          match Pe_file.rva_to_offset pf name_ptr_rva with
          | None -> Ok ()
          | Some name_ptr_off ->
            let rec loop i =
              if i >= n_names then Ok ()
              else
                match Binary_reader.at_offset r (name_ptr_off + i * 4) (fun r -> Binary_reader.read_u32_le r) with
                | Error e -> Error e
                | Ok v -> name_rvas.(i) <- v; loop (i + 1)
            in
            loop 0
        in

        let ordinal_indexes = Array.make n_names 0 in
        let* () =
          match Pe_file.rva_to_offset pf ordinal_table_rva with
          | None -> Ok ()
          | Some ord_off ->
            let rec loop i =
              if i >= n_names then Ok ()
              else
                match Binary_reader.at_offset r (ord_off + i * 2) (fun r -> Binary_reader.read_u16_le r) with
                | Error e -> Error e
                | Ok v -> ordinal_indexes.(i) <- v; loop (i + 1)
            in
            loop 0
        in

        let name_by_eat_index = Hashtbl.create n_names in
        for i = 0 to n_names - 1 do
          let eat_idx = ordinal_indexes.(i) in
          (match Pe_file.read_cstring_at_rva pf name_rvas.(i) with
          | Some name -> Hashtbl.replace name_by_eat_index eat_idx name
          | None -> ())
        done;

        let dir_start = Int32.to_int dir.virtual_address in
        let dir_end = dir_start + Int32.to_int dir.size in
        let is_forwarder rva =
          let v = Int32.to_int rva in
          v >= dir_start && v < dir_end
        in

        let entries = Array.init n_exports (fun i ->
          let rva = export_rvas.(i) in
          let name = Hashtbl.find_opt name_by_eat_index i in
          let biased_ordinal = i + Int32.to_int ordinal_base in
          let forwarder =
            if is_forwarder rva then Pe_file.read_cstring_at_rva pf rva
            else None
          in
          let actual_rva = if forwarder <> None then 0l else rva in
          { ordinal = biased_ordinal; rva = actual_rva; name; forwarder }
        ) in
        Ok (Array.to_list entries)

(** Parse the export directory from raw .edata section bytes. *)
let parse_exports (edata_bytes : bytes) (edata_rva : int32) : (export_entry list, Error.t) result =
  let r = Binary_reader.of_bytes edata_bytes in
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

  let rva_to_offset rva =
    let off = Int32.to_int (Int32.sub rva edata_rva) in
    if off < 0 || off >= Bytes.length edata_bytes then
      Error (Error.Offset_out_of_bounds { offset = off; size = Bytes.length edata_bytes })
    else Ok off
  in

  let* eat_off = rva_to_offset eat_rva in
  let n_exports = Int32.to_int addr_table_entries in
  let export_rvas = Array.make n_exports 0l in
  let* () =
    let rec loop i =
      if i >= n_exports then Ok ()
      else
        match Binary_reader.at_offset r (eat_off + i * 4) (fun r -> Binary_reader.read_u32_le r) with
        | Error e -> Error e
        | Ok v -> export_rvas.(i) <- v; loop (i + 1)
    in
    loop 0
  in

  let n_names = Int32.to_int num_name_ptrs in
  let name_rvas = Array.make n_names 0l in
  let* () =
    match rva_to_offset name_ptr_rva with
    | Error _ -> Ok ()
    | Ok name_ptr_off ->
      let rec loop i =
        if i >= n_names then Ok ()
        else
          match Binary_reader.at_offset r (name_ptr_off + i * 4) (fun r -> Binary_reader.read_u32_le r) with
          | Error e -> Error e
          | Ok v -> name_rvas.(i) <- v; loop (i + 1)
      in
      loop 0
  in

  let ordinal_indexes = Array.make n_names 0 in
  let* () =
    match rva_to_offset ordinal_table_rva with
    | Error _ -> Ok ()
    | Ok ord_off ->
      let rec loop i =
        if i >= n_names then Ok ()
        else
          match Binary_reader.at_offset r (ord_off + i * 2) (fun r -> Binary_reader.read_u16_le r) with
          | Error e -> Error e
          | Ok v -> ordinal_indexes.(i) <- v; loop (i + 1)
      in
      loop 0
  in

  let name_by_eat_index = Hashtbl.create n_names in
  for i = 0 to n_names - 1 do
    let eat_idx = ordinal_indexes.(i) in
    (match rva_to_offset name_rvas.(i) with
    | Error _ -> ()
    | Ok off ->
      match Pe_file.read_cstring_at_offset edata_bytes off with
      | Some name -> Hashtbl.replace name_by_eat_index eat_idx name
      | None -> ())
  done;

  let edata_start = Int32.to_int edata_rva in
  let edata_end = edata_start + Bytes.length edata_bytes in
  let is_forwarder rva =
    let v = Int32.to_int rva in
    v >= edata_start && v < edata_end
  in

  let entries = Array.init n_exports (fun i ->
    let rva = export_rvas.(i) in
    let name = Hashtbl.find_opt name_by_eat_index i in
    let biased_ordinal = i + Int32.to_int ordinal_base in
    let forwarder =
      if is_forwarder rva then
        match rva_to_offset rva with
        | Error _ -> None
        | Ok off -> Pe_file.read_cstring_at_offset edata_bytes off
      else None
    in
    let actual_rva = if forwarder <> None then 0l else rva in
    { ordinal = biased_ordinal; rva = actual_rva; name; forwarder }
  ) in
  Ok (Array.to_list entries)

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
