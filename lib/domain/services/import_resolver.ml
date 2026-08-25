(** Domain service: parse PE imports from .idata section. *)

type import_by =
  | ByOrdinal of int
  | ByName of { hint: int; name: string }

type import_entry = {
  dll_name: string;
  entries: import_by list;
}

let ( let* ) = Result.bind

(** Parse all imports from the raw .idata section bytes given the section's RVA. *)
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
  Format.fprintf fmt "DLL: %s\n" entry.dll_name;
  List.iter (fun imp ->
    match imp with
    | ByOrdinal n -> Format.fprintf fmt "  [%d]\n" n
    | ByName { hint; name } -> Format.fprintf fmt "  [hint=%d] %s\n" hint name
  ) entry.entries
