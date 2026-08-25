(** Archive (.lib) parser application service. *)

let ( let* ) = Result.bind

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

let parse_linker_member1 data =
  let member_r = Binary_reader.of_bytes data in
  match Binary_reader.read_u32_be member_r with
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
      Archive.LinkerMember1 { offsets; symbols }

let parse_longnames data =
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

let parse_archive ~parse_coff_object buf =
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
            | "/" -> parse_linker_member1 data
            | "//" -> parse_longnames data
            | _ ->
              (match parse_coff_object data with
               | Ok pf -> Archive.Object pf
               | Error _ -> Archive.Raw data)
          in
          read_members ({ Archive.header = hdr; content } :: acc)
    in
    read_members []
  end
