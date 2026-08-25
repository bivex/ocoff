(** COFF archive (.lib) aggregate root.

    Layout per section "Archive (Library) File Format" of the PE/COFF specification. *)

type member_content =
  | Object of Pe_file.t
  | LinkerMember1 of {
      offsets: int32 list;  (** big-endian file offsets to member headers *)
      symbols: string list;
    }
  | LinkerMember2 of {
      member_offsets: int32 list;
      symbols: string list;
      indices: int list;  (** 1-based indexes into member_offsets *)
    }
  | LongnamesMember of string list
  | Raw of bytes  (** unparsed or unknown member content *)

type member_header = {
  name: string;    (** 16 bytes, slash-terminated (e.g. "foo.obj/" or "/12") *)
  date: int64;     (** seconds since 1970-01-01 *)
  user_id: string;
  group_id: string;
  mode: int;       (** octal file mode *)
  size: int;       (** member data size in bytes *)
}

type member = {
  header: member_header;
  content: member_content;
}

type t = {
  members: member list;
}

let signature = "!<arch>\n"
let signature_size = 8

let make members = { members }
let members t = t.members

let linker_member1 t =
  List.find_opt (fun m ->
    match m.content with LinkerMember1 _ -> true | _ -> false
  ) t.members

let linker_member2 t =
  List.find_opt (fun m ->
    match m.content with LinkerMember2 _ -> true | _ -> false
  ) t.members

let object_members t =
  List.filter_map (fun m ->
    match m.content with Object f -> Some (m.header, f) | _ -> None
  ) t.members

let pp fmt t =
  Format.fprintf fmt "<Archive: %d members>" (List.length t.members)
