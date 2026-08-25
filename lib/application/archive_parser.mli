(** Archive (.lib) parser application component. *)

val archive_signature : string

val parse_archive :
  parse_coff_object:(bytes -> (Pe_file.t, Error.t) result) ->
  bytes ->
  (Archive.t, Error.t) result
