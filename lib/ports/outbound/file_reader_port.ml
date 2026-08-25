(** Outbound port: read files from filesystem. *)

module type S = sig
  val read_file : string -> (bytes, [`File_not_found of string | `Io_error of string]) result
end
