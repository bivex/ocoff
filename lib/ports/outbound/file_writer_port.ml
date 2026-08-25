(** Outbound port: write files to filesystem. *)

module type S = sig
  val write_file : string -> bytes -> (unit, [`Io_error of string]) result
end
