(** PE/COFF Parser Application Service. *)

val parse_pe_file : bytes -> (Pe_file.t, Error.t) result
val parse_coff_object : bytes -> (Pe_file.t, Error.t) result
val parse_archive : bytes -> (Archive.t, Error.t) result
val parse_any : bytes -> ([ `Pe of Pe_file.t | `Coff of Pe_file.t | `Archive of Archive.t ], Error.t) result
