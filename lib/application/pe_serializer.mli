(** PE/COFF Serializer Application Service. *)

val serialize_pe_file : Pe_file.t -> (bytes, Error.t) result
val serialize_coff_object : Pe_file.t -> (bytes, Error.t) result
