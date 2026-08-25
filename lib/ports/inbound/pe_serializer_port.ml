(** Inbound port: serialize PE/COFF structures to bytes. *)

module type S = sig
  (** Serialize a PE file back to bytes. *)
  val serialize_pe_file : Pe_file.t -> (bytes, Error.t) result

  (** Serialize a COFF object file to bytes. *)
  val serialize_coff_object : Pe_file.t -> (bytes, Error.t) result
end
