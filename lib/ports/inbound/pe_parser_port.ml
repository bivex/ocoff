(** Inbound port: parse PE/COFF binary formats. *)

module type S = sig
  (** Parse a PE image file (EXE/DLL) from bytes.
      Returns an error if the bytes are not a valid PE image. *)
  val parse_pe_file : bytes -> (Pe_file.t, Error.t) result

  (** Parse a COFF object file from bytes. *)
  val parse_coff_object : bytes -> (Pe_file.t, Error.t) result

  (** Parse a COFF archive (.lib) from bytes. *)
  val parse_archive : bytes -> (Archive.t, Error.t) result

  (** Attempt to auto-detect and parse any supported format. *)
  val parse_any : bytes -> ([`Pe of Pe_file.t | `Coff of Pe_file.t | `Archive of Archive.t], Error.t) result
end
