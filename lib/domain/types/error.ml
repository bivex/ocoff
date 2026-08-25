(** Domain-level error type for PE/COFF parsing and serialization.

    All operations that can fail return [(_, Error.t) result] rather than
    raising exceptions, preserving referential transparency in the domain
    layer. *)

(** The set of failures that can occur when parsing or serializing PE/COFF
    binary data. *)
type t =
  | Unexpected_eof of { offset: int; needed: int; available: int }
      (** A read at [offset] required [needed] bytes but only [available]
          bytes remained in the buffer. *)
  | Invalid_signature of { offset: int; expected: bytes; got: bytes }
      (** A magic-number or signature check failed.  [expected] is the
          canonical byte sequence; [got] is what was found in the buffer. *)
  | Invalid_value of { field: string; value: int; reason: string }
      (** A numeric value decoded from the binary is outside the set of
          values that the specification permits for [field]. *)
  | Unsupported_format of string
      (** The input represents a valid but unsupported variant of the
          format (e.g. a ROM image or a future PE version). *)
  | Offset_out_of_bounds of { offset: int; size: int }
      (** A computed file offset [offset] lies outside the buffer whose
          total length is [size]. *)
  | String_not_terminated of { offset: int }
      (** A NUL-terminated string starting at [offset] had no NUL byte
          before the end of the buffer. *)

(** [pp fmt e] pretty-prints error [e] to formatter [fmt]. *)
let pp fmt = function
  | Unexpected_eof { offset; needed; available } ->
      Format.fprintf fmt
        "Unexpected EOF at offset 0x%x: needed %d byte(s), only %d available"
        offset needed available
  | Invalid_signature { offset; expected; got } ->
      let hex_bytes b =
        Bytes.to_seq b
        |> Seq.map (fun c -> Printf.sprintf "%02x" (Char.code c))
        |> List.of_seq
        |> String.concat " "
      in
      Format.fprintf fmt
        "Invalid signature at offset 0x%x: expected [%s], got [%s]"
        offset (hex_bytes expected) (hex_bytes got)
  | Invalid_value { field; value; reason } ->
      Format.fprintf fmt
        "Invalid value 0x%x for field '%s': %s"
        value field reason
  | Unsupported_format msg ->
      Format.fprintf fmt "Unsupported format: %s" msg
  | Offset_out_of_bounds { offset; size } ->
      Format.fprintf fmt
        "Offset 0x%x is out of bounds (buffer size: 0x%x)"
        offset size
  | String_not_terminated { offset } ->
      Format.fprintf fmt
        "NUL-terminated string starting at offset 0x%x is not terminated"
        offset

(** [to_string e] converts error [e] to a human-readable string. *)
let to_string e = Format.asprintf "%a" pp e
