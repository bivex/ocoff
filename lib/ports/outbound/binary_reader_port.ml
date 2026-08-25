(** Outbound port: abstract binary reading interface.
    Adapters implement this to feed bytes to the parsers. *)

module type S = sig
  type t

  (** Create a reader from a byte buffer. *)
  val of_bytes : bytes -> t

  (** Current read position. *)
  val pos : t -> int

  (** Total number of bytes available. *)
  val length : t -> int

  (** Number of bytes remaining from current position. *)
  val remaining : t -> int

  (** Seek to absolute position. *)
  val seek : t -> int -> (unit, Error.t) result

  (** Advance position by n bytes. *)
  val skip : t -> int -> (unit, Error.t) result

  (** Read a single unsigned byte. *)
  val read_u8 : t -> (int, Error.t) result

  (** Read a little-endian unsigned 16-bit integer. *)
  val read_u16_le : t -> (int, Error.t) result

  (** Read a little-endian signed 16-bit integer. *)
  val read_i16_le : t -> (int, Error.t) result

  (** Read a little-endian unsigned 32-bit integer. *)
  val read_u32_le : t -> (int32, Error.t) result

  (** Read a little-endian signed 32-bit integer. *)
  val read_i32_le : t -> (int32, Error.t) result

  (** Read a little-endian 64-bit integer. *)
  val read_u64_le : t -> (int64, Error.t) result

  (** Read a big-endian unsigned 32-bit integer (used in archive format). *)
  val read_u32_be : t -> (int32, Error.t) result

  (** Read exactly n bytes. *)
  val read_bytes : t -> int -> (bytes, Error.t) result

  (** Read exactly n bytes as a string. *)
  val read_string : t -> int -> (string, Error.t) result

  (** Read a null-terminated string (up to max_len bytes). *)
  val read_cstring : t -> ?max_len:int -> unit -> (string, Error.t) result

  (** Peek at the next n bytes without advancing position. *)
  val peek_bytes : t -> int -> (bytes, Error.t) result

  (** Run a parser at a specific absolute offset, restoring position after. *)
  val at_offset : t -> int -> (t -> ('a, Error.t) result) -> ('a, Error.t) result
end
