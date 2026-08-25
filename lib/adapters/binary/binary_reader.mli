(** Bounds-checked stateful binary cursor over byte buffers. *)

type t

val of_bytes : bytes -> t
val pos : t -> int
val length : t -> int
val remaining : t -> int
val seek : t -> int -> (unit, Error.t) result
val skip : t -> int -> (unit, Error.t) result
val read_u8 : t -> (int, Error.t) result
val read_u16_le : t -> (int, Error.t) result
val read_i16_le : t -> (int, Error.t) result
val read_u32_le : t -> (int32, Error.t) result
val read_i32_le : t -> (int32, Error.t) result
val read_u64_le : t -> (int64, Error.t) result
val read_u32_be : t -> (int32, Error.t) result
val read_bytes : t -> int -> (bytes, Error.t) result
val read_string : t -> int -> (string, Error.t) result
val read_cstring : t -> ?max_len:int -> unit -> (string, Error.t) result
val peek_bytes : t -> int -> (bytes, Error.t) result
val at_offset : t -> int -> (t -> ('a, Error.t) result) -> ('a, Error.t) result
