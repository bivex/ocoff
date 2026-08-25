(** Outbound port: abstract binary writing interface. *)

module type S = sig
  type t

  val create : ?initial_size:int -> unit -> t
  val pos : t -> int
  val to_bytes : t -> bytes

  val write_u8 : t -> int -> unit
  val write_u16_le : t -> int -> unit
  val write_i16_le : t -> int -> unit
  val write_u32_le : t -> int32 -> unit
  val write_i32_le : t -> int32 -> unit
  val write_u64_le : t -> int64 -> unit
  val write_bytes : t -> bytes -> unit
  val write_string : t -> string -> unit
  val write_zero_pad : t -> int -> unit  (* write n zero bytes *)
  val write_align : t -> int -> unit     (* pad to alignment boundary *)
end
