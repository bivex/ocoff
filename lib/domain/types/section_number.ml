(** COFF Section Number Values.

    Defined in section "Section Number Values" of the Microsoft PE/COFF specification. *)

type t =
  | Undefined      (** 0 - external or common symbol *)
  | Absolute       (** -1 - absolute non-relocatable value *)
  | Debug          (** -2 - general type or debugging information (.file) *)
  | Section of int (** >= 1 - 1-based index into section table *)
  | Special of int (** other negative / non-standard numbers *)

let of_int16 = function
  | 0 -> Undefined
  | -1 -> Absolute
  | -2 -> Debug
  | n when n > 0 -> Section n
  | n -> Special n

let to_int16 = function
  | Undefined -> 0
  | Absolute -> -1
  | Debug -> -2
  | Section n -> n
  | Special n -> n

let to_string = function
  | Undefined -> "IMAGE_SYM_UNDEFINED"
  | Absolute -> "IMAGE_SYM_ABSOLUTE"
  | Debug -> "IMAGE_SYM_DEBUG"
  | Section n -> Printf.sprintf "Section %d" n
  | Special n -> Printf.sprintf "Special(%d)" n

let pp fmt t = Format.pp_print_string fmt (to_string t)
