(** Generic Bitmask Flag Set Functor and Helpers.
    Provides reusable decoding, encoding, membership checking, and pretty-printing
    for bitmask flag sets across domain types. *)

let pp_flags to_str fmt flags =
  match flags with
  | [] -> Format.pp_print_string fmt "(none)"
  | _ ->
    let strs = List.map to_str flags in
    Format.pp_print_string fmt (String.concat " | " strs)

module type FLAG_SPEC = sig
  type flag
  val flag_bits : (flag * int) list
  val flag_to_string : flag -> string
end

module Make (S : FLAG_SPEC) = struct
  type t = S.flag list

  let of_uint16 n =
    List.filter_map
      (fun (flag, bit) -> if n land bit <> 0 then Some flag else None)
      S.flag_bits

  let to_uint16 flags =
    List.fold_left
      (fun acc flag ->
         match List.assoc_opt flag S.flag_bits with
         | Some bit -> acc lor bit
         | None -> acc)
      0
      flags

  let has t flag = List.mem flag t

  let pp fmt flags = pp_flags S.flag_to_string fmt flags
end
