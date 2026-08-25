(** Domain service: compute PE optional header checksum.
    Algorithm from IMAGEHLP.DLL, as referenced in the PE specification. *)

(** Compute the PE checksum for the given image bytes.
    The checksum field at [checksum_offset] (4 bytes) is excluded from the computation. *)
let compute (buf : bytes) ~(checksum_offset : int) : int32 =
  let len = Bytes.length buf in
  let sum = ref 0 in
  let i = ref 0 in
  while !i < len do
    let lo = Bytes.get_uint8 buf !i in
    let hi = if !i + 1 < len then Bytes.get_uint8 buf (!i + 1) else 0 in
    let word =
      (* Exclude the 4-byte CheckSum field in the Optional Header *)
      if !i >= checksum_offset && !i <= checksum_offset + 3 then 0
      else if !i + 1 >= checksum_offset && !i + 1 <= checksum_offset + 3 then
        if !i = checksum_offset - 1 then lo else hi lsl 8
      else lo lor (hi lsl 8)
    in
    sum := !sum + word;
    let carry = !sum lsr 16 in
    sum := (!sum land 0xffff) + carry;
    i := !i + 2
  done;
  let final_fold = (!sum land 0xffff) + (!sum lsr 16) in
  let result = (final_fold land 0xffff) + len in
  Int32.of_int result
