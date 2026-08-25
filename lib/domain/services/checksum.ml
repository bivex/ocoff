(** Domain service: compute PE optional header checksum.
    Algorithm from IMAGEHLP.DLL, as referenced in the PE specification. *)

let compute (buf : bytes) ~(checksum_offset : int) : int32 =
  let len = Bytes.length buf in
  let rec sum_range acc idx end_idx =
    if idx + 1 < end_idx then
      let w = Bytes.get_uint16_le buf idx in
      sum_range (acc + w) (idx + 2) end_idx
    else if idx < end_idx then
      acc + Bytes.get_uint8 buf idx
    else acc
  in
  let s1 =
    if checksum_offset > 0 then sum_range 0 0 (min checksum_offset len)
    else 0
  in
  let s2 =
    let start2 = checksum_offset + 4 in
    if start2 < len then sum_range 0 start2 len
    else 0
  in
  let total_sum = s1 + s2 in
  let rec fold_carries s =
    let carry = s lsr 16 in
    if carry <> 0 then fold_carries ((s land 0xffff) + carry)
    else s land 0xffff
  in
  let folded = fold_carries total_sum in
  let result = (folded + len) land 0xffffffff in
  Int32.of_int result
