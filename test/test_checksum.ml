open Ocoff

let test_checksum_computation () =
  let raw = Bytes.of_string "MZ\x00\x00\x00\x00\x00\x00" in
  let csum = Checksum.compute raw ~checksum_offset:4 in
  Alcotest.(check bool) "checksum is computed" true (Int32.compare csum 0l > 0)

let tests = [
  Alcotest.test_case "compute_checksum" `Quick test_checksum_computation;
]
