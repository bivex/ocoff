open Ocoff

let test_invalid_signatures () =
  let bad_pe = Bytes.of_string "NOT_A_PE_FILE" in
  Alcotest.(check bool) "bad pe rejected" true (Result.is_error (Pe_parser.parse_pe_file bad_pe));
  let bad_arch = Bytes.of_string "NOT_AN_ARCHIVE" in
  Alcotest.(check bool) "bad archive rejected" true (Result.is_error (Pe_parser.parse_archive bad_arch));
  let empty = Bytes.empty in
  Alcotest.(check bool) "empty coff rejected" true (Result.is_error (Pe_parser.parse_coff_object empty))

let tests = [
  Alcotest.test_case "invalid_signatures" `Quick test_invalid_signatures;
]
