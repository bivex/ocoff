open Ocoff

let test_binary_roundtrip () =
  let w = Binary_writer.create () in
  Binary_writer.write_u8 w 0x42;
  Binary_writer.write_u16_le w 0x1234;
  Binary_writer.write_i16_le w (-100);
  Binary_writer.write_u32_le w 0xdeadbeef_l;
  Binary_writer.write_u64_le w 0x0102030405060708L;
  Binary_writer.write_string w "Hello";
  Binary_writer.write_u8 w 0;
  let bytes = Binary_writer.to_bytes w in

  let r = Binary_reader.of_bytes bytes in
  Alcotest.(check int) "read_u8" 0x42 (Result.get_ok (Binary_reader.read_u8 r));
  Alcotest.(check int) "read_u16_le" 0x1234 (Result.get_ok (Binary_reader.read_u16_le r));
  Alcotest.(check int) "read_i16_le" (-100) (Result.get_ok (Binary_reader.read_i16_le r));
  Alcotest.(check int32) "read_u32_le" 0xdeadbeef_l (Result.get_ok (Binary_reader.read_u32_le r));
  Alcotest.(check int64) "read_u64_le" 0x0102030405060708L (Result.get_ok (Binary_reader.read_u64_le r));
  Alcotest.(check string) "read_cstring" "Hello" (Result.get_ok (Binary_reader.read_cstring r ()));
  Alcotest.(check int) "remaining is 0" 0 (Binary_reader.remaining r)

let test_binary_bounds () =
  let r = Binary_reader.of_bytes (Bytes.of_string "ab") in
  Alcotest.(check bool) "read 2 bytes ok" true (Result.is_ok (Binary_reader.read_bytes r 2));
  Alcotest.(check bool) "read past eof fails" true (Result.is_error (Binary_reader.read_u8 r))

let tests = [
  Alcotest.test_case "roundtrip" `Quick test_binary_roundtrip;
  Alcotest.test_case "bounds" `Quick test_binary_bounds;
]
