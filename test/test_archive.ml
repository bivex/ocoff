open Ocoff

let build_sample_archive () =
  let w = Binary_writer.create () in
  Binary_writer.write_string w "!<arch>\n";
  Binary_writer.write_string w "test.obj/       ";
  Binary_writer.write_string w "1700000000  ";
  Binary_writer.write_string w "      ";
  Binary_writer.write_string w "      ";
  Binary_writer.write_string w "0       ";
  let coff_obj = Test_coff.build_sample_coff () in
  let obj_len = Bytes.length coff_obj in
  Binary_writer.write_string w (Printf.sprintf "%-10d" obj_len);
  Binary_writer.write_string w "`\n";
  Binary_writer.write_bytes w coff_obj;
  if obj_len mod 2 = 1 then Binary_writer.write_string w "\n";
  Binary_writer.to_bytes w

let test_archive_parse () =
  let raw = build_sample_archive () in
  let res = Pe_parser.parse_archive raw in
  Alcotest.(check bool) "parse archive ok" true (Result.is_ok res);
  let arch = Result.get_ok res in
  Alcotest.(check int) "1 member" 1 (List.length (Archive.members arch));
  let objs = Archive.object_members arch in
  Alcotest.(check int) "1 object member" 1 (List.length objs);
  let (hdr, pf) = List.hd objs in
  Alcotest.(check string) "member name" "test.obj/" hdr.name;
  Alcotest.(check int) "object machine" 0x8664 pf.coff_header.machine

let tests = [
  Alcotest.test_case "parse_sample_archive" `Quick test_archive_parse;
]
