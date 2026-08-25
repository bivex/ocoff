open Ocoff

let build_sample_edata () =
  let w = Binary_writer.create () in
  Binary_writer.write_u32_le w 0l;
  Binary_writer.write_u32_le w 0l;
  Binary_writer.write_u16_le w 1;
  Binary_writer.write_u16_le w 0;
  Binary_writer.write_u32_le w 0x2050l;
  Binary_writer.write_u32_le w 1l;
  Binary_writer.write_u32_le w 2l;
  Binary_writer.write_u32_le w 2l;
  Binary_writer.write_u32_le w 0x2028l;
  Binary_writer.write_u32_le w 0x2030l;
  Binary_writer.write_u32_le w 0x2038l;
  Binary_writer.write_u32_le w 0x1000l;
  Binary_writer.write_u32_le w 0x1050l;
  Binary_writer.write_u32_le w 0x2060l;
  Binary_writer.write_u32_le w 0x2070l;
  Binary_writer.write_u16_le w 0;
  Binary_writer.write_u16_le w 1;
  let cur = Binary_writer.pos w in
  Binary_writer.write_zero_pad w (0x50 - cur);
  Binary_writer.write_string w "test.dll\x00";
  let cur2 = Binary_writer.pos w in
  Binary_writer.write_zero_pad w (0x60 - cur2);
  Binary_writer.write_string w "fn_add\x00";
  let cur3 = Binary_writer.pos w in
  Binary_writer.write_zero_pad w (0x70 - cur3);
  Binary_writer.write_string w "fn_sub\x00";
  Binary_writer.to_bytes w

let test_export_resolver () =
  let edata_bytes = build_sample_edata () in
  let edata_rva = 0x2000l in
  let res = Export_resolver.parse_exports edata_bytes edata_rva in
  Alcotest.(check bool) "parse exports ok" true (Result.is_ok res);
  let entries = Result.get_ok res in
  Alcotest.(check int) "2 exports" 2 (List.length entries);
  let exp1 = Export_resolver.find_by_name entries "fn_add" in
  Alcotest.(check bool) "found fn_add" true (exp1 <> None);
  let e1 = Option.get exp1 in
  Alcotest.(check int) "fn_add ordinal is 1" 1 e1.ordinal;
  Alcotest.(check int32) "fn_add rva is 0x1000" 0x1000l e1.rva;
  let exp2 = Export_resolver.find_by_ordinal entries 2 in
  Alcotest.(check bool) "found ordinal 2" true (exp2 <> None);
  let e2 = Option.get exp2 in
  Alcotest.(check (option string)) "ordinal 2 is fn_sub" (Some "fn_sub") e2.name;
  Alcotest.(check int32) "fn_sub rva is 0x1050" 0x1050l e2.rva

let tests = [
  Alcotest.test_case "parse_exports" `Quick test_export_resolver;
]
