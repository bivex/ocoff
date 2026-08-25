open Ocoff

let build_sample_coff () =
  let w = Binary_writer.create () in
  Binary_writer.write_u16_le w 0x8664; (* Machine: AMD64 *)
  Binary_writer.write_u16_le w 1;      (* NumberOfSections: 1 *)
  Binary_writer.write_u32_le w 1700000000l; (* TimeDateStamp *)
  Binary_writer.write_u32_le w 60l;    (* PointerToSymbolTable: at offset 60 *)
  Binary_writer.write_u32_le w 2l;     (* NumberOfSymbols: 2 (1 sym + 1 aux) *)
  Binary_writer.write_u16_le w 0;      (* SizeOfOptionalHeader: 0 *)
  Binary_writer.write_u16_le w 0x0004; (* Characteristics *)

  (* Section Header: .text (offset 20..60 = 40 bytes) *)
  Binary_writer.write_string w ".text\x00\x00\x00";
  Binary_writer.write_u32_le w 16l;    (* VirtualSize *)
  Binary_writer.write_u32_le w 0l;     (* VirtualAddress (0 in obj) *)
  Binary_writer.write_u32_le w 16l;    (* SizeOfRawData *)
  Binary_writer.write_u32_le w 116l;   (* PointerToRawData *)
  Binary_writer.write_u32_le w 0l;     (* PointerToRelocations *)
  Binary_writer.write_u32_le w 0l;     (* PointerToLinenumbers *)
  Binary_writer.write_u16_le w 0;      (* NumberOfRelocations *)
  Binary_writer.write_u16_le w 0;      (* NumberOfLinenumbers *)
  Binary_writer.write_u32_le w 0x60000020l; (* Characteristics *)

  (* Primary Symbol Table Entry: 18 bytes at offset 60..78 *)
  Binary_writer.write_string w "main\x00\x00\x00\x00";
  Binary_writer.write_u32_le w 0l;     (* Value *)
  Binary_writer.write_u16_le w 1;      (* SectionNumber = 1 *)
  Binary_writer.write_u16_le w 0x20;   (* Type: Function *)
  Binary_writer.write_u8 w 2;          (* StorageClass: External *)
  Binary_writer.write_u8 w 1;          (* NumberOfAuxSymbols: 1 *)

  (* Auxiliary Record: Function Definition (18 bytes at offset 78..96) *)
  Binary_writer.write_u32_le w 0l;     (* TagIndex *)
  Binary_writer.write_u32_le w 16l;    (* TotalSize = 16 *)
  Binary_writer.write_u32_le w 0l;     (* PointerToLinenumber *)
  Binary_writer.write_u32_le w 0l;     (* PointerToNextFunction *)
  Binary_writer.write_u16_le w 0;      (* Unused *)

  (* String Table: 20 bytes at offset 96..116 *)
  Binary_writer.write_u32_le w 20l;    (* Size = 20 *)
  Binary_writer.write_string w "some_long_symbol_name\x00";

  (* Raw section data: 16 bytes at offset 116..132 *)
  Binary_writer.write_string w "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xc3";
  Binary_writer.to_bytes w

let test_coff_object_parse () =
  let raw = build_sample_coff () in
  let res = Pe_parser.parse_coff_object raw in
  Alcotest.(check bool) "parse coff ok" true (Result.is_ok res);
  let pf = Result.get_ok res in
  Alcotest.(check bool) "is object" true (Pe_file.is_object pf);
  Alcotest.(check int) "machine AMD64" 0x8664 pf.coff_header.machine;
  Alcotest.(check int) "1 section" 1 (List.length pf.sections);
  let sec = List.hd pf.sections in
  Alcotest.(check string) "section name .text" ".text" (Section_header.name_string sec);
  Alcotest.(check int) "1 symbol (with aux)" 1 (List.length pf.symbol_table);
  let sym = List.hd pf.symbol_table in
  Alcotest.(check string) "symbol name main" "main"
    (Symbol_name.resolve (Coff_symbol.name sym) ~string_table:pf.string_table);
  Alcotest.(check bool) "symbol is function" true (Coff_symbol.is_function sym);
  Alcotest.(check bool) "symbol is external" true (Coff_symbol.is_external sym);
  Alcotest.(check int) "has 1 aux record" 1 (List.length (Coff_symbol.aux_records sym));
  let sec_data = Pe_file.section_data pf sec in
  Alcotest.(check int) "section data length 16" 16 (Bytes.length sec_data)

let test_coff_serialization () =
  let raw = build_sample_coff () in
  let pf = Result.get_ok (Pe_parser.parse_coff_object raw) in
  let ser_res = Pe_serializer.serialize_coff_object pf in
  Alcotest.(check bool) "serialize ok" true (Result.is_ok ser_res);
  let ser_bytes = Result.get_ok ser_res in
  let pf2 = Result.get_ok (Pe_parser.parse_coff_object ser_bytes) in
  Alcotest.(check int) "re-parsed machine matches" pf.coff_header.machine pf2.coff_header.machine;
  Alcotest.(check int) "re-parsed sections count" (List.length pf.sections) (List.length pf2.sections)

let tests = [
  Alcotest.test_case "parse_sample_coff" `Quick test_coff_object_parse;
  Alcotest.test_case "serialize_coff" `Quick test_coff_serialization;
]
