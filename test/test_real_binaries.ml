open Ocoff

let test_real_guron_exe () =
  let path = "/Volumes/External/temppp1/source/Guron/Win32/Debug/Guron.exe" in
  if Sys.file_exists path then begin
    let res = Ocoff.load_file path in
    Alcotest.(check bool) "load Guron.exe ok" true (Result.is_ok res);
    match Result.get_ok res with
    | `Pe pf ->
      Alcotest.(check int) "x86 machine" 0x014c pf.coff_header.machine;
      Alcotest.(check int) "6 sections" 6 (List.length pf.sections);
      let imports = Result.get_ok (Import_resolver.parse_pe_imports pf) in
      Alcotest.(check bool) "has imports" true (List.length imports > 0)
    | _ -> Alcotest.fail "expected PE image"
  end

let test_real_libeay32_dll () =
  let path = "/Volumes/External/temppp1/source/Guron/Win32/Debug/libeay32.dll" in
  if Sys.file_exists path then begin
    let res = Ocoff.load_file path in
    Alcotest.(check bool) "load libeay32.dll ok" true (Result.is_ok res);
    match Result.get_ok res with
    | `Pe pf ->
      Alcotest.(check int) "x86 machine" 0x014c pf.coff_header.machine;
      let exports = Result.get_ok (Export_resolver.parse_pe_exports pf) in
      Alcotest.(check bool) "has 4000+ exports" true (List.length exports > 4000)
    | _ -> Alcotest.fail "expected PE DLL"
  end

let test_csharp_avalonia_dll () =
  let path = "/Users/password9090/.nuget/packages/avalonia.fonts.inter/12.1.0/lib/net10.0/Avalonia.Fonts.Inter.dll" in
  if Sys.file_exists path then begin
    let res = Ocoff.load_file path in
    Alcotest.(check bool) "load Avalonia .NET 10 DLL ok" true (Result.is_ok res);
    match Result.get_ok res with
    | `Pe pf ->
      let oh = Option.get pf.optional_header in
      let clr_dir = Optional_header.data_directory oh Data_directory.ClrRuntimeHeader in
      Alcotest.(check bool) "has CLR runtime header" true (clr_dir <> None && Data_directory.is_present (Option.get clr_dir));
      let imports = Result.get_ok (Import_resolver.parse_pe_imports pf) in
      Alcotest.(check int) "1 imported DLL (mscoree.dll)" 1 (List.length imports);
      let mscoree = List.hd imports in
      Alcotest.(check string) "mscoree.dll" "mscoree.dll" mscoree.dll_name
    | _ -> Alcotest.fail "expected PE DLL"
  end

let test_csharp_extensions_dll () =
  let path = "/Users/password9090/.nuget/packages/microsoft.extensions.caching.abstractions/10.0.10/lib/net8.0/Microsoft.Extensions.Caching.Abstractions.dll" in
  if Sys.file_exists path then begin
    let res = Ocoff.load_file path in
    Alcotest.(check bool) "load Extensions .NET 8 DLL ok" true (Result.is_ok res);
    match Result.get_ok res with
    | `Pe pf ->
      let oh = Option.get pf.optional_header in
      let clr_dir = Optional_header.data_directory oh Data_directory.ClrRuntimeHeader in
      Alcotest.(check bool) "has CLR runtime header" true (clr_dir <> None && Data_directory.is_present (Option.get clr_dir));
      let imports = Result.get_ok (Import_resolver.parse_pe_imports pf) in
      Alcotest.(check int) "1 imported DLL (mscoree.dll)" 1 (List.length imports)
    | _ -> Alcotest.fail "expected PE DLL"
  end

let tests = [
  Alcotest.test_case "guron_exe" `Quick test_real_guron_exe;
  Alcotest.test_case "libeay32_dll" `Quick test_real_libeay32_dll;
  Alcotest.test_case "csharp_avalonia_dll" `Quick test_csharp_avalonia_dll;
  Alcotest.test_case "csharp_extensions_dll" `Quick test_csharp_extensions_dll;
]
