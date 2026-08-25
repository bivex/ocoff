(** ocoffdump — CLI tool for inspecting PE/COFF binary files. *)

open Cmdliner

let dump_cmd =
  let doc = "Dump PE/COFF binary structure to stdout." in
  let path_arg =
    let doc = "Path to PE/COFF file (EXE, DLL, OBJ, or LIB)." in
    Arg.(required & pos 0 (some file) None & info [] ~doc ~docv:"FILE")
  in
  let format_flag =
    let doc = "Output format: text (default) or json." in
    Arg.(value & opt string "text" & info ["f"; "format"] ~doc)
  in
  let sections_flag =
    let doc = "Show section data hex dumps." in
    Arg.(value & flag & info ["s"; "sections"] ~doc)
  in
  let symbols_flag =
    let doc = "Show symbol table." in
    Arg.(value & flag & info ["S"; "symbols"] ~doc)
  in
  let imports_flag =
    let doc = "Show imports." in
    Arg.(value & flag & info ["i"; "imports"] ~doc)
  in
  let exports_flag =
    let doc = "Show exports." in
    Arg.(value & flag & info ["e"; "exports"] ~doc)
  in
  let run path _format show_sections _show_symbols show_imports show_exports =
    match Ocoff.load_file path with
    | Error e ->
      Printf.eprintf "Error: %s\n" (Error.to_string e);
      `Error (false, Error.to_string e)
    | Ok (`Pe pf | `Coff pf) ->
      Ocoff.dump_pe pf;
      if show_sections then begin
        Printf.printf "\n=== Section Data ===\n";
        List.iter (fun sec ->
          let data = Pe_file.section_data pf sec in
          if Bytes.length data > 0 then begin
            Printf.printf "\n[%s] %d bytes\n" (Section_header.name_string sec) (Bytes.length data);
            Pe_printer.pp_hex_dump Format.std_formatter data ~max_bytes:256
          end
        ) pf.Pe_file.sections
      end;
      if show_imports then begin
        Printf.printf "\n=== Imports ===\n";
        (match Ocoff.Pe_file.find_section_by_name pf ".idata" with
         | None -> Printf.printf "(no .idata section)\n"
         | Some sec ->
           let data = Pe_file.section_data pf sec in
           let idata_rva = sec.Section_header.virtual_address in
           match Import_resolver.parse_imports ~idata_bytes:data ~idata_rva with
           | Error e -> Printf.printf "Error parsing imports: %s\n" (Error.to_string e)
           | Ok entries ->
             List.iter (Import_resolver.pp_entry Format.std_formatter) entries)
      end;
      if show_exports then begin
        Printf.printf "\n=== Exports ===\n";
        (match Ocoff.Pe_file.find_section_by_name pf ".edata" with
         | None -> Printf.printf "(no .edata section)\n"
         | Some sec ->
           let data = Pe_file.section_data pf sec in
           let edata_rva = sec.Section_header.virtual_address in
           match Export_resolver.parse_exports data edata_rva with
           | Error e -> Printf.printf "Error parsing exports: %s\n" (Error.to_string e)
           | Ok entries ->
             Printf.printf "%d exports:\n" (List.length entries);
             List.iter (Export_resolver.pp_entry Format.std_formatter) entries)
      end;
      `Ok ()
    | Ok (`Archive arch) ->
      Format.printf "%a\n" Archive.pp arch;
      let objs = Archive.object_members arch in
      Printf.printf "Object members: %d\n" (List.length objs);
      List.iter (fun (hdr, pf) ->
        Printf.printf "\n--- %s ---\n" hdr.Archive.name;
        Ocoff.dump_pe pf
      ) objs;
      `Ok ()
  in
  Cmd.v (Cmd.info "dump" ~doc)
    Term.(ret (const run $ path_arg $ format_flag $ sections_flag $
               symbols_flag $ imports_flag $ exports_flag))

let info_cmd =
  let doc = "Show high-level info about a PE/COFF file." in
  let path_arg =
    Arg.(required & pos 0 (some file) None & info [] ~docv:"FILE")
  in
  let run path =
    match Ocoff.load_file path with
    | Error e ->
      Printf.eprintf "Error: %s\n" (Error.to_string e);
      `Error (false, Error.to_string e)
    | Ok (`Pe pf) ->
      Printf.printf "Type:     PE image\n";
      Printf.printf "Machine:  0x%04x\n" pf.Pe_file.coff_header.Coff_header.machine;
      Printf.printf "Sections: %d\n" (List.length pf.Pe_file.sections);
      Printf.printf "Symbols:  %d\n" (List.length pf.Pe_file.symbol_table);
      `Ok ()
    | Ok (`Coff pf) ->
      Printf.printf "Type:     COFF object\n";
      Printf.printf "Machine:  0x%04x\n" pf.Pe_file.coff_header.Coff_header.machine;
      Printf.printf "Sections: %d\n" (List.length pf.Pe_file.sections);
      Printf.printf "Symbols:  %d\n" (List.length pf.Pe_file.symbol_table);
      `Ok ()
    | Ok (`Archive arch) ->
      Printf.printf "Type:     COFF archive (library)\n";
      Printf.printf "Members:  %d\n" (List.length (Archive.members arch));
      Printf.printf "Objects:  %d\n" (List.length (Archive.object_members arch));
      `Ok ()
  in
  Cmd.v (Cmd.info "info" ~doc)
    Term.(ret (const run $ path_arg))

let main_cmd =
  let doc = "Inspect and analyze PE/COFF binary files." in
  let info = Cmd.info "ocoffdump" ~version:"0.1.0" ~doc in
  Cmd.group info [dump_cmd; info_cmd]

let () = exit (Cmd.eval main_cmd)
