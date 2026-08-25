(** Ocoff — PE/COFF library public API facade.

    A pure OCaml library for parsing, inspecting, and serializing
    Microsoft Portable Executable (PE) and Common Object File Format (COFF)
    binary files. Built with DDD + Hexagonal Architecture. *)

(** Domain types *)
module Error = Error
module Machine_type = Machine_type
module Characteristics = Characteristics
module Subsystem = Subsystem
module Dll_characteristics = Dll_characteristics
module Section_flags = Section_flags
module Relocation_type = Relocation_type
module Storage_class = Storage_class
module Section_number = Section_number

(** Domain model *)
module Dos_stub = Dos_stub
module Data_directory = Data_directory
module Coff_header = Coff_header
module Optional_header = Optional_header
module Section_header = Section_header
module Coff_relocation = Coff_relocation
module Symbol_name = Symbol_name
module Coff_symbol = Coff_symbol
module Pe_file = Pe_file
module Archive = Archive

(** Adapters *)
module Binary_reader = Binary_reader
module Binary_writer = Binary_writer
module File_io = File_io
module Pe_printer = Pe_printer

(** Application services *)
module Pe_parser = Pe_parser
module Pe_serializer = Pe_serializer

(** Domain services *)
module Export_resolver = Export_resolver
module Import_resolver = Import_resolver
module Checksum = Checksum

(** High-level convenience API *)

(** Parse any PE/COFF file from a file path. *)
let load_file path =
  match File_io.read_file path with
  | Error (`File_not_found p) ->
    Error (Error.Unsupported_format (Printf.sprintf "File not found: %s" p))
  | Error (`Io_error msg) ->
    Error (Error.Unsupported_format (Printf.sprintf "I/O error: %s" msg))
  | Ok buf ->
    Pe_parser.parse_any buf

(** Parse PE image file from bytes. *)
let parse_pe = Pe_parser.parse_pe_file

(** Parse COFF object from bytes. *)
let parse_coff = Pe_parser.parse_coff_object

(** Parse COFF archive from bytes. *)
let parse_archive = Pe_parser.parse_archive

(** Pretty-print a PE file to stdout. *)
let dump_pe pf =
  Pe_printer.pp_pe_file Format.std_formatter pf
