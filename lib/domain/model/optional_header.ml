(** PE optional header (IMAGE_OPTIONAL_HEADER).

    Present in image files (.exe, .dll); optional (absent) in COFF object
    files.  Two variants exist:

    - {b PE32} (magic 0x10b): 32-bit image, [image_base] is 32-bit.
    - {b PE32+} (magic 0x20b): 64-bit image, [image_base] is 64-bit,
      [base_of_data] is absent.

    The header is immediately followed by an array of
    {!Data_directory.t} entries whose count is given by
    [windows_fields.number_of_rva_and_sizes]. *)

(** Distinguishes between the two supported PE image formats. *)
type pe_format =
  | Pe32     (** 32-bit image, magic 0x10b *)
  | Pe32plus (** 64-bit image, magic 0x20b *)

(** Decode a [pe_format] from the 2-byte magic field.

    Returns [None] for any value that is neither 0x10b nor 0x20b. *)
let pe_format_of_magic = function
  | 0x10b -> Some Pe32
  | 0x20b -> Some Pe32plus
  | _     -> None

(** Fields common to both PE32 and PE32+ (the "standard fields" block). *)
type standard_fields = {
  magic: int;
  (** Raw magic value: 0x10b for PE32, 0x20b for PE32+. *)
  major_linker_version: int;
  (** Major version number of the linker that produced this image. *)
  minor_linker_version: int;
  (** Minor version number of the linker. *)
  size_of_code: int32;
  (** Sum of all code (text) section sizes or the size of the largest
      code section, rounded to [file_alignment]. *)
  size_of_initialized_data: int32;
  (** Sum of all initialised-data section sizes, rounded to [file_alignment]. *)
  size_of_uninitialized_data: int32;
  (** Sum of all uninitialised-data (BSS) section sizes. *)
  address_of_entry_point: int32;
  (** RVA of the entry-point function, or 0 for DLLs with no entry point. *)
  base_of_code: int32;
  (** RVA of the start of the code section. *)
  base_of_data: int32 option;
  (** RVA of the start of the data section.  Present only in PE32;
      absent ([None]) in PE32+. *)
}

(** Windows-specific fields that follow the standard fields block. *)
type windows_fields = {
  image_base: int64;
  (** Preferred load address of the first byte of the image.
      4 bytes in PE32 (stored as uint32, widened here); 8 bytes in PE32+. *)
  section_alignment: int32;
  (** Alignment of sections in memory (bytes); must be >= [file_alignment].
      Typically 0x1000 (4 KiB). *)
  file_alignment: int32;
  (** Alignment of raw section data in the file (bytes).
      Must be a power of two between 512 and 64 KiB.  Typically 0x200. *)
  major_os_version: int;
  (** Major version of the required operating system. *)
  minor_os_version: int;
  (** Minor version of the required operating system. *)
  major_image_version: int;
  (** Major version of the image. *)
  minor_image_version: int;
  (** Minor version of the image. *)
  major_subsystem_version: int;
  (** Major version of the subsystem (e.g. 6 for Vista+). *)
  minor_subsystem_version: int;
  (** Minor version of the subsystem. *)
  win32_version_value: int32;
  (** Reserved; must be zero. *)
  size_of_image: int32;
  (** Total size of the image in memory, including headers, rounded to
      [section_alignment]. *)
  size_of_headers: int32;
  (** Combined size of the MS-DOS stub, PE signature, COFF header, optional
      header, and section table, rounded up to [file_alignment]. *)
  checksum: int32;
  (** Image checksum.  Validated for drivers and certain system DLLs. *)
  subsystem: int;
  (** Required execution subsystem (raw uint16).  See IMAGE_SUBSYSTEM_* constants. *)
  dll_characteristics: int;
  (** Bit flags describing DLL attributes (raw uint16).  See IMAGE_DLLCHARACTERISTICS_* constants. *)
  size_of_stack_reserve: int64;
  (** Amount of virtual-address space reserved for the initial thread stack.
      4 bytes in PE32; 8 bytes in PE32+. *)
  size_of_stack_commit: int64;
  (** Amount of virtual-address space initially committed for the stack.
      4 bytes in PE32; 8 bytes in PE32+. *)
  size_of_heap_reserve: int64;
  (** Amount of virtual-address space reserved for the default process heap.
      4 bytes in PE32; 8 bytes in PE32+. *)
  size_of_heap_commit: int64;
  (** Amount of virtual-address space initially committed for the heap.
      4 bytes in PE32; 8 bytes in PE32+. *)
  loader_flags: int32;
  (** Reserved; must be zero. *)
  number_of_rva_and_sizes: int32;
  (** Number of data-directory entries that follow this header.
      The PE spec defines 16 entries; earlier images may have fewer. *)
}

(** The complete optional header, combining format, standard fields,
    Windows-specific fields, and the data directory array. *)
type t = {
  format: pe_format;
  (** Whether this is a PE32 or PE32+ image. *)
  standard: standard_fields;
  (** Standard fields block. *)
  windows: windows_fields;
  (** Windows-specific fields block. *)
  data_directories: Data_directory.t array;
  (** Array of data directory entries, indexed by {!Data_directory.kind_of_index}.
      Length equals [windows.number_of_rva_and_sizes], capped at 16. *)
}

(** Construct an optional header record. *)
let make ~format ~standard ~windows ~data_directories =
  { format; standard; windows; data_directories }

let format t = t.format
let standard t = t.standard
let windows t = t.windows
let data_directories t = t.data_directories

(** Return [true] for a 64-bit (PE32+) image. *)
let is_64bit t = match t.format with Pe32plus -> true | Pe32 -> false

(** Look up a data directory entry by kind.  Returns [None] when the
    directory array does not contain an entry for the requested index. *)
let data_directory t kind =
  let idx = match kind with
    | Data_directory.ExportTable           -> 0
    | Data_directory.ImportTable           -> 1
    | Data_directory.ResourceTable         -> 2
    | Data_directory.ExceptionTable        -> 3
    | Data_directory.CertificateTable      -> 4
    | Data_directory.BaseRelocationTable   -> 5
    | Data_directory.Debug                 -> 6
    | Data_directory.Architecture          -> 7
    | Data_directory.GlobalPtr             -> 8
    | Data_directory.TlsTable              -> 9
    | Data_directory.LoadConfigTable       -> 10
    | Data_directory.BoundImport           -> 11
    | Data_directory.Iat                   -> 12
    | Data_directory.DelayImportDescriptor -> 13
    | Data_directory.ClrRuntimeHeader      -> 14
    | Data_directory.Reserved              -> 15
  in
  if idx < Array.length t.data_directories then
    Some t.data_directories.(idx)
  else
    None

let pp_format fmt = function
  | Pe32     -> Format.pp_print_string fmt "PE32"
  | Pe32plus -> Format.pp_print_string fmt "PE32+"

let pp fmt t =
  Format.fprintf fmt
    "<Optional header: %a base=0x%Lx entry=0x%lx sections_align=0x%lx dirs=%d>"
    pp_format t.format
    t.windows.image_base
    t.standard.address_of_entry_point
    t.windows.section_alignment
    (Array.length t.data_directories)
