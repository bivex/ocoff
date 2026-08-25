(** Windows subsystem identifiers.

    Encodes the [Subsystem] field of [IMAGE_OPTIONAL_HEADER] as defined in
    the PE/COFF specification.  The subsystem determines the runtime
    environment required to run the image. *)

(** All [IMAGE_SUBSYSTEM_*] constants from the specification. *)
type t =
  | Unknown                (** 0 – unknown subsystem *)
  | Native                 (** 1 – device drivers and native Windows processes *)
  | WindowsGui             (** 2 – Windows graphical user interface (GUI) *)
  | WindowsCui             (** 3 – Windows character-subsystem (console) *)
  | Os2Cui                 (** 5 – OS/2 character subsystem *)
  | PosixCui               (** 7 – POSIX character subsystem *)
  | NativeWindows          (** 8 – native Win9x driver *)
  | WindowsCeGui           (** 9 – Windows CE *)
  | EfiApplication         (** 10 – EFI application *)
  | EfiBootServiceDriver   (** 11 – EFI driver with boot-services *)
  | EfiRuntimeDriver       (** 12 – EFI driver with run-time services *)
  | EfiRom                 (** 13 – EFI ROM image *)
  | Xbox                   (** 14 – Xbox system *)
  | WindowsBootApplication (** 16 – Windows boot application *)
  | XboxCodeCatalog        (** 17 – Xbox code-catalog *)

(** [of_uint16 n] decodes the 16-bit subsystem integer [n].

    Returns [Error (`Unknown_subsystem n)] for values not recognised by
    this implementation. *)
let of_uint16 = function
  | 0  -> Ok Unknown
  | 1  -> Ok Native
  | 2  -> Ok WindowsGui
  | 3  -> Ok WindowsCui
  | 5  -> Ok Os2Cui
  | 7  -> Ok PosixCui
  | 8  -> Ok NativeWindows
  | 9  -> Ok WindowsCeGui
  | 10 -> Ok EfiApplication
  | 11 -> Ok EfiBootServiceDriver
  | 12 -> Ok EfiRuntimeDriver
  | 13 -> Ok EfiRom
  | 14 -> Ok Xbox
  | 16 -> Ok WindowsBootApplication
  | 17 -> Ok XboxCodeCatalog
  | n  -> Error (`Unknown_subsystem n)

(** [to_uint16 t] encodes subsystem [t] as its 16-bit wire value. *)
let to_uint16 = function
  | Unknown                -> 0
  | Native                 -> 1
  | WindowsGui             -> 2
  | WindowsCui             -> 3
  | Os2Cui                 -> 5
  | PosixCui               -> 7
  | NativeWindows          -> 8
  | WindowsCeGui           -> 9
  | EfiApplication         -> 10
  | EfiBootServiceDriver   -> 11
  | EfiRuntimeDriver       -> 12
  | EfiRom                 -> 13
  | Xbox                   -> 14
  | WindowsBootApplication -> 16
  | XboxCodeCatalog        -> 17

(** [to_string t] returns a human-readable label for subsystem [t]. *)
let to_string = function
  | Unknown                -> "Unknown"
  | Native                 -> "Native"
  | WindowsGui             -> "Windows GUI"
  | WindowsCui             -> "Windows CUI"
  | Os2Cui                 -> "OS/2 CUI"
  | PosixCui               -> "POSIX CUI"
  | NativeWindows          -> "Native Windows"
  | WindowsCeGui           -> "Windows CE GUI"
  | EfiApplication         -> "EFI Application"
  | EfiBootServiceDriver   -> "EFI Boot Service Driver"
  | EfiRuntimeDriver       -> "EFI Runtime Driver"
  | EfiRom                 -> "EFI ROM"
  | Xbox                   -> "Xbox"
  | WindowsBootApplication -> "Windows Boot Application"
  | XboxCodeCatalog        -> "Xbox Code Catalog"

(** [pp fmt t] pretty-prints subsystem [t] to formatter [fmt]. *)
let pp fmt t = Format.pp_print_string fmt (to_string t)
