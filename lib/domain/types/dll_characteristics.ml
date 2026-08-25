(** DLL characteristics flags.

    Encodes the [DllCharacteristics] field of [IMAGE_OPTIONAL_HEADER] as
    defined in the PE/COFF specification.  Each bit enables or documents a
    specific loader or security feature. *)

(** A single DLL-characteristics flag bit. *)
type flag =
  | HighEntropyVa      (** 0x0020 – ASLR with 64-bit address space *)
  | DynamicBase        (** 0x0040 – DLL can be relocated at load time *)
  | ForceIntegrity     (** 0x0080 – code-integrity checks enforced *)
  | NxCompat           (** 0x0100 – image is NX-compatible *)
  | NoIsolation        (** 0x0200 – isolation-aware but do not isolate *)
  | NoSeh              (** 0x0400 – no structured exception handling *)
  | NoBind             (** 0x0800 – do not bind the image *)
  | AppContainer       (** 0x1000 – must execute in an AppContainer *)
  | WdmDriver          (** 0x2000 – WDM driver *)
  | GuardCf            (** 0x4000 – Control Flow Guard enabled *)
  | TerminalServerAware(** 0x8000 – terminal-server aware *)

(** A set of DLL-characteristics flags, represented as a list of all
    flags whose corresponding bit is set. *)
type t = flag list

(** Association between each flag and its bit mask. *)
let flag_bits : (flag * int) list = [
  (HighEntropyVa,       0x0020);
  (DynamicBase,         0x0040);
  (ForceIntegrity,      0x0080);
  (NxCompat,            0x0100);
  (NoIsolation,         0x0200);
  (NoSeh,               0x0400);
  (NoBind,              0x0800);
  (AppContainer,        0x1000);
  (WdmDriver,           0x2000);
  (GuardCf,             0x4000);
  (TerminalServerAware, 0x8000);
]

(** [of_uint16 n] decodes the 16-bit integer [n] from the optional header
    into the list of set [flag] values. *)
let of_uint16 n =
  List.filter_map
    (fun (flag, bit) -> if n land bit <> 0 then Some flag else None)
    flag_bits

(** [to_uint16 flags] encodes the flag list [flags] back to a 16-bit
    integer suitable for writing to the optional header. *)
let to_uint16 flags =
  List.fold_left
    (fun acc flag ->
       match List.assoc_opt flag flag_bits with
       | Some bit -> acc lor bit
       | None -> acc)
    0
    flags

(** [has t flag] is [true] iff [flag] is present in the flag set [t]. *)
let has t flag = List.mem flag t

let flag_to_string = function
  | HighEntropyVa       -> "HIGH_ENTROPY_VA"
  | DynamicBase         -> "DYNAMIC_BASE"
  | ForceIntegrity      -> "FORCE_INTEGRITY"
  | NxCompat            -> "NX_COMPAT"
  | NoIsolation         -> "NO_ISOLATION"
  | NoSeh               -> "NO_SEH"
  | NoBind              -> "NO_BIND"
  | AppContainer        -> "APPCONTAINER"
  | WdmDriver           -> "WDM_DRIVER"
  | GuardCf             -> "GUARD_CF"
  | TerminalServerAware -> "TERMINAL_SERVER_AWARE"

(** [pp fmt t] pretty-prints the flag set [t] to formatter [fmt] as a
    pipe-separated list of flag names. *)
let pp fmt flags =
  match flags with
  | [] -> Format.pp_print_string fmt "(none)"
  | _ ->
    let strs = List.map flag_to_string flags in
    Format.pp_print_string fmt (String.concat " | " strs)
