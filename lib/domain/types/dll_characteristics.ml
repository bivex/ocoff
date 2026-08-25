(** DLL characteristics flags.
    Encodes the [DllCharacteristics] field of [IMAGE_OPTIONAL_HEADER]. *)

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

include Flag_set.Make(struct
  type nonrec flag = flag
  let flag_bits = flag_bits
  let flag_to_string = flag_to_string
end)
