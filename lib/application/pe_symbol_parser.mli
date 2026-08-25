(** COFF Symbol and String Table parser application component. *)

val parse_symbol_table :
  Binary_reader.t ->
  int32 ->
  int ->
  (Coff_symbol.t list, Error.t) result

val parse_string_table :
  Binary_reader.t ->
  int32 ->
  int ->
  (string, Error.t) result
