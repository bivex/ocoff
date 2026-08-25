(** Filesystem adapter: reads and writes files to disk. *)

let read_file path =
  match open_in_bin path with
  | exception Sys_error msg ->
    if String.length msg > 0 then
      Error (`File_not_found path)
    else
      Error (`Io_error msg)
  | ic ->
    let len = in_channel_length ic in
    let buf = Bytes.create len in
    (try
      really_input ic buf 0 len;
      close_in ic;
      Ok buf
    with exn ->
      close_in_noerr ic;
      Error (`Io_error (Printexc.to_string exn)))

let write_file path data =
  match open_out_bin path with
  | exception Sys_error msg -> Error (`Io_error msg)
  | oc ->
    (try
      output_bytes oc data;
      close_out oc;
      Ok ()
    with exn ->
      close_out_noerr oc;
      Error (`Io_error (Printexc.to_string exn)))
