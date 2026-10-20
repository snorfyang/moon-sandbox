;; A real WASI Preview 1 file reader. No host file-reading function is injected.
;; The trusted host writes a UTF-8 path at 1024 and calls run(pointer, length).
;; fd 3 is the only preopen; output lives at 4096 and its length at address 8.
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read"
    (func $read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_close"
    (func $close (param i32) (result i32)))
  (memory (export "memory") 2 2)
  (func (export "run") (param $path i32) (param $len i32) (result i32)
    (local $errno i32) (local $fd i32) (local $total i32) (local $count i32)
    ;; lookupflags=1 follows symlinks; WASI must still contain resolution.
    ;; rights_base=2 is FD_READ; no writes, creates, or inherited rights.
    (local.set $errno (call $open
      (i32.const 3) (i32.const 1) (local.get $path) (local.get $len)
      (i32.const 0) (i64.const 2) (i64.const 0) (i32.const 0) (i32.const 0)))
    (if (local.get $errno) (then (return (local.get $errno))))
    (local.set $fd (i32.load (i32.const 0)))
    ;; Read until EOF or the bounded buffer is full. A full buffer exceeds the
    ;; backend's maximum grant (65535), so it is an error rather than truncation.
    (block $done (loop $next
      (i32.store (i32.const 16) (i32.add (i32.const 4096) (local.get $total)))
      (i32.store (i32.const 20) (i32.sub (i32.const 65536) (local.get $total)))
      (local.set $errno (call $read (local.get $fd) (i32.const 16) (i32.const 1) (i32.const 24)))
      (br_if $done (local.get $errno))
      (local.set $count (i32.load (i32.const 24)))
      (br_if $done (i32.eqz (local.get $count)))
      (local.set $total (i32.add (local.get $total) (local.get $count)))
      (br_if $done (i32.eq (local.get $total) (i32.const 65536)))
      (br $next)))
    (i32.store (i32.const 8) (local.get $total))
    (drop (call $close (local.get $fd)))
    (local.get $errno)))
