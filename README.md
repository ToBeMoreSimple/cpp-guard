# cpp-guard

Static analysis tool for C++ safety — catches memory leaks, null pointers, unsafe casts, and more.

```
$ cpp-guard scan

══ cpp-guard audit report ══
  Project: my-project

  ✗ [cpp-memory-leak] src/buggy.cpp:7 — `data` allocated with `new` but no matching `delete`
    → Use `std::unique_ptr` / `std::shared_ptr` to manage ownership.

  ⚠ [cpp-null-deref] src/buggy.cpp:49 — pointer `p` dereferenced without null check
    → Add `if (ptr != nullptr) { ... }` before dereferencing.

  ⚠ [cpp-empty-catch] src/buggy.cpp:30 — empty `catch(...)` silently swallows exceptions
    → At minimum, log the exception.

── Summary ──
  Files: 1  Functions: 9  Classes: 0
  4 errors  4 warnings  2 info  — 10 total
```

## 8 safety checks

| Check | Severity | Description |
|-------|----------|-------------|
| `cpp-memory-leak` | ✗ error | `new` without matching `delete` |
| `cpp-null-deref` | ⚠ warning | pointer deref without null check |
| `cpp-use-after-delete` | ⚠ warning | using pointer after `delete` |
| `cpp-cstyle-cast` | ⚠ warning | C-style cast — type-unsafe |
| `cpp-empty-catch` | ⚠ warning | empty catch block swallowing exceptions |
| `cpp-destructor-throw` | ✗ error | destructor throws — calls `std::terminate()` |
| `cpp-sensitive-print` | ⚠ warning | passwords/tokens/keys in debug output |
| `cpp-delete-check` | ℹ info | `delete` without `ptr = nullptr` |

## Quick start

```bash
cargo install --git https://github.com/ToBeMoreSimple/cpp-guard
cd your-cpp-project
cpp-guard scan
```

## MCP server mode

```bash
cpp-guard mcp
```

## Configuration

Create `.cppguard.toml` in your project root to customize behavior:

```toml
# Disable checks that don't apply to your project
disabled_checks = [
    "cpp-empty-catch",       # if using -fno-exceptions
    "cpp-destructor-throw",  # if using -fno-exceptions
]
```

Or pass on the command line:

```bash
cpp-guard scan --disable cpp-empty-catch,cpp-destructor-throw
```

## License

MIT
