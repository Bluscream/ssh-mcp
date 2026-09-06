# ssh-mcp

SSH command execution, SFTP transfer and host telemetry, as an MCP server.

```bash
ssh-mcp --config ssh-mcp.toml                    # execute only
ssh-mcp --config ssh-mcp.toml --allow-download \
        --root /home/you/downloads               # transfers enabled
ssh-mcp --config ssh-mcp.toml --strict-host-keys # no trust-on-first-use
```

## Tools

| Tool | Does |
| --- | --- |
| `ssh_execute` | Runs a command on a configured server, returning stdout, stderr and exit code. |
| `ssh_transfer` | Uploads or downloads over SFTP, with globs, recursion and multiple paths. |
| `ssh_list_servers` | Lists configured servers with connection state and telemetry. Never dials out. |

## Host keys

A fingerprint mismatch means either a legitimate key rotation or an active
man-in-the-middle, and telling them apart needs knowledge a language model does
not have. So:

- Overriding a **mismatched** key requires `--allow-host-key-override`, off by
  default. Without it the `save_new_fingerprint` argument is not even
  advertised, so the model is not invited to retry with it.
- Recording a **previously unseen** key follows OpenSSH's
  `StrictHostKeyChecking=accept-new` and is on by default; `--strict-host-keys`
  turns it off.
- A key accepted during a run is remembered for that process, so one approval is
  not demanded again on every later call.
- Fingerprints are normalised, so one written without the `SHA256:` prefix is
  not read as a mismatch — which would be indistinguishable from an attack.

## Command filtering

Per-server `whitelist` and `blacklist` regexes. The blacklist applies even to
whitelisted commands. Patterns are compiled when the config loads, so an
unparseable pattern is a startup error rather than a rule that silently never
matches — a blacklist that fails open is worse than none.

## Safety

- Downloads are refused unless `--allow-download`; local paths are confined to
  `--root`.
- Command output is capped at 256 KiB per stream, with truncation reported.
- Profiles with neither a key nor a password are rejected at load.
- HTTP requires a bearer token unless `--allow-unauthenticated`.

## Configuration

See [`ssh-mcp.example.toml`](ssh-mcp.example.toml). Credentials belong in the
environment via `${VAR}`, never in the file.

## Development

```bash
./scripts/build.sh --release
```

## License

[Unlicense](LICENSE) (public domain).
