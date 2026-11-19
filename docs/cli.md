# The `mortise` command line

`mortise run` starts a command with a project's secrets in its environment,
so they never sit in a `.env` file on disk and never need pasting into an
agent's chat.

```bash
cargo install --path crates/mortise-cli     # installs `mortise`

mortise run --project api --env dev -- npm run dev
```

The binary holds no keys and never opens the vault. It asks the running app
over a local socket, the app asks you, and the answer goes straight into the
command's environment. Mortise then *becomes* that command (`exec`), so exit
codes, signals, Ctrl-C and job control behave exactly as if you had run it
directly.

## Telling it what to load

**A whole environment:** `--project` / `--env`, or a `.mortise.toml` at the
top of the repository. The file only holds names, so it is safe to commit:

```toml
project = "api"
environment = "dev"
```

With that in place, `mortise run -- npm run dev` works from anywhere in the
repository. Flags override the file. Unknown keys in it are an error, so a
typo cannot quietly load a different environment.

**Specific variables:** a template, passed with `--env-file` (repeatable).
Values of the form `mortise://<project>/<environment>/<KEY>` come from the
vault; anything else is used as written:

```text
DATABASE_URL=mortise://api/dev/DATABASE_URL
STRIPE_KEY=mortise://payments/prod/STRIPE_SECRET_KEY
LOG_LEVEL=debug
```

Only the referenced keys are requested. Both forms can be combined; template
lines win over the whole environment, and later lines win over earlier ones.

**Precedence with your shell:** vault values replace variables already set,
unless you pass `--no-override`.

## Approval

The first request for a project/environment from a directory brings Mortise
to the front and asks:

- **Directory** and **Started by** (`mortise ← zsh ← claude`) come from the
  macOS kernel, not from the request, so they cannot be faked by the caller.
  If the first entry is not your `mortise` binary, something else is asking.
- **Says it will run** is the command line the caller reports. It is shown as
  a claim.

*Allow once* serves that request only. *Allow for 8 hours* also covers later
requests for the same project and environment from that directory tree — the
nearest parent holding `.mortise.toml` or `.git`, never your home directory or
`/`. Live grants are listed under **Settings → Command line**, where each can
be revoked. Grants are held in memory only: quitting Mortise ends them all.

If the vault is locked, the command waits (up to two minutes) while you
unlock. Unanswered approvals time out after two minutes as well.

## Agent sessions

A directory grant covers every process run from that directory. To give one
agent access — and nothing else on the machine — start it through Mortise:

```bash
mortise agent --project api --env dev -- claude
```

The app asks once ("Start an agent session…?"). If you approve, `mortise`
becomes the agent (`exec`, same pid), and the session is bound to that exact
process: its pid **and start time**, as the kernel reports them. From then
on, a `mortise run` is served without a prompt only if the agent is among its
kernel-reported ancestors — `mortise ← sh ← claude` is covered; a process in
the same directory that the agent did not start is not, and neither is a
later process that happens to get the same pid.

The session ends when the agent exits, after 8 hours, or when you revoke it
in Settings. Nothing is put in the agent's own environment: tell it to prefix
commands with `mortise run --` (for example in `CLAUDE.md`), so values reach
only the commands that need them and not the agent's context.

## Access log

Every decision — allowed, served by a grant or session, denied, timed out or
refused — is recorded under **Settings → Command line → Recent access**: when,
which project and environment, which keys (never values), the process chain
and the claimed command. The log is sealed in the vault like search metadata,
kept on this Mac only (never synced), and capped at the newest 1,000 entries.

## Failures

Nothing runs unless every requested value was delivered. A missing project,
environment or key, a denial, a timeout, or Mortise not running all stop
before the command starts, with exit status 1. Command-line mistakes exit 2;
a command that cannot be found exits 127, like a shell.

## Current limits

- Personal-vault projects only. Projects shared with a team live in separate
  vault files that normal project operations do not route to yet
  (see `product-readiness.md`, gap 1).
- A directory grant covers any process run from that directory, including
  one that changes into it first. Use an agent session, or *Allow once*,
  when that matters.
- Requests do not count as activity, so the normal idle auto-lock still
  applies; a long-lived agent will hit the unlock prompt after it.
- The child process can read its own environment. Injection keeps secrets
  out of files, chat logs and git — not away from the program you chose to
  give them to.
