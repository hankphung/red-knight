# red-knight

A local, offline filter that sits between your files and a coding agent. It
intercepts file reads and command output, classifies and redacts images, and
refuses files and output that match a keyword denylist.

Nothing it does touches the network. Classification and OCR run on your own
machine, today through Apple's Vision framework.

It currently binds to **Claude Code on macOS** -- that is where it is built and
tested, not where the idea stops. See [Scope today](#scope-today).

It exists for two concrete cases:

- **personal images at home** — you point Claude at a directory and a photo of
  your family, or your passport, or a screenshot with a half-visible message
  thread, goes out with it.
- **secret text, at home and at work** — an `.env` file, a credentials dump, a
  document marked confidential, a production screenshot with a token in the
  header.

## Scope today

Runs on **macOS 12+** with **Claude Code**. Both are current bindings rather than
design limits: the vision work sits behind a small JSON contract that a different
backend can satisfy, and the harness only has to offer hooks that can rewrite a
tool call's input and output. See [Expanding it](#expanding-it) for what that
would take on other systems, and [docs/PORTING.md](docs/PORTING.md) for measured
evidence on Linux.

## This is the last line of defence, not the first

The work that actually keeps data out of a model happens before this tool is
involved. If you install this and change nothing else, you have not improved
your situation very much.

**Where the real protection comes from:**

- **Don't paste production screenshots, and don't drag in personal photos.**
  Pasted and drag-dropped images never reach this filter at all -- they are not a
  tool call, so no hook runs on them. For personal images this is the likeliest
  route of all, which makes the habit not a supporting control here but the only
  one. See "What still gets through".
- **Keep secrets out of the working tree.** A secret manager, your keychain, or
  environment variables injected at run time. A `.env` the assistant can't read
  because it isn't there is the only `.env` that is reliably safe.
- **Scope what the assistant can read.** Run it in the project directory, not in
  `$HOME`. Use permission rules to deny paths you never want touched. Don't
  point it at a personal photo library, a Downloads folder, or a mounted share.
- **Use a sandbox for anything you don't trust.** A container with only the
  project mounted bounds the blast radius in a way a content filter cannot.
- **Read before you send.** Look at the screenshot you are about to attach.
  Check what a command printed before you let it into the context.
- **Know your telemetry settings.** If your organisation has OpenTelemetry or
  analytics export enabled, tool output is captured before hooks run.

This tool is the backstop for the times you do all that and slip anyway —
because you are tired, or in a hurry, or because the token was in the part of
the screenshot you weren't looking at. That is a real category of accident and
it is worth catching. It is also the only category it catches.

**Passing the filter does not mean the content is safe.** It means nothing the
filter knows how to recognise was found. The section on
[what still gets through](#what-still-gets-through) is not a disclaimer at the
bottom — it is the part that determines whether this is useful to you or
actively dangerous, because a backstop you lean on is dangerous precisely
because you lean on it.

This is not a security boundary. It raises the cost of an accident. It does
nothing against anyone trying to get data out on purpose.

## What it catches

Two hooks, both configured in `~/.claude/settings.json`:

| hook | covers | behaviour |
| --- | --- | --- |
| `PreToolUse` on `Read` | every file read through the `Read` tool | images are classified and redacted; other files are keyword-scanned and refused on a hit |
| `PostToolUse` on `Bash` | what a Bash command printed | keyword-scanned; the whole output is replaced on a hit |

### Images

```
image
|- path is not an image / not a Read  -> pass through, no decision
|- classify
|   |- screenshot : synthetic render carrying >=5 words of interface text
|   |- board      : confident document quad over 25-98% of the frame, bright,
|   |               with writing -- cropped and perspective-rectified, so
|   |               everything off-board is gone by construction
|   |- other      -> DENY
|- human gate
|   |- board      : any face/human box, or person-mask coverage >0.4% -> DENY
|   |- screenshot : coverage >12% -> DENY (an embedded photo);
|   |               otherwise face box, human box AND the person mask's
|   |               bounding box are painted, each grown by 12%
|- keyword denylist -> DENY (checked before anything is redacted)
|- redact secrets and PII found in OCR text
|- re-encode to cache/ (drops EXIF) and rewrite the Read path to it
```

Any exception at any stage denies the read. That is why the Read hook is
installed with `onFailure: "block"`: a hook that fails open is worse than no
hook, because you stop checking.

**Why the classifier demands positive evidence.** Apple's person segmentation
false-positives badly on smooth abstract gradients — measured up to 0.72
coverage on a plain wallpaper with no person in it. So the filter never asks
"is there a human here"; it asks "is this one of the two things I allow", and
anything it cannot positively identify is denied. It is also why `screenshot`
requires real interface text: without that requirement, gradient wallpapers
landed in the lenient branch.

The board branch is *tried* first but falls through rather than disqualifying:
an embedded photo inside an ordinary screenshot also reads as a "surface", and
such a screenshot must still reach the screenshot branch so its human gate
applies.

Painting uses three regions per person — the face box, the human box, and the
**person mask's bounding box** — because a detector box clips limbs and hair,
which left visible slivers of the original photo in testing.

The board crop is the strongest property here, because it is geometric rather
than statistical: whatever was outside the board quad is discarded, so people
standing around a whiteboard are removed without ever being detected.

### Text files

Checked against the keyword denylist and refused outright on a match. Nothing is
rewritten — a text file is clean or it is refused.

Matching is a whitespace-normalised, case-insensitive substring pass (plus any
`re:` entries), so a term broken across a newline still matches. The
damage-tolerant passes used for images are deliberately *not* applied here: they
exist to undo OCR errors, and on real source text they would only misfire.

### Bash output

`bashguard` applies the same denylist to what a command printed, and replaces
the output via `updatedToolOutput` when a term appears, so the content never
reaches the model.

It deliberately does **not** parse the command to work out which files it reads.
That is undecidable once pipes, globs, `xargs`, `find -exec`, `eval` or `sh -c`
are in play, and a parser that guesses is a parser that fails open. Checking the
output instead is reader-independent: `cat`, `head`, `grep`, `awk` and
`python3 -c "print(open(...).read())"` are all caught by one rule that knows
nothing about any of them.

The command has already run by the time this fires. That is acceptable here
because what is being prevented is *disclosure*, not a side effect — nothing
leaves the machine until the output reaches the model. It would not be
acceptable for a rule meant to stop a destructive command; that needs
`PreToolUse`.

The whole output is replaced, never just the matching lines, because a document
marked CONFIDENTIAL in its header would otherwise have the marking stripped and
the body sent.

## What still gets through

Read this list as the specification of what the tool is, not as fine print.

- **Pasted and drag-dropped images bypass it entirely.** They never become a
  tool call, so no hook sees them -- not the image filter, not the keyword
  denylist, nothing. Be blunt with yourself about what that means. If your
  concern is personal photos, dragging one into the prompt is almost certainly
  how it would actually happen, and that is precisely the path this tool cannot
  see. It guards the quieter door. For images you hand over yourself, the
  protection is your own habit and nothing in this repository changes that.

  This is not a defect to be fixed in a later version; it is a consequence of
  where the filter sits. Hooks run on tool calls, and a pasted image is not one.
  Covering it would mean filtering at capture time instead -- a different tool,
  wrapping whatever takes the screenshot.
- **A document that is sensitive *as a whole* is redacted, not rejected.** This
  is the sharpest gap in the design. The patterns look for token-shaped things:
  key prefixes, email structure, Luhn-valid digits. A payslip, bank statement or
  identity document contains almost none of that -- a salary figure is just a
  number, a home address matches nothing, a national insurance number with
  spaces in it misses the IBAN pattern. Such a file can pass with **nothing**
  redacted and a confident allow, which is worse than a denial because it looks
  handled. The keyword denylist is the only defence today, and it fires only on
  words you thought to list. Deciding reject-versus-redact from a document's
  *composition* rather than from individual pattern matches is not implemented.
- **Binary files are not keyword-scanned.** Detection is a NUL byte in the first
  8 KB; a term inside a PDF, a zip, an Office document or a compiled artefact is
  not caught.
- **Transformed output escapes the Bash guard.** base64 is decoded before
  matching, but hex (`xxd`), compression, encryption, chunking across several
  commands and any bespoke encoding all defeat it.
- **Telemetry sees the original.** Claude Code records tool output for
  OpenTelemetry/analytics *before* hooks run. If that is enabled in your
  environment, the raw output is captured regardless of what the hook decides.
- **False negatives are certain.** OCR misses rotated, low-contrast and very
  small text. Face detection is near its floor at ~24px avatars. Secret patterns
  are heuristics. No rule set is complete, and a term that is not in
  `keywords.txt` is not a term this tool knows about.
- **Only `Read` and Bash output are covered.** Grep results, MCP tools that
  return file contents, and anything else that surfaces data by another route
  are untouched.
- **A combined command loses everything.** One term anywhere in the output
  blocks all of it, including the unrelated parts. Run unrelated things
  separately.
- **Commands and files under the install directory are skipped**, or inspecting
  the filter's own files would self-trip.
- **A synthetic diagram with no text at all is denied** — no positive evidence.
  This is a false positive you will hit.
- **A bright synthetic screenshot whose embedded image forms a strong quad** can
  be classed as a board and cropped to that region, losing UI context. Safe, but
  surprising; `board_min_quad_conf` is the knob.

## Choosing what runs

The two cases this covers -- photographs at home, credentials at work -- do not
overlap much, and you may want only one of them. Each check is independent.

| | class gate | people | secrets | keywords (images) | keywords (files) |
| --- | --- | --- | --- | --- | --- |
| `strict` (default) | on | on | on | on | on |
| `secrets` | -- | -- | on | on | on |
| `images` | on | on | -- | -- | -- |
| `off` | -- | -- | -- | -- | -- |

Pick one at install time, or change `profile` in `config.json` afterwards:

```sh
./install.sh --profile secrets          # or strict | images | off
./install.sh --no-bash-hook             # skip output scanning, saves ~14ms/call
```

Be clear about what each one gives up, because turning a check off is consent,
not a failure, and nothing will warn you later:

- **`secrets`** does not gate images at all. A photograph -- of a person, of
  anything -- passes straight through. Choose it if your concern is a leaked
  token, not a leaked picture.
- **`images`** does not scan text. An API key in a screenshot is sent in full,
  and the keyword denylist does not apply to files or command output either.
- **`off`** is for disabling without uninstalling. It is not a safe default.

Individual checks override the profile, so you can take a profile and add one
thing back:

```json
{ "profile": "secrets", "features": { "image_humans": true } }
```

The Bash hook is separate from all of this: it is a hook installed or not at
install time, since an uninstalled hook costs nothing while a disabled one still
spawns a process on every command.

## Install

Requires macOS 12 (Monterey) or newer, the Xcode command line tools (for
`swiftc`), Python 3, and Pillow.

```sh
git clone <this repo> claude-local-filter
cd claude-local-filter
./install.sh
```

The installer checks the prerequisites, compiles `visionscan` and `bashguard`
from their Swift sources, copies everything into `~/.claude/local-filter`, and
**merges** the two hooks into `~/.claude/settings.json` — your other settings
and other hooks are left alone, and the previous file is backed up alongside it
first. It prints what it changed.

It is idempotent: re-running updates the code and the hook entries in place, and
never overwrites your `config.json` or `keywords.txt`.

```sh
INSTALL_DIR=~/somewhere/else ./install.sh   # different location
FILTER_PYTHON=/opt/homebrew/bin/python3 ./install.sh   # pick the interpreter
```

Restart Claude Code afterwards — hooks are read at startup.

Then **edit `~/.claude/local-filter/keywords.txt`**. It ships with four generic
markings as placeholders. A denylist with nobody's actual project names in it
catches very little.

### Uninstall

```sh
./uninstall.sh            # remove the hooks; leave the files and your keywords
./uninstall.sh --purge    # remove the hooks and delete the install directory
```

It removes only hook entries that point at the install directory, backs up
`settings.json` first, and leaves everything else in it untouched.

## Overriding a denial

When the filter denies an image you actually need to send:

```sh
~/.claude/local-filter/allow-image <path> [--raw] [--show] [--yes]
```

It prints what Vision found, why the filter denied it, and what approving will
do, then asks you to confirm. That prompt is the point — an override you can
take without looking is the same as no filter.

```
--show   open it in Preview first
--raw    send it untouched; by default secrets in its text are still painted
--yes    skip the confirmation (for scripts; defeats the purpose)
```

The approval:

- is keyed by the file's **content** hash, so editing the file drops it
- is **consumed by the first read** that uses it
- **expires** after `override_ttl_seconds` (15 min); expired tokens are swept on
  the next run
- never skips re-encoding, because approving what you can see in an image is not
  approving its EXIF, which can carry GPS

Pending approvals live in `overrides/`. Delete the directory's contents to
revoke everything at once.

`allow-image` refuses a keyword hit and exits 2. Set `keywords_block_override`
to `false` in `config.json` if you want approvals to beat the denylist.

## The keyword denylist

`keywords.txt` holds terms that deny a file outright — no redaction, and by
default no override. It is checked against the text of both the source and what
would actually be sent, plus the filename.

```
confidential
do not distribute
re:\bACME-\d{4}\b
```

One entry per line; blank lines and `#` comments ignored; `re:` prefixes a
case-insensitive regular expression.

For an **image**, matching runs three passes, because OCR damage is the normal
case rather than the exception:

1. case-insensitive substring
2. the same with all spaces and punctuation removed, so `CONF IDENTIAL` hits
   (needs 4+ characters)
3. the same with OCR-confusable characters folded together, so `C0NFIDENTIAL`
   and `conf1dentia|` hit (needs 6+ characters)

Each confusable class collapses to one character rather than picking a
representative — `1` can be OCR for either `l` or `i`, so all three must meet.

**The matched term never reaches Claude.** The deny reason cites the line number
in `keywords.txt` and nothing else, because that reason goes into the
transcript, which would leak the very word you are blocking. The term is written
to `log.jsonl` on your disk, and `allow-image` prints it in your own terminal.

Other scanning details:

- files under the install directory are skipped, or reading `keywords.txt` would
  match every term in it
- binary files are skipped (NUL byte in the first 8 KB)
- files over `text_scan_max_bytes` (64 MB) are **denied**, not half-scanned —
  scanning part of a file and passing it would be fail-open
- throughput is roughly 70 MB/s

## Configuration

Edit `config.json` in the install directory. Defaults live in `DEFAULTS` in
`imgfilter.py`; anything you set overrides them. The likely first edits:

| key | effect |
| --- | --- |
| `min_words_screenshot` | raise if photos sneak into the screenshot class, lower if sparse UI screenshots get denied |
| `screenshot_redact_humans` | `false` denies screenshots containing avatars instead of painting over them |
| `redact_emails` | `false` if addresses in screenshots are not a concern |
| `board_min_quad_conf` / `board_min_quad_area` | if whiteboard photos are being denied, check `quad_conf` and `quad_area` in `log.jsonl` first |
| `keywords_block_override` | `false` lets `allow-image` approve past a keyword hit |
| `override_ttl_seconds` | how long an unused approval stays valid |

## Performance

| case | cost |
| --- | --- |
| screenshot, warm | ~0.4 s |
| board photo, warm | ~0.9 s |
| 6016px image | ~2.9 s |
| first image read after a reboot | one-time ~20 s Vision model load |
| ordinary non-image read | ~60 ms |
| every Bash call | ~14 ms (process spawn alone is ~11 ms) |

Measured on an Apple Silicon Mac; yours will differ.

### Why the Bash guard is Swift

It runs on every Bash call, where Python's interpreter floor (~36 ms) dominated
the ~52 ms total. Swift starts in ~13 ms against a ~11 ms process-spawn floor.

Getting there needed two fixes that profiling found and guesswork did not:

- the base64 scan ran `NSRegularExpression` over the whole output (20 ms on
  190 KB). A byte pre-scan for a 32+ character run now skips the regex entirely
  unless one exists.
- literal matching used Swift `String.contains`, which is grapheme-aware and
  cost 24 ms on 190 KB. Matching now happens on UTF-8 bytes via
  `Data.range(of:)`, and the output is bridged to a `String` only if a `re:`
  rule needs it.

190 KB of output went from 58 ms to 16 ms on those two alone.

Two implementations of one rule is a drift hazard, so `bashfilter.py` stays as
the reference implementation and `parity-test` asserts the two agree on 25 cases
(including the line numbers each cites). Run it after touching either, or after
editing `keywords.txt`.

## Files

```
src/visionscan.swift     Apple Vision: OCR word boxes, faces, humans, person
                         segmentation, document quad
src/imgfilter.py         classification, policy, redaction, hook I/O
src/allow-image          approve one image, once, past the filter
src/bashguard.swift      PostToolUse: keyword check on Bash output
src/bashfilter.py        the same logic in Python: reference impl, not wired in
src/parity-test          asserts bashguard == bashfilter.py
src/config.json          tunable thresholds
src/keywords.txt         example denylist -- replace with your own
install.sh / uninstall.sh
docs/PORTING.md          measured analysis of a Linux/Windows port
```

Created in the install directory at run time, and never committed:

```
cache/        redacted copies; safe to delete any time
overrides/    pending approvals (one JSON per content hash)
log.jsonl     what was redacted -- entity types, counts and matched terms
visionscan    compiled by the installer
bashguard     compiled by the installer
```

`log.jsonl` records the file paths it saw and the keyword terms that matched. It
stays on your disk; don't copy it anywhere.

Rebuild a helper after editing its Swift:

```sh
swiftc -O -o visionscan visionscan.swift
swiftc -O -o bashguard bashguard.swift && ./parity-test
```

## Expanding it

Nothing here is fundamentally macOS- or Claude-specific. Two axes, with different
amounts of work.

### Other harnesses

The filter needs two things from a harness: a hook before a tool call that can
**rewrite its input** (to swap in the redacted copy), and one after a command
that can **replace its output**. Blocking alone is not enough -- a block-only
hook would have to *deny* an image where this one redacts it, which is a much
worse tool to live with.

| harness | tool-call hooks | can rewrite input/output |
| --- | --- | --- |
| Claude Code | `PreToolUse` / `PostToolUse` | yes -- what this uses |
| Codex | config-file hooks, modelled on Claude Code's | yes; hosted tools are a blind spot |
| OpenCode | in-process TS/JS plugins, `tool.execute.before`/`after` | yes |
| Aider, Goose | none documented | -- |

Rewriting is the uncommon capability. Most agents can stop a tool call; far fewer
can alter what it sees. Verify against each project's current docs before
building, since this moves quickly.

### Other operating systems

[docs/PORTING.md](docs/PORTING.md) has the detail, measured in a Linux container
rather than cited.

- **Linux: near parity.** Every Vision capability has a working, offline,
  permissively-licensed replacement. The scanner runs about 2x slower, but there
  is no 20-second cold start, and quad detection is actually better than Vision's.
- **Windows: achievable**, weakest on human detection. `bashguard` would be Go
  rather than Swift, which is poorly supported there.
- **Person segmentation is the one capability that cannot be matched.** A
  replacement exists and is far faster, but much coarser, and its thresholds do
  not transfer -- so the policy, not just the numbers, has to be re-tuned per
  platform. Where a capability cannot be matched, deny the class rather than
  approximate it.

The recommended shape is **per-platform backends behind the existing `visionscan`
JSON contract**, not capability detection inside one module. That schema is
already the interface, and the Linux implementation was a drop-in that needed no
changes to `imgfilter.py`.

### A different approach entirely

Hooks are per-harness by construction, so covering N agents means N
implementations. A **local redacting proxy** on the API path would be
harness-agnostic in one go -- and it would close the pasted-image gap above,
because a pasted image is in the request body even though it is not a tool call.

The cost is real: such a proxy terminates TLS and becomes your trust boundary,
and it has to track each provider's request format. Several local LLM redaction
proxies already exist, but they are text-only -- the image half is the part this
project has solved and they have not.

## Licence

MIT. See [LICENSE](LICENSE).

The warranty disclaimer is not boilerplate here. This tool reduces the chance of
an accidental disclosure; it does not prevent one, and the "What still gets
through" section above is the honest account of where it fails.
