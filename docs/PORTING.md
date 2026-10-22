# Porting the image filter off macOS

What it would take to run this filter on Linux and Windows, and what it costs.

Everything marked **[M]** was measured on this machine; **[E]** is estimated or
taken from documentation. The Linux numbers come from a real `linux/arm64`
container on this Apple Silicon host (Docker Desktop, 14 CPUs, CPU-only — no
GPU, no NPU). Windows could not be tested at all and is design plus
documentation.

---

## Verdict

**Linux: parity is achievable for the secret-text path and *nearly* achievable
for the personal-image path. Recommended.**

Every Vision capability has a working, permissively-licensed, offline
replacement. Measured end-to-end the Linux scanner runs **0.9–2.1 s** against
macOS's **0.33–0.83 s** — roughly 2× slower, and in the same order of
magnitude the filter already lives in. Two capabilities come out *better* than
macOS: document-quad detection is faster and cleaner, and there is no 20-second
cold model load. `bashguard` compiles unmodified and is faster than on macOS.

**Windows: achievable, with the weakest human-detection story of the three.
Recommended with one policy change.**

Windows has a genuinely good built-in OCR with word boxes, and a built-in face
detector — but that face detector returns **no confidence score**, which the
filter's `face_conf` knob depends on. The rest is the same ONNX stack as Linux.

**The one thing that cannot be matched anywhere: Vision's full-resolution person
segmentation.** The replacement runs at a fixed 192×192. For this filter's
thresholds that turns out to be acceptable, and the reasoning is given below —
but it is a real reduction in resolution and it is the single place I would
expect a miss.

### The finding that matters most

Porting the OCR *naively* produces the exact failure the filter exists to
prevent: a redaction that looks done and isn't.

With a direct port, every secret on a 6016 px image was painted — but only
**85–90 % of each secret's box**. A legible sliver of every token survived
**[M]**. That is worse than a clean denial, because the log says `allow` and the
image looks redacted.

The cause is not the OCR. It is that `box_pad` is a flat **3 pixels**, which is
nothing against 88-px-tall text, and the replacement's boxes sit a few percent
tighter than Vision's. The fix is one config line: make the text pad
proportional, as `human_box_grow` already is for human regions.

| `text_box_grow` | worst-covered secret, 900×320 | worst-covered secret, 6016×6016 | frame painted |
|---|---|---|---|
| 0.00 (today) | 0.970 | **0.850** | 0.87 % |
| 0.05 | 1.000 | 0.917 | 1.05 % |
| 0.10 | 1.000 | 0.958 | 1.24 % |
| **0.15** | **1.000** | **1.000** | 1.41 % |

**[M]** — Recommend `text_box_grow: 0.15`. It restores full coverage of every
secret for an extra 0.5 % of the frame painted. This is worth adopting on
**macOS too**: Vision's boxes are tight for the same reason, and a flat 3 px pad
is just as thin there.

### Honest limits of this evidence

- Ground truth is **9 secret instances across 2 images**. The coverage numbers
  are a sanity check, not a measured error rate.
- **I could not test true-positive human detection at all.** There is no
  photograph of a person on this machine that isn't the user's own, and I did
  not use those. Every face/person number below is either a *false*-positive
  measurement or published. The claim "YuNet finds the faces Vision finds" is
  **not** something I verified, and it is the biggest untested assumption here.
- arm64 only. x86_64 notes are marked **[E]**.

---

## Recommended stack

### Linux

| Capability | Component | Size | Licence | Latency vs macOS |
|---|---|---|---|---|
| OCR + word boxes | **RapidOCR** (`rapidocr-onnxruntime`), PP-OCRv4 det+rec | 16 MB, **in the wheel** | Apache-2.0 | dominant cost; see table below |
| Face boxes | **YuNet** via `cv2.FaceDetectorYN` | 232 KB | **MIT** | 7–49 ms (faster) |
| Person mask + bbox | **PP-HumanSeg** via ONNX Runtime | 6.2 MB | Apache-2.0 (verify dir) | 8–14 ms (much faster) |
| Whole-person boxes | *omit* — derive from the person mask | — | — | — |
| Document quad + confidence | **OpenCV** Canny → `approxPolyDP` + edge-support score | 0 | Apache-2.0 | 0–27 ms (faster) |
| HEIC decode | **pillow-heif** | ~3 MB | BSD-3 over libheif (LGPL-3) | ~570 ms @ 6016² (comparable) |
| Bash guard | **the existing `bashguard.swift`, unmodified** | — | — | **faster** |

Install: `pip install pillow pillow-heif numpy opencv-python-headless onnxruntime rapidocr-onnxruntime`
plus two model files. ≈ **160 MB** of wheels + **23 MB** of models **[M]**.
No system packages beyond `libgl1`/`libglib2.0-0`.

### Windows

| Capability | Component | Size | Licence | Notes |
|---|---|---|---|---|
| OCR + word boxes | **`Windows.Media.Ocr`** via `winrt`/`winsdk` | 0 — in the OS | OS | `OcrWord.BoundingRect` is a real per-word box **[E]** |
| OCR fallback | RapidOCR, as Linux | 16 MB | Apache-2.0 | needed when no OCR language pack |
| Face boxes | **`Windows.Media.FaceAnalysis.FaceDetector`** | 0 — in the OS | OS | **no confidence score** |
| Face (recommended instead) | **YuNet**, as Linux | 232 KB | MIT | keeps `face_conf` meaningful |
| Person mask | **PP-HumanSeg**, as Linux | 6.2 MB | Apache-2.0 | no built-in equivalent exists |
| Document quad | **OpenCV**, as Linux | 0 | Apache-2.0 | identical |
| HEIC | **pillow-heif** | ~3 MB | BSD-3 / LGPL-3 | identical |
| Bash guard | **rewrite in Go** (not Swift) | ~2 MB exe | — | see below |

**Use YuNet on Windows rather than the built-in detector.** `DetectedFace`
exposes only `FaceBox` — no score. The filter deliberately runs `face_conf` at
0.25 because "false positives are cheap"; with no score that knob disappears and
every detection becomes binary. Keeping YuNet also keeps one tuning story across
the two non-Apple platforms.

---

## Evidence, capability by capability

### 1. OCR word boxes — the critical one

PP-OCR detects *text lines*, not words, which looked like a blocker. It isn't:
`return_word_box=True` returns **one box per character** **[M]** (a 17-character
line returns 17 boxes). Characters regroup into words trivially, giving
granularity *finer* than Vision's.

There is a trap. Treating those per-character boxes as "words" and letting
`group_lines` rejoin them inserts a space between every character, which
destroys every regex in `RULES`. Measured redaction recall went to **0.000**
**[M]** — a silent, total failure of the secret-text path. The fix is to
reconstruct tokens from the line *string* and take each token's box as the union
of its characters' boxes.

Recall of Vision's painted area, after that fix:

| Image | RapidOCR | Tesseract `image_to_data` |
|---|---|---|
| 900×320 screenshot | **0.974** | 0.693 |
| 6016×6016 | **0.883** | 0.766 |

**[M]**. Two things drove the result:

- **Pre-upscaling small images is the single biggest lever.** At native
  resolution RapidOCR scored 0.702; upscaling the 900×320 shot ~2× took it to
  **0.982** **[M]**. Small UI text is below PP-OCR's comfortable input scale.
- **Tesseract is not adequate here.** It found only 2 of the 5 secret kinds on
  the screenshot, missing the email, the Anthropic key and the OpenAI key
  **[M]** — exactly the high-entropy strings this filter is for. It is also
  *slower* on large images (4.5 s at 6016² vs RapidOCR's 0.8 s). Keep it only as
  an emergency fallback.

Recall **plateaus around 0.90** on the large image regardless of settings —
even at full 6016 px input, which costs **12.3 s** **[M]**. That residual gap
is not closable by tuning; it is closed by `text_box_grow`, above.

`onnxtr` (docTR on ONNX) scored 0.930/0.860 with native word boxes, but pulls
weights from Hugging Face at first use. Rejected on the runtime-download
grounds in the licence section.

**Degradation vs macOS:** Vision is better at garbled/rotated/low-contrast text,
and this gap widens on photographs. The entropy rule does real rescue work — on
the large image RapidOCR missed `openai_key` *as a named kind* but
`high_entropy` caught the same token **[M]**. Keep that rule; it is load-bearing
off macOS.

### 2. Face detection

YuNet at bounded resolution is fast and clean. At **native** resolution it is
dangerous:

| Image | ≤1024 px | native |
|---|---|---|
| 6016×6016, text-heavy, **no faces present** | 0 faces, 41 ms | **89 faces**, 544 ms |

**[M]**. Every phantom scored **below 0.5** (max 0.46). So:

- Always cap the long side at **1024 px** before detection.
- Raise `face_conf` from 0.25 to **0.5** on non-Apple platforms.

Both are necessary. Left at 0.25 and native resolution, every large screenshot
would hit 89 "faces" — and on the board branch *any* face is an instant deny, so
the filter would reject essentially all whiteboard photos.

**Degradation vs macOS, and it is real:** capping at 1024 px means a 24-px
avatar in a 6016-px image becomes 4 px and is gone. The README already flags
~24 px as Vision's floor; on Linux that floor scales with the image. Tiling at
1024 px restores the resolution but costs **0.74 s** at 6016² and still produced
86 phantoms **[M]** — it buys recall and loses precision. I do not recommend it.

### 3. Person segmentation — the one that cannot be matched

PP-HumanSeg runs at a fixed **192×192** input in **8–14 ms regardless of image
size** **[M]**, against Vision's full-resolution mask folded into a 0.3–0.8 s
call. It is 30× faster and far coarser.

The useful test I *could* run was false positives, and it reproduces Vision's
known pathology almost exactly. On four macOS gradient wallpapers containing no
people:

| Wallpaper | Vision coverage | PP-HumanSeg coverage |
|---|---|---|
| iMac Purple | 0.720 | 0.745 |
| iMac Silver | 0.469 | 0.737 |
| iMac Blue | 0.222 | 0.728 |
| iMac Green | 0.110 | 0.697 |

**[M]** — and this independently confirms the README's claim of up to 0.72 on a
plain wallpaper.

Two conclusions:

1. **The existing design transfers intact.** The filter never asks "is there a
   human here"; it asks "is this a class I allow". That decision was forced by
   Vision's false positives and it is equally forced by PP-HumanSeg's — which
   are *worse*, sitting near 0.73 uniformly. Any design that used segmentation
   as a positive signal would fail on both platforms.
2. **You cannot carry thresholds across.** PP-HumanSeg would read 0.697 where
   Vision read 0.110. Re-tune `person_coverage_block` and friends per backend.

**Why 192×192 is nonetheless acceptable here** — this is the argument I'd want
challenged:

- `screenshot_coverage_block` (12 %) and `screenshot_nobox_coverage` (5 %) are
  far above the mask's resolution floor. No concern.
- `person_coverage_block` (0.4 %) is ~147 mask pixels of 36 864. Representable,
  but a *small or distant* person in a large photo may not survive the
  downsample — this is the genuine miss risk.
- It is mitigated by geometry, not by the model: the board branch **crops to the
  quad first**, and the mask is computed on the cropped, rectified board. Anyone
  standing *around* the whiteboard is already gone by construction. What remains
  to detect is a person *within* the board region, who is large in that frame.

**If you do not accept that argument, the right answer is to deny, not to
approximate.** Setting `board` class to deny whenever the person mask is
non-empty — rather than trusting a 0.4 % threshold at 192×192 — costs you some
legitimate whiteboard photos and costs nothing in latency. Given that this
filter is a backstop against leaking personal images, I would take that trade on
any machine where board photos are rare. It is a one-line policy change, and it
is strictly safer than the alternative.

Rejected alternatives, for the record: **RMBG-1.4** is **non-commercial only**
(verified — commercial use needs a separate BRIA agreement), so it is unusable
at the office. **Ultralytics YOLO** segmentation is **AGPL-3.0**, same problem.
**MODNet** *is* Apache-2.0 (I checked — the frequently-repeated
"non-commercial weights" claim is wrong) and would give a much finer mask at
~25 MB, but it is a matting model tuned for portraits and I did not benchmark
it; it is the upgrade path if 192×192 proves too coarse in practice.

### 4. Document quad — fully replaced, and better

This was expected to be hard, because the filter leans on Vision's *confidence*
to separate a board photo from a flat screenshot. A plain contour finder gives
no such score.

An edge-support score supplies the equivalent: sample along each side of the
candidate quad and measure the share backed by real image gradient, discarding
any side lying on the image border (the frame edge is not evidence of a
surface). The weakest side governs.

| Image | Vision conf | OpenCV conf | time |
|---|---|---|---|
| 900×320 screenshot | 0.00 | **0.00** | <1 ms |
| 1000×400 screenshot | 0.00 | **0.00** | <1 ms |
| 1400×1000 board | 0.99 | **1.00** | 10 ms |
| 4032×2880 board | 0.99 | **1.00** | 13 ms |
| 6016×6016 board | 0.99 | **1.00** | 27 ms |
| 6016² gradient wallpaper | 0.00 | **0.00** | 21 ms |

**[M]** — a clean separation on every image tested, faster than Vision, with no
model and no download. `board_min_quad_conf: 0.5` transfers unchanged.

### 5. HEIC

`pillow-heif` decodes a 6016×6016 HEIC in **~570 ms** **[M]**, comparable to the
`sips` path, and removes the subprocess hop entirely. Note libheif is **LGPL-3**
— fine when dynamically linked as the wheel does, but worth a glance if you ever
ship a static bundle.

### 6. `bashguard`

`bashguard.swift` **compiles unmodified** on Linux (`swift:6.0-noble`, 1.1 s)
and runs **faster than on macOS** **[M]**:

| | small output | 190 KB output |
|---|---|---|
| Linux | **4 ms** | **25 ms** |
| macOS | ~14 ms (README) | 40 ms |

Linux's process-spawn floor is effectively zero against macOS's ~11 ms, so the
optimisation work described in the README pays off even better there. No change
needed.

**Windows: do not use Swift.** Swift on Windows exists but needs the Visual
Studio toolchain and has uneven Foundation coverage — `NSRegularExpression` and
`String(contentsOfFile:)` are exactly the corners that bite. Rewrite in **Go**:
single static `.exe`, trivial cross-compile from any platform, no runtime to
install, and `regexp` plus byte-slice scanning map directly onto what the Swift
version does. Rust is equally fine. **Python is not an option here** — it runs
on every Bash call and Windows process startup is slower than macOS's, so the
~36 ms interpreter floor that drove the original Swift rewrite is worse, not
better. `bashfilter.py` stays the reference implementation and `parity-test`
should gain the Go binary as a third subject.

---

## Latency

### macOS baseline **[M]**, best of 3, warm

| Image | `visionscan` |
|---|---|
| 900×320 screenshot | 0.333 s |
| 1000×400 screenshot | 0.342 s |
| 1400×1000 board | 0.421 s |
| 4032×2880 board | 0.404 s |
| 6016×6016 JPEG | 0.445 s |
| 6016×6016 HEIC | 0.755–0.826 s |

### Linux scanner **[M]**, same images, full subprocess spawn

| Image | fast config | recommended config | vs macOS |
|---|---|---|---|
| 900×320 | 0.675 s | 0.884 s | 2.0–2.7× |
| 1000×400 | 0.640 s | 0.917 s | 1.9–2.7× |
| 1400×1000 board | 0.743 s | 1.273 s | 1.8–3.0× |
| 4032×2880 board | 0.887 s | 1.718 s | 2.2–4.3× |
| 6016×6016 JPEG | 1.169 s | 1.889 s | 2.6–4.2× |
| 6016×6016 HEIC | 1.466 s | 2.104 s | 1.8–2.5× |

*fast* = `max_side_len 2000`, upscale to 1600. *recommended* =
`max_side_len 3000`, upscale to 2400 — slower, but it detected all five secret
kinds by name on both ground-truth images where the fast config named three and
left the other two to the entropy rule **[M]**.

Both configs reach **worst-secret-coverage 1.000** once `text_box_grow: 0.15`
is applied **[M]**. If latency matters more than named-kind telemetry, the fast
config is defensible.

### Where the Linux time goes **[M]**

| Component | Cost |
|---|---|
| Python start + imports (`numpy`, `cv2`, `onnxruntime`, `rapidocr`) | **185 ms** |
| `RapidOCR()` constructor | **134 ms** |
| YuNet + PP-HumanSeg session construction | 21 ms |
| **Fixed overhead per invocation** | **≈ 340 ms** |
| OCR | 0.4–2.0 s (dominant) |
| YuNet @ ≤1024 | 7–49 ms |
| PP-HumanSeg | 8–14 ms |
| Quad | 0–27 ms |
| Decode (JPEG/PNG) | 2–81 ms |
| Decode (HEIC 6016²) | ~570 ms |

**Two latency notes worth acting on.**

1. **~340 ms is paid before any work happens**, and `decide()` calls `scan()`
   **twice** for a board — once on the original, once on the crop. That is ~680
   ms of pure startup on the board path. A **long-lived helper process** behind
   a unix socket (or a `--batch` mode taking both images in one invocation)
   removes it entirely and would bring the board path close to macOS. This is
   the highest-value optimisation available and it is pure engineering, no
   accuracy cost.
2. **There is no 20-second cold start.** ONNX sessions construct in
   milliseconds. The macOS first-read-after-boot penalty simply doesn't exist
   off macOS — a real quality-of-life win.

### x86_64 **[E]**

Untested. Expect OCR and segmentation to be *faster* than these arm64 numbers on
a modern desktop x86 part (AVX-512 VNNI, which ONNX Runtime exploits well), and
slower on older or low-power x86. The arm64 figures here are a reasonable
middle estimate, not a floor. GPU execution providers (CUDA, DirectML) would
change the picture entirely but are not worth the dependency weight for
sub-second workloads.

---

## Licence and offline-weights review

A privacy filter that fetches models at runtime undermines itself. Status:

| Component | Licence | Weights offline? |
|---|---|---|
| RapidOCR + PP-OCRv4 | Apache-2.0 | **Yes — shipped inside the wheel** (16 MB) |
| RapidOCR v3 + PP-OCRv6 | Apache-2.0 | **Yes — in the wheel** (30 MB) |
| YuNet | **MIT** (verified) | Manual file, **git-LFS** — see below |
| PP-HumanSeg | Apache-2.0 *(verify the model dir)* | Manual file |
| OpenCV | Apache-2.0 | n/a |
| ONNX Runtime | MIT | n/a |
| Tesseract | Apache-2.0 | apt package |
| pillow-heif | BSD-3 over libheif **LGPL-3** | n/a |
| MODNet | Apache-2.0 (verified) | Manual file |
| **`onnxtr`** | Apache-2.0 | **No — pulls from Hugging Face at first use** |
| **RMBG-1.4** | **Non-commercial only** (verified) | — |
| **Ultralytics YOLO** | **AGPL-3.0** | — |

**Rejected for office use:** RMBG-1.4 and Ultralytics on licence; `onnxtr` on
runtime fetching.

**A correction to the brief:** YuNet is **not** bundled with
`opencv-python`, despite shipping "since 4.5.4" — that refers to the
`FaceDetectorYN` *API*, not the weights. The weights live in `opencv_zoo`
behind **git-LFS**, and a plain `raw.githubusercontent.com` fetch silently
returns a **131-byte pointer file** instead of the model **[M]**. Any installer
must use the `media.githubusercontent.com/media/...` endpoint and **verify the
file size**, or it will fail at runtime in a confusing way.

Recommendation: **vendor both model files into the repository** (232 KB + 6.2 MB
= 6.4 MB) rather than downloading at install time. It keeps the licences
auditable, makes installs hermetic, and matches the tool's own premise. The
PP-HumanSeg model directory's licence should be read directly before an office
rollout — `opencv_zoo` is Apache-2.0 overall but explicitly defers to per-model
terms.

---

## One codebase or per-platform backends?

**Recommend: per-platform backends behind the `visionscan` JSON contract that
already exists. Do not add capability detection to `imgfilter.py`.**

The architecture is already right. `imgfilter.py` shells out to a binary and
parses a fixed JSON schema — `width`, `height`, `text[]`, `faces[]`, `humans[]`,
`personCoverage`, `personBBox`, `docQuad`, `errors[]`. That schema is the
interface, and nothing in it is Apple-specific. My Linux implementation is a
drop-in that emits the identical schema; `imgfilter.py` needed **no changes at
all** to consume it.

Keep that and ship:

```
visionscan            # macOS, Swift + Vision        (exists)
visionscan-onnx       # Linux + Windows, Python      (new)
bashguard             # macOS + Linux, Swift         (exists, portable as-is)
bashguard.exe         # Windows, Go                  (new)
```

Select by `sys.platform` at the one line that builds the subprocess argv.

Why not a capability-detection layer inside one module:

- **The thresholds are not portable, and that is the whole argument.**
  PP-HumanSeg reads 0.697 where Vision reads 0.110; `face_conf` must be 0.25 on
  macOS and 0.5 on Linux; `text_box_grow` matters more off macOS. A unified
  module would need a per-backend threshold table anyway — which is a
  per-platform backend wearing a disguise, with the coupling hidden instead of
  declared. Make `config.json` take a per-backend block and keep the seam
  visible.
- **Fail-closed gets harder.** The filter's central property is that any
  exception denies. One module importing `onnxruntime` inside a `try` on macOS,
  or `Vision` on Linux, multiplies the paths where a partial import leaves the
  policy layer running with a half-initialised backend. A subprocess that either
  prints valid JSON or exits non-zero has exactly two outcomes, and
  `imgfilter.py` already treats the second as deny.
- **The process boundary is already paid for.** There is no efficiency to
  recover by inlining — and if you want it back, the fix is the long-lived
  helper above, which works the same way for every backend.

The one thing worth sharing is the **schema itself**: write it down as a
contract with a conformance test that runs each backend over a fixed corpus and
asserts the output shape, `docQuad.conf` separation, and secret coverage. That
is what stops the two implementations drifting — the same role `parity-test`
plays for `bashguard` vs `bashfilter.py`, which is a pattern this repo already
trusts.

---

## What to change, in order

1. **`text_box_grow: 0.15`** — on every platform, macOS included. Closes the
   85 %-coverage partial-redaction hole. One line.
2. **Per-backend threshold blocks in `config.json`** — `face_conf` 0.5 and
   re-tuned person-coverage numbers for the ONNX backend.
3. **Vendor `yunet.onnx` and `pphumanseg.onnx`** into the repo. Never fetch
   weights at runtime.
4. **Cap face detection at 1024 px long side.** Non-negotiable; without it
   large images produce ~89 phantom faces.
5. **Decide the board-branch person policy explicitly** — threshold at
   192×192, or deny any non-empty mask. Denying is the safer default.
6. **Long-lived helper process** when the double-scan latency on boards starts
   to bite.
7. **Go `bashguard` for Windows**, added to `parity-test` as a third subject.

## What stays worse off macOS, permanently

- **Small faces.** Capping at 1024 px loses avatars that Vision finds. No
  mitigation that doesn't cost precision.
- **Person-mask resolution.** 192×192 vs full-res. Acceptable given where the
  thresholds sit and the board crop, but it is the likeliest place to miss.
- **OCR on damaged text.** Vision is better on rotated, low-contrast and very
  small text; the gap widens on photographs versus screenshots.
- **~2× latency on small images**, mostly fixed process overhead, mostly
  recoverable via a resident helper.
- **Untested true-positive human detection.** Before trusting either non-Apple
  platform with the personal-image path, run a corpus of real photographs of
  people through both backends and compare. I could not, and nothing above
  substitutes for it.
