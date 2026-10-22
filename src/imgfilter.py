#!/usr/bin/env python3
"""Local image filter: redact sensitive text, gate human imagery.

Reads a PreToolUse hook payload on stdin, emits a hook decision on stdout.
Fails closed: any unexpected condition denies the read.
"""
import base64
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
VISIONSCAN = os.path.join(HERE, "visionscan")
CACHE = os.path.join(HERE, "cache")
LOG = os.path.join(HERE, "log.jsonl")
OVERRIDES = os.path.join(HERE, "overrides")
KEYWORDS = os.path.join(HERE, "keywords.txt")
PATHS = os.path.join(HERE, "paths.txt")
CONF = os.path.join(HERE, "config.json")

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".heic", ".tif", ".tiff"}

# A PDF is binary, so the text scan skips it, and it is not an image extension,
# so the image checks never saw it either -- while the Read tool renders its
# pages and sends them to the model. It is inspected as what it actually
# becomes: a sequence of page images.
PDF_EXT = {".pdf"}

DEFAULTS = {
    # Which checks run. "profile" picks a set; anything in "features" overrides
    # it individually. A check that is switched off does not run and cannot
    # deny -- that is consent, not a failure, and is different from a check
    # that errors (which still denies).
    "profile": "strict",
    "features": {},
    # classification
    "color_ratio_photo": 0.35,     # unique colours / pixels above this => photographic
    "flat_frac_photo": 0.10,       # fraction of near-flat pixels below this => photographic
    "board_min_quad_area": 0.25,   # board quad must cover this much of the frame
    "board_max_quad_area": 0.98,   # above this it is the whole frame, not a surface
    "board_min_quad_conf": 0.5,    # a flat UI screenshot scores 0 here
    "board_min_brightness": 135,   # mean luma inside the quad
    # human gate
    "person_coverage_block": 0.004,   # >0.4% of pixels masked as person => block
    "face_conf": 0.25,                # deliberately low: false positives are cheap
    "human_conf": 0.25,
    "screenshot_redact_humans": True, # screenshots: paint over avatars instead of blocking
    "screenshot_coverage_block": 0.12,# unless a real photo is embedded in the screenshot
    "screenshot_nobox_coverage": 0.05,# person pixels but nothing to paint over => block
    "min_words_screenshot": 5,        # positive evidence it really is an interface
    "min_words_board": 2,             # a board/diagram worth sending has writing on it
    # text
    "override_ttl_seconds": 900,     # an unused approval goes stale
    "keywords_block_override": True, # a keyword hit cannot be approved away
    "keyword_squash_min": 4,         # shorter terms skip punctuation-blind matching
    "keyword_fold_min": 6,           # and shorter still skip OCR-confusable folding
    "text_scan_max_bytes": 64 << 20, # beyond this a file cannot be cleared, so it is denied
    "entropy_min_len": 24,
    "entropy_threshold": 4.0,
    "redact_emails": True,
    "box_pad": 3,
    "text_box_grow": 0.15,   # flat padding is nothing against 80px text
    "secret_to_line_end": True,  # OCR splits long tokens; paint the whole tail
    "human_box_grow": 0.12,  # grow human regions by 12% of their own size
    # pdf
    "pdf_max_pages": 25,        # beyond this a document cannot be cleared, so it is denied
    "pdf_render_scale": 2.0,    # 2x the page box: OCR needs the resolution
    "pdf_when_unscannable": "deny",  # profile has no image checks but text_keywords is on
}


FEATURES = ("image_class_gate", "image_humans", "image_secrets",
            "image_keywords", "text_keywords", "path_filter")

PROFILES = {
    # everything on -- images gated and redacted, keywords everywhere
    "strict":  dict(dict.fromkeys(FEATURES, True), path_filter=False),
    # credentials and keywords only; images are not gated or scanned for people
    "secrets": {"path_filter": False, "image_class_gate": False, "image_humans": False,
                "image_secrets": True, "image_keywords": True, "text_keywords": True},
    # photos and people only; no text scanning anywhere
    "images":  {"image_class_gate": True, "image_humans": True,
                "image_secrets": False, "image_keywords": False, "text_keywords": False},
    # text and command output only -- no image analysis at all. This is the
    # portable profile: everything in it is pure Python and runs anywhere.
    "text":    {"text_keywords": True},
    # nothing runs; for turning the filter off without uninstalling it
    "off":     dict.fromkeys(FEATURES, False),
}


def features(conf):
    # Start from all-off so a feature a profile forgets to mention defaults to
    # off rather than KeyError-ing or silently inheriting something else.
    base = dict.fromkeys(FEATURES, False)
    base.update(PROFILES.get(conf.get("profile", "strict"), PROFILES["strict"]))
    for k, v in (conf.get("features") or {}).items():
        if k in base:
            base[k] = bool(v)
    return base


def load_conf():
    conf = dict(DEFAULTS)
    try:
        with open(CONF) as fh:
            conf.update(json.load(fh))
    except FileNotFoundError:
        pass
    return conf


# --------------------------------------------------------------------------
# secret / PII patterns.  OCR is lossy, so anchor on prefixes and structure,
# never on an exact full-token charset.
# --------------------------------------------------------------------------
RULES = [
    ("aws_access_key",  re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{10,20}\b")),
    ("anthropic_key",   re.compile(r"sk-ant-[A-Za-z0-9_\-]{6,}")),
    ("openai_key",      re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{16,}")),
    ("github_token",    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{10,}")),
    ("slack_token",     re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{8,}")),
    ("google_api_key",  re.compile(r"\bAIza[0-9A-Za-z_\-]{25,40}\b")),
    ("jwt",             re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{4,}")),
    ("private_key",     re.compile(r"-{3,}\s*BEGIN[A-Z ]*PRIVATE KEY")),
    ("bearer",          re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{12,}")),
    ("basic_auth_url",  re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:@/]+:[^\s:@/]+@")),
    ("assigned_secret", re.compile(
        r"(?i)\b(?:api[_\-]?key|apikey|secret|password|passwd|pwd|pw|passphrase|token|"
        r"credential|auth|private[_\-]?key|conn(?:ection)?[_\-]?string)s?\b"
        r"\s*[:=.;,]\s*(?:\S{1,10}\s+)?\S{6,}")),
    ("email",           re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("iban",            re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")),
]

CARD_RE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")

# For these, a half-painted match is a visible secret, so painting runs to the
# end of the line: OCR splits and mangles long tokens, and the fragment the
# regex matched is not reliably the whole thing. An email is self-delimiting
# and does not need it.
SECRET_KINDS = {
    "aws_access_key", "anthropic_key", "openai_key", "github_token", "slack_token",
    "google_api_key", "jwt", "private_key", "bearer", "basic_auth_url",
    "assigned_secret", "high_entropy", "card_number", "iban",
}


def luhn(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def shannon(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def find_spans(line, conf):
    """-> [(start, end, kind)] over `line`."""
    spans = []
    for kind, rx in RULES:
        if kind == "email" and not conf["redact_emails"]:
            continue
        for m in rx.finditer(line):
            spans.append((m.start(), m.end(), kind))
    for m in CARD_RE.finditer(line):
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and luhn(digits):
            spans.append((m.start(), m.end(), "card_number"))
    for m in re.finditer(r"\S+", line):
        tok = m.group()
        if len(tok) >= conf["entropy_min_len"] and shannon(tok) >= conf["entropy_threshold"]:
            if re.search(r"[A-Za-z]", tok) and re.search(r"\d", tok):
                spans.append((m.start(), m.end(), "high_entropy"))
    return spans


# --------------------------------------------------------------------------
def group_lines(words):
    """Group OCR words into lines, keeping each word's char range."""
    items = sorted(words, key=lambda w: (w["box"]["y"], w["box"]["x"]))
    lines, cur = [], []
    for w in items:
        if not cur:
            cur = [w]
            continue
        ref = cur[-1]["box"]
        b = w["box"]
        overlap = min(ref["y"] + ref["h"], b["y"] + b["h"]) - max(ref["y"], b["y"])
        if overlap > 0.4 * min(ref["h"], b["h"]):
            cur.append(w)
        else:
            lines.append(cur)
            cur = [w]
    if cur:
        lines.append(cur)

    out = []
    for ln in lines:
        ln = sorted(ln, key=lambda w: w["box"]["x"])
        text, ranges, pos = "", [], 0
        for w in ln:
            if text:
                text += " "
                pos += 1
            ranges.append((pos, pos + len(w["text"]), w["box"]))
            text += w["text"]
            pos += len(w["text"])
        out.append((text, ranges))
    return out


def boxes_for_text(words, conf):
    hits = []
    for text, ranges in group_lines(words):
        for s, e, kind in find_spans(text, conf):
            idx = [i for i, (ws, we, _) in enumerate(ranges) if ws < e and we > s]
            if not idx:
                continue
            last = len(ranges) - 1 if (conf["secret_to_line_end"] and kind in SECRET_KINDS) \
                else idx[-1]
            # Merge into ONE box spanning the match. Painting each word box
            # separately leaves the gaps between them bare -- and a gap is
            # exactly where OCR dropped glyphs it could not read, i.e. the
            # characters most likely to still be legible in the image.
            covered = [ranges[i][2] for i in range(idx[0], last + 1)]
            x0 = min(b["x"] for b in covered)
            y0 = min(b["y"] for b in covered)
            x1 = max(b["x"] + b["w"] for b in covered)
            y1 = max(b["y"] + b["h"] for b in covered)
            hits.append(({"x": x0, "y": y0, "w": x1 - x0, "h": y1 - y0, "c": 1.0}, kind))
    return hits


# --------------------------------------------------------------------------
def image_stats(img):
    from PIL import ImageFilter
    small = img.convert("RGB")
    small.thumbnail((400, 400))
    px = small.width * small.height
    cols = small.getcolors(maxcolors=px * 2)
    color_ratio = (len(cols) / px) if cols else 1.0
    edges = small.convert("L").filter(ImageFilter.FIND_EDGES)
    hist = edges.histogram()
    flat_frac = sum(hist[:8]) / float(px)
    return color_ratio, flat_frac


def quad_area_frac(quad, w, h):
    c = quad["corners"]
    a = 0.0
    for i in range(4):
        x1, y1 = c[i]
        x2, y2 = c[(i + 1) % 4]
        a += x1 * y2 - x2 * y1
    return abs(a) / 2.0 / float(w * h)


def rectify(img, quad):
    """Warp the board quad to a full upright image; everything off-board is dropped."""
    from PIL import Image
    tl, tr, br, bl = quad["corners"]

    def dist(p, q):
        return math.hypot(p[0] - q[0], p[1] - q[1])

    w = int(max(dist(tl, tr), dist(bl, br)))
    h = int(max(dist(tl, bl), dist(tr, br)))
    if w < 32 or h < 32:
        return None
    # PIL QUAD order: upper-left, lower-left, lower-right, upper-right
    data = (tl[0], tl[1], bl[0], bl[1], br[0], br[1], tr[0], tr[1])
    return img.transform((w, h), Image.Transform.QUAD, data, Image.Resampling.BICUBIC)


def vision_available():
    return os.path.exists(VISIONSCAN) and os.access(VISIONSCAN, os.X_OK)


def scan(path):
    res = subprocess.run([VISIONSCAN, path], capture_output=True, timeout=25)
    if res.returncode != 0:
        raise RuntimeError("visionscan failed: %s" % res.stderr.decode()[:200])
    return json.loads(res.stdout)


def paint(img, boxes, pad, frac=0.0):
    """`frac` grows each box by a share of its own size -- a detector box clips
    limbs and hair, so human regions need a margin a flat pixel pad cannot give."""
    from PIL import ImageDraw
    d = ImageDraw.Draw(img)
    for box in boxes:
        px = pad + frac * box["w"]
        py = pad + frac * box["h"]
        d.rectangle(
            [box["x"] - px, box["y"] - py, box["x"] + box["w"] + px, box["y"] + box["h"] + py],
            fill=(0, 0, 0),
        )
    return img


def log(record):
    try:
        record["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        with open(LOG, "a") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        pass


# --------------------------------------------------------------------------
def _norm(s):
    return re.sub(r"\s+", " ", s.lower()).strip()


def _squash(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


# Characters OCR routinely swaps. Folded on BOTH sides, so the comparison stays
# symmetric and "C0NFIDENTIAL" meets "confidential".
# Each class collapses to one canonical character rather than picking a
# representative: "1" can be OCR for either "l" or "i", so all three must meet.
_CONFUSABLES = str.maketrans({
    "0": "o",
    "l": "1", "i": "1", "|": "1", "!": "1",
    "5": "s", "8": "b", "2": "z",
})


def _fold(s):
    # Translate BEFORE squashing: "|" is punctuation, so squashing first would
    # drop it instead of folding it onto "1".
    return _squash(s.lower().translate(_CONFUSABLES)).replace("rn", "m").replace("vv", "w")


def load_rules(path):
    """-> [(lineno, raw, kind, matcher)]; kind is 'text' or 'regex'."""
    out = []
    try:
        with open(path) as fh:
            lines = fh.readlines()
    except OSError:
        return out
    for n, line in enumerate(lines, 1):
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if entry.lower().startswith("re:"):
            pat = entry[3:].strip()
            try:
                out.append((n, entry, "regex", re.compile(pat, re.IGNORECASE)))
            except re.error:
                pass  # a broken pattern must not take the whole list down
        else:
            out.append((n, entry, "text", entry))
    return out


def load_keywords():
    return load_rules(KEYWORDS)


def load_paths():
    return load_rules(PATHS)


def path_hits(path, conf):
    """Match the whole path, exactly -- no OCR-damage passes; a path is text."""
    rules = load_paths()
    return keyword_hits([path], rules, conf, ocr=False) if rules else []


_CMD_TOKEN = re.compile(r"[^\s;|&()<>'\"]+")


def command_path_hits(command, conf):
    r"""Path rules against a COMMAND string.

    A path rule is anchored for a path (`\.pem$`), but in a command `$` means
    end-of-command, so `cat x.pem | head` would never match. Match each
    path-shaped token separately, and the whole command too so that unanchored
    literal rules still work.
    """
    rules = load_paths()
    if not rules:
        return []
    found = {}
    for tok in _CMD_TOKEN.findall(command):
        if "/" in tok or tok.startswith("."):
            for n, raw in keyword_hits([tok.strip("'\"")], rules, conf, ocr=False):
                found[n] = raw
    for n, raw in keyword_hits([command], rules, conf, ocr=False):
        found[n] = raw
    return sorted(found.items())


def keyword_hits(haystacks, keywords, conf, ocr=True):
    """Match every entry against the OCR text and the filename.  OCR mangles
    spacing and punctuation, so a literal term is also matched with both
    stripped -- 'CONF IDENTIAL' and 'confidential' must both hit."""
    normed = [_norm(h) for h in haystacks if h]
    squashed = [_squash(h) for h in haystacks if h] if ocr else []
    folded = [_fold(h) for h in haystacks if h] if ocr else []
    hits = []
    for lineno, raw, kind, m in keywords:
        if kind == "regex":
            if any(m.search(h) for h in normed):
                hits.append((lineno, raw))
            continue
        needle = _norm(m)
        if any(needle in h for h in normed):
            hits.append((lineno, raw))
            continue
        if not ocr:
            continue  # a real file has exact text; squash/fold would only misfire
        sq = _squash(m)
        if len(sq) >= conf["keyword_squash_min"] and any(sq in h for h in squashed):
            hits.append((lineno, raw))
            continue
        fo = _fold(m)
        if len(fo) >= conf["keyword_fold_min"] and any(fo in h for h in folded):
            hits.append((lineno, raw))
    return hits


def scan_text(sc):
    return " ".join(t["text"] for t in sc.get("text", []))


def scan_text_file(path, keywords, conf):
    """Keyword-scan a non-image file.  Returns a sorted [(lineno, term)] list,
    or None when the file is not something we can meaningfully scan (binary,
    unreadable, a directory) -- those pass through rather than being denied,
    since the Read itself will fail or carries no text to match."""
    longest = max((len(_norm(r)) for _, r, _, _ in keywords), default=0)
    overlap = max(longest, 64)
    found = {}
    consumed = 0
    try:
        with open(path, "rb") as fh:
            buf = fh.read(1 << 20)
            if not buf:
                return []
            if b"\x00" in buf[:8192]:
                return None  # binary
            while True:
                text = buf.decode("utf-8", "replace")
                for lineno, raw in keyword_hits([text], keywords, conf, ocr=False):
                    found[lineno] = raw
                consumed += len(buf)
                if consumed >= conf["text_scan_max_bytes"]:
                    break
                nxt = fh.read(1 << 20)
                if not nxt:
                    break
                # carry an overlap so a term straddling a chunk edge still matches
                buf = buf[-overlap:] + nxt
    except OSError:
        return None
    return sorted(found.items())


def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sweep_overrides(conf):
    """Drop expired approvals, including ones orphaned by an edit to the file
    they were issued for -- nothing will ever look those up again."""
    now = time.time()
    try:
        names = os.listdir(OVERRIDES)
    except OSError:
        return
    for name in names:
        if not name.endswith(".json"):
            continue
        token = os.path.join(OVERRIDES, name)
        try:
            with open(token) as fh:
                rec = json.load(fh)
            stale = now - rec.get("created", 0) > conf["override_ttl_seconds"]
        except (OSError, ValueError):
            stale = True
        if stale:
            try:
                os.unlink(token)
            except OSError:
                pass


def find_override(digest, conf):
    """An approval is keyed by CONTENT hash, so swapping the file drops it."""
    token = os.path.join(OVERRIDES, "%s.json" % digest)
    try:
        with open(token) as fh:
            rec = json.load(fh)
    except (OSError, ValueError):
        return None
    if time.time() - rec.get("created", 0) > conf["override_ttl_seconds"]:
        try:
            os.unlink(token)
        except OSError:
            pass
        return None
    return rec


def consume_override(digest):
    try:
        os.unlink(os.path.join(OVERRIDES, "%s.json" % digest))
    except OSError:
        pass


def render_pdf(path, conf):
    """Rasterise every page. Returns (page_png_paths, total_pages)."""
    outdir = os.path.join(CACHE, "pdf-%s" % hashlib.sha256(path.encode()).hexdigest()[:16])
    shutil.rmtree(outdir, ignore_errors=True)  # stale pages from an earlier read of this path
    os.makedirs(outdir, exist_ok=True)
    res = subprocess.run([VISIONSCAN, "--pdf", path, outdir,
                          str(int(conf["pdf_max_pages"])), str(float(conf["pdf_render_scale"]))],
                         capture_output=True, timeout=180)
    if res.returncode != 0:
        raise RuntimeError("pdf render failed: %s" % res.stderr.decode()[:200])
    d = json.loads(res.stdout)
    if d.get("errors"):
        raise RuntimeError("pdf render errors: %s" % "; ".join(d["errors"])[:200])
    return d.get("pages") or [], int(d.get("total") or 0)


def stitch_pdf(page_paths, src):
    """Re-assemble the redacted pages. The result is a raster PDF -- the text
    layer, embedded metadata and any attachments are gone, so what the model
    reads is exactly what was inspected."""
    from PIL import Image
    imgs = [Image.open(p).convert("RGB") for p in page_paths]
    try:
        st = os.stat(src)
        key = "%s:%s:%s" % (src, st.st_mtime_ns, st.st_size)
    except OSError:
        key = src
    dest = os.path.join(CACHE, "pdf-%s.pdf" % hashlib.sha256(key.encode()).hexdigest()[:24])
    imgs[0].save(dest, "PDF", save_all=True, append_images=imgs[1:], resolution=150.0)
    return dest


def decide_pdf(path, conf, override=None):
    """One refused page refuses the file: a document is read as a whole, and
    letting the clean pages through would just relocate the question."""
    pages, total = render_pdf(path, conf)
    base = dict(rendered=len(pages), total=total)
    if not pages:
        return dict(decision="deny", cls="pdf", kinds={}, stats=base,
                    reason="the PDF produced no renderable pages, so nothing in it could be "
                           "checked")
    if total > len(pages):
        return dict(decision="deny", cls="pdf", kinds={}, stats=base,
                    reason="the PDF has %d pages, over the %d-page cap, so it could not be "
                           "cleared in full (raise pdf_max_pages in config.json to allow it)"
                           % (total, int(conf["pdf_max_pages"])))
    kinds, outs = {}, []
    for n, page in enumerate(pages, 1):
        r = decide(page, conf, override, known_class="document")
        if r["decision"] == "deny":
            return dict(decision="deny", cls="pdf", kinds={},
                        stats=dict(base, page=n, **(r.get("stats") or {})),
                        _terms=r.get("_terms"),
                        reason="page %d of %d %s" % (n, len(pages), r["reason"]))
        for k, v in (r.get("kinds") or {}).items():
            kinds[k] = kinds.get(k, 0) + v
        outs.append(r["path"])
    return dict(decision="allow", cls="pdf", path=stitch_pdf(outs, path),
                kinds=kinds, stats=base)


def open_image(path):
    """PIL can't decode HEIC/HEIF; macOS `sips` can. Returns (image, usable_path)."""
    from PIL import Image, UnidentifiedImageError
    try:
        img = Image.open(path)
        img.load()
        return img, path
    except (UnidentifiedImageError, OSError):
        pass
    dest = os.path.join(CACHE, "norm-%s.png" % hashlib.sha256(path.encode()).hexdigest()[:16])
    res = subprocess.run(["/usr/bin/sips", "-s", "format", "png", path, "--out", dest],
                         capture_output=True, timeout=30)
    if res.returncode != 0 or not os.path.exists(dest):
        raise RuntimeError("cannot decode image: %s" % res.stderr.decode()[:160])
    img = Image.open(dest)
    img.load()
    return img, dest


def decide_approved(img, path, conf, override, orig_name=""):
    """You looked at this image and approved it, so the class and human gates
    are skipped.  The image is still re-encoded -- approving what you can see is
    not approving the EXIF, which can carry GPS."""
    keywords = load_keywords() if features(conf)["image_keywords"] else []
    if keywords and conf["keywords_block_override"]:
        sc = scan(path)
        hits = keyword_hits([scan_text(sc), orig_name], keywords, conf)
        if hits:
            return dict(decision="deny", cls="override:blocked", _terms=[r for _, r in hits],
                        stats=dict(keyword_lines=[n for n, _ in hits]),
                        reason="matched the keyword denylist (keywords.txt line%s %s), which an "
                               "approval does not override"
                               % ("" if len(hits) == 1 else "s",
                                  ", ".join(str(n) for n, _ in hits)))

    kinds = {}
    out = img.copy()
    if override["mode"] == "redact" and features(conf)["image_secrets"]:
        final = scan(path)
        text_hits = boxes_for_text(final["text"], conf)
        for _, kind in text_hits:
            kinds[kind] = kinds.get(kind, 0) + 1
        paint(out, [b for b, _ in text_hits], conf["box_pad"], conf["text_box_grow"])

    dest = os.path.join(CACHE, "ovr-%s.png" % override["digest"][:24])
    out.save(dest)
    return dict(decision="allow", cls="override:%s" % override["mode"], path=dest,
                kinds=kinds, stats=dict(approved_at=override.get("created")))


def decide(path, conf, override=None, known_class=None):
    feat = features(conf)
    orig_name = os.path.basename(path)
    img, path = open_image(path)
    if img.mode != "RGB":
        img = img.convert("RGB")

    if override is not None:
        return decide_approved(img, path, conf, override, orig_name)

    color_ratio, flat_frac = image_stats(img)
    photographic = color_ratio > conf["color_ratio_photo"] or flat_frac < conf["flat_frac_photo"]

    first = scan(path)
    words = first["text"]
    stats = dict(color_ratio=round(color_ratio, 4), flat_frac=round(flat_frac, 4),
                 words=len(words), photographic=photographic)

    # A rendered PDF page needs no classifier: we know what it is from the file
    # type, which is firmer evidence than the heuristics below could give.
    work, work_path, cls = img, path, known_class

    quad = first.get("docQuad")
    area = quad_area_frac(quad, first["width"], first["height"]) if quad else 0.0
    # A confident quad covering a proper sub-region means there is a distinct
    # surface in frame (a board, a sheet, a document).  A flat UI screenshot
    # yields confidence 0 over the whole frame, which is how the two separate.
    has_surface = (quad is not None
                   and quad["conf"] >= conf["board_min_quad_conf"]
                   and conf["board_min_quad_area"] <= area <= conf["board_max_quad_area"])
    stats["quad_area"] = round(area, 3)
    stats["quad_conf"] = round(quad["conf"], 3) if quad else 0.0

    # Try the board branch FIRST when there is a distinct surface in frame, but
    # let it fall through rather than disqualify: an embedded photo inside an
    # ordinary screenshot also reads as a "surface", and such a screenshot must
    # still reach the screenshot branch so its human gate applies.
    if cls is None and has_surface and len(words) >= conf["min_words_board"]:
        warped = rectify(img, quad)
        if warped is not None:
            luma = warped.convert("L")
            mean = sum(i * c for i, c in enumerate(luma.histogram())) / float(
                warped.width * warped.height)
            if mean >= conf["board_min_brightness"]:
                cls, work = "board", warped
                work_path = os.path.join(CACHE, "crop-%s.png" % hashlib.sha256(
                    path.encode()).hexdigest()[:16])
                warped.save(work_path)

    # A screenshot is a synthetic render carrying interface text.  Requiring the
    # text keeps smooth gradients and abstract art out of this class -- person
    # segmentation false-positives badly on those, and this is the lenient branch.
    # `not photographic` is what stops a real board photo landing here uncropped.
    if cls is None and not photographic and len(words) >= conf["min_words_screenshot"]:
        cls = "screenshot"

    if cls is None and not feat["image_class_gate"]:
        # Gate off: the image is allowed through unclassified, but it gets the
        # STRICT human policy below -- we know less about it, not more.
        cls = "unclassified"
    if cls is None:
        return dict(decision="deny", cls="other", stats=stats,
                    reason="not a UI screenshot (synthetic render with >=%d words of interface "
                           "text; this had %d words, photographic=%s) and not a bright, rectifiable "
                           "board or diagram (quad_area=%.2f conf=%.2f)"
                           % (conf["min_words_screenshot"], len(words), photographic,
                              area, stats["quad_conf"]))

    # Re-scan whatever we will actually send (for boards: the cropped surface,
    # so anything that was outside the board is already gone).
    final = scan(work_path) if work_path != path else first

    keywords = load_keywords() if feat["image_keywords"] else []
    if keywords:
        # Check the source AND what would be sent: a term cropped off a board is
        # genuinely gone, but a term anywhere in the file still means "deny".
        hits = keyword_hits([scan_text(first), scan_text(final), orig_name], keywords, conf)
        if hits:
            stats["keyword_lines"] = [n for n, _ in hits]
            return dict(decision="deny", cls=cls, stats=stats, _terms=[r for _, r in hits],
                        reason="matched the keyword denylist (keywords.txt line%s %s); the term "
                               "itself is deliberately not repeated here"
                               % ("" if len(hits) == 1 else "s",
                                  ", ".join(str(n) for n, _ in hits)))

    if feat["image_humans"]:
        faces = [b for b in final["faces"] if b["c"] >= conf["face_conf"]]
        humans = [b for b in final["humans"] if b["c"] >= conf["human_conf"]]
        coverage = final.get("personCoverage", 0.0)
    else:
        faces, humans, coverage = [], [], 0.0
    stats["coverage"] = round(coverage, 4)
    stats["profile"] = conf.get("profile", "strict")

    def blocked(reason):
        return dict(decision="deny", cls=cls, stats=stats, reason=reason)

    if cls in ("board", "unclassified"):
        if faces or humans or coverage > conf["person_coverage_block"]:
            return blocked("human figure or body part on the board image "
                           "(faces=%d humans=%d coverage=%.3f)" % (len(faces), len(humans), coverage))
    else:
        if coverage > conf["screenshot_coverage_block"]:
            return blocked("screenshot contains a large human image (coverage=%.3f)" % coverage)
        if (faces or humans) and not conf["screenshot_redact_humans"]:
            return blocked("human imagery in screenshot (faces=%d humans=%d)"
                           % (len(faces), len(humans)))
        if coverage > conf["screenshot_nobox_coverage"] and not faces and not humans:
            return blocked("person pixels detected (coverage=%.3f) with no box to redact" % coverage)

    text_hits = boxes_for_text(final["text"], conf) if feat["image_secrets"] else []
    kinds = {}
    for _, kind in text_hits:
        kinds[kind] = kinds.get(kind, 0) + 1
    human_boxes = faces + humans
    if feat["image_humans"] and final.get("personBBox"):
        human_boxes = human_boxes + [final["personBBox"]]
    if human_boxes:
        kinds["human_region"] = len(human_boxes)

    out = work.copy()
    paint(out, [b for b, _ in text_hits], conf["box_pad"], conf["text_box_grow"])
    paint(out, human_boxes, conf["box_pad"], conf["human_box_grow"])

    try:
        st = os.stat(path)
        key = "%s:%s:%s" % (path, st.st_mtime_ns, st.st_size)
    except OSError:
        key = path
    dest = os.path.join(CACHE, "%s.png" % hashlib.sha256(key.encode()).hexdigest()[:24])
    out.save(dest)  # re-encode drops EXIF and any trailing data
    return dict(decision="allow", cls=cls, path=dest, kinds=kinds, stats=stats)


def emit_deny(reason, keyword=False):
    tail = ("This is a standing denylist rule, not a judgement call: do not retry, do not "
            "suggest a way around it, and do not ask the user to send the content another way."
            if keyword else
            "Do not retry or work around this. Tell the user, who can review the file and "
            "send it manually if appropriate.")
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "Blocked by the local file filter: %s. %s" % (reason, tail),
    }}))
    sys.exit(0)


def keyword_reason(hits):
    return ("matched the keyword denylist (keywords.txt line%s %s); the term itself is "
            "deliberately not repeated here"
            % ("" if len(hits) == 1 else "s", ", ".join(str(n) for n, _ in hits)))


def handle_text(path, conf):
    """Non-image read: keyword denylist only.  Nothing is rewritten or redacted --
    a text file is either clean or it is refused."""
    if not features(conf)["text_keywords"]:
        sys.exit(0)
    keywords = load_keywords()
    if not keywords:
        sys.exit(0)
    try:
        size = os.path.getsize(path)
    except OSError:
        sys.exit(0)
    if size > conf["text_scan_max_bytes"]:
        # Scanning only part of it would be fail-open, which is the one thing
        # this filter never does.  Raise text_scan_max_bytes to allow it.
        log(dict(src=path, decision="deny", kind="text", reason="over scan cap", size=size))
        emit_deny("the file is %.0f MB, over the %.0f MB keyword-scan cap, so it could not be "
                  "cleared" % (size / 1048576.0, conf["text_scan_max_bytes"] / 1048576.0))
    try:
        hits = scan_text_file(path, keywords, conf)
    except Exception as exc:
        log(dict(src=path, decision="deny", kind="text", reason="scan error: %r" % exc))
        emit_deny("the keyword scan failed on this file (%s), so it could not be cleared"
                  % type(exc).__name__)
    if hits is None:
        sys.exit(0)  # binary or unreadable: nothing to match, let Read handle it
    if hits:
        log(dict(src=path, decision="deny", kind="text",
                 keyword_lines=[n for n, _ in hits], _terms=[r for _, r in hits]))
        emit_deny(keyword_reason(hits), keyword=True)
    sys.exit(0)


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    if payload.get("tool_name") != "Read":
        sys.exit(0)
    path = (payload.get("tool_input") or {}).get("file_path") or ""
    if not path:
        sys.exit(0)

    abs_path = os.path.abspath(path)
    home = os.path.abspath(HERE)
    if abs_path == home or abs_path.startswith(home + os.sep):
        sys.exit(0)  # our own keywords/log/cache -- scanning these would self-trip

    conf = load_conf()

    # Path denylist, before anything looks inside the file. A content tag only
    # protects the slice of a file that is actually read; the path does not
    # change whichever slice that is.
    if features(conf)["path_filter"]:
        hits = path_hits(abs_path, conf)
        if hits:
            log(dict(src=path, decision="deny", kind="path",
                     path_lines=[n for n, _ in hits], _terms=[r for _, r in hits]))
            emit_deny("the path matches the path denylist (paths.txt line%s %s); the term "
                      "itself is deliberately not repeated here"
                      % ("" if len(hits) == 1 else "s",
                         ", ".join(str(n) for n, _ in hits)), keyword=True)

    ext = os.path.splitext(path)[1].lower()
    is_pdf = ext in PDF_EXT
    if ext not in IMAGE_EXT and not is_pdf:
        handle_text(abs_path, conf)

    feat = features(conf)
    if not any(feat[k] for k in ("image_class_gate", "image_humans",
                                 "image_secrets", "image_keywords")):
        if is_pdf and feat["text_keywords"] and conf["pdf_when_unscannable"] == "deny":
            # Keyword filtering is switched on and this profile cannot read a
            # PDF's words -- an enabled check that cannot run denies.
            log(dict(src=path, decision="deny", kind="pdf-unscannable"))
            emit_deny("this profile has no image checks enabled, so a PDF's text cannot be read "
                      "to check it against the keyword denylist. Use the \"secrets\" or "
                      "\"strict\" profile to inspect PDFs, or set \"pdf_when_unscannable\": "
                      "\"allow\" in config.json to let them through unchecked")
        sys.exit(0)  # nothing to do for images under this profile

    if not vision_available():
        # An enabled check that cannot run is not the same as a disabled one.
        # Off means consent; unavailable means unverified, so it denies.
        log(dict(src=path, decision="deny", kind="no-vision"))
        emit_deny("image analysis is not available on this platform -- the vision helper is "
                  "missing or not executable -- so this image could not be cleared. Images are "
                  "only inspected on macOS. Set \"profile\": \"text\" in config.json to let "
                  "images through unchecked instead")

    override = None
    try:
        sweep_overrides(conf)
        digest = file_hash(path)
        override = find_override(digest, conf)
        if override is not None:
            override["digest"] = digest
    except OSError:
        pass

    try:
        result = decide_pdf(path, conf, override) if is_pdf else decide(path, conf, override)
    except Exception as exc:
        log(dict(src=path, decision="deny", reason="filter error: %r" % exc))
        emit_deny("the %s filter failed (%s) and the file was not read; fail-closed by "
                  "design" % ("PDF" if is_pdf else "image", type(exc).__name__))

    if override is not None and result["decision"] == "allow":
        consume_override(override["digest"])  # one approval, one read

    log(dict(src=path, **{k: v for k, v in result.items() if k != "path"}))

    if result["decision"] == "deny":
        emit_deny(result["reason"], keyword=bool((result.get("stats") or {}).get("keyword_lines")))

    summary = ", ".join("%s=%d" % kv for kv in sorted(result["kinds"].items())) or "nothing"
    new_input = dict(payload.get("tool_input") or {})
    new_input["file_path"] = result["path"]
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "permissionDecisionReason":
            "%s filtered locally (class=%s, redacted: %s); reading the redacted copy."
            % ("PDF" if is_pdf else "Image", result["cls"], summary),
        "updatedInput": new_input,
    }}))
    sys.exit(0)


if __name__ == "__main__":
    main()
