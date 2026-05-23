#!/usr/bin/env python3
"""
Consolidate finding drafts into per-finding directories under piolium/findings/.

Reads every *.md file in <piolium_dir>/findings-draft/, parses its frontmatter,
keeps only Verdict: VALID drafts with Severity-Original in {CRITICAL, HIGH,
MEDIUM}, assigns deterministic severity-prefixed IDs (C1, C2..., H1, H2...,
M1, M2...), creates <piolium_dir>/findings/<ID>-<slug>/evidence/ for each,
copies the draft plus any adversarial review and chamber debate transcript,
writes metadata.json for variant findings, and emits a manifest JSON to both
stdout and <piolium_dir>/findings-draft/consolidation-manifest.json.

The manifest is the hand-off to the orchestrator: it lists each finding's
assigned ID, slug, folder, and original draft path so the orchestrator can
dispatch one poc-builder per entry without having to parse frontmatter itself.

Revisit mode: pass --continue-ids to seed the severity counters from the
max existing ID already present in <piolium_dir>/findings/. New finding
directories created in this mode also receive a metadata.json stamped with
round / revisit_id / model / agent_sdk (pulled from env vars the
orchestrator sets) so future revisits can attribute each finding to the
pass that produced it.

Env vars read in continuation mode:
    PIOLIUM_REVISIT_ROUND     integer round number (2 = first revisit)
    PIOLIUM_REVISIT_ID        ISO timestamp identifying the revisit
    PIOLIUM_REVISIT_MODEL     model string (e.g. opus-4.7)
    PIOLIUM_REVISIT_AGENT_SDK platform string (e.g. claude-code)

Usage:
    consolidate_drafts.py [piolium_dir] [--continue-ids]

piolium_dir defaults to "piolium". Exit codes:
    0  success
    1  no VALID Medium-or-higher drafts to consolidate
    2  usage error / piolium_dir missing
    3  I/O error during consolidation
"""

import json
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM"]
SEVERITY_PREFIX = {"CRITICAL": "C", "HIGH": "H", "MEDIUM": "M"}

FILENAME_RE = re.compile(r"^([a-z]+\d*)-(\d+)(?:-(.+))?\.md$")
KV_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 _-]*):\s*(.*)$")
EXISTING_FOLDER_RE = re.compile(r"^([CHM])(\d+)-")


@dataclass
class Draft:
    source_path: Path
    filename: str
    phase: str = ""
    sequence: str = ""
    slug: str = ""
    verdict: str = ""
    severity: str = ""
    debate_path: str = ""
    origin_finding: str = ""
    origin_pattern: str = ""
    assigned_id: str = ""
    origin_resolved_id: str = ""
    triage_priority: str = ""
    folder: Optional[Path] = field(default=None)

    @property
    def is_variant(self) -> bool:
        return bool(self.origin_finding)


def parse_frontmatter(path: Path) -> dict:
    """Parse the draft's Key: value header.

    The finding-draft template begins with '# [Title]' followed by a blank
    line, then Key: value lines, then a blank line, then '## Summary'. We
    skip leading blanks and the '#' title line, collect Key: value pairs
    until either a blank line or a '##' section heading appears.
    """
    out: dict = {}
    try:
        with path.open() as f:
            in_fm = False
            for line in f:
                s = line.rstrip("\n")
                if not in_fm:
                    if not s.strip():
                        continue  # leading blank lines
                    if s.startswith("# ") and not s.startswith("## "):
                        continue  # title line
                    if s.startswith("## "):
                        break  # no frontmatter at all
                    m = KV_RE.match(s)
                    if m:
                        out[m.group(1).strip()] = m.group(2).strip()
                        in_fm = True
                    continue
                # inside frontmatter
                if not s.strip():
                    break
                if s.startswith("## "):
                    break
                m = KV_RE.match(s)
                if m:
                    out[m.group(1).strip()] = m.group(2).strip()
    except OSError:
        pass
    return out


def parse_filename(filename: str) -> tuple[str, str, str]:
    m = FILENAME_RE.match(filename)
    if not m:
        base = filename[:-3] if filename.endswith(".md") else filename
        return "", "", base
    return m.group(1), m.group(2), m.group(3) or ""


def slugify(text: str) -> str:
    s = (text or "").lower().strip()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"[\s_]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s[:60] or "unknown"


def load_drafts(draft_dir: Path) -> list[Draft]:
    drafts: list[Draft] = []
    if not draft_dir.is_dir():
        return drafts
    for entry in sorted(os.listdir(draft_dir)):
        if not entry.endswith(".md"):
            continue
        if entry == "consolidation-manifest.json":
            continue
        path = draft_dir / entry
        if not path.is_file():
            continue
        fm = parse_frontmatter(path)
        phase_prefix, seq_from_name, slug_from_name = parse_filename(entry)
        d = Draft(source_path=path, filename=entry)
        d.phase = (fm.get("Phase") or phase_prefix or "").strip()
        d.sequence = (fm.get("Sequence") or seq_from_name or "").strip()
        slug_source = fm.get("Slug") or slug_from_name or path.stem
        d.slug = slugify(slug_source)
        d.verdict = (fm.get("Verdict") or "").strip().upper()
        d.severity = (fm.get("Severity-Original") or "").strip().upper()
        d.debate_path = (fm.get("Debate") or "").strip()
        d.origin_finding = (fm.get("Origin-Finding") or "").strip()
        d.origin_pattern = (fm.get("Origin-Pattern") or "").strip()
        d.triage_priority = (fm.get("Triage-Priority") or "").strip().lower()
        drafts.append(d)
    return drafts


def scan_existing_ids(findings_dir: Path) -> dict[str, int]:
    """Return the max existing ID number per severity prefix under findings/.

    Scans directory names matching `<C|H|M><number>-...` and returns a
    dict like {"C": 2, "H": 4, "M": 0} so a revisit run can seed its
    counters from that floor.
    """
    maxes = {"C": 0, "H": 0, "M": 0}
    if not findings_dir.is_dir():
        return maxes
    for entry in os.listdir(findings_dir):
        m = EXISTING_FOLDER_RE.match(entry)
        if not m:
            continue
        prefix = m.group(1)
        try:
            num = int(m.group(2))
        except ValueError:
            continue
        if num > maxes.get(prefix, 0):
            maxes[prefix] = num
    return maxes


def assign_ids(
    drafts: list[Draft],
    seed_counters: Optional[dict[str, int]] = None,
) -> tuple[list[Draft], list[dict], list[Draft]]:
    """Partition drafts into (kept, dropped, deferred).

    `deferred` are drafts that passed verdict + severity gates but were tagged
    `Triage-Priority: skip` by the finding-triager agent. They are not
    promoted to `piolium/findings/` (no PoC build) but are preserved under
    `piolium/findings-deferred/` so a human or follow-up audit can review.
    """
    kept: list[Draft] = []
    dropped: list[dict] = []
    deferred: list[Draft] = []
    for d in drafts:
        if d.verdict != "VALID":
            dropped.append(
                {"file": d.filename, "reason": f"verdict={d.verdict or 'MISSING'}"}
            )
            continue
        if d.severity not in SEVERITY_PREFIX:
            dropped.append(
                {"file": d.filename, "reason": f"severity={d.severity or 'MISSING'}"}
            )
            continue
        if d.triage_priority == "skip":
            deferred.append(d)
            continue
        kept.append(d)

    def sort_key(d: Draft):
        sev_rank = SEVERITY_ORDER.index(d.severity)
        # variants sort after non-variants of the same severity so the parent
        # exists in the id map by the time variant resolution runs.
        variant_rank = 1 if d.is_variant else 0
        try:
            seq_num = int(d.sequence)
        except (TypeError, ValueError):
            seq_num = 0
        return (sev_rank, variant_rank, d.phase, seq_num, d.filename)

    kept.sort(key=sort_key)

    # Seed counters from existing findings/ when running in revisit
    # continuation mode so new IDs don't collide with round-1 folders.
    counters = {sev: 0 for sev in SEVERITY_PREFIX}
    if seed_counters:
        for sev, prefix in SEVERITY_PREFIX.items():
            counters[sev] = seed_counters.get(prefix, 0)
    for d in kept:
        counters[d.severity] += 1
        d.assigned_id = f"{SEVERITY_PREFIX[d.severity]}{counters[d.severity]}"
    return kept, dropped, deferred


def resolve_variants(kept: list[Draft]) -> None:
    path_to_id: dict[str, str] = {}
    for d in kept:
        if d.is_variant:
            continue
        path_to_id[str(d.source_path)] = d.assigned_id
        path_to_id[d.source_path.name] = d.assigned_id
        path_to_id[f"piolium/findings-draft/{d.source_path.name}"] = d.assigned_id
        path_to_id[f"findings-draft/{d.source_path.name}"] = d.assigned_id

    for d in kept:
        if not d.is_variant:
            continue
        origin = d.origin_finding.strip()
        if not origin:
            continue
        if origin in path_to_id:
            d.origin_resolved_id = path_to_id[origin]
            continue
        basename = os.path.basename(origin)
        if basename in path_to_id:
            d.origin_resolved_id = path_to_id[basename]


def copy_if_exists(src: Path, dest: Path) -> bool:
    if src.is_file():
        shutil.copy2(src, dest)
        return True
    return False


def resolve_debate_path(raw: str, piolium_dir: Path) -> Optional[Path]:
    if not raw:
        return None
    p = Path(raw)
    candidates = [p]
    if not p.is_absolute():
        candidates.append(Path.cwd() / p)
        # Tolerate drafts that stored an piolium-relative path.
        if raw.startswith("piolium/"):
            candidates.append(piolium_dir.parent / p)
        else:
            candidates.append(piolium_dir / p)
    for c in candidates:
        if c.is_file():
            return c
    return None


def consolidate(piolium_dir: Path, continue_ids: bool = False) -> int:
    draft_dir = piolium_dir / "findings-draft"
    findings_dir = piolium_dir / "findings"
    adv_dir = piolium_dir / "adversarial-reviews"

    drafts = load_drafts(draft_dir)
    if not drafts:
        print(f"error: no draft files found in {draft_dir}", file=sys.stderr)
        return 1

    seed_counters: Optional[dict[str, int]] = None
    if continue_ids:
        seed_counters = scan_existing_ids(findings_dir)
        print(
            f"continue-ids: seeding counters from existing findings/: "
            f"C={seed_counters.get('C', 0)} H={seed_counters.get('H', 0)} "
            f"M={seed_counters.get('M', 0)}",
            file=sys.stderr,
        )

    revisit_meta: Optional[dict] = None
    if continue_ids:
        round_raw = os.environ.get("PIOLIUM_REVISIT_ROUND", "").strip()
        try:
            round_int = int(round_raw) if round_raw else 0
        except ValueError:
            round_int = 0
        revisit_meta = {
            "round": round_int or None,
            "revisit_id": os.environ.get("PIOLIUM_REVISIT_ID", "") or None,
            "model": os.environ.get("PIOLIUM_REVISIT_MODEL", "") or None,
            "agent_sdk": os.environ.get("PIOLIUM_REVISIT_AGENT_SDK", "") or None,
        }

    kept, dropped, deferred = assign_ids(drafts, seed_counters=seed_counters)
    deferred_out = _copy_deferred(deferred, piolium_dir)
    if not kept:
        manifest = {
            "piolium_dir": str(piolium_dir),
            "findings": [],
            "deferred": deferred_out,
            "dropped": dropped,
            "counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "total": 0,
                "dropped": len(dropped),
                "deferred": len(deferred_out),
            },
        }
        _write_manifest(draft_dir, manifest)
        print(json.dumps(manifest, indent=2))
        if deferred_out:
            print(
                f"warning: 0 VALID drafts promoted; "
                f"{len(deferred_out)} were deferred by triage (skip). "
                f"See {piolium_dir}/findings-deferred/.",
                file=sys.stderr,
            )
        else:
            print(
                "warning: no VALID Medium-or-higher drafts to consolidate",
                file=sys.stderr,
            )
        return 1

    resolve_variants(kept)
    findings_dir.mkdir(parents=True, exist_ok=True)

    findings_out: list[dict] = []
    for d in kept:
        folder = findings_dir / f"{d.assigned_id}-{d.slug}"
        evidence = folder / "evidence"
        evidence.mkdir(parents=True, exist_ok=True)
        d.folder = folder

        shutil.copy2(d.source_path, folder / "draft.md")

        if adv_dir.is_dir():
            for candidate in (
                adv_dir / f"{d.slug}-review.md",
                adv_dir / f"{d.source_path.stem}-review.md",
            ):
                if copy_if_exists(candidate, folder / "adversarial-review.md"):
                    break

        debate = resolve_debate_path(d.debate_path, piolium_dir)
        if debate is not None:
            shutil.copy2(debate, folder / "debate.md")

        meta: dict = {}
        if d.is_variant:
            meta.update(
                {
                    "is_variant": True,
                    "origin_finding_id": d.origin_resolved_id,
                    "origin_finding_draft": d.origin_finding,
                    "origin_pattern": d.origin_pattern,
                }
            )
        else:
            # Revisit findings always need a round stamp so the final report
            # can attribute them. Non-revisit runs don't emit metadata.json
            # for non-variants (backwards-compat with the report-assembler).
            if revisit_meta and revisit_meta.get("round"):
                meta["is_variant"] = False
        if revisit_meta and revisit_meta.get("round"):
            # Variant or not, round-2+ findings carry the revisit stamp so
            # round-1 findings stay distinguishable by the absence of
            # metadata.json (or by round==1 if explicitly written later).
            meta.update(
                {
                    "round": revisit_meta["round"],
                    "revisit_id": revisit_meta.get("revisit_id"),
                    "model": revisit_meta.get("model"),
                    "agent_sdk": revisit_meta.get("agent_sdk"),
                }
            )
        if meta:
            (folder / "metadata.json").write_text(
                json.dumps(meta, indent=2) + "\n"
            )

        findings_out.append(
            {
                "id": d.assigned_id,
                "slug": d.slug,
                "severity": d.severity,
                "folder": str(folder),
                "draft_path": str(d.source_path),
                "is_variant": d.is_variant,
                "origin_finding_id": d.origin_resolved_id if d.is_variant else "",
            }
        )

    counts = {
        "critical": sum(1 for d in kept if d.severity == "CRITICAL"),
        "high": sum(1 for d in kept if d.severity == "HIGH"),
        "medium": sum(1 for d in kept if d.severity == "MEDIUM"),
        "total": len(kept),
        "dropped": len(dropped),
        "deferred": len(deferred_out),
    }
    findings_out = _sort_by_triage_priority(findings_out, kept)
    manifest = {
        "piolium_dir": str(piolium_dir),
        "findings": findings_out,
        "deferred": deferred_out,
        "dropped": dropped,
        "counts": counts,
    }
    _write_manifest(draft_dir, manifest)
    print(json.dumps(manifest, indent=2))
    msg = (
        f"consolidated {counts['total']} findings "
        f"(C:{counts['critical']} H:{counts['high']} M:{counts['medium']})"
    )
    if counts["deferred"]:
        msg += f", deferred {counts['deferred']} (triage=skip)"
    msg += f", dropped {counts['dropped']}"
    print(msg, file=sys.stderr)
    return 0


def _copy_deferred(deferred: list[Draft], piolium_dir: Path) -> list[dict]:
    """Copy triage-deferred drafts into piolium/findings-deferred/ and return
    a serializable summary for the manifest. Each deferred draft is preserved
    so a human or follow-up audit can override the skip verdict.
    """
    if not deferred:
        return []
    deferred_dir = piolium_dir / "findings-deferred"
    deferred_dir.mkdir(parents=True, exist_ok=True)
    out: list[dict] = []
    for d in deferred:
        target = deferred_dir / d.source_path.name
        try:
            shutil.copy2(d.source_path, target)
        except OSError as exc:
            print(f"warning: could not defer {d.source_path}: {exc}", file=sys.stderr)
            continue
        out.append(
            {
                "filename": d.source_path.name,
                "slug": d.slug,
                "severity": d.severity,
                "triage_priority": d.triage_priority,
                "deferred_path": str(target),
                "source_path": str(d.source_path),
            }
        )
    return out


# Order in which P-priorities are processed by downstream poc-builder fan-out.
# Lower index = higher priority; unknown / missing priorities sort after P2 so
# the orchestrator still builds them but only after the explicitly-prioritized
# set has consumed its budget.
TRIAGE_PRIORITY_RANK = {"p0": 0, "p1": 1, "p2": 2, "": 3}


def _sort_by_triage_priority(
    findings_out: list[dict], kept: list[Draft]
) -> list[dict]:
    """Return findings_out sorted so triage P0 entries come first, then P1,
    then P2, then anything without a triage marker. Within each priority
    bucket the existing severity ordering is preserved (CRITICAL → HIGH →
    MEDIUM as already established by `assign_ids`).
    """
    by_id: dict[str, str] = {}
    for d in kept:
        by_id[d.assigned_id] = (d.triage_priority or "").lower()
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}

    def key(entry: dict):
        prio = by_id.get(entry.get("id", ""), "")
        prio_rank = TRIAGE_PRIORITY_RANK.get(prio, 3)
        sev_rank = severity_rank.get(entry.get("severity", ""), 9)
        return (prio_rank, sev_rank, entry.get("id", ""))

    return sorted(findings_out, key=key)


def _write_manifest(draft_dir: Path, manifest: dict) -> None:
    draft_dir.mkdir(parents=True, exist_ok=True)
    path = draft_dir / "consolidation-manifest.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    continue_ids = False
    positional: list[str] = []
    for arg in argv:
        if arg == "--continue-ids":
            continue_ids = True
        else:
            positional.append(arg)
    if len(positional) > 1:
        print(
            "usage: consolidate_drafts.py [piolium_dir] [--continue-ids]",
            file=sys.stderr,
        )
        sys.exit(2)

    piolium_dir = Path(positional[0]) if positional else Path("piolium")
    if not piolium_dir.is_dir():
        print(f"error: piolium dir not found: {piolium_dir}", file=sys.stderr)
        sys.exit(2)
    try:
        sys.exit(consolidate(piolium_dir, continue_ids=continue_ids))
    except OSError as e:
        print(f"error: I/O failure during consolidation: {e}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
