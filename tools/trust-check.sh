#!/usr/bin/env bash
# Check the public evidence for this project from three independent sources, with no
# account and no token: the OpenSSF Scorecard API, deps.dev and OSV.
#
#   tools/trust-check.sh [--repo OWNER/NAME] [--package PYPI_NAME] [--version X.Y.Z]
#                        [--require-package]
#
# Exit status:
#   0  every source answered and none reported a critical finding
#   1  a source could not be checked (not public yet, not found, no network). This is
#      "not verified", never "fine".
#   2  a critical finding (see docs/VERIFY.md, "What counts as critical")
#
# It reads three public web APIs and writes nothing. It needs bash, curl and python3.
# What it shows is how the project is built and maintained, and whether known
# vulnerabilities are listed against the published package. It does not show the
# absence of vulnerabilities. See docs/VERIFY.md.
set -u

REPO="${TRUST_REPO:-tokenorama/tokenorama}"
PKG="${TRUST_PACKAGE:-tokenorama}"
VERSION=""
REQUIRE_PKG=0

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --repo)            REPO="${2:?--repo needs OWNER/NAME}"; shift 2 ;;
    --package)         PKG="${2:?--package needs a PyPI name}"; shift 2 ;;
    --version)         VERSION="${2:?--version needs a version}"; shift 2 ;;
    --require-package) REQUIRE_PKG=1; shift ;;
    -h|--help)         usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 64 ;;
  esac
done

case "$REPO" in
  */*) ;;
  *) echo "--repo must look like OWNER/NAME, got: $REPO" >&2; exit 64 ;;
esac
case "$REPO$PKG$VERSION" in
  *[!A-Za-z0-9._/-]*) echo "refusing odd characters in arguments" >&2; exit 64 ;;
esac

for tool in curl python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "needs $tool on PATH" >&2; exit 1; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# get NAME URL: save the body as $WORK/NAME.json and the HTTP status as $WORK/NAME.code
# (000 when no answer came back at all).
get() {
  local code
  code="$(curl -sS --proto '=https' --tlsv1.2 --max-time 30 -H 'Accept: application/json' \
            -o "$WORK/$1.json" -w '%{http_code}' "$2" 2>"$WORK/$1.err")" || code=000
  printf '%s' "$code" >"$WORK/$1.code"
}

OWNER="${REPO%%/*}"
NAME="${REPO#*/}"

get scorecard "https://api.scorecard.dev/projects/github.com/$OWNER/$NAME"
get project   "https://api.deps.dev/v3/projects/github.com%2F$OWNER%2F$NAME"
get package   "https://api.deps.dev/v3/systems/pypi/packages/$PKG"

# The version to check: --version, else the default (latest) one deps.dev names.
if [ -z "$VERSION" ] && [ "$(cat "$WORK/package.code")" = 200 ]; then
  VERSION="$(python3 -I - "$WORK/package.json" <<'PY'
import json, sys
vs = json.load(open(sys.argv[1])).get("versions", [])
pick = [v for v in vs if v.get("isDefault")] or vs[-1:]
print(pick[0]["versionKey"]["version"] if pick else "")
PY
)"
fi
if [ -n "$VERSION" ]; then
  get version "https://api.deps.dev/v3/systems/pypi/packages/$PKG/versions/$VERSION"
  # OSV is a POST with a JSON body; build it with python so the values are quoted safely.
  BODY="$(python3 -I -c 'import json,sys; print(json.dumps({"package":{"name":sys.argv[1],"ecosystem":"PyPI"},"version":sys.argv[2]}))' "$PKG" "$VERSION")"
  code="$(curl -sS --proto '=https' --tlsv1.2 --max-time 30 -H 'Content-Type: application/json' \
            -d "$BODY" -o "$WORK/osv.json" -w '%{http_code}' https://api.osv.dev/v1/query \
            2>"$WORK/osv.err")" || code=000
  printf '%s' "$code" >"$WORK/osv.code"
  # Advisories deps.dev lists against that version, with their scores.
  python3 -I - "$WORK" <<'PY'
import json, os, subprocess, sys
w = sys.argv[1]
try:
    keys = [k["id"] for k in json.load(open(f"{w}/version.json")).get("advisoryKeys", [])]
except Exception:
    keys = []
out = []
for k in keys:
    p = subprocess.run(["curl", "-sS", "--proto", "=https", "--max-time", "30",
                        "https://api.deps.dev/v3/advisories/" + k],
                       capture_output=True, text=True)
    try:
        out.append(json.loads(p.stdout))
    except Exception:
        out.append({"advisoryKey": {"id": k}, "fetch_failed": True})
json.dump(out, open(f"{w}/advisories.json", "w"))
PY
fi

python3 -I - "$WORK" "$REPO" "$PKG" "$VERSION" "$REQUIRE_PKG" <<'PY'
import json, os, sys

work, repo, pkg, version, require_pkg = sys.argv[1:6]
require_pkg = require_pkg == "1"
unverified, critical = [], []


def code(name):
    try:
        return open(f"{work}/{name}.code").read().strip()
    except OSError:
        return "---"


def body(name):
    try:
        return json.load(open(f"{work}/{name}.json"))
    except Exception:
        return None


def why_not(name, label):
    c = code(name)
    if c == "000":
        try:
            err = open(f"{work}/{name}.err").read().strip().splitlines()[-1]
        except Exception:
            err = "no answer"
        return f"{label}: no answer ({err})"
    if c == "404":
        return f"{label}: not found (HTTP 404)"
    return f"{label}: HTTP {c}"


print(f"Repository  github.com/{repo}")
print(f"Package     {pkg} (PyPI)" + (f" {version}" if version else ""))

# 1. Scorecard ------------------------------------------------------------------------
print("\n== OpenSSF Scorecard (api.scorecard.dev) ==")
sc = body("scorecard") if code("scorecard") == "200" else None
if not sc or "checks" not in sc:
    msg = why_not("scorecard", "Scorecard")
    print(msg + "\n  No published result. The repository may be private, or Scorecard has not run on it yet.")
    unverified.append(msg)
else:
    print(f"score {sc.get('score')} / 10   scored {sc.get('date')}   commit {str(sc.get('repo', {}).get('commit'))[:12]}")
    checks = sc["checks"]
    for c in sorted(checks, key=lambda c: (c["score"] if c["score"] >= 0 else 99, c["name"])):
        s = "n/a" if c["score"] < 0 else str(c["score"])
        print(f"  {s:>3}  {c['name']}")
    dw = [c for c in checks if c["name"] == "Dangerous-Workflow"]
    if dw and 0 <= dw[0]["score"] < 10:
        critical.append(f"Scorecard Dangerous-Workflow scored {dw[0]['score']}/10: {dw[0].get('reason')}")

# 2. deps.dev project -----------------------------------------------------------------
print("\n== deps.dev: project ==")
pj = body("project") if code("project") == "200" else None
if not pj:
    msg = why_not("project", "deps.dev project")
    print(msg)
    unverified.append(msg)
else:
    print(f"licence {pj.get('license')}   open issues {pj.get('openIssuesCount')}   "
          f"OSS-Fuzz {'yes' if pj.get('ossFuzz') else 'no'}")
    if pj.get("scorecard"):
        print(f"deps.dev copy of Scorecard: {pj['scorecard'].get('overallScore')} "
              f"on {pj['scorecard'].get('date')}")

# 3. deps.dev package, advisories, OSV -----------------------------------------------
print("\n== deps.dev: package and OSV ==")
if code("package") == "404":
    msg = f"{pkg} is not published on PyPI (deps.dev has no such package)"
    print(msg)
    if require_pkg:
        unverified.append(msg)
    else:
        print("  Skipped: pass --require-package to treat this as unverified.")
elif code("package") != "200" or not version:
    msg = why_not("package", "deps.dev package")
    print(msg)
    unverified.append(msg)
else:
    ver = body("version") if code("version") == "200" else None
    if ver is None:
        msg = why_not("version", f"deps.dev {pkg} {version}")
        print(msg)
        unverified.append(msg)
    else:
        print(f"{pkg} {version}  published {ver.get('publishedAt')}  licences {ver.get('licenses')}")
        print(f"  build provenance records on deps.dev: {len(ver.get('slsaProvenances', []))}"
              f"   attestations: {len(ver.get('attestations', []))}")
        advs = body("advisories") or []
        print(f"  advisories listed by deps.dev: {len(advs)}")
        for a in advs:
            score = a.get("cvss3Score")
            print(f"    {a['advisoryKey']['id']}  CVSS3 {score}  {a.get('title', '')[:70]}")
            if a.get("fetch_failed"):
                unverified.append(f"could not read advisory {a['advisoryKey']['id']}")
            elif score is not None and score >= 9.0:
                critical.append(f"{pkg} {version}: {a['advisoryKey']['id']} (CVSS3 {score})")
    # OSV is asked on its own, so a gap at deps.dev never hides an OSV finding.
    if code("osv") != "200":
        msg = why_not("osv", "OSV")
        print(msg)
        unverified.append(msg)
    else:
        vulns = (body("osv") or {}).get("vulns", [])
        print(f"  vulnerabilities listed by OSV: {len(vulns)}")
        for v in vulns:
            sev = (v.get("database_specific") or {}).get("severity", "unrated")
            print(f"    {v['id']}  severity {sev}  {v.get('summary', '')[:70]}")
            if str(sev).upper() == "CRITICAL":
                critical.append(f"{pkg} {version}: {v['id']} (OSV severity CRITICAL)")

print("\n== Result ==")
for c in critical:
    print("CRITICAL  " + c)
for u in unverified:
    print("NOT VERIFIED  " + u)
if critical:
    print("exit 2: critical finding")
    sys.exit(2)
if unverified:
    print("exit 1: at least one source could not be checked, so this is not a pass")
    sys.exit(1)
print("exit 0: all sources answered; no critical finding. This is not a statement that the code is free of vulnerabilities.")
PY
