#!/usr/bin/env python3
"""
orbit_check.py — Traction authenticity signal analysis for GitHub repos.

Implements a lightweight version of the detection signals from He et al.,
"Six Million (Suspected) Fake Stars in GitHub" (arXiv:2412.13459, ICSE 2026):
  1. Star-event burst detection (fake campaigns cluster in time)
  2. Stargazer account-quality analysis (low-activity account prevalence)

IMPORTANT FRAMING RULE: output is statistical SIGNAL TIERS, never fraud
verdicts. Every number in the report must trace to this script's JSON output.

Data access: the GraphQL API (stargazers connection, starredAt + inline
account fields). GitHub restricted the REST stargazers endpoint to repo
admins/collaborators (changelog, Jun 30 2026); GraphQL still serves the same
data to any authenticated caller, so authentication is REQUIRED:

  python3 orbit_check.py --login       # one-time browser auth (device flow,
                                       # zero scopes); token cached locally
  export GITHUB_TOKEN=ghp_...          # alternative: fine-grained PAT;
                                       # overrides --login
  python3 orbit_check.py repos.txt     # one owner/name per line
  python3 orbit_check.py --repo modelcontextprotocol/servers

Rate budget: GraphQL = 5,000 points/hr. One page of 100 stargazers with
inline account fields costs ~1 point; a 10-repo run at default settings
(4,000 events each) spends well under 500 points and finishes in minutes.

Privacy: stargazer logins are never written to output — only aggregate
statistics leave this process, so scores.json is safe to publish.
"""

import argparse
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import date, datetime, timezone

GRAPHQL_URL = "https://api.github.com/graphql"

# Public client id of the Anwen Labs "orbit-check" OAuth app (device flow
# enabled, NO scopes — public read only). Not a secret.
OAUTH_CLIENT_ID = "Ov23liHhh0N5EuoJsfRw"
DEVICE_CODE_URL = "https://github.com/login/device/code"
ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"

# Burst conditions are only meaningful when the observed window spans enough
# calendar days — a truncated capture of a launch day is 100% top-day-share
# by construction. Narrower windows tier on account quality alone.
MIN_BURST_WINDOW_DAYS = 14

STARGAZER_QUERY = """
query($owner: String!, $name: String!, $cursor: String, $pageSize: Int!,
      $direction: OrderDirection!) {
  rateLimit { cost remaining resetAt }
  repository(owner: $owner, name: $name) {
    nameWithOwner
    stargazerCount
    forkCount
    createdAt
    pushedAt
    description
    issues(states: OPEN) { totalCount }
    stargazers(first: $pageSize, after: $cursor,
               orderBy: {field: STARRED_AT, direction: $direction}) {
      pageInfo { hasNextPage endCursor }
      edges {
        starredAt
        node {
          createdAt
          followers { totalCount }
          repositories(privacy: PUBLIC) { totalCount }
        }
      }
    }
  }
}
"""


def token_cache_path():
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/.config")
    return os.path.join(base, "orbit-check", "token")


def read_cached_token():
    try:
        with open(token_cache_path()) as f:
            return f.read().strip()
    except OSError:
        return ""


def write_cached_token(token):
    path = token_cache_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token)
    return path


def resolve_token():
    """GITHUB_TOKEN env always wins; falls back to the --login cache."""
    return os.environ.get("GITHUB_TOKEN", "") or read_cached_token()


def oauth_post(url, params):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(params).encode())
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "anwen-traction-research")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def device_login(client_id):
    """GitHub Device Flow: user authorizes in their browser, API calls run on
    their own rate budget (5,000 points/hr). No scopes are requested — the tool
    reads public data only. Token is cached locally; delete the file to log out.
    """
    if not client_id:
        sys.exit("--login needs an OAuth client id: pass --client-id or set "
                 "ORBIT_CHECK_CLIENT_ID.\nMaintainers: register a GitHub OAuth "
                 "app with device flow enabled; only its public client id is "
                 "needed (no secret), pasted into OAUTH_CLIENT_ID.")
    grant = oauth_post(DEVICE_CODE_URL, {"client_id": client_id, "scope": ""})
    print(f"\nOpen {grant['verification_uri']} and enter code: "
          f"{grant['user_code']}\n(expires in {int(grant['expires_in']) // 60} "
          f"min; no account permissions are requested)\n", file=sys.stderr)
    interval = int(grant.get("interval", 5))
    deadline = time.time() + int(grant["expires_in"])
    while time.time() < deadline:
        time.sleep(interval)
        resp = oauth_post(ACCESS_TOKEN_URL, {
            "client_id": client_id,
            "device_code": grant["device_code"],
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code"})
        if "access_token" in resp:
            path = write_cached_token(resp["access_token"])
            print(f"authorized — token cached at {path}", file=sys.stderr)
            return resp["access_token"]
        err = resp.get("error")
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval = int(resp.get("interval", interval + 5))
            continue
        sys.exit(f"device flow failed: {err}: {resp.get('error_description', '')}")
    sys.exit("device flow timed out before authorization")


def gql_post(query, variables, token, attempt=0):
    req = urllib.request.Request(
        GRAPHQL_URL, data=json.dumps({"query": query, "variables": variables}).encode())
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "anwen-traction-research")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code in (502, 503):  # transient GraphQL gateway errors
            time.sleep(10)
            return gql_post(query, variables, token)
        if e.code in (403, 429) and attempt < 5:  # secondary rate limit
            wait = int(e.headers.get("Retry-After") or 60)
            print(f"  [rate] secondary limit ({e.code}), sleeping {wait}s",
                  file=sys.stderr)
            time.sleep(wait)
            return gql_post(query, variables, token, attempt + 1)
        raise
    if body.get("errors"):
        raise RuntimeError(f"GraphQL: {body['errors'][0].get('message', body['errors'])}")
    rl = body["data"].get("rateLimit") or {}
    if rl.get("remaining", 5000) < 20:
        reset = datetime.fromisoformat(rl["resetAt"].replace("Z", "+00:00"))
        wait = max((reset - datetime.now(timezone.utc)).total_seconds(), 0) + 5
        print(f"  [rate] {rl['remaining']} points left, sleeping {int(wait)}s",
              file=sys.stderr)
        time.sleep(wait)
    return body["data"]


def fetch_stargazers(owner, name, token, max_events, direction):
    """Star events with inline account fields, 100 per request.

    Newest-first (DESC) by default: purchased campaigns on *currently
    trending* repos live in the recent window, and the REST-era bias toward
    launch history is exactly what produced false burst flags. Deleted or
    suspended accounts surface as null nodes and are counted per event.
    Logins are deliberately not retained.
    """
    events, cursor, meta = [], None, None
    while len(events) < max_events:
        page = min(100, max_events - len(events))
        data = gql_post(STARGAZER_QUERY, {
            "owner": owner, "name": name, "cursor": cursor,
            "pageSize": page, "direction": direction}, token)
        repo = data["repository"]
        if repo is None:
            raise RuntimeError(f"repository {owner}/{name} not found")
        if meta is None:
            meta = {
                "full_name": repo["nameWithOwner"],
                "stars": repo["stargazerCount"],
                "forks": repo["forkCount"],
                "created_at": repo["createdAt"],
                "pushed_at": repo["pushedAt"],
                "open_issues": repo["issues"]["totalCount"],
                "description": (repo["description"] or "")[:200],
            }
        conn = repo["stargazers"]
        for edge in conn["edges"]:
            node = edge["node"]
            events.append({
                "starred_at": edge["starredAt"],
                "deleted": node is None,
                "followers": node["followers"]["totalCount"] if node else None,
                "public_repos": node["repositories"]["totalCount"] if node else None,
                "account_created_at": node["createdAt"] if node else None,
            })
        if not conn["pageInfo"]["hasNextPage"]:
            break
        cursor = conn["pageInfo"]["endCursor"]
        time.sleep(0.7)  # pace pagination below the secondary-limit radar
    return meta, events


def burst_metrics(events):
    """Daily star counts; flag statistical bursts.

    Fake-star campaigns concentrate in short windows (He et al. found
    coordinated bursts from account clusters). Signals:
      - burst_ratio: max daily stars / median nonzero daily stars
      - spike_days: days exceeding mean + 3*stdev of nonzero days
      - top_day_share: fraction of all observed stars landing on the top day
    window_span_days records how many calendar days the observed window
    covers — assign_tier ignores burst conditions below MIN_BURST_WINDOW_DAYS.
    """
    if not events:
        return {}
    days = Counter(e["starred_at"][:10] for e in events)
    counts = sorted(days.values())
    med = statistics.median(counts)
    mean = statistics.mean(counts)
    stdev = statistics.pstdev(counts) if len(counts) > 1 else 0.0
    threshold = mean + 3 * stdev
    spikes = {d: c for d, c in days.items() if c > threshold and c >= 10}
    top_day, top_count = max(days.items(), key=lambda kv: kv[1])
    dates = sorted(days)
    span = (date.fromisoformat(dates[-1]) - date.fromisoformat(dates[0])).days + 1
    return {
        "observed_events": len(events),
        "distinct_days": len(days),
        "window_from": dates[0],
        "window_to": dates[-1],
        "window_span_days": span,
        "median_daily": med,
        "max_daily": top_count,
        "top_day": top_day,
        "burst_ratio": round(top_count / med, 1) if med else None,
        "top_day_share": round(top_count / len(events), 3),
        "spike_days": dict(sorted(spikes.items(), key=lambda kv: -kv[1])[:10]),
    }


def account_metrics(events):
    """Account-quality signals over EVERY fetched stargazer.

    GraphQL returns account fields inline with each star event, so there is
    no sampling step (the REST version checked an n=150 sample). Heuristics
    per He et al.'s account clustering:
      weak account:  zero followers AND <=1 public repo
      young-weak:    weak AND account younger than 90 days when it starred
    """
    if not events:
        return {}
    checked = deleted = weak = young_weak = 0
    ages = []
    for ev in events:
        if ev["deleted"]:
            deleted += 1
            continue
        checked += 1
        created = datetime.fromisoformat(ev["account_created_at"].replace("Z", "+00:00"))
        starred = datetime.fromisoformat(ev["starred_at"].replace("Z", "+00:00"))
        age_at_star = (starred - created).days
        ages.append(age_at_star)
        if ev["followers"] == 0 and ev["public_repos"] <= 1:
            weak += 1
            if age_at_star < 90:
                young_weak += 1
    return {
        "profiles_checked": checked,
        "deleted_accounts": deleted,
        "weak_account_pct": round(100 * weak / checked, 1) if checked else None,
        "young_weak_account_pct": round(100 * young_weak / checked, 1) if checked else None,
        "median_account_age_at_star_days": statistics.median(ages) if ages else None,
    }


def assign_tier(burst, profiles):
    """Conservative signal tiers. Tier language, never verdicts.

    Tier 3 (elevated signals):  burst_ratio>=50 or top_day_share>=0.25,
                                AND young_weak_account_pct>=30
    Tier 2 (moderate signals):  any one of the above conditions
    Tier 1 (baseline):          none of the above
    Insufficient: <100 observed events or <50 profiles checked

    Burst conditions are only evaluated when the observed window spans
    >= MIN_BURST_WINDOW_DAYS calendar days; a repo that earned its whole
    observed window in a few days (launch capture) would otherwise flag on
    top-day concentration by construction. Narrow windows tier on account
    quality alone.
    """
    if not burst or burst.get("observed_events", 0) < 100:
        return "insufficient-data"
    if not profiles or (profiles.get("profiles_checked") or 0) < 50:
        return "insufficient-data"
    window_ok = (burst.get("window_span_days") or 0) >= MIN_BURST_WINDOW_DAYS
    burst_hit = window_ok and ((burst.get("burst_ratio") or 0) >= 50
                               or (burst.get("top_day_share") or 0) >= 0.25)
    acct_hit = (profiles.get("young_weak_account_pct") or 0) >= 30
    if burst_hit and acct_hit:
        return "tier-3-elevated"
    if burst_hit or acct_hit:
        return "tier-2-moderate"
    return "tier-1-baseline"


def analyze(owner, name, token, max_events, direction):
    which = "newest" if direction == "DESC" else "oldest"
    print(f"[{owner}/{name}] fetching up to {max_events} star events "
          f"({which} first, profiles inline)...", file=sys.stderr)
    meta, events = fetch_stargazers(owner, name, token, max_events, direction)
    burst = burst_metrics(events)
    profiles = account_metrics(events)
    tier = assign_tier(burst, profiles)
    if meta["stars"] > len(events):
        end = "most recent" if direction == "DESC" else "first"
        coverage = f"analysis covers {end} {len(events)} of {meta['stars']} stars"
    else:
        coverage = "full star history analyzed"
    return {"repo": meta, "burst": burst, "profiles": profiles,
            "signal_tier": tier, "coverage_note": coverage}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("repo_file", nargs="?", help="file with owner/name per line")
    p.add_argument("--repo", help="single owner/name")
    p.add_argument("--max-events", type=int, default=4000,
                   help="star events to fetch per repo (100 per request)")
    p.add_argument("--direction", choices=["newest", "oldest"], default="newest",
                   help="which end of the star history to examine (default: newest)")
    p.add_argument("--out", default="scores.json")
    p.add_argument("--login", action="store_true",
                   help="authorize via GitHub device flow (your own rate budget); token cached locally")
    p.add_argument("--client-id", default=os.environ.get("ORBIT_CHECK_CLIENT_ID", OAUTH_CLIENT_ID),
                   help="OAuth app client id for --login (public, not a secret)")
    args = p.parse_args()

    if args.login:
        device_login(args.client_id)
        if not (args.repo or args.repo_file):
            return

    token = resolve_token()
    if not token:
        sys.exit("a token is required: run --login (device flow, zero account "
                 "permissions) or set GITHUB_TOKEN. GitHub restricted anonymous/"
                 "REST stargazer access (changelog 2026-06-30); this tool uses "
                 "the authenticated GraphQL API.")

    repos = []
    if args.repo:
        repos.append(args.repo)
    if args.repo_file:
        with open(args.repo_file) as f:
            repos += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

    direction = "DESC" if args.direction == "newest" else "ASC"
    results = []
    for full in repos:
        owner, name = full.split("/", 1)
        try:
            results.append(analyze(owner, name, token, args.max_events, direction))
        except Exception as e:
            results.append({"repo": {"full_name": full}, "error": str(e)})
    with open(args.out, "w") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(),
                   "methodology": "orbit-check v2 (GraphQL) — see methodology.md",
                   "window_direction": args.direction,
                   "results": results}, f, indent=2)
    print(f"wrote {args.out}", file=sys.stderr)
    for r in results:
        n = r["repo"]["full_name"]
        print(f"{n}: {r.get('signal_tier', 'ERROR: ' + r.get('error', '?'))}")


if __name__ == "__main__":
    main()
