# orbit-check

Open, reproducible measurement of **traction-authenticity signals** on public GitHub repositories — star-event burst analysis and stargazer account-quality sampling, reported as conservative signal tiers.

> **What this is not:** a fraud detector. Signal tiers describe how much an observed pattern deviates from organic baselines. They are never a verdict about any repository, maintainer, or organization. See [methodology.md](methodology.md) for exactly what each tier does and does not mean, and for the correction process.

Published by **Anwen Labs**. Method adapted from He et al., *"Six Million (Suspected) Fake Stars in GitHub"* (arXiv:2412.13459, ICSE 2026).

## What it measures

1. **Temporal burst analysis** — burst ratio, top-day share, and 3σ spike days across the star-event history. Coordinated campaigns concentrate stars in short windows; organic growth decays over days.
2. **Stargazer account-quality sampling** — an evenly spaced sample (default n=150) of stargazer profiles checked for follower count, public repos, account age at star time, and deletion.
3. **Adoption cross-check (manual)** — package download counts vs. stars, reported as a ratio, not a verdict.

Output is one of four tiers: `tier-1-baseline`, `tier-2-moderate`, `tier-3-elevated`, or `insufficient-data`. Thresholds are published in [methodology.md](methodology.md) precisely so they can be criticized.

## Run it yourself

Authenticate once — analysis then runs on **your own** GitHub API quota (5,000 GraphQL points/hr). The tool reads public data only and requests **zero account permissions**.

> Authentication is required: GitHub restricted anonymous/REST access to stargazer data in June 2026. orbit-check uses the authenticated GraphQL API, which serves the same public star-event data to any signed-in caller — see the data-access note in [methodology.md](methodology.md).

```bash
# option A: one-time browser login (device flow; token cached locally —
# delete the cache file, whose path is printed at login, to log out)
python3 orbit_check.py --login

# option B: bring your own fine-grained PAT;
# GITHUB_TOKEN always takes precedence over a cached login
export GITHUB_TOKEN=ghp_...

# single repo (default: most recent 4,000 star events, newest first)
python3 orbit_check.py --repo owner/name

# batch: one owner/name per line
python3 orbit_check.py repos.txt

# examine launch-era history instead of the recent window
python3 orbit_check.py --repo owner/name --direction oldest --max-events 8000
```

No dependencies beyond the Python 3 standard library. Account statistics cover **every** stargazer in the observed window (profile fields arrive inline with each star event — no sampling). Stargazer identities are never written to output; `scores.json` contains aggregates only, and result files are committed alongside each report for reproducibility.

Rate budget: a 10-repo run at default settings costs well under 500 of your 5,000 hourly GraphQL points and finishes in a few minutes; requests are paced to respect GitHub's secondary rate limits.

## Corrections

Maintainers who believe a flagged signal is explained by a legitimate event (press coverage, Hacker News front page, conference talk) can contact us with the date. Verified explanations are published alongside the tier.

## License

MIT — see [LICENSE](LICENSE).
