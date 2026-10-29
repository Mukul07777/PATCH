# 30-second pitch

"Dependabot opens the security PR, the major-version bump breaks your build, and the CVE sits in production. PatchPilot finishes the job. Nemotron Nano triages, Super writes the fix, and Ultra steps in only when Super fails. Then it proves the exploit works on the old version, proves it's closed on the new one, and attacks its own fix with variants. In our recorded PyJWT run on Nebius Token Factory it read the PyJWT changelog through Tavily, went green on attempt two, closed the exploit, blocked seven of eight variants, and told us about the one still open. You get a hashed proof certificate, not a promise."

About 96 words: aim for 30 seconds at a brisk pace, and trim the "In our recorded PyJWT run" sentence first if it runs long.

## 15-second version
"Security bots open the PR and stop when the build breaks. PatchPilot rewrites your code until the tests pass, proves the exploit is closed, and attacks its own fix, using Nemotron Nano, Super and Ultra on Nebius Token Factory."

## Delivery notes
- Lead with the pain (red Dependabot PR), not the tech.
- Say the three numbers from the recorded run only: attempt three, exploit closed, seven of eight variants blocked.
- Close on "proof certificate, not a promise"; pause before it.
- Recorded run: `20261029-153834-job` (authsvc, Nebius Token Factory): 8 Tavily sources, green on attempt 2 after Super-to-Ultra escalation with 3 changelog lines quoted, exploit proven closed, 7/8 variants blocked, 110.7 s end to end. Full benchmark: 6 of 6 cases green.

## One-liners
1. Dependabot opens the PR. PatchPilot makes it pass, attacks its own fix, and hands you a proof certificate.
2. Green tests aren't proof: PatchPilot runs the exploit before and after, and tells you what's still open.
3. Three Nemotron tiers routed by failure: Nano triages, Super fixes, Ultra only when Super can't.
