# 30-second pitch

"Dependabot opens the security PR, the major-version bump breaks your build, and the CVE sits in production. PatchPilot finishes the job. Nemotron Nano triages, Super writes the fix, and Ultra steps in only when Super fails. Then it proves the exploit works on the old version, proves it's closed on the new one, and attacks its own fix with variants. In our recorded PyJWT run it went green on attempt three, closed the exploit, blocked seven of eight variants, and told us about the one still open. You get a hashed proof certificate, not a promise."

## One-liners
1. Dependabot opens the PR. PatchPilot makes it pass, attacks its own fix, and hands you a proof certificate.
2. Green tests aren't proof: PatchPilot runs the exploit before and after, and tells you what's still open.
3. Three Nemotron tiers routed by failure: Nano triages, Super fixes, Ultra only when Super can't.
