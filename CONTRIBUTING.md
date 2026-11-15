# Adding an attack path to AETHER

The value of the range is that **others extend it**. A new path = a complete
**Exploit -> Remediate -> Detect** triad. Follow this recipe (use AP01 as a living reference).

## Checklist for an `APxx` path

A path is not considered "ready" until it has all **5 pieces**:

- [ ] **1. Flag** in `terraform/variables.tf` -> `variable "enable_apXX" { default = false }`.
- [ ] **2. Misconfig as code**: the vulnerable resource, in whichever domain module applies
      (`entra-identity`, `azure-resources` or `hybrid-ad`), wrapped in `count = var.enable_apXX ? 1 : 0`.
- [ ] **3. Seed** (when Terraform can't reach it): idempotent `scripts/seed-apXX.ps1`, invoked by `aether.ps1`.
- [ ] **4. Doc** `docs/attack-paths/APxx-<slug>.md` using the template below.
- [ ] **5. Detection**: `detections/kql/APxx-*.kql` **and** `detections/sigma/APxx-*.yml`.

And register the row in the *Catalog* table of the `README.md`.

## Path doc template

```markdown
# APxx — <name>

- **Layer:** Entra | Azure | Hybrid
- **Cost:** ~0 | low | VM
- **MITRE ATT&CK:** Txxxx (<tactic/technique>)
- **Maps to cert:** CARTP | CARTE | CRTO | CRTE
- **Precondition:** <what the range leaves seeded>

## 🎯 Learning objective
<What the student understands by the end.>

## 🔴 Exploit (how it is exploited)
<Attack steps at a training level + public reference tooling.
No new offensive capabilities: describe the technique and link known docs/tooling.>

## 🟢 Remediate (remediation)
<The correct configuration, with the exact cmdlet/resource. Ideally the "antidote" that
your module applies when the flag goes back to false.>

## 🔵 Detect
<Which event/log gives it away + link to detections/kql and detections/sigma.>

## 📚 References
<Links: MITRE, MS docs, public writeups.>
```

## Principles

- **Always idempotent.** `deploy` twice = same state. `reset` removes the vuln without touching the base.
- **Realistic, not toy.** Prefer misconfigs you've seen in real engagements.
- **Clean teardown.** Nothing should survive a `destroy`.
- **Detection is part of the path, not an extra.** Without KQL/Sigma, the path doesn't ship.

## Suggested git flow

```bash
git switch -c path/apXX-<slug>
# ... implement the 5 pieces ...
git commit -m "AP-XX: <name> (exploit/remediate/detect)"
```
