# before-the-first-sync

Everything that has to be right before an Active Directory forest is
synchronised to Entra ID — checked against a **real forest**, built from scratch
and torn down in the same job.

## The problem

Hybrid identity migrations rarely fail at the sync. They fail at the objects,
weeks earlier, in ways nobody looked for: a `.local` namespace that cannot be
verified, two people holding the same address in different letter case, a
disabled leaver holding the sign-in name a new starter needs. The sync then
works exactly as designed, and the outcome is users who cannot sign in.

The second failure is worse and quieter. **Narrowing an OU filter deletes the
objects that fall out of scope** — along with their mailboxes, group memberships
and licences. It is not a disable. It looks like housekeeping.

## What this proves

A domain controller is built, a forest is populated with deliberately broken
objects, and the assessment runs against **live directory data** rather than
fixtures. Then the mechanically safe fixes are applied in that forest and it is
assessed again.

The point is not that the assessment finds problems. It is that it finds
**exactly the ones that were planted**, which is the only way to tell a useful
check from one that fires on everything:

| | |
|---|---|
| Objects in the forest | 12 |
| With planted defects | 10, each declaring the finding it must produce |
| Declared clean | 2, and a finding against either fails the run |

The defects live in [`lab-objects.json`](lab-objects.json). A check that fires
on everything and a check that fires on the right things produce identically
confident output until that file exists.

## The checks worth reading

**An unverified UPN suffix is not a sync error.** The object syncs; its sign-in
name is silently rewritten to the tenant's default domain. So the symptom
arrives as a user who cannot sign in with the address on their business card,
which is a far harder thing to trace back to a decision made weeks earlier.

**Disabled objects hold their names.** A long-forgotten leaver occupies the
`userPrincipalName` a current employee needs, and Entra refuses both. The object
causing it is invisible in every list anybody thinks to check, so the report
names both sides and says the disabled one is not exempt.

**Address duplicates hide in letter case.** `proxyAddresses` carries its type as
a prefix, and that prefix's case is meaningful: `SMTP:` is the primary address,
`smtp:` an alias. Read two raw values side by side and they look different.
Entra treats them as the same address and refuses both objects.

**An attribute that cannot be evaluated is never reported as passing.** If an
object has no `userPrincipalName` there is no suffix to check, and a report that
quietly counts it as having a valid suffix is worse than one that never looked —
it has told somebody the object is ready. Those come back `Unevaluated`.

**OU filters match on component boundaries.** `OU=Sales,DC=corp,DC=local` must
not capture `OU=NotSales,DC=corp,DC=local`. The obvious implementation is an
`EndsWith`, and it has exactly that bug.

## The one that deletes people

[`Compare-SyncScope`](module/SyncReadiness/SyncReadiness.psm1) reports what a
filter change would do before it does it, and grades it against a threshold the
plan has to state for itself.

Entra Connect ships a circuit breaker here — the
[export deletion threshold](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-feature-prevent-accidental-deletes),
enabled by default at 500, which aborts an export carrying more deletions than
that before removing anything. It is worth knowing precisely what it does not
cover:

- It is **per export**, so 499 deletions pass without comment.
- A change staged across two runs passes twice.
- The limit is a default nobody in the room chose.

So this reports the count whatever it is. The plan in this lab states a
threshold of **zero** — a filter change must not delete anything — and the run
fails if the comparison is graded anything less than `Critical`.

## What remediation deliberately will not do

[`Repair-ForestObjects.ps1`](scripts/vm/Repair-ForestObjects.ps1) fixes only
what is safe to change without asking anybody: stripping an illegal character
from a UPN, adding the `SMTP:` prefix an address is missing. Those change the
representation of an identity, not the identity.

It refuses the rest, and names what it refused:

- A **duplicate UPN** cannot be resolved mechanically, because deciding which of
  two people keeps the name is a business question and getting it wrong locks
  somebody out of their account.
- An **unverified suffix** is not an object problem. Rewriting every affected
  user would change what they sign in with, when the right fix is usually to
  verify the domain.
- An **oversized attribute** has to be shortened by somebody who knows what it
  is for.

The second assessment then expects those to still be there. **A remediation pass
that came back clean would mean it had made decisions it had no standing to
make** — so the run fails if the mechanical fixes did not land *and* fails if
the judgement calls silently disappeared.

## Secrets that are never transmitted

The directory services restore password and the lab accounts' password are
generated **on the domain controller** and never returned. They have to exist;
nothing outside the machine needs them, and the machine is destroyed at the end
of the run. A secret that is never transmitted cannot be intercepted, logged by
Run Command, or left in a state file.

They are also built a character at a time into a `SecureString` rather than
through `ConvertTo-SecureString -AsPlainText`, so the plaintext never exists as
a managed string. PSScriptAnalyzer objects to that pattern and is right to.

## Cost

| | |
|---|---|
| `Standard_D2as_v4` Windows | $0.188/hour |
| A 25-minute run | ~**$0.08** |

`Bsv2` and `DASv5` both have a quota of **zero** on this subscription, which
Azure reports as "Capacity Restrictions" — wording that reads like a transient
shortage rather than a limit on the account. Both `az vm list-skus` and
`az vm list-usage` were checked before choosing.

There is **no public IP and no inbound rule**. Run Command reaches the machine
through the Azure guest agent, so a domain controller in this lab is never
addressable from the internet. Opening RDP "just for troubleshooting" is how a
lab domain controller ends up in somebody's botnet.

## Running it

Run **Assess** from the Actions tab. It builds the forest, assesses, remediates,
assesses again, and destroys everything in the same job — including when it
fails, because a lab that only cleans up on the happy path bills for its own
bugs. A nightly workflow removes anything a cancelled run left behind, deleting
by resource group name rather than from state.

## Status

| | |
|---|---|
| Unit tests | 40, green, no forest required |
| PSScriptAnalyzer, `terraform validate`, `tflint`, `checkov`, `actionlint`, `shellcheck` | clean |
| Assessment against synthetic facts | passes: 10/10 defects found, 0 false positives, scope change `Critical` |
| Live run against a real forest | not yet run |

This section will say so plainly until the assessment has run end to end against
a domain controller.

## What this does not do

**It does not synchronise anything.** That is a deliberate boundary, not an
omission. Neither Entra Connect nor Entra Cloud Sync can be registered without
completing an interactive wizard — Microsoft's own
[Cloud Sync documentation](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/reference-powershell)
states that its PowerShell module "might not work correctly if … the
configuration wizard has not finished successfully", and every cmdlet in it
operates on a job a wizard already created. Since the agent lives on a machine
this lab rebuilds every run, registration would be needed every run, and a lab
that needs a human at a console mid-run is not a proof.

So this covers the work that comes before that wizard, which is where these
migrations actually go wrong. The cloud side — Conditional Access, privileged
access review, pre-merge collision analysis — is
[a separate lab](https://github.com/zuqdah/entra-cutover-without-lockout).

It also assesses users only. Groups, contacts and computers have their own
attribute rules, and the module would need extending for each.
