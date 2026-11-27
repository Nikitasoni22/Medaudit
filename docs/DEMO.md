# MedAudit demonstration

Use Python 3.12 and a fresh synthetic installation. Install the locked runtime
dependencies with `python -m pip install --require-hashes --only-binary=:all: -r requirements.lock`,
then run `python run.py --demo`.

Open the hospital at `http://127.0.0.1:8000` and the auditor at
`http://127.0.0.1:8001`. The README lists the synthetic demo credentials.

1. **Normal access:** sign in as `dr.rao`, open P-1001, and explain the assigned
   care relationship. A receptionist sees demographics; an IT admin manages users
   and assignments but cannot inspect clinical records.
2. **Denied access:** return to the directory and open P-1002 three times. Its
   clinical fields stay hidden; each attempt produces an access-denied event.
3. **Emergency:** enter a meaningful reason and use Break glass on P-1002. The
   time-limited grant applies to this patient and is recorded at critical severity.
4. **Independent assurance:** sign in to the auditor as `auditor1`. Explain the
   verified head, event distribution, and pending-review queue. The status is a
   verification result, not an overall claim that the deployment is secure.
5. **Review:** open Emergency reviews, read the reason, and mark reviewed or
   flagged with a note. The console trail retains the reviewer, time, prior
   revision, and immutable history. Avoid putting clinical details in review notes.
6. **Findings:** inspect the repeated-denial rule and source event numbers. A
   finding directs investigation; it does not prove an intrusion.
7. **Checkpoint and experiment:** publish a checkpoint. Run
   `python scripts/demo_lab.py` to show altered ciphertext and complete rollback
   detection without changing the running dataset. For the older live attack
   scripts, use a disposable install and stop concurrent logging before restoring
   files; backup/restore is an operator action, not an Internet endpoint.
8. **Evidence:** filter an export for P-1002. Download JSON to inspect verified
   head, checkpoint references, filters, content digest, and audit-event records.
   CSV downloads neutralize formula prefixes. The digest is not a signature.
9. **Engineering:** show requirement IDs, STRIDE threats, test references, and the
   component model. Simulate admin + clinical access + assigned=true: access is
   still denied because the role has no clinical permission.

For a repeatable automated rehearsal, install development dependencies, run
`python -m playwright install chromium`, and execute
`python scripts/browser_check.py`. The script starts its own temporary services
and writes screenshots to `docs/screenshots/`. It never resets the operator's data.

To start over manually, choose a **new** data directory with `--data` rather than
deleting a potentially valuable install. The included known passwords are for
synthetic demonstrations only.
