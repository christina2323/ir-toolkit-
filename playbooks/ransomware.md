# Playbook: Ransomware

**Goal:** stop encryption spreading, preserve evidence, restore safely.

## 1. Contain (minutes matter)
- [ ] Isolate affected hosts from the network (EDR isolate / unplug network, **do not power off** if memory evidence matters)
- [ ] Disable compromised accounts; reset privileged credentials
- [ ] Block known C2 IPs/domains; suspend file shares and backup-system write access

## 2. Preserve evidence
- [ ] Capture memory and disk images of at least one affected host
- [ ] Save ransom note, encrypted file samples, and extension names
- [ ] Export relevant logs (auth, EDR, firewall, VPN) to write-once storage

## 3. Scope
- [ ] Identify patient zero and initial access vector (phish, exposed RDP/VPN, vulnerable edge device)
- [ ] Look for persistence, lateral movement, and data exfiltration (double extortion)

## 4. Eradicate & recover
- [ ] Rebuild from known-good images; restore from offline/immutable backups
- [ ] Patch the entry vector; rotate all credentials and secrets
- [ ] Monitor closely for re-infection

## 5. Notify
- [ ] Legal/compliance, insurer, law enforcement, and regulators as required
