# Playbook: Compromised Account / SSH Brute Force

## 1. Identify
- [ ] Run `python -m irkit logs /var/log/auth.log`
- [ ] Note any "successful login after repeated failures" findings

## 2. Contain
- [ ] Lock the account and kill active sessions
- [ ] Block the source IP at the firewall
- [ ] Rotate passwords, SSH keys, API tokens used by the account

## 3. Investigate
- [ ] Review shell history, new cron jobs, new SSH `authorized_keys`, new users, new services
- [ ] Check outbound connections and file changes after the login time

## 4. Harden
- [ ] Disable password auth for SSH; require keys + MFA
- [ ] Add fail2ban / rate limiting; restrict SSH by source IP or VPN
