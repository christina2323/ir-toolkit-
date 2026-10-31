# Playbook: Phishing

**Goal:** contain a reported phishing email and determine whether anyone was compromised.

## 1. Identify
- [ ] Get the original message as `.eml` (with full headers), not a screenshot
- [ ] Extract sender, reply-to, URLs, attachments: `python -m irkit iocs email.txt --defang`
- [ ] Check SPF/DKIM/DMARC results in the headers

## 2. Contain
- [ ] Search mail logs for every recipient of the same sender/subject/URL
- [ ] Purge the message from all mailboxes
- [ ] Block sender domain, URLs, and attachment hashes at gateway/proxy/EDR

## 3. Assess impact
- [ ] Who clicked? (proxy / DNS logs)
- [ ] Who entered credentials or opened the attachment?
- [ ] For each: reset password, revoke sessions/tokens, review MFA devices and mailbox rules

## 4. Recover & learn
- [ ] Re-enable accounts after verification
- [ ] Notify affected users; report to the abuse contact of the hosting provider
- [ ] Update detections and awareness training
