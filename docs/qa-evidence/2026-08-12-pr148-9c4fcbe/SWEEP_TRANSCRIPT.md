# Sweep transcript — PR #148 / #142 @ 9c4fcbe

Fixture: `akismet/akismet.php` Temporary Allow, expiry ~6h, `alert_on_deny` on, recipient `haktan+expiry-warn@handldigital.com`.

## First sweep
```
warned=["akismet/akismet.php"]
```
Mail sent once (MailHog ID `z3oyZbFPutazH9b2i-UtPgKx6DNmrkfEuBnVYPRQ_q8=@mailhog.mamppro`).

## Second sweep (+30s)
```
warned=[]
```
No duplicate mail (idempotent warned map).

## Renew (live QA by Frink Luna)
Direct renew produced a new expiry and cleared the warned flag.
