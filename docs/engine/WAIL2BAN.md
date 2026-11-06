# Wail2Ban: password guessing, bans, internet logins

Read for: `src\Edr.Engine\Wail2Ban.cs`, `Native\Firewall.cs`, the `wail2ban` settings, IP helpers in `Ip` (Edr.Core).

Wail2Ban is **the only part of FreeEDR that enforces** anything. Everything else only detects.

## 1. Behaviour
* **Counts** failed network logons per address from Security **4625** (RDP, SMB, any network logon with a source
  address; a 4625 without a source address is a local logon and never counted) and **RemoteDesktopServices-RdpCoreTS 140**.
  One RDP failure logged in both places (within 3 s) counts once.
* **Threshold**: `failCount` (5) failures within `windowSeconds` (30 min):
  * **Blocking** (`wail2ban.block = true`, default): inbound block-all firewall rule `a a a wail2ban block IP: <ip>`
    (description `Expire: <time>`), Medium "Blocked <ip> after N failed logons", Application log 1000 (1001 on failure).
  * **Report only** (`wail2ban.block = false`): Medium "Password guessing from <ip> (N failed logons)" (`kind = guess`),
    no firewall rule, no strike.
  * Below the threshold: Low "Failed network logon from <ip>" (Network ▸ Sign-in attempts, so it can be banned or trusted early).
* **Escalation**: ban length 5^strike minutes (5 min, 25 min, ~2 h, ~10 h, ~2 days, …); one strike is forgiven per 24 h
  without a new ban; capped at **90 days for public**, **7 days for private/LAN/loopback** addresses (W7). Private
  ranges: 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, 127/8, fc00::/7, fe80::/10, ::1.
* **Expiry**: every 60 s the rules are read (firewall registry store) and expired ones removed (Application log 2000).
  `never` = permanent (a user ban). Permanent bans are re-applied every minute if someone removes the rule by hand
  (only while blocking is on).
* **Successful logins from the internet (W8)**: Security **4624** logon type 3 / 10 from a public, non-trusted address →
  **High** "Successful login as <user> from <ip> (public internet)" (once per address+user per 30 min), shown as
  *Was this you?* on Home.
* **Never banned**: this PC's own addresses (refreshed every 5 minutes; exact match, W1), `0.0.0.0`,
  `255.255.255.255`, `::`, and every trusted address/network (`exclusions.json` → `wail2ban[].cidr`; Network ▸ Trusted).
  "Unban and watch again" clears an address from the bans, verdicts, trusted list and strikes.
* **Engine restart**: the last window of 4625 refills the counters only (no events), skipping failures older than the
  address's last ban (Q11); the event log bookmarks resume the live subscriptions without loss.
* **IPv6 Remote Desktop** (`wail2ban.blockRdpIpv6`, off by default): rules `Block RDP IPv6 (TCP/UDP 3389)` block inbound
  RDP from every IPv6 address (failures there cannot be counted). Switching it off removes the rules.
* The installer disables **Remote Desktop - Shadow (TCP-In)** (C4). FreeEDR does not change other Remote Desktop settings.
* **Pausing** Wail2Ban stops counting and new bans; existing bans stay until they expire or are unbanned.

## 2. Data
* `data\wail2ban_strikes.txt`: `ip strikes epoch` per line (the original Wail2Ban format), written atomically, at most
  once per 30 s during attacks, flushed every minute and at shutdown.
* In memory: failures per address (sliding window, 50,000 addresses at most, oldest evicted with one warning), strikes
  (pruned when decayed to 0 and older than 7 days), the 30-minute login cache, the current ban list for `status.json`.
* Firewall rules are added and removed with `netsh advfirewall` (the address is validated first) and read from
  `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules`.

## 3. Limits
With Remote Desktop on and NLA off, RDP is reachable before sign-in: Wail2Ban reports and blocks guessing and internet
logins, but cannot stop pre-authentication exploits. Keep NLA on, or limit Remote Desktop to the LAN or a VPN (owner
decision C2: NLA stays off for one client; documented).
