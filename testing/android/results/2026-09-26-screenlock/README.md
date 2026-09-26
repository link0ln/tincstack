# DisconnectOnScreenOff and per-app split routing on the emulator (2026-09-26)

Emulator: `wsy-android-emulator` image, API 34 `google_apis` x86_64, headless.
Inviter: `tincstack/core:ww-mn` (master core). App: debug build of this branch,
`-PtincAbis=x86_64`. Logs are filtered (SELinux `avc:` noise and uiautomator
screen dumps dropped, the invitation token redacted; `tinc.yaml` keys are
redacted by `join-on-emulator.sh` itself).

| log | what | result |
|---|---|---|
| `ab-old.log` | the owner's scenario with the OLD app (`/opt/gitrepo/tincapp` v0.42, debug build from a copy): standalone network, `DisconnectOnScreenOff = yes`, lock 95 s, unlock | tincd **not** back after unlock |
| `ab-new.log` | the same scenario, this branch (`tinc.yaml` with `DisconnectOnScreenOff: yes`) | tincd back 0 s after unlock |
| `lock-https.log` | `TRANSPORT=https lock-cycle-on-emulator.sh`: 3 cycles locked 95 s + PIN-keyguard cycle + negatives | PASS |
| `lock-quic.log` | `TRANSPORT=quic SECURE=0 lock-cycle-on-emulator.sh`: 3 cycles locked 95 s + negatives | PASS |
| `lock-pin.log` | `CYCLES=0 LOCKED_WAIT=20 SECURE=1`: PIN cycle again, notification disconnect attempt | PASS (notification step not reachable, see below) |
| `split-https.log` | `TRANSPORT=https split-routing-on-emulator.sh`: whitelist and blacklist set through the picker, per-UID pings | PASS |

## The old app's failure, as measured (`ab-old.log`)

```
15:08:56.967 ScreenStateReceiver: Screen off: stopping tinc daemon for network "solo"
  (poll 10 s later: tun0 gone -- the VPN is down, traffic leaves outside it while locked)
15:09:07.113 ActivityManager: freezing 3436 org.pacien.tincapp
15:09:57.043 ActivityManager: Stopping service due to app idle: u0a192 -1m17s373ms org.pacien.tincapp/.service.TincVpnService
15:09:57.046 ScreenStateReceiver: Screen state receiver unregistered
15:09:57.049 TincVpnService: Stopping any running tinc daemon.
  (unlock at 18:10:34 local: nothing; tincd never restarted, process alive but receiver gone)
```

1. SCREEN_OFF ran only `tinc stop`; tincd held the last tun fd (the service
   closes its copy after startup), so the VPN went down with it.
2. With the VPN gone nothing kept the plain started service alive: the system
   froze the process (cached-app freezer) 10 s later and stopped the service
   "due to app idle" ~60 s after the screen went off.
3. `onDestroy` -> `stopVpn()` -> `ScreenStateReceiver.unregisterWatcher()`
   unregistered the receiver and wiped `savedNetName`/`disconnectedByScreenOff`:
   the unlock had nobody to hear it.
4. The `startService` fallback (background start, forbidden since Android 8)
   and the `passphrase = null` reconnect were never reached in this run: the
   receiver was already gone. Both are real defects of that code but not what
   the owner saw.

## The new app (`lock-*.log`)

Per cycle: tincd gone 1 s after `KEYCODE_SLEEP`; tun0 stays, a ping into the
tunnel is unanswered (dropped, not leaked); for 95 s the app process keeps the
same pid and the service stays `isForeground=true types=00000400`
(`systemExempted`); on unlock tincd is back in 0-2 s and the inviter answers
through the tunnel 0-3 s later, over https and over quic (`dump connections`
shows `transport https` / `transport quic`). `tun fds: app 1, tincd 1`: the
service keeps its descriptor and each relaunched tincd gets its own SCM_RIGHTS
duplicate.

PIN keyguard: SCREEN_ON with the bouncer up leaves the session suspended
(`ScreenOn(keyguardLocked=true) ... (no action)`); the PIN unlock's
USER_PRESENT resumes it. The first PIN run failed exactly there: the receiver
was registered `RECEIVER_NOT_EXPORTED`, and USER_PRESENT comes from SystemUI
(not the system uid), so it never arrived. Fixed (registered exported; the
three actions are protected broadcasts) and re-run: PASS.

Negatives: an explicit disconnect followed by a lock/unlock stays down (no
tincd, no tun0, service stopped).

Not shown here:

- The stock image shows no keyguard after `KEYCODE_SLEEP` without a PIN, so
  the swipe cycles resume on SCREEN_ON (`keyguardLocked=false`); USER_PRESENT
  is exercised only by the PIN run.
- The notification's Disconnect action on a *locked* screen: the lock screen
  showed no notification at all (the channel is IMPORTANCE_LOW; even with
  `lock_screen_show_silent_notifications=1` none appeared). The state machine
  rule (disconnect while suspended is final) is unit tested; on the unlocked
  screen the action works (`lock-quic.log`).
- Real Doze / app-standby after a long unplugged idle, OEM task killers (MIUI,
  EMUI, ...), a real radio and its wake-ups: emulator limits.

## Split routing (`split-https.log`)

Two code-less debuggable probe apps (`docker/probe-apps.sh`), UIDs 10193
(`net.tincstack.probe.a`) and 10194 (`net.tincstack.probe.b`); `run-as <pkg>
ping` to the inviter's tunnel address runs as that UID.

- no list: a reaches, b reaches;
- picker -> "Only the selected apps", tick probe.a, Save -> `AllowApplication:
  net.tincstack.probe.a` in `tinc.yaml`; reconnect: **a reaches, b does not**;
  VPN network `Uids: <{10193-10193, 20193-20193}>`, `ip rule ... uidrange
  10193-10193 lookup tun0`;
- picker -> "All apps except the selected ones", Save -> `DisallowApplication:
  net.tincstack.probe.a` (the other key removed); reconnect: **a does not,
  b reaches**; `Uids: <{0-10191, 10194-20191, 20194-99999}>` (10192 is the app
  itself, always excluded).

## Found on the way (not fixed here)

`zero-config-port655.log`: a network whose `tinc.yaml` has no `Port` (what
the app's "Generate" tool writes: `Name` only) is materialised by the daemon
with `Port=655`; on Android an app may not bind below 1024:
`Can't bind to 0.0.0.0 port 655/tcp: Permission denied` -> `Unable to create
any listening socket!` -> `Terminating`. With `Port: 0` the same file runs
(`ab-new.log`). Joined networks are unaffected (`tinc join` writes `Port: 0`).
Before that, the service already refuses a network with no `tinc.yaml` at all:
`establish()` -> "At least one address must be specified" (no address before
the daemon has materialised the pool), measured in the first A/B attempt; a
`Name`-only file takes the same code path (inferred, not run).
