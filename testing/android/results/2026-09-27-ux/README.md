# Android app redesign: every flow through the UI (2026-09-27)

Emulator: `tincstack/android-emulator:ws-u` (API 34 `google_apis` x86_64,
headless). For `before/` and `after/` the display was set to 720x1600 at
280 dpi, the same size in dp as a 1080x2400 / 420 dpi phone; `ui-flows/` is
the emulator's own 1080x2400. Founder: a Linux node (`tincstack/node:ws-u`,
the core of this tree) on its own docker network. App: debug build of this
branch, `-PtincAbis=x86_64`. **before** = master `e90715c`, **after** = this
branch. Screenshots are 540 px wide and palette-quantised; the invitations
in them belong to lab founders that no longer exist. Logs are `.txt`
(`*.log` is git-ignored), with invitation tokens and keys redacted.

The app is English only (owner's decision, 2026-09-27): the other locales
were stale legacy text and are gone. The Russian **before** shots are what the
owner's phone showed.

## The owner's P0, measured on master

The report: pasting `<ip>:655/<token>` said "error", yet a network appeared;
Connect then hung forever; after a restart the app showed a "network.conf"
error.

1. **The error.** The pasted text ended in a line break. The app handed it
   to `tinc join` as an argument; the core's `cmd_join` strips blanks only
   from an invitation it reads from stdin, never from argv, so the parser
   refused it: "Invalid invitation URL." (`before/04-join-trailing-space-ru`,
   `before/12-join-garbage`). Nothing reached the inviter.
2. **The phantom network.** Before parsing anything, the CLI's `make_names`
   had already created `networks/<net>/<net>/`, and the app listed every
   directory under `networks/` as a network: a failed join left one behind
   (`before/05-list-after-failed-join-ru`). Every other failure did the same;
   after the audit's five failed joins the list held `home`, `net1`..`net4`
   (`before/17-list-after-en-light`).
3. **The hang.** Tapping the phantom: VPN consent, then the
   POST_NOTIFICATIONS dialog, asked in the middle of the connect, paused the
   activity. Meanwhile the service failed (no `tinc.yaml`, so no address)
   and sent its failure as a one-shot event, which a paused activity never
   receives. The "Starting VPN..." spinner stayed up for good
   (`before/07-after-consent-ru`, `09-after-notif-allow-ru`, and
   `10-after-notif-35s-ru` 35 s later).
4. **The restart error.** The persisted failure was stored as text in the
   locale it was produced in, naming the legacy `network.conf`; the real
   cause was "there is no tinc.yaml" (`before/11-restart-error-ru`).

## What fixes it (and makes it impossible)

- The invitation is found in whatever was pasted (blanks, line breaks,
  surrounding prose; `Invitation.find`, unit-tested) and handed to the core
  normalised. The button stays disabled until the text holds one.
- The join is all or nothing. The CLI runs against a staging directory
  (`files/joining/join-<n>/tinc.yaml`), and only a successful join is renamed
  into `networks/<name>` in one step. A failure deletes the staging
  directory. When the app starts, it removes staging leftovers from a
  process that died mid-join, and every `networks/` entry without a
  non-empty `tinc.yaml` (`sweep.txt`).
- The network name comes from the network itself: its YAML stanza, or the
  name of the node it dials when the invitation carries no NetName. The user
  no longer types one.
- The notification permission is asked once, before the VPN consent, never
  in the middle of a connect.
- The connection state is process-wide state that the screen observes
  (`VpnStatus`), not an event a paused screen can miss. A failure is kept
  across restarts with its network and details until dismissed; with one
  language left it can no longer outlive the locale it was written in, and
  its texts name `tinc.yaml`, the only config file.
- Nothing hangs silently. 20 s after a connect without a reachable peer, the
  screen says so, with the log one tap away (`after/23-not-answering`). A join
  gets 20 s to reach the inviter and 90 s in all; its failure is put in words,
  with the endpoint, plus "Nothing was saved". The core's own output is
  under Details.
- A join that ran out its deadline crashed the app: the killed CLI made the
  stderr reader thread throw. That killed a running VPN too. Fixed; if the
  process dies anyway, the next start reports "Connection lost" rather than
  claiming to be disconnected.

## Flows, before and after

| flow | before (master) | after (this branch) | shots |
|---|---|---|---|
| first launch | a list screen of legalese; wrench, then Configure, then "Join network via invitation URL or QR code"; a dialog asking for a "tinc network name" | the join form itself: paste or scan, "Join and connect" disabled until the text holds an invitation | before/01, 02, 03; after/01-first-launch, ui-flows/01 |
| invitation in the clipboard | nothing | offered on the form ("Use it") when the field is empty | after/02-clipboard-offer, 03-invitation-detected |
| keyboard after a paste | not measured | hidden as soon as the text holds an invitation, so "Join and connect" is not under it; the screen resizes around the keyboard | ui-flows/06 |
| two invitations pasted together | not measured | "This isn't an invitation" (it used to offer a host named after the first token) | unit test |
| text that is no invitation | dialled anyway, then "Invalid invitation URL." plus a phantom network | "This isn't an invitation", before dialling | before/12; ui-flows/02 |
| **invitation with blanks / line break** (the owner's P0) | "Invalid invitation URL." plus a phantom network | accepted, joined, connected | before/04, 05; ui-flows/06 |
| unreachable inviter | 136 s spinner, "Could not connect to inviter. Please make sure the URL you entered is valid.", phantom | 27 s: "No answer from 10.44.81.99:655. ... port 655 may be blocked ...", nothing saved | before/13; after/27, 28; ui-flows/03 |
| wrong token | a bare base64 key as the whole message | "10.44.81.10:655 answered, but this invitation doesn't match it ...", nothing saved | before/14; after/29; ui-flows/04 |
| invitation already used | "Invitation cancelled. Please try again and contact the inviter..." | "... turned this invitation down. It was probably used already (an invitation works only once) ...", Details shows the core's words | before/15; after/30; ui-flows/05 |
| join and connect | join, back to the list, tap the network, consent, notification dialog mid-connect, then a spinner that never ended (P0) | one tap: notification permission, VPN consent, "Connected" 27-32 s later, one network named `node_a` | before/07, 09, 10; ui-flows/07-09 |
| restart after a failure | stale "network.conf" error in the old locale | the failure kept until dismissed, in the current texts; a session the process lost shows "Connection lost" (not screenshotted); the phantom source is gone | before/11 |
| peer not answering | nothing distinguishes it from starting | "Looking for node_a…", then after 20 s "node_a isn't answering yet ..." and View log | after/22, 23 |
| VPN permission refused | not measured | "Couldn't connect. tincstack needs your permission to set up a VPN.", View log / Dismiss | after/24, 25 |
| status | a separate status screen with tabs, never idle (uiautomator could not dump it) | the main screen: a big state button, "Linked to node_a over Standard", this device and its address (tap to copy), peers | before/18, 19; after/10, 11 |
| peers | a node dump table | a list: direct or via whom, transport, RTT; tap a peer for `tinc info` | after/13, 14 |
| connection type | not in the UI | Standard / Single UDP flow / Obfuscated / HTTPS / QUIC, with types the peers do not offer disabled; writes `PreferredTransports`, and "Reconnect" applies it | after/15 |
| apps using the VPN | the picker first asks which network (phantoms included) | all apps / only these / all except these, with search and ticked apps first, then Save | before/21; after/16, 17 |
| pause while locked | a switch inside the app picker (Configure, then "Choose which apps use the VPN") | a switch on the main screen, saved as soon as it is flipped | after/12 |
| switching networks while connected | not measured | locked, with "Disconnect to switch networks." | after/12b |
| log | a separate viewer that redrew every 250 ms (never idle) | Connection / App toggle, control noise filtered out, follows the tail, copy and share | before/20; after/18, 18b |
| remove a network | only by deleting its directory from a file manager, through the app's DocumentsProvider | menu, Remove network, confirmation; disconnects first | after/31, then after/01 |
| menu, about, notification | help linking to tincapp.euxane.net | add network, log, remove, about | after/19, 20, 21 |
| phantom leftovers from the old app | listed as networks | removed at app start | after/32; sweep.txt |
| CONNECT intent for a network that does not exist | not measured | "ghost has no configuration ..." | after/33 |
| dark theme | none: the dark screenshots are byte-identical to the light ones (before/01, before/17) | Material 3, dynamic colour; every shot in both themes | after/*-dark |

Removed as legacy: "Open configuration directory" (a DocumentsProvider
that exposed the key-holding `tinc.yaml`), "Generate node configuration and
keys" (a phone cannot be a founder here; it tried to bind port 655), the
manual link to tincapp.euxane.net, the network-name field, and the stale
non-English translations.

## Tests

All but the last row on the final debug APK (branch commit `70cd301`; later
commits touch only scripts and results), under `flock /tmp/tincstack-lab.lock`, one emulator at a
time. Logs in `logs/`.

| command | what | exit | log |
|---|---|---|---|
| `gradle.sh -PtincAbis=x86_64 cleanMergeDebugResources assembleDebug testDebugUnitTest` (in `tincstack/android-build:ws-u`) | build + 77 unit tests in 12 classes, 0 failures | 0 | `logs/unit.txt` |
| `IMAGE=tincstack/android-emulator:ws-u TINCSTACK_TAG=ws-u SHOTS=... platforms/android/docker/ui-flows-on-emulator.sh` | first launch; "hello world" refused; 3 failed joins (unreachable 27 s, bad token 12 s, used 11 s), each leaving no network and no staging directory; the owner's padded invitation joined through the UI, notification permission and VPN consent tapped, Connected 27 s after the tap, one network `node_a`, ping to the founder's tunnel address 3/3, the founder sees the phone, Disconnect removes tun0 | 0 | `logs/ui-flows.txt` |
| the same, second run (kept up for the next line) | the same steps: 27 s / 12 s / 15 s, Connected 32 s after the tap, ping 3/3 | 0 | `logs/ui-flows-2.txt` |
| `sweep-proof.sh` (a scratch helper, not in the tree; on that lab) | phantom directories from the old app (`home/home`, `net1/net1`, an empty `tinc.yaml`, a stray file, `joining/join-1`) are gone after the app starts, each logged; `CONNECT tinc:ghost` shows "ghost has no configuration ..."; a joined network whose `tinc.yaml` is corrupted gets "Couldn't connect: The configuration of node_a can't be used: ..." from the service | 0 | `logs/sweep.txt`, after/32-34 |
| `LAB=wsu-d2 ... TRANSPORT=https platforms/android/docker/lock-cycle-on-emulator.sh` | stream D2's DisconnectOnScreenOff proof, the switch now on the main screen: join through the UI, 3 cycles locked 95 s (tincd gone 1 s after lock, back 0 s after unlock), the PIN keyguard cycle, explicit disconnect stays final; the notification's Disconnect on a locked screen was not reachable on the emulator, as in D2 | 0 (second run; see below) | `logs/lock-https.txt` |
| `LAB=wsu-d2 ... BUILD_IMAGE=tincstack/android-build:ws-u TRANSPORT=https platforms/android/docker/split-routing-on-emulator.sh` | stream D2's split-routing proof through the new picker: none (a and b reach), whitelist (a only), blacklist (b only), per UID | 0 (second run; see below) | `logs/split-https.txt` |
| `CORE_IMAGE=tincstack/core:ws-u IMAGE=tincstack/android-emulator:ws-u testing/transports/android-emulator-test.sh` | the NDK core's https/quic carriers and ClientHellos (no app involved): the Android node connects over https and quic; its ClientHellos equal the Linux dialler's (t13i3012h2, 1542 B; q13i0311h3, 1477 B, the same transport parameters) | 0 (second run; see below) | `logs/transports.txt` |
| `after-shots.sh` (a scratch helper, not in the tree) | every screen above in light and dark, driven through the UI | 0 | `logs/after-shots.txt` |

The `after/` shots were taken with the build just before `70cd301`. That
commit hides the keyboard once an invitation is recognised, resizes the
main screen around the keyboard and tightens the parser; none of the
screens in `after/` show a keyboard. The `ui-flows/` shots are from the
final build.

### Found during this verification

- **The keyboard covered "Join and connect"** on the main screen after a
  paste (the main screen did not resize around it), so the one button of the
  first-launch screen was hidden until the keyboard was dismissed. Fixed in
  `70cd301`: the keyboard goes away once the text holds an invitation, and the
  main screen resizes like the add-network screen.
- **Two invitations pasted together** were accepted as one, with a host made
  of the first token and the second address. Fixed in `70cd301`; unit test
  `twoInvitationsPastedTogetherAreNotOne`.
- UI harness races (not app defects), fixed in `d055ca1` and `7f4b774`:
  - `ui_type` read the field's position before the clipboard card had pushed
    it down.
  - The keyboard could appear after `ui_hide_ime` had looked for it, so the
    tap meant for "Join" landed on Gboard's clipboard chip, which pasted the
    clipboard into the field. Keyboard and screen are now waited for, and the
    typed text is read back.
  - `app_networks` failed on a fresh install, before the app had created
    `files/`. That killed `ui-join.sh` silently, and with it the first
    `lock-cycle` run (exit 1).
- The first `split-routing` run exited 125: its probe apps are built with
  `tincstack/android-build`, which exists here only as `:ws-u`, so it needs
  `BUILD_IMAGE`. Environment, not code.
- The service's check for an **emptied** `tinc.yaml` cannot be reached from
  the UI: the main screen drops such a network within its refresh and shows
  the join form, which made the first `sweep-proof` run fail (exit 1). The
  check that can be reached, a corrupted `tinc.yaml`, is proven instead.
- The first `android-emulator-test.sh` run failed its first step 2 s after
  the emulator reported booted: "Could not connect to 10.47.14.12 port 655:
  Network is unreachable" (`logs/transports-run1.txt`). The guest's network
  was not up yet, and the test does not wait for it. The second run passed.
  This test runs the NDK binaries as root and does not involve the app.

## Not covered

- Camera QR scan: the emulator has no camera scene with a code in it. The
  scan result goes into the same field and through the same parser that the
  UI test exercises.
- The Paused state was not screenshotted here; `lock-cycle` proves it on the
  wire.
- Only the x86_64 debug APK was built and tested (`-PtincAbis=x86_64`), not
  the 4-ABI build.
