# Roadmap

Ideas for later. What already works is described in the [README](README.md); how it's built is in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

**North star:** the Mac is plugged into the TV, you pick up your phone, tap one icon, and it just works. When you're not using it, nothing can control the Mac.

**Decisions so far:**
- The phone side stays a web app. A native iOS app would give real haptics, Bonjour discovery and easy Face ID, but needs Xcode builds and an Apple developer account to avoid 7-day signing.
- There's no setting to keep the Mac awake; the Mac's own sleep settings stay in charge.
- Waking a fully asleep Mac from the phone is out of scope. It needs a Bonjour Sleep Proxy (Apple TV or HomePod) or Wake-on-LAN, which a web page can't send.

## Connecting

- **Fall back when the `.local` name doesn't resolve.** Some routers and mesh systems block mDNS. The phone could remember the Mac's last known IPs and try the hostname and those IPs in parallel, taking whichever answers first.
- **Explain networks that block device-to-device traffic.** Guest and many office or dorm networks use "client isolation". Detect it and say so in the phone app instead of spinning forever.
- **Optional: advertise a Bonjour service** (`_http._tcp` "Mac Touchpad") for debugging and a possible native app.
- **Intel Macs:** `tools/build_app.sh` assumes Apple Silicon (`/opt/homebrew`, `-arch arm64`). Supporting Intel would mean reading the Homebrew prefix and architecture at build time.

## Easy to use, easy to switch off

- **A "Show QR code" window** from the menu bar: big and readable on the TV from the couch, carrying the setup URL and certificate fingerprint.
- **Automatic on/off:**
  - **TV mode:** arm automatically when an external display is connected, and disarm when it's unplugged.
  - **Idle timeout:** disarm after N minutes with no phone connected.
  - **Off button on the phone:** turning it back on from the phone is allowed only for paired phones.
- **Armed/disarmed state:** the listener stays up, but input is injected only while armed. When disarmed, the phone shows "Mac Touchpad is off. Turn on?".
- **A better first-run guide on the phone:** when the app is opened in Safari instead of from the Home Screen, show a step-by-step overlay pointing at the Share button.
- **Report in the phone app when Accessibility is missing.** Today the status is green but the cursor doesn't move.

## Security

- **Face ID per session via WebAuthn/passkeys.** This needs the HTTPS setup the app already has. Open question: does Safari accept a `.local` host as the WebAuthn relying-party ID? Value check: the phone is already behind Face ID, so this mainly protects an already-unlocked phone.
- **Protect `devices.json` and `tls/server.key`** from other software running as the user, for example by moving them into the keychain or signing the device list.
- **Rate-limit wrong pairing codes** per device as well as per IP, and add a "Reset pairing code" item to the menu.
- **Restrict the local CA further:** a serverAuth-only extended key usage, and constraints on email/URI names. Existing phones would need to reinstall the profile.

## Polish

- Tune pointer feel and defaults on more phones; the tunables are at the top of `web/app.js`.
- Smart zoom (two-finger double-tap), three-finger drag, and the four-finger pinch for Launchpad/Apps.
- A landscape keyboard layout, and keeping the pad usable while the iOS keyboard is open.
