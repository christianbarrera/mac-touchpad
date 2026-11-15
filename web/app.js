'use strict';
/*
 * Mac Touchpad: phone side.
 *
 * Raw touch events only update accumulators; one requestAnimationFrame loop
 * turns them into at most one move + one scroll message per frame. If the
 * socket backs up (Wi-Fi hiccup), deltas keep coalescing instead of queueing,
 * so the cursor never "replays" a backlog.
 */
(() => {
  const $ = (s) => document.querySelector(s);

  // ------------------------------------------------------------------ settings
  const DEFAULTS = { sens: 1.3, accel: 1.0, scroll: 1.8, natural: true, dragTap: true, awake: true, haptics: true, autocorrect: true, strip: 'right' };
  const S = { ...DEFAULTS };
  try { Object.assign(S, JSON.parse(localStorage.getItem('mtp.settings') || '{}')); } catch (_) {}
  const saveSettings = () => { try { localStorage.setItem('mtp.settings', JSON.stringify(S)); } catch (_) {} };

  // ---------------------------------------------------------------- tunables
  const TAP_MS = 250;          // max finger-down time for a tap
  const TAP_SLOP = 10;         // px a finger may wander and still be a tap
  const DEADZONE = 3;          // px before a one-finger touch starts moving the cursor
  const DTAP_MS = 300;         // tap -> touch gap that arms tap-then-drag
  const DTAP_DIST = 50;        // ...and how close the second touch must land
  const HOLD_MS = 220;         // holding still that long after a tap starts a drag
  const TWO_TAP_MS = 320;      // max duration of a two-finger tap
  const SWIPE3_DIST = 45;      // px the three-finger centroid must travel to count as a swipe
  const PINCH_SLOP = 24;       // px the finger spacing must change before two fingers mean "zoom"
  const ROTATE_SLOP = 15;      // degrees of twist before rotate events start (during a pinch)
  const SCROLL_LOCK = 12;      // px of two-finger travel that locks the gesture to scrolling
  const SPREAD4 = 40;          // px four fingers must spread apart for Show Desktop
  const STRIP_W = 60;          // px: width of the one-finger scroll strip
  const STRIP_GAIN = 1.4;      // the strip scrolls a bit faster (a thumb travels less)

  // ------------------------------------------------------------- connection
  const base = location.pathname.replace(/[^/]*$/, '');
  const WS_URL = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + base + 'ws';
  let ws = null, wsOpen = false, retry = 0, retryTimer = null, lastRx = 0, hiddenAt = 0;
  let hostName = '', rtt = null, macNatural = null;
  let halted = false;   // stop auto-reconnecting (pairing refused / phone forgotten) until the user taps
  let paused = false;   // the Mac hung up because nothing was sent for a while; the next touch reconnects
  let pairInBrowser = false;
  // iOS keeps Safari's storage separate from the Home Screen app's, so pair from the icon.
  const iosSafariTab = /iPhone|iPad|iPod/.test(navigator.userAgent) &&
    !(navigator.standalone || matchMedia('(display-mode: standalone)').matches);

  const statusEl = $('#status'), statusText = $('#statusText'), latencyEl = $('#latency');
  const overlayBtn = $('#overlayBtn');

  // ---- this phone's identity (lives only in this Home Screen app's storage)
  // localStorage holds {id, name, pk:true}. The key itself is a P-256 key pair in
  // IndexedDB whose private half is non-extractable: this page can sign with it,
  // but no script can read it out. The Mac only ever gets the public half.
  // Fallback where WebCrypto is missing (plain HTTP): a shared key {id, key} + HMAC.
  const loadDevice = () => { try { return JSON.parse(localStorage.getItem('mtp.device') || 'null'); } catch (_) { return null; } };
  const saveDevice = (d) => { try { d ? localStorage.setItem('mtp.device', JSON.stringify(d)) : localStorage.removeItem('mtp.device'); } catch (_) {} };
  // HMAC-SHA256(key hex, message) -> hex. WebCrypto when the page is a secure context
  // (HTTPS), else the pure-JS fallback in hmac.js (Safari hides crypto.subtle on http).
  async function hmacHex(keyHex, msg) {
    if (window.crypto && crypto.subtle && window.isSecureContext) {
      try {
        const raw = new Uint8Array(keyHex.match(/../g).map((h) => parseInt(h, 16)));
        const k = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const sig = new Uint8Array(await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(msg)));
        return Array.from(sig, (b) => b.toString(16).padStart(2, '0')).join('');
      } catch (_) { /* fall through */ }
    }
    return MTPCrypto.hmacSha256Hex(keyHex, msg);
  }
  const PK_CONTEXT = 'mac-touchpad auth v1:';
  const canPk = !!(window.isSecureContext && window.crypto && crypto.subtle && window.indexedDB);
  const toHex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
  function keyStore(mode, fn) {
    return new Promise((resolve, reject) => {
      const open = indexedDB.open('mtp', 1);
      open.onupgradeneeded = () => open.result.createObjectStore('keys');
      open.onerror = () => reject(open.error);
      open.onsuccess = () => {
        const db = open.result;
        try {
          const tx = db.transaction('keys', mode);
          const req = fn(tx.objectStore('keys'));
          tx.oncomplete = () => { db.close(); resolve(req.result); };
          tx.onerror = tx.onabort = () => { db.close(); reject(tx.error); };
        } catch (e) { db.close(); reject(e); }
      };
    });
  }
  const loadKeyPair = () => canPk ? keyStore('readonly', (st) => st.get('device')).catch(() => null) : Promise.resolve(null);
  const dropKeyPair = () => { if (canPk) keyStore('readwrite', (st) => st.delete('device')).catch(() => {}); };
  const signHex = async (pair, msg) => toHex(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode(msg)));
  const pubHex = async (pair) => toHex(await crypto.subtle.exportKey('raw', pair.publicKey));
  // Make a key pair, and only trust it once it has survived a round trip through storage.
  async function newKeyPair() {
    const made = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    await keyStore('readwrite', (st) => st.put({ publicKey: made.publicKey, privateKey: made.privateKey }, 'device'));
    const pair = await keyStore('readonly', (st) => st.get('device'));
    if (!pair || !pair.privateKey) throw new Error('key did not persist');
    await signHex(pair, 'self-test');
    return pair;
  }

  // Answer the Mac's challenge, or ask to pair if this phone has no identity yet.
  async function onHello(sock, nonce) {
    const alive = () => ws === sock && sock.readyState === WebSocket.OPEN;
    let dev = loadDevice();
    let pair = await loadKeyPair();
    if (dev && dev.pk && !dev.key && !pair) { saveDevice(null); dev = null; }   // key lost: pair again
    if (dev && dev.id) {
      const msg = { t: 'auth', id: dev.id };
      if (dev.key) msg.mac = await hmacHex(dev.key, nonce);
      if (pair) { try { msg.sig = await signHex(pair, PK_CONTEXT + nonce); } catch (_) {} }
      if (alive()) sock.send(JSON.stringify(msg));
      return;
    }
    if (iosSafariTab && !pairInBrowser) {
      halt('First, add this to your Home Screen',
        'Tap Share (square with ↑, or “…” then Share) → Add to Home Screen → Add. Then open the new Touchpad icon and approve it on your Mac.',
        'Use it in Safari instead');
      overlayBtn.onclick = () => { pairInBrowser = true; overlayBtn.onclick = null; };
      try { sock.close(); } catch (_) {}
      return;
    }
    const req = { t: 'pair', name: deviceName() };
    if (canPk) { try { req.pub = await pubHex(await newKeyPair()); } catch (_) { /* shared-key pairing instead */ } }
    if (alive()) sock.send(JSON.stringify(req));
  }

  // Signed in. If the Mac still holds an old shared key for this phone, swap it for a public key.
  function afterAuth(sock, usesPublicKey) {
    const dev = loadDevice();
    if (!dev) return;
    if (usesPublicKey) {
      if (dev.key || !dev.pk) { delete dev.key; dev.pk = true; saveDevice(dev); }
      return;
    }
    if (!canPk || !dev.key) return;
    (async () => {
      const pair = (await loadKeyPair()) || (await newKeyPair());
      const pub = await pubHex(pair);
      if (ws === sock && sock.readyState === WebSocket.OPEN) sock.send(JSON.stringify({ t: 'rekey', pub }));
    })().catch(() => {});
  }

  const deviceName = () => /iPad/.test(navigator.userAgent) ? 'iPad' : /iPhone/.test(navigator.userAgent) ? 'iPhone'
    : /Android/.test(navigator.userAgent) ? 'Android phone' : 'Browser';

  const MESSAGES = {
    connecting:     ['Connecting…', 'Connecting to your Mac…', 'Make sure the Mac is awake, the touchpad server is running, and your phone is on the same Wi-Fi.'],
    disconnected:   ['Reconnecting…', 'Looking for your Mac…', 'Make sure the Mac is awake, the touchpad server is running, and your phone is on the same Wi-Fi.'],
    authenticating: ['Checking…', 'Checking this phone’s key…', ''],
    pairing:        ['Approve on Mac', 'Approve this phone on your Mac', 'A dialog is showing on the Mac’s screen. Click “Allow”. This is needed once per phone.'],
    paused:         ['Paused', 'Paused', 'Nothing was sent for a while, so the Mac disconnected this phone. Touch anywhere to reconnect.'],
  };

  function setStatus(state, title, sub, button) {
    statusEl.dataset.state = state;
    document.body.classList.toggle('offline', state !== 'connected');
    document.body.classList.toggle('blocked', state === 'blocked');
    if (state === 'connected') {
      statusText.textContent = hostName ? hostName.replace(/\.local$/, '') : 'Connected';
      $('#aboutHost').textContent = hostName || location.host;
      return;
    }
    latencyEl.textContent = '';
    rtt = null;
    const m = MESSAGES[state] || ['Not connected', title, sub];
    statusText.textContent = m[0];
    $('#overlayText').textContent = title || m[1];
    $('#overlaySub').textContent = sub ?? m[2];
    overlayBtn.hidden = !button;
    if (button) overlayBtn.textContent = button;
  }

  function halt(title, sub, button) {
    halted = true;
    clearTimeout(retryTimer); retryTimer = null;
    setStatus('blocked', title, sub, button);
  }
  overlayBtn.addEventListener('click', () => { halted = false; retry = 0; connect(); });

  function authed() {
    wsOpen = true; retry = 0; lastRx = performance.now();
    setStatus('connected');
    ping();
  }

  function connect() {
    clearTimeout(retryTimer); retryTimer = null;
    if (halted) return;
    if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) return;
    setStatus(retry ? 'disconnected' : 'connecting');
    let sock;
    try { sock = new WebSocket(WS_URL); } catch (_) { scheduleReconnect(); return; }
    ws = sock;
    // Abandon a connect attempt that hangs (e.g. Mac asleep).
    const connectTimeout = setTimeout(() => { if (ws === sock && sock.readyState !== WebSocket.OPEN) dropSocket(); }, 4000);
    sock.onopen = () => {
      if (ws !== sock) return;
      clearTimeout(connectTimeout);
      lastRx = performance.now();
      setStatus('authenticating');
    };
    sock.onmessage = (ev) => {
      if (ws !== sock) return;
      lastRx = performance.now();
      let m; try { m = JSON.parse(ev.data); } catch (_) { return; }
      switch (m.t) {
        case 'hello': {
          hostName = m.host || '';
          checkForUpdate();
          // Scroll the same way as the Mac's own trackpad, unless the user picked a direction here.
          if (typeof m.natural === 'boolean') macNatural = m.natural;
          if (typeof m.natural === 'boolean' && !S.naturalSet && S.natural !== m.natural) {
            S.natural = m.natural; saveSettings(); renderSettings();
          }
          onHello(sock, m.nonce).catch(() => { if (ws === sock) dropSocket(); });
          break;
        }
        case 'auth_ok': authed(); afterAuth(sock, !!m.pk); break;
        case 'rekeyed': afterAuth(sock, true); break;
        case 'pair_wait':
          if (m.code) {
            setStatus('pairing', `Type ${m.code} on your Mac`,
              'A dialog is showing on the Mac’s screen. Type this code into it and click “Allow”. This is needed once per phone.');
          } else setStatus('pairing');
          break;
        case 'paired':
          saveDevice(m.key ? { id: m.id, key: m.key, name: m.name } : { id: m.id, name: m.name, pk: true });
          flash('Paired with your Mac');
          authed();
          break;
        case 'locked': flash('Mac is locked: unlock it first', 1800); break;
        case 'idle': paused = true; break;        // the Mac closes the socket right after
        case 'auth_fail':
          saveDevice(null);
          dropKeyPair();
          halt('This phone isn’t paired anymore', 'It was removed on the Mac (or the Mac’s list was reset). Pair again to keep using it.', 'Pair again');
          break;
        case 'pair_denied': {
          const mins = Math.max(1, Math.ceil((m.retry_in || 0) / 60));
          const why = {
            refused: ['Your Mac didn’t allow this phone', `You can try again in about ${mins} min.`],
            cooldown: ['Pairing was refused recently', `Try again in about ${mins} min.`],
            busy: ['Another device is pairing right now', 'Finish or dismiss the dialog on the Mac, then try again.'],
            locked: ['New phones are turned off on this Mac', 'Pairing was disabled when the server was started (--no-pairing).'],
            closed: ['This Mac already has a paired phone', 'To add this one, run  ./touchpad pair  on the Mac, then tap Try again within 2 minutes.'],
            badcode: ['That code didn’t match', 'Tap Try again, then type the new code shown here into the dialog on the Mac.'],
          }[m.reason] || ['Pairing failed', ''];
          halt(why[0], why[1], 'Try again');
          break;
        }
        case 'p':
          if (typeof m.i === 'number') {
            const sample = performance.now() - m.i;
            rtt = rtt == null ? sample : rtt * 0.7 + sample * 0.3;
            latencyEl.textContent = Math.round(rtt) + ' ms';
          }
          break;
      }
    };
    sock.onclose = () => { if (ws !== sock) return; clearTimeout(connectTimeout); dropSocket(); };
    sock.onerror = () => { /* onclose follows */ };
  }

  // Forget the current socket immediately (don't wait for a slow TCP close) and retry.
  function dropSocket() {
    const old = ws;
    ws = null; wsOpen = false;
    if (old) { old.onclose = old.onmessage = old.onopen = null; try { old.close(); } catch (_) {} }
    endDrag();
    if (halted) return;               // keep the "refused / forgotten" message up
    if (paused) { setStatus('paused'); return; }
    setStatus('disconnected');
    scheduleReconnect();
  }

  function scheduleReconnect() {
    if (retryTimer || halted) return;
    const delay = Math.min(4000, 250 * Math.pow(1.7, retry++));
    retryTimer = setTimeout(() => { retryTimer = null; connect(); }, delay);
  }

  function reconnectNow() { if (halted) return; paused = false; retry = 0; clearTimeout(retryTimer); retryTimer = null; if (!wsOpen) connect(); }

  function send(obj) {
    if (!wsOpen || ws.readyState !== WebSocket.OPEN) return false;
    ws.send(JSON.stringify(obj));
    return true;
  }
  const canStream = () => wsOpen && ws.bufferedAmount < 1024;

  function ping() { send({ t: 'p', i: performance.now() }); }
  setInterval(() => {
    if (!wsOpen) return;
    if (performance.now() - lastRx > 6000) dropSocket();   // silent death (Wi-Fi sleep etc.)
    else ping();
  }, 2000);

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { hiddenAt = performance.now(); endDrag(); releaseWakeLock(); return; }
    // iOS freezes backgrounded pages; a socket that looks open is often dead.
    if (wsOpen && performance.now() - hiddenAt > 3000) dropSocket();
    reconnectNow();
    acquireWakeLock();
  });
  window.addEventListener('pageshow', reconnectNow);
  window.addEventListener('online', reconnectNow);

  // ----------------------------------------------------------- frame loop
  const pend = { mx: 0, my: 0, sx: 0, sy: 0, z: 0, r: 0 };
  // Trackpad-style phases, so the Mac treats our scrolling/zooming like a real
  // trackpad's (elastic edges, swipe between pages, smooth pinch zoom).
  let scrollPh = '';              // '' | 'touch' (fingers down) | 'momStart' | 'mom'
  let zoomOn = false, rotOn = false;
  let momentum = null;            // {vx, vy} in px/ms while coasting after a scroll flick
  let rafId = 0, lastFrame = 0, speedEma = 0;
  const r2 = (v) => Math.round(v * 100) / 100;

  function frame(now) {
    step(now);
    const busy = touches.size || momentum || pend.mx || pend.my || pend.sx || pend.sy;
    rafId = busy ? requestAnimationFrame(frame) : 0;
  }

  // One flush of the accumulators. Normally driven by rAF; touchmove calls it
  // directly if rAF is starved (iOS Low Power Mode caps rAF at 30 fps).
  function step(now) {
    const dt = Math.min(50, Math.max(8, now - lastFrame));
    lastFrame = now;

    if (momentum) {
      pend.sx += momentum.vx * dt;
      pend.sy += momentum.vy * dt;
      const decay = Math.pow(0.95, dt / 16.7);
      momentum.vx *= decay; momentum.vy *= decay;
      if (Math.hypot(momentum.vx, momentum.vy) < 0.02) { momentum = null; endMomentum(); }
    }

    if (!wsOpen) { pend.mx = pend.my = pend.sx = pend.sy = pend.z = pend.r = 0; }

    if (pend.mx || pend.my) {
      const speed = Math.hypot(pend.mx, pend.my) / dt;            // phone px per ms
      speedEma = speedEma * 0.4 + speed * 0.6;
      // Slow = precise, fast = cross the TV in one swipe.
      const gain = S.sens * (1 + S.accel * 1.9 * Math.min(3, Math.max(0, speedEma - 0.1)));
      if (canStream()) {
        send({ t: 'm', x: r2(pend.mx * gain), y: r2(pend.my * gain) });
        pend.mx = pend.my = 0;
      }
    } else {
      speedEma *= 0.5;
    }

    if (pend.sx || pend.sy) {
      const k = S.scroll * (S.natural ? 1 : -1);
      if (canStream()) {
        const msg = { t: 's', x: r2(pend.sx * k), y: r2(pend.sy * k) };
        if (scrollPh === 'touch' || scrollPh === 'touchStart') {
          msg.ph = scrollPh === 'touchStart' ? 'b' : 'c'; scrollPh = 'touch';
        } else if (scrollPh === 'momStart' || scrollPh === 'mom') {
          msg.mo = scrollPh === 'momStart' ? 'b' : 'c'; scrollPh = 'mom';
        }
        send(msg);
        pend.sx = pend.sy = 0;
      }
    }

    if (pend.z && canStream()) {
      send({ t: 'z', ph: zoomOn ? 'c' : 'b', v: Math.round((Math.exp(pend.z) - 1) * 10000) / 10000 });
      zoomOn = true; pend.z = 0;
    }
    if (pend.r && canStream()) {
      send({ t: 'rot', ph: rotOn ? 'c' : 'b', v: r2(pend.r) });
      rotOn = true; pend.r = 0;
    }
  }

  // ---- phase bookkeeping
  function beginScroll() { if (!scrollPh) scrollPh = 'touchStart'; }
  // Fingers lifted. Optionally coast with momentum, like a flicked trackpad.
  function endScroll(vx, vy) {
    step(performance.now());
    if (scrollPh === 'touch') send({ t: 's', x: 0, y: 0, ph: 'e' });
    scrollPh = '';
    if (vx !== undefined && Math.hypot(vx, vy) > 0.25) {
      momentum = { vx, vy }; scrollPh = 'momStart'; kick();
    }
  }
  function endMomentum() {
    if (scrollPh === 'mom') send({ t: 's', x: 0, y: 0, mo: 'e' });
    if (scrollPh === 'mom' || scrollPh === 'momStart') scrollPh = '';
  }
  function stopMomentum() { if (momentum) { momentum = null; pend.sx = pend.sy = 0; } endMomentum(); }
  function endPinch() {
    step(performance.now());
    if (zoomOn) send({ t: 'z', ph: 'e', v: 0 });
    if (rotOn) send({ t: 'rot', ph: 'e', v: 0 });
    zoomOn = rotOn = false; pend.z = pend.r = 0;
  }
  const FALLBACK_MS = 24;
  function kick() {
    const now = performance.now();
    if (!rafId) { lastFrame = now; rafId = requestAnimationFrame(frame); }
    else if (now - lastFrame > FALLBACK_MS) step(now);
  }

  // ------------------------------------------------------------- feedback
  const pad = $('#pad'), flashEl = $('#flash'), hintEl = $('#hint');
  const dots = new Map();
  let flashTimer = 0;

  function haptic() {
    if (navigator.vibrate) { navigator.vibrate(8); return; }       // Android
    if (!S.haptics) return;
    // iOS 18+: toggling a <input switch> via its label produces a system haptic.
    // Only works inside a user-activation event (touchend / pointerup / click).
    try {
      const label = document.createElement('label');
      label.ariaHidden = 'true';
      label.style.display = 'none';
      const input = document.createElement('input');
      input.type = 'checkbox';
      input.setAttribute('switch', '');
      label.appendChild(input);
      document.head.appendChild(label);
      label.click();
      label.remove();
    } catch (_) {}
  }

  function flash(text, ms = 350) {
    flashEl.textContent = text;
    flashEl.classList.add('show');
    clearTimeout(flashTimer);
    flashTimer = setTimeout(() => flashEl.classList.remove('show'), ms);
  }

  function ripple(x, y, right) {
    const r = padRect;
    const el = document.createElement('div');
    el.className = 'ripple' + (right ? ' right' : '');
    el.style.left = (x - r.left) + 'px';
    el.style.top = (y - r.top) + 'px';
    pad.appendChild(el);
    setTimeout(() => el.remove(), 400);
  }

  function placeDot(id, x, y) {
    let el = dots.get(id);
    if (!el) {
      el = document.createElement('div');
      el.className = 'touchdot';
      pad.appendChild(el);
      dots.set(id, el);
    }
    const r = padRect;
    el.style.transform = `translate3d(${x - r.left}px, ${y - r.top}px, 0)`;
    el.classList.toggle('drag', !!(g && g.mode === 'drag'));
  }
  function removeDot(id) { const el = dots.get(id); if (el) { el.remove(); dots.delete(id); } }

  let hintTimer = 0;
  function dismissHint() {
    if (hintTimer || hintEl.classList.contains('gone')) return;
    hintTimer = setTimeout(() => hintEl.classList.add('gone'), 4000);
  }

  // ------------------------------------------------------------- gestures
  const touches = new Map();      // identifier -> {x, y, sx, sy}
  let g = null;                   // current gesture
  let lastTap = null;             // {t, x, y} of the last one-finger tap
  let holdTimer = 0;
  // ---- Portrait lock. iOS ignores orientation locks for web apps, so when the
  // phone turns sideways the whole page is rotated back (CSS on html.rot-cw /
  // html.rot-ccw) and touch points are mapped into the page's own portrait frame.
  let rot = '';                                   // '' | 'cw' | 'ccw'
  function updateRotation() {
    const W = innerWidth, H = innerHeight;
    let next = '';
    if (W > H) {
      // window.orientation (iOS): 90 = phone turned counter-clockwise, -90 = clockwise.
      const a = typeof window.orientation === 'number' ? window.orientation
        : (screen.orientation ? (screen.orientation.angle === 270 ? -90 : screen.orientation.angle) : 90);
      next = a === -90 ? 'cw' : 'ccw';
    }
    const root = document.documentElement;
    root.style.setProperty('--vw', W + 'px');
    root.style.setProperty('--vh', H + 'px');
    root.classList.toggle('rot', !!next);
    root.classList.toggle('rot-cw', next === 'cw');
    root.classList.toggle('rot-ccw', next === 'ccw');
    rot = next;
    padRect = padOrigin();
  }
  // Screen (client) coordinates -> page coordinates (identity when upright).
  function toLocal(x, y) {
    if (rot === 'cw') return { x: y, y: innerWidth - x };
    if (rot === 'ccw') return { x: innerHeight - y, y: x };
    return { x, y };
  }
  const P = (t) => toLocal(t.clientX, t.clientY);
  // The pad's top-left corner in page coordinates (layout offsets ignore the rotation).
  function padOrigin() {
    let left = 0, top = 0;
    for (let el = pad; el && el !== document.body; el = el.offsetParent) { left += el.offsetLeft; top += el.offsetTop; }
    return { left, top };
  }
  let padRect = padOrigin();
  const dragBadge = $('#dragBadge');
  let holdLatched = false;        // "Hold click" button on the remote

  function clearHold() { clearTimeout(holdTimer); holdTimer = 0; }

  function startDrag() {
    clearHold();
    if (!g || g.mode !== 'maybeDrag') return;
    g.mode = 'drag';
    g.dead = false;
    send({ t: 'd', b: 'l' });
    dragBadge.hidden = false;
    for (const el of dots.values()) el.classList.add('drag');
  }

  function endDrag() {
    if (g && g.mode === 'drag') { send({ t: 'u' }); g.mode = 'done'; }
    if (holdLatched) { holdLatched = false; send({ t: 'u' }); $('#holdBtn').classList.remove('on'); }
    dragBadge.hidden = true;
  }

  function click(button, x, y) {
    send({ t: 'c', b: button });
    ripple(x, y, button === 'r');
    flash(button === 'r' ? 'Right click' : 'Click');
    haptic();
  }

  // Three-finger swipes, mapped like the Mac's own trackpad defaults.
  // Fingers left → Control-← (previous desktop), right → Control-→, as on the Magic Trackpad.
  function swipe3(dx, dy) {
    let key, label;
    if (Math.abs(dy) >= Math.abs(dx)) {
      [key, label] = dy < 0 ? ['up', 'Mission Control'] : ['down', 'App windows'];
    } else {
      [key, label] = dx < 0 ? ['left', '← Previous desktop'] : ['right', 'Next desktop →'];
    }
    send({ t: 'k', k: key, m: ['ctrl'] });
    flash(label);
    haptic();
  }

  // ---- geometry of the fingers currently down
  function fingerGeometry() {
    const pts = [...touches.values()];
    const n = pts.length || 1;
    const cx = pts.reduce((a, p) => a + p.x, 0) / n, cy = pts.reduce((a, p) => a + p.y, 0) / n;
    const r = pts.reduce((a, p) => a + Math.hypot(p.x - cx, p.y - cy), 0) / n;   // mean spread
    let d = 0, ang = 0;
    if (pts.length >= 2) {
      d = Math.hypot(pts[1].x - pts[0].x, pts[1].y - pts[0].y);
      ang = Math.atan2(pts[1].y - pts[0].y, pts[1].x - pts[0].x) * 180 / Math.PI;
    }
    return { cx, cy, r, d, ang };
  }
  const wrap180 = (x) => ((x + 540) % 360) - 180;

  function startTwo(now, t0, moved, ts) {
    const f = fingerGeometry();
    g = { mode: 'two', lock: '', t0, moved, vx: 0, vy: 0, lastTs: ts,
          d0: f.d, a0: f.ang, d: f.d, a: f.ang, cx: f.cx, cy: f.cy, travel: 0, hx: 0, hy: 0, twist: 0 };
  }
  function startMulti(n, now) {
    const f = fingerGeometry();
    g = { mode: n >= 4 ? 'four' : 'three', t0: now, ax: 0, ay: 0, fired: false, moved: false, r0: f.r, cx: f.cx, cy: f.cy };
  }
  // Leaving a two-finger gesture (finger lifted, or more fingers arrived).
  function finishTwo(vx, vy) {
    if (g.lock === 'pinch') endPinch();
    else if (g.lock === 'scroll') endScroll(vx, vy);
  }

  // ---- one-finger scroll strip along the right (or left) edge
  const strip = $('#strip'), stripSwap = $('#stripSwap');
  const SWAP_HOLD_MS = 450;    // holding a thumb still on the empty opposite edge moves the strip there
  function updateStrip() {
    strip.hidden = stripSwap.hidden = S.strip === 'off';
    strip.classList.toggle('left', S.strip === 'left');
    stripSwap.classList.toggle('right', S.strip === 'left');   // the button sits opposite the strip
  }
  function swapStrip() {
    if (S.strip === 'off') return;
    S.strip = S.strip === 'right' ? 'left' : 'right';
    saveSettings(); updateStrip(); renderSettings();
    flash(S.strip === 'left' ? '← Scroll strip on the left' : 'Scroll strip on the right →');
    haptic();
  }
  // Is this point on the empty edge opposite the strip?
  function inOppositeEdge(q) {
    if (S.strip === 'off') return false;
    const x = q.x - padRect.left;
    return S.strip === 'left' ? x >= pad.offsetWidth - STRIP_W : x <= STRIP_W;
  }
  function inStrip(q) {
    if (S.strip === 'off') return false;
    const x = q.x - padRect.left;
    return S.strip === 'left' ? x <= STRIP_W : x >= pad.offsetWidth - STRIP_W;
  }

  pad.addEventListener('touchstart', (e) => {
    e.preventDefault();           // also blocks edge-swipe-back, long-press menus, magnifier
    stopMomentum();
    padRect = padOrigin();
    const now = performance.now();
    if (!g && e.target.closest && e.target.closest('#stripSwap')) {   // the ⇆ button
      stripSwap.classList.add('pressed');
      setTimeout(() => stripSwap.classList.remove('pressed'), 150);
      swapStrip();
      return;
    }
    for (const t of e.changedTouches) {
      const q = P(t);
      touches.set(t.identifier, { x: q.x, y: q.y, sx: q.x, sy: q.y });
      placeDot(t.identifier, q.x, q.y);
    }
    const n = touches.size;
    if (!g) {
      const t = P(e.changedTouches[0]);
      if (n === 1 && inStrip(t)) {
        g = { mode: 'strip', t0: now, moved: false, vx: 0, vy: 0, lastTs: e.timeStamp };
        strip.classList.add('on');
      } else if (n === 1) {
        const armed = S.dragTap && lastTap && now - lastTap.t < DTAP_MS &&
          Math.hypot(t.x - lastTap.x, t.y - lastTap.y) < DTAP_DIST;
        g = { mode: armed ? 'maybeDrag' : 'one', t0: now, moved: false, dead: true, ax: 0, ay: 0 };
        if (armed) holdTimer = setTimeout(startDrag, HOLD_MS);
        else if (inOppositeEdge(t)) {
          const mine = g;
          g.swapTimer = setTimeout(() => {
            if (g === mine && g.mode === 'one' && !g.moved && touches.size === 1) { swapStrip(); g.mode = 'done'; }
          }, SWAP_HOLD_MS);
        }
      } else if (n === 2) {
        startTwo(now, now, false, e.timeStamp);
      } else {
        startMulti(n, now);
      }
    } else if (n >= 3 && (g.mode === 'one' || g.mode === 'maybeDrag' || g.mode === 'two')) {
      // Third finger arrived: a three-finger gesture. Drop any scroll/move/zoom in flight.
      clearHold();
      if (g.mode === 'two') finishTwo();
      pend.mx = pend.my = pend.sx = pend.sy = 0;
      startMulti(n, g.t0 && now - g.t0 < 150 ? g.t0 : now);
    } else if (n >= 4 && g.mode === 'three' && !g.fired) {
      startMulti(n, g.t0);
    } else if (n >= 2 && (g.mode === 'one' || g.mode === 'maybeDrag')) {
      // Second finger arrived: it's a two-finger gesture. Keep the first finger's
      // start time so a slightly staggered two-finger tap still counts.
      clearHold();
      startTwo(now, g.moved ? now : g.t0, g.moved, e.timeStamp);
      pend.mx = pend.my = 0;
    }
    dismissHint();
    kick();
  }, { passive: false });

  pad.addEventListener('touchmove', (e) => {
    e.preventDefault();
    if (!g) return;
    let sx = 0, sy = 0, k = 0;
    for (const t of e.changedTouches) {
      const p = touches.get(t.identifier);
      if (!p) continue;
      const q = P(t);
      sx += q.x - p.x; sy += q.y - p.y; k++;
      p.x = q.x; p.y = q.y;
      if (!g.moved && Math.hypot(p.x - p.sx, p.y - p.sy) > TAP_SLOP) g.moved = true;
      placeDot(t.identifier, p.x, p.y);
    }
    if (!k) return;

    switch (g.mode) {
      case 'one':
        if (g.dead) {
          g.ax += sx; g.ay += sy;
          if (Math.hypot(g.ax, g.ay) > DEADZONE) { g.dead = false; pend.mx += g.ax; pend.my += g.ay; }
        } else { pend.mx += sx; pend.my += sy; }
        break;
      case 'maybeDrag':
        g.ax += sx; g.ay += sy;
        if (g.moved) { startDrag(); pend.mx += g.ax; pend.my += g.ay; }
        break;
      case 'drag':
        pend.mx += sx; pend.my += sy;
        break;
      case 'strip': {
        if (!g.moved) break;                     // a tap in the strip still clicks
        beginScroll();
        pend.sy += sy * STRIP_GAIN;
        const dt = Math.max(4, e.timeStamp - g.lastTs);
        g.lastTs = e.timeStamp;
        g.vx = 0;
        g.vy = g.vy * 0.6 + (sy * STRIP_GAIN / dt) * 0.4;
        break;
      }
      case 'two': {
        const f = fingerGeometry();
        const cx = f.cx - g.cx, cy = f.cy - g.cy;          // centroid delta this event
        g.cx = f.cx; g.cy = f.cy;
        const da = wrap180(f.ang - g.a);
        const ratio = g.d > 0 && f.d > 0 ? f.d / g.d : 1;
        g.d = f.d; g.a = f.ang;
        g.travel += Math.hypot(cx, cy);
        g.twist += da;
        if (!g.lock) {
          // Decide what these two fingers are doing: zooming (spacing changes)
          // or scrolling (moving together). Hold scroll until we know.
          g.hx += cx; g.hy += cy;
          const spread = Math.abs(f.d - g.d0);
          if (spread > PINCH_SLOP && spread > g.travel * 1.2) g.lock = 'pinch';
          else if (Math.abs(wrap180(f.ang - g.a0)) > ROTATE_SLOP * 1.5 && g.travel < SCROLL_LOCK * 2) g.lock = 'pinch';
          else if (g.travel > SCROLL_LOCK) {
            g.lock = 'scroll'; beginScroll(); pend.sx += g.hx; pend.sy += g.hy;
          }
          if (g.lock === 'pinch') { g.moved = true; g.twist = wrap180(f.ang - g.a0); }
          break;
        }
        if (g.lock === 'scroll') {
          pend.sx += cx; pend.sy += cy;
          const dt = Math.max(4, e.timeStamp - g.lastTs);
          g.lastTs = e.timeStamp;
          g.vx = g.vx * 0.6 + (cx / dt) * 0.4;
          g.vy = g.vy * 0.6 + (cy / dt) * 0.4;
        } else {
          pend.z += Math.log(ratio);
          // Rotation starts only after a real twist, so zooming doesn't wobble.
          // Screen angles grow clockwise; macOS rotation is counter-clockwise-positive.
          if (g.rot) pend.r -= da;
          else if (Math.abs(g.twist) > ROTATE_SLOP) { g.rot = true; pend.r -= g.twist; }
        }
        break;
      }
      case 'three':
      case 'four': {
        if (g.fired) break;
        const f = fingerGeometry();
        g.ax += f.cx - g.cx; g.ay += f.cy - g.cy;
        g.cx = f.cx; g.cy = f.cy;
        if (g.mode === 'four' && f.r - g.r0 > SPREAD4 && f.r - g.r0 > Math.hypot(g.ax, g.ay)) {
          g.fired = true;
          send({ t: 'k', k: 'f11', m: [] });
          flash('Show Desktop');
          haptic();
        } else if (Math.hypot(g.ax, g.ay) > SWIPE3_DIST) {
          g.fired = true; swipe3(g.ax, g.ay);
        }
        break;
      }
    }
    kick();
  }, { passive: false });

  function onTouchEnd(e, cancelled) {
    e.preventDefault();
    const now = performance.now();
    lastTouchEnd = now;
    if (pend.mx || pend.my) step(now);   // land the last bit of motion before any click/release
    const before = touches.size;
    for (const t of e.changedTouches) { touches.delete(t.identifier); removeDot(t.identifier); }
    if (e.touches.length === 0) {       // iOS can drop touches; resync
      touches.clear();
      for (const id of [...dots.keys()]) removeDot(id);
    }
    const n = touches.size;
    if (!g) return;
    clearTimeout(g.swapTimer);
    const dur = now - g.t0;
    const t = P(e.changedTouches[0]);

    if (g.mode === 'three' || g.mode === 'four') {
      if (n < before) {
        // Three-finger tap: Look up (dictionary / data detectors), like a trackpad.
        if (g.mode === 'three' && !cancelled && !g.fired && !g.moved && dur < TWO_TAP_MS + 80) {
          send({ t: 'k', k: 'd', m: ['ctrl', 'cmd'] });
          flash('Look up');
          haptic();
        }
        g = n ? { mode: 'done' } : null;
      }
    } else if (g.mode === 'two') {
      if (n < before) {
        // The first lifted finger ends a two-finger gesture.
        if (!cancelled && !g.moved && dur < TWO_TAP_MS) {
          click('r', t.x, t.y);
        } else if (g.lock === 'scroll' && e.timeStamp - g.lastTs < 80) {
          finishTwo(g.vx, g.vy);
        } else {
          finishTwo();
        }
        g = n ? { mode: 'done' } : null;
      }
    } else if (g.mode === 'strip') {
      if (n === 0) {
        strip.classList.remove('on');
        if (!g.moved && !cancelled && dur < TAP_MS) click('l', t.x, t.y);
        else if (g.moved) endScroll(0, e.timeStamp - g.lastTs < 80 ? g.vy : 0);
        g = null;
      }
    } else if (n === 0) {
      clearHold();
      if (g.mode === 'drag') {
        send({ t: 'u' });
        dragBadge.hidden = true;
      } else if ((g.mode === 'one' || g.mode === 'maybeDrag') && !cancelled && !g.moved && dur < TAP_MS) {
        if (holdLatched) {            // a tap ends a latched "Hold click"
          endDrag();
          flash('Released');
          haptic();
        } else {
          click('l', t.x, t.y);
          lastTap = { t: now, x: t.x, y: t.y };
        }
      }
      g = null;
    }
    if (n === 0 && g && g.mode === 'done') g = null;
  }
  pad.addEventListener('touchend', (e) => onTouchEnd(e, false), { passive: false });
  pad.addEventListener('touchcancel', (e) => onTouchEnd(e, true), { passive: false });

  // Belt and braces against iOS page gestures anywhere outside scrollable sheets.
  document.addEventListener('touchmove', (e) => {
    if (!e.target.closest('.allow-touch')) e.preventDefault();
  }, { passive: false });
  for (const ev of ['gesturestart', 'gesturechange', 'gestureend']) {
    document.addEventListener(ev, (e) => e.preventDefault(), { passive: false });
  }
  document.addEventListener('dblclick', (e) => e.preventDefault(), { passive: false });
  document.addEventListener('contextmenu', (e) => e.preventDefault());
  window.addEventListener('resize', updateRotation);
  window.addEventListener('orientationchange', () => setTimeout(updateRotation, 50));
  updateRotation();

  // ------------------------------------------------------------- remote
  function pressKey(btn) {
    if (btn.dataset.media) send({ t: 'media', k: btn.dataset.media });
    else if (btn.dataset.key) {
      const mods = btn.dataset.mods ? btn.dataset.mods.split(',') : [];
      send({ t: 'k', k: btn.dataset.key, m: mods });
    }
  }

  function wireButton(btn) {
    let repeatTimer = 0;
    const stop = () => { clearTimeout(repeatTimer); repeatTimer = 0; btn.classList.remove('pressed'); };
    btn.addEventListener('pointerdown', (e) => {
      e.preventDefault();           // keep focus (and the iOS keyboard) where it is
      btn.classList.add('pressed');
      pressKey(btn);
      if (btn.hasAttribute('data-repeat')) {
        const rep = (delay) => { repeatTimer = setTimeout(() => { pressKey(btn); rep(90); }, delay); };
        rep(400);
      }
    });
    btn.addEventListener('pointerup', () => { stop(); haptic(); });
    btn.addEventListener('pointercancel', stop);
    btn.addEventListener('pointerleave', stop);
  }
  document.querySelectorAll('.rbtn[data-key], .rbtn[data-media], .key[data-key]').forEach(wireButton);

  $('#holdBtn').addEventListener('click', () => {
    if (holdLatched) { endDrag(); }
    else { holdLatched = true; send({ t: 'd', b: 'l' }); $('#holdBtn').classList.add('on'); dragBadge.hidden = false; }
    haptic();
  });

  // ------------------------------------------------------------- keyboard
  // A visible, multi-line box that mirrors what has been typed on the Mac. Each
  // edit is diffed against the last text sent, so autocorrect, predictive text,
  // dictation and edits in the middle all turn into the right Backspaces + text
  // (the Mac's cursor is assumed to sit at the end of what we typed).
  const kbInput = $('#kbinput'), kbBar = $('#kbbar');
  let composing = false, sent = '', lastBs = 0;

  const seg = typeof Intl !== 'undefined' && Intl.Segmenter ? new Intl.Segmenter() : null;
  // One Backspace on the Mac deletes one grapheme (e.g. a whole emoji), so diff by graphemes.
  const graphemes = (str) => seg ? Array.from(seg.segment(str), (x) => x.segment) : Array.from(str);

  function syncInput() {
    const now = kbInput.value;
    if (now === sent) return;
    const a = graphemes(sent), b = graphemes(now);
    let i = 0;
    while (i < a.length && i < b.length && a[i] === b[i]) i++;
    // Unchanged tail after the edit. Short tails are cheaper to retype; long ones
    // (a correction far back) are skipped over with the arrow keys instead.
    let j = 0;
    while (j < a.length - i && j < b.length - i && a[a.length - 1 - j] === b[b.length - 1 - j]) j++;
    const hop = j >= 4 ? j : 0;
    for (let k = 0; k < hop; k++) send({ t: 'k', k: 'left' });
    for (let d = i; d < a.length - hop; d++) send({ t: 'k', k: 'backspace' });
    const added = b.slice(i, b.length - hop).join('');
    if (added) send({ t: 'txt', s: added });
    for (let k = 0; k < hop; k++) send({ t: 'k', k: 'right' });
    sent = now;
    fitInput();
  }

  function clearInput() { kbInput.value = ''; sent = ''; fitInput(); }

  // Grow with the text, up to a few lines, then scroll inside the box.
  function fitInput() {
    kbInput.style.height = 'auto';
    kbInput.style.height = Math.min(kbInput.scrollHeight, 140) + 'px';
    kbInput.scrollTop = kbInput.scrollHeight;
    padRect = padOrigin();
  }

  function sendBackspace() {          // Backspace in an empty box still deletes on the Mac
    const t = performance.now();
    if (t - lastBs < 40) return;      // beforeinput + keydown can both report the same press
    lastBs = t;
    send({ t: 'k', k: 'backspace' });
  }

  function applyKbSettings() {
    const on = S.autocorrect ? 'on' : 'off';
    kbInput.setAttribute('autocorrect', on);
    kbInput.setAttribute('autocapitalize', S.autocorrect ? 'sentences' : 'off');
    kbInput.spellcheck = !!S.autocorrect;
  }

  kbInput.addEventListener('compositionstart', () => { composing = true; });
  kbInput.addEventListener('compositionend', () => { composing = false; syncInput(); });
  kbInput.addEventListener('input', () => { if (!composing) syncInput(); });
  kbInput.addEventListener('beforeinput', (e) => {
    if (e.inputType === 'deleteContentBackward' && kbInput.value === '') sendBackspace();
    // Return sends Return to the Mac and starts a fresh box.
    if (e.inputType === 'insertLineBreak' || e.inputType === 'insertParagraph') {
      e.preventDefault(); syncInput(); send({ t: 'k', k: 'return' }); clearInput();
    }
  });
  kbInput.addEventListener('keydown', (e) => {
    if (e.key === 'Backspace' && kbInput.value === '') sendBackspace();
    if (e.key === 'Enter' && !e.isComposing) {
      e.preventDefault(); syncInput(); send({ t: 'k', k: 'return' }); clearInput();
    }
  });
  // Password mode: a masked field instead of the live box. Nothing is sent while
  // you type, and iOS doesn't autocorrect, predict or learn what goes into a
  // password field. Return sends the whole thing followed by Return, then wipes it.
  const pwInput = $('#pwinput'), kbPass = $('#kbPass');
  let pwMode = false, switchingAt = -1e9, lastPwSend = 0;

  function setPwMode(on) {
    pwMode = on;
    switchingAt = performance.now();        // focus hops between the two fields: don't close the bar
    kbPass.setAttribute('aria-pressed', String(on));
    pwInput.value = '';
    kbInput.hidden = on;
    pwInput.hidden = !on;
    (on ? pwInput : kbInput).focus();
    if (!on) fitInput();
    padRect = padOrigin();
  }

  function sendPassword() {
    const t = performance.now();
    if (t - lastPwSend < 150) return;       // beforeinput + keydown can both report the same Return
    lastPwSend = t;
    const secret = pwInput.value;
    pwInput.value = '';
    if (!wsOpen) { flash('Not connected', 1200); return; }
    if (secret) send({ t: 'txt', s: secret });
    send({ t: 'k', k: 'return' });
    flash(secret ? 'Sent' : 'Return');
    haptic();
  }

  pwInput.addEventListener('beforeinput', (e) => {
    if (e.inputType === 'insertLineBreak' || e.inputType === 'insertParagraph') { e.preventDefault(); sendPassword(); }
  });
  pwInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.isComposing) { e.preventDefault(); sendPassword(); }
  });
  kbPass.addEventListener('pointerdown', (e) => { e.preventDefault(); setPwMode(!pwMode); haptic(); });

  const onKbBlur = () => {
    // Give focus a moment to land: moving between the two fields is not "keyboard closed".
    setTimeout(() => {
      const a = document.activeElement;
      if (a === kbInput || a === pwInput || performance.now() - switchingAt < 400) return;
      setKeyboard(false, true);
    }, 0);
  };
  kbInput.addEventListener('blur', onKbBlur);
  pwInput.addEventListener('blur', onKbBlur);
  $('#kbClear').addEventListener('pointerdown', (e) => {
    e.preventDefault();
    if (pwMode) pwInput.value = ''; else clearInput();
    haptic();
  });
  // Never leave a typed password sitting in a field nobody is looking at.
  document.addEventListener('visibilitychange', () => { if (document.hidden) pwInput.value = ''; });

  function setKeyboard(on, fromBlur) {
    $('#btnKeyboard').setAttribute('aria-pressed', String(on));
    kbBar.hidden = !on;
    if (!on && pwMode) {                    // closing the keyboard always leaves password mode
      pwMode = false;
      kbPass.setAttribute('aria-pressed', 'false');
      pwInput.hidden = true;
      kbInput.hidden = false;
    }
    pwInput.value = '';
    if (on) { applyKbSettings(); fitInput(); kbInput.focus(); }
    else if (!fromBlur) { kbInput.blur(); pwInput.blur(); }
    padRect = padOrigin();
    if (!on) maybeReload();
  }

  // ------------------------------------------------------------- toolbar
  $('#btnKeyboard').addEventListener('click', () => {
    setKeyboard($('#btnKeyboard').getAttribute('aria-pressed') !== 'true');
  });
  $('#btnRemote').addEventListener('click', () => {
    const remote = $('#remote');
    remote.hidden = !remote.hidden;
    document.body.classList.toggle('remote-open', !remote.hidden);
    $('#btnRemote').setAttribute('aria-pressed', String(!remote.hidden));
    padRect = padOrigin();
    try { localStorage.setItem('mtp.remote', remote.hidden ? '0' : '1'); } catch (_) {}
  });
  $('#btnSettings').addEventListener('click', () => toggleSettings());
  $('#closeSettings').addEventListener('click', () => toggleSettings(false));

  function toggleSettings(force) {
    const sheet = $('#settings');
    const open = force ?? sheet.hidden;
    sheet.hidden = !open;
    $('#btnSettings').setAttribute('aria-pressed', String(open));
  }

  // ------------------------------------------------------------- settings UI
  function renderSettings() {
    document.querySelectorAll('[data-setting]').forEach((el) => {
      const key = el.dataset.setting;
      if (el.type === 'checkbox') el.checked = !!S[key];
      else el.value = S[key];
      const out = document.querySelector(`output[data-for="${key}"]`);
      if (out) out.textContent = Number(S[key]).toFixed(1) + '×';
    });
  }
  document.querySelectorAll('[data-setting]').forEach((el) => {
    el.addEventListener('input', () => {
      const key = el.dataset.setting;
      S[key] = el.type === 'checkbox' ? el.checked : el.tagName === 'SELECT' ? el.value : parseFloat(el.value);
      if (key === 'natural') S.naturalSet = true;   // stop following the Mac's setting
      saveSettings();
      renderSettings();
      if (key === 'awake') S.awake ? acquireWakeLock() : releaseWakeLock();
      if (key === 'autocorrect') applyKbSettings();
      if (key === 'strip') updateStrip();
    });
  });
  $('#resetSettings').addEventListener('click', () => {
    Object.assign(S, DEFAULTS); delete S.naturalSet;
    if (macNatural !== null) S.natural = macNatural;
    saveSettings(); renderSettings(); updateStrip();
  });
  renderSettings();
  updateStrip();

  // ------------------------------------------------------------- wake lock
  // Keep the phone screen on while you're actively using it, but let it sleep
  // after WAKE_IDLE_MS without a touch, so a phone in a pocket can't keep
  // clicking and typing on the Mac.
  const WAKE_IDLE_MS = 2 * 60 * 1000;
  let wakeLock = null, lastTouch = performance.now();
  async function acquireWakeLock() {
    if (!S.awake || wakeLock || !('wakeLock' in navigator) || document.hidden) return;
    if (performance.now() - lastTouch > WAKE_IDLE_MS) return;
    try {
      wakeLock = await navigator.wakeLock.request('screen');
      wakeLock.addEventListener('release', () => { wakeLock = null; });
    } catch (_) { wakeLock = null; }
  }
  function releaseWakeLock() { if (wakeLock) { wakeLock.release().catch(() => {}); wakeLock = null; } }
  const markActive = () => { lastTouch = performance.now(); if (paused) reconnectNow(); };
  document.addEventListener('touchstart', markActive, { passive: true, capture: true });
  document.addEventListener('pointerdown', markActive, { passive: true, capture: true });
  // Needs a user gesture on some iOS versions.
  document.addEventListener('touchend', acquireWakeLock, { passive: true });
  setInterval(() => { if (wakeLock && performance.now() - lastTouch > WAKE_IDLE_MS) releaseWakeLock(); }, 10000);

  // ------------------------------------------------------------- install tip
  const standalone = navigator.standalone || matchMedia('(display-mode: standalone)').matches;
  let tipDismissed = false;
  try { tipDismissed = localStorage.getItem('mtp.tip') === '1'; } catch (_) {}
  if (!standalone && !tipDismissed && /iPhone|iPad|iPod/.test(navigator.userAgent)) $('#installTip').hidden = false;
  $('#dismissTip').addEventListener('click', () => {
    $('#installTip').hidden = true;
    try { localStorage.setItem('mtp.tip', '1'); } catch (_) {}
  });

  // ------------------------------------------------------------- offline shell
  // HTTPS only: the service worker caches the app, so the icon opens instantly
  // (showing "Looking for your Mac…") even when the Mac is off or asleep.
  // When a newer version arrives, reload into it as soon as you're not mid-gesture or typing.
  let updatePending = false, lastTouchEnd = 0;
  function checkForUpdate() {
    try { navigator.serviceWorker?.controller?.postMessage({ t: 'check' }); } catch (_) {}
  }
  function maybeReload() {
    if (!updatePending) return;
    const idle = touches.size === 0 && kbBar.hidden && performance.now() - lastTouchEnd > 1500;
    if (idle) { flash('Updating…'); setTimeout(() => location.reload(), 300); updatePending = false; }
    else setTimeout(maybeReload, 1000);
  }
  if ('serviceWorker' in navigator && window.isSecureContext) {
    navigator.serviceWorker.register('sw.js', { scope: base }).catch(() => {});
    navigator.serviceWorker.addEventListener('message', (e) => {
      if (e.data && e.data.t === 'updated' && !updatePending) { updatePending = true; maybeReload(); }
    });
  }

  // ------------------------------------------------------------- start
  try { if (localStorage.getItem('mtp.remote') === '1') $('#btnRemote').click(); } catch (_) {}
  connect();
  acquireWakeLock();
})();
