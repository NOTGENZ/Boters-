/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║           Boters+ v2.0 | Advanced Client-Side            ║
 * ║       Anti-Bot, Anti-Scraper & Fraud Mitigation          ║
 * ║   Mobile-First · Privacy-First · Zero Dependencies       ║
 * ╚══════════════════════════════════════════════════════════╝
 *
 * Detection Signals (19+):
 *  - UserAgent classification         - WebDriver / Selenium flags
 *  - Headless Chrome heuristics       - Mouse entropy & movement
 *  - Click pattern analysis           - Keyboard rhythm cadence
 *  - Touch vs pointer consistency     - Canvas fingerprint probe
 *  - WebGL renderer inspection        - AudioContext probe
 *  - DevTools open detection          - Iframe / embedded context
 *  - Screen geometry anomalies        - Plugin count heuristics
 *  - Hardware concurrency probe       - Permission query anomalies
 *  - Language/timezone spoofing       - Console object tampering
 *  - Scroll behavior (human entropy)
 *
 * Challenge Types:
 *  - Math puzzle (randomized)
 *  - Drag-to-unlock slider
 *  - Honeypot field (passive)
 *
 * Session: LocalStorage-backed, configurable expiry, tamper-aware
 * Callbacks: onVerified, onBlocked, onChallengeShown
 */

(function (global) {
    'use strict';

    // ─── Constants ────────────────────────────────────────────────────────────
    const LS_KEY        = 'btp_v2_session';
    const LS_FAIL_KEY   = 'btp_v2_fails';
    const VERSION       = '2.0.0';

    // ─── Risk thresholds ──────────────────────────────────────────────────────
    const RISK = {
        LOW:         30,  // auto-pass, no challenge
        MEDIUM:      60,  // show soft challenge
        HIGH:        85,  // show hard challenge + log
        BLOCK:      130,  // hard block, no challenge option
    };

    // ─── Helpers ──────────────────────────────────────────────────────────────
    const $ = (id) => document.getElementById(id);
    const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
    const rand  = (lo, hi)    => Math.floor(Math.random() * (hi - lo + 1)) + lo;
    const now   = () => Date.now();

    function entropy(arr) {
        if (!arr || arr.length < 2) return 0;
        const deltas = [];
        for (let i = 1; i < arr.length; i++) deltas.push(arr[i] - arr[i - 1]);
        const mean = deltas.reduce((a, b) => a + b, 0) / deltas.length;
        const variance = deltas.reduce((a, b) => a + (b - mean) ** 2, 0) / deltas.length;
        return Math.sqrt(variance); // std deviation
    }

    // ─── Main Class ───────────────────────────────────────────────────────────
    class BotersPlus {
        constructor(userConfig = {}) {
            this.config = {
                expiryDays:       3,
                minTimeMs:        2500,
                maxTimeMs:        7200000,
                maxClicksPerSec:  5,
                maxFailAttempts:  3,
                enableDevToolsDet:true,
                enableCanvasDet:  true,
                enableWebGLDet:   true,
                enableAudioDet:   true,
                blockOnMaxFails:  true,
                challengeType:    'auto',  // 'math' | 'slider' | 'auto'
                onVerified:       null,
                onBlocked:        null,
                onChallengeShown: null,
                debugMode:        false,
                ...userConfig
            };

            this._state = {
                riskScore:       0,
                riskReasons:     [],
                isVerified:      false,
                isBlocked:       false,
                mousePoints:     [],    // {x,y,t}
                mouseTimestamps: [],
                scrollTimestamps:[],
                clickTimestamps: [],
                keyTimestamps:   [],
                inputEventCount: 0,
                loadTime:        now(),
                challengeShown:  false,
                mouseMovedOnce:  false,
                touchDevice:     false,
            };

            this._log('Boters+ v' + VERSION + ' initializing…');
            this._boot();
        }

        // ─── Boot Sequence ────────────────────────────────────────────────────
        _boot() {
            // Check existing valid session first
            if (this._checkSession()) {
                this._log('Valid session found — auto-pass.');
                this._state.isVerified = true;
                return;
            }

            // Check fail lockout
            if (this._isLockedOut()) {
                this._log('User locked out due to max failures.');
                this._block('Too many failed verification attempts.');
                return;
            }

            this._injectCSS();

            // Passive signals (async-safe)
            this._signalUA();
            this._signalWebDriver();
            this._signalScreenGeometry();
            this._signalPlugins();
            this._signalHardwareConcurrency();
            this._signalLanguageTimezone();
            this._signalIframe();
            this._signalConsole();
            this._signalPermissions(); // async, non-blocking
            if (this.config.enableCanvasDet)  this._signalCanvas();
            if (this.config.enableWebGLDet)   this._signalWebGL();
            if (this.config.enableAudioDet)   this._signalAudio();
            if (this.config.enableDevToolsDet) this._signalDevTools();

            // Behavioral listeners (passive, collect data over time)
            this._setupBehaviorListeners();

            // Evaluate after minimum human dwell time
            setTimeout(() => this._evaluate(), this.config.minTimeMs);

            // Hard max session timer
            setTimeout(() => {
                if (!this._state.isVerified) {
                    this._showChallenge('Session timed out. Please verify.');
                }
            }, this.config.maxTimeMs);
        }

        // ─── Session Management ───────────────────────────────────────────────
        _checkSession() {
            try {
                const raw = localStorage.getItem(LS_KEY);
                if (!raw) return false;
                const session = JSON.parse(raw);
                const expiryMs = this.config.expiryDays * 86400000;
                if (
                    session &&
                    session.verified === true &&
                    session.ts &&
                    (now() - session.ts) < expiryMs &&
                    session.v === VERSION.split('.')[0] // major version match
                ) {
                    return true;
                }
                localStorage.removeItem(LS_KEY);
            } catch (_) {}
            return false;
        }

        _saveSession() {
            try {
                localStorage.setItem(LS_KEY, JSON.stringify({
                    verified: true,
                    ts: now(),
                    v: VERSION.split('.')[0]
                }));
            } catch (_) {}
        }

        _isLockedOut() {
            if (!this.config.blockOnMaxFails) return false;
            try {
                const raw = localStorage.getItem(LS_FAIL_KEY);
                if (!raw) return false;
                const data = JSON.parse(raw);
                // Reset lockout after 1 hour
                if (now() - data.ts > 3600000) {
                    localStorage.removeItem(LS_FAIL_KEY);
                    return false;
                }
                return data.count >= this.config.maxFailAttempts;
            } catch (_) {}
            return false;
        }

        _recordFail() {
            try {
                const raw = localStorage.getItem(LS_FAIL_KEY);
                let data = raw ? JSON.parse(raw) : { count: 0, ts: now() };
                data.count += 1;
                data.ts = now();
                localStorage.setItem(LS_FAIL_KEY, JSON.stringify(data));
                if (data.count >= this.config.maxFailAttempts) {
                    this._block('Maximum verification attempts exceeded. Try again in 1 hour.');
                }
            } catch (_) {}
        }

        // ─── Signal Detectors ─────────────────────────────────────────────────

        _addRisk(score, reason) {
            this._state.riskScore += score;
            this._state.riskReasons.push(`[+${score}] ${reason}`);
            this._log(`Risk +${score}: ${reason} (total: ${this._state.riskScore})`);
        }

        _subRisk(score, reason) {
            this._state.riskScore = Math.max(0, this._state.riskScore - score);
            this._log(`Risk -${score}: ${reason} (total: ${this._state.riskScore})`);
        }

        /** 1. UserAgent classification */
        _signalUA() {
            const ua = navigator.userAgent.toLowerCase();
            if (/bot|crawl|spider|slurp|facebookexternalhit|ia_archiver|netseer/i.test(ua)) {
                this._addRisk(120, 'Known bot UserAgent');
            } else if (/headlesschrome|phantomjs|slimerjs/i.test(ua)) {
                this._addRisk(110, 'Headless browser UA');
            } else if (/android|iphone|ipad/i.test(ua)) {
                this._addRisk(3,  'Mobile UA (low risk)');
                this._state.touchDevice = true;
            } else if (/windows/i.test(ua)) {
                this._addRisk(10, 'Windows desktop UA');
            } else if (/linux/i.test(ua) && !/android/i.test(ua)) {
                this._addRisk(45, 'Linux desktop UA (elevated)');
            } else if (/mac os x/i.test(ua)) {
                this._addRisk(8,  'macOS UA');
            } else {
                this._addRisk(25, 'Unknown UA');
            }
        }

        /** 2. WebDriver / automation flags */
        _signalWebDriver() {
            if (navigator.webdriver === true) {
                this._addRisk(120, 'navigator.webdriver = true (Selenium/Playwright)');
            }
            // Phantom / older Selenium artifacts
            if (window._phantom || window.__phantom || window.callPhantom) {
                this._addRisk(110, 'PhantomJS global detected');
            }
            if (window.__selenium_evaluate || window.__webdriver_evaluate ||
                window.__driver_evaluate || window.__webdriver_script_fn) {
                this._addRisk(110, 'Selenium evaluate hook detected');
            }
            if (document.$cdc_asdjflasutopfhvcZLmcfl_ ||
                document.$wdc_ ||
                window.$cdc_asdjflasutopfhvcZLmcfl_) {
                this._addRisk(110, 'ChromeDriver injection artifact ($cdc_)');
            }
        }

        /** 3. Screen geometry anomalies */
        _signalScreenGeometry() {
            const sw = screen.width, sh = screen.height;
            const ww = window.innerWidth, wh = window.innerHeight;

            // Headless browsers often report 0×0 or absurd sizes
            if (sw === 0 || sh === 0) {
                this._addRisk(90, 'Screen size is 0×0');
            }
            if (sw < 200 || sh < 200) {
                this._addRisk(50, 'Suspiciously small screen');
            }
            // Window larger than screen (common in headless VMs)
            if (ww > sw + 20 || wh > sh + 20) {
                this._addRisk(40, 'Window exceeds screen bounds');
            }
            // Available area equals full screen (no OS chrome → headless)
            if (screen.availWidth === sw && screen.availHeight === sh) {
                this._addRisk(15, 'No OS taskbar space detected');
            }
        }

        /** 4. Plugin count */
        _signalPlugins() {
            const count = navigator.plugins ? navigator.plugins.length : -1;
            if (count === 0) {
                this._addRisk(30, 'No browser plugins (common in headless)');
            } else if (count > 0 && count <= 3) {
                this._addRisk(10, 'Very few browser plugins');
            }
        }

        /** 5. Hardware concurrency */
        _signalHardwareConcurrency() {
            const cores = navigator.hardwareConcurrency;
            if (!cores || cores < 1) {
                this._addRisk(30, 'Hardware concurrency unavailable');
            } else if (cores === 1) {
                this._addRisk(15, 'Single core (possible VM/headless)');
            }
        }

        /** 6. Language / Timezone inconsistency */
        _signalLanguageTimezone() {
            const lang = navigator.language || '';
            if (!lang) {
                this._addRisk(20, 'No browser language set');
                return;
            }
            try {
                const tzOffset = new Date().getTimezoneOffset();
                // Detect if timezone is UTC and language implies non-UTC country
                // (basic heuristic — bots often run in UTC)
                if (tzOffset === 0 && /^(zh|ja|ko|hi|ar|ru)/i.test(lang)) {
                    this._addRisk(20, 'UTC timezone but non-UTC language region');
                }
            } catch (_) {}
        }

        /** 7. Iframe / embedded context detection */
        _signalIframe() {
            try {
                if (window.self !== window.top) {
                    this._addRisk(35, 'Page is embedded in an iframe');
                }
            } catch (_) {
                // Cross-origin iframe — accessing window.top throws
                this._addRisk(50, 'Cross-origin iframe detected');
            }
        }

        /** 8. Console object tampering */
        _signalConsole() {
            if (!window.console || typeof console.log !== 'function') {
                this._addRisk(30, 'console.log is missing or overridden');
            }
        }

        /** 9. Permissions API anomalies */
        async _signalPermissions() {
            if (!navigator.permissions || !navigator.permissions.query) return;
            try {
                const r = await navigator.permissions.query({ name: 'notifications' });
                // Headless usually returns 'denied' instantly with no prompts
                if (r.state === 'denied') {
                    this._addRisk(10, 'Notifications permission pre-denied');
                }
            } catch (_) {}
        }

        /** 10. Canvas fingerprint probe (headless returns blank/uniform canvas) */
        _signalCanvas() {
            try {
                const canvas = document.createElement('canvas');
                canvas.width = 200; canvas.height = 50;
                const ctx = canvas.getContext('2d');
                ctx.textBaseline = 'alphabetic';
                ctx.fillStyle = '#f60';
                ctx.fillRect(125, 1, 62, 20);
                ctx.fillStyle = '#069';
                ctx.font = '11pt "Arial"';
                ctx.fillText('Boters+ 😀 ☃', 2, 15);
                ctx.fillStyle = 'rgba(102,204,0,0.7)';
                ctx.font = '18pt "Arial"';
                ctx.fillText('Boters+ 😀 ☃', 4, 17);
                const data = canvas.toDataURL();

                // A truly blank or very-short data URL means canvas is spoofed/blocked
                if (!data || data.length < 500) {
                    this._addRisk(40, 'Canvas fingerprint is blank or spoofed');
                }
            } catch (_) {
                this._addRisk(20, 'Canvas fingerprint failed');
            }
        }

        /** 11. WebGL renderer inspection */
        _signalWebGL() {
            try {
                const canvas  = document.createElement('canvas');
                const gl      = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (!gl) {
                    this._addRisk(25, 'WebGL unavailable');
                    return;
                }
                const ext      = gl.getExtension('WEBGL_debug_renderer_info');
                if (!ext) return;
                const renderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '';
                const vendor   = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)   || '';
                const combined = (renderer + ' ' + vendor).toLowerCase();

                if (/swiftshader|llvmpipe|virtualbox|vmware|mesa offscreen/i.test(combined)) {
                    this._addRisk(70, `Virtual/software WebGL renderer: "${renderer}"`);
                } else if (/google/i.test(combined) && /swiftshader/i.test(combined)) {
                    this._addRisk(80, 'SwiftShader (headless Chrome renderer)');
                }
            } catch (_) {}
        }

        /** 12. AudioContext probe (headless often produces silent/zeroed output) */
        _signalAudio() {
            try {
                const AudioCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
                if (!AudioCtx) { this._addRisk(10, 'AudioContext unavailable'); return; }

                const ctx    = new AudioCtx(1, 44100, 44100);
                const osc    = ctx.createOscillator();
                const comp   = ctx.createDynamicsCompressor();

                [['knee','40'],['ratio','12'],['reduction','-20'],['attack','0'],['release','0.25']]
                    .forEach(([p, v]) => { try { comp[p].value = v; } catch(_){} });

                osc.connect(comp);
                comp.connect(ctx.destination);
                osc.start(0);

                ctx.startRendering().then(buf => {
                    const data   = buf.getChannelData(0);
                    const sample = Array.from(data.slice(4500, 4600));
                    const allZero = sample.every(v => v === 0);
                    if (allZero) this._addRisk(40, 'AudioContext output is all-zero (headless)');
                }).catch(() => {});
            } catch (_) {}
        }

        /** 13. DevTools open detection (size-based) */
        _signalDevTools() {
            const THRESHOLD = 160;
            const check = () => {
                const widthDiff  = window.outerWidth  - window.innerWidth;
                const heightDiff = window.outerHeight - window.innerHeight;
                if (widthDiff > THRESHOLD || heightDiff > THRESHOLD) {
                    if (!this._devToolsOpen) {
                        this._devToolsOpen = true;
                        this._addRisk(25, 'DevTools panel likely open');
                    }
                } else {
                    this._devToolsOpen = false;
                }
            };
            setInterval(check, 1000);
            check();
        }

        // ─── Behavioral Listeners ─────────────────────────────────────────────

        _setupBehaviorListeners() {
            // Mouse movement entropy
            document.addEventListener('mousemove', (e) => {
                if (this._state.isVerified) return;
                const t = now();
                this._state.mousePoints.push({ x: e.clientX, y: e.clientY, t });
                this._state.mouseTimestamps.push(t);
                this._state.mouseMovedOnce = true;

                // Keep last 60 points
                if (this._state.mousePoints.length > 60) {
                    this._state.mousePoints.shift();
                    this._state.mouseTimestamps.shift();
                }
            }, { passive: true });

            // Touch confirms real device
            document.addEventListener('touchstart', () => {
                this._state.touchDevice = true;
                this._subRisk(10, 'Touch event — real device confirmed');
            }, { passive: true, once: true });

            // Scroll entropy
            document.addEventListener('scroll', () => {
                if (this._state.isVerified) return;
                this._state.scrollTimestamps.push(now());
                if (this._state.scrollTimestamps.length > 20) this._state.scrollTimestamps.shift();
            }, { passive: true });

            // Rapid click detection
            document.addEventListener('click', (e) => {
                if (this._state.isVerified) return;
                const t = now();
                this._state.clickTimestamps.push(t);
                if (this._state.clickTimestamps.length > this.config.maxClicksPerSec) {
                    this._state.clickTimestamps.shift();
                }
                if (this._state.clickTimestamps.length === this.config.maxClicksPerSec) {
                    const span = t - this._state.clickTimestamps[0];
                    if (span <= 1000) {
                        this._addRisk(35, 'Rapid burst clicks detected');
                        this._showChallenge('Unusual clicking pattern detected.');
                    }
                }
            });

            // Keyboard rhythm cadence
            document.addEventListener('keydown', (e) => {
                if (this._state.isVerified) return;
                this._state.keyTimestamps.push(now());
                if (this._state.keyTimestamps.length > 30) this._state.keyTimestamps.shift();
            }, { passive: true });

            // Typing / input interaction lowers risk
            document.addEventListener('input', (e) => {
                if (this._state.isVerified) return;
                if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
                    this._state.inputEventCount++;
                    if (this._state.inputEventCount <= 5) {
                        this._subRisk(2, 'Human input event');
                    }
                }
            }, { passive: true });
        }

        // ─── Behavioral Analysis ──────────────────────────────────────────────

        _analyzeBehavior() {
            // Mouse entropy check
            if (this._state.mousePoints.length >= 10) {
                const xs = this._state.mousePoints.map(p => p.x);
                const ys = this._state.mousePoints.map(p => p.y);
                const xE = entropy(xs);
                const yE = entropy(ys);
                const mouseEntropy = (xE + yE) / 2;

                if (mouseEntropy < 2 && !this._state.touchDevice) {
                    // Very linear / robotic mouse movement
                    this._addRisk(30, `Very low mouse entropy (${mouseEntropy.toFixed(2)}) — robotic movement`);
                } else if (mouseEntropy > 5) {
                    this._subRisk(15, `High mouse entropy (${mouseEntropy.toFixed(2)}) — human-like movement`);
                }
            } else if (!this._state.touchDevice && !this._state.mouseMovedOnce) {
                this._addRisk(20, 'No mouse movement detected (desktop UA)');
            }

            // Keyboard rhythm
            const kts = this._state.keyTimestamps;
            if (kts.length >= 5) {
                const keyEntropy = entropy(kts);
                if (keyEntropy < 1) {
                    this._addRisk(20, 'Uniform keyboard cadence — possible automation');
                } else {
                    this._subRisk(10, 'Variable keyboard rhythm — human-like');
                }
            }

            // Scroll entropy
            if (this._state.scrollTimestamps.length >= 3) {
                const scrollEntropy = entropy(this._state.scrollTimestamps);
                if (scrollEntropy > 10) {
                    this._subRisk(8, 'Human-like scroll behavior');
                }
            }

            // Touch device — lower baseline risk significantly
            if (this._state.touchDevice) {
                this._subRisk(20, 'Touch device confirmed');
            }
        }

        // ─── Evaluation ───────────────────────────────────────────────────────

        _evaluate() {
            if (this._state.isVerified || this._state.isBlocked) return;

            this._analyzeBehavior();

            const score = this._state.riskScore;
            this._log(`Final risk score: ${score}. Reasons: ${this._state.riskReasons.join('; ')}`);

            if (score >= RISK.BLOCK) {
                this._block('Automated access detected. Human verification not available.');
            } else if (score >= RISK.MEDIUM) {
                const type = score >= RISK.HIGH ? 'hard' : 'soft';
                this._showChallenge(null, type);
            } else {
                // Low risk — auto-verify silently
                this._log('Risk is low — auto-verifying.');
                this._verifySuccess(true);
            }
        }

        // ─── Challenge UI ─────────────────────────────────────────────────────

        _showChallenge(reason, difficulty = 'soft') {
            if (this._state.challengeShown || $('btp-overlay')) return;
            this._state.challengeShown = true;

            const challengeType = this.config.challengeType === 'auto'
                ? (difficulty === 'hard' ? 'math' : 'slider')
                : this.config.challengeType;

            const overlay = document.createElement('div');
            overlay.id    = 'btp-overlay';
            overlay.setAttribute('role', 'dialog');
            overlay.setAttribute('aria-modal', 'true');
            overlay.setAttribute('aria-label', 'Human verification required');

            overlay.innerHTML = this._buildChallengeHTML(reason, challengeType, difficulty);
            document.body.appendChild(overlay);

            // Wire up challenge logic
            if (challengeType === 'slider') {
                this._wireSlider();
            } else {
                this._wireMath();
            }

            if (typeof this.config.onChallengeShown === 'function') {
                this.config.onChallengeShown({ score: this._state.riskScore, difficulty, type: challengeType });
            }

            // Animate in
            requestAnimationFrame(() => {
                const card = $('btp-card');
                if (card) card.classList.add('btp-visible');
            });
        }

        _buildChallengeHTML(reason, type, difficulty) {
            const msg = reason || (difficulty === 'hard'
                ? 'Additional verification required for this session.'
                : 'Quick check — confirm you\'re human.');

            const challengeInner = type === 'slider'
                ? this._buildSliderHTML()
                : this._buildMathHTML();

            return `
<div class="btp-overlay-bg"></div>
<div class="btp-wrap">
  <div class="btp-card" id="btp-card" role="document">
    <div class="btp-brand">
      <div class="btp-shield">
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6L12 2z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
          <path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </div>
      <div class="btp-brand-text">
        <span class="btp-title">Boters<sup>+</sup></span>
        <span class="btp-sub">Security Verification</span>
      </div>
    </div>

    <div class="btp-divider"></div>

    <p class="btp-msg">${this._escHTML(msg)}</p>

    <!-- Honeypot: never visible to humans -->
    <input type="text" id="btp-hp" tabindex="-1" autocomplete="off"
           style="position:absolute;opacity:0;height:0;width:0;pointer-events:none;left:-9999px" aria-hidden="true">

    <div class="btp-challenge-area">
      ${challengeInner}
    </div>

    <div class="btp-footer">
      <svg viewBox="0 0 16 16" fill="none" aria-hidden="true" class="btp-lock">
        <rect x="3" y="7" width="10" height="8" rx="1.5" stroke="currentColor" stroke-width="1.2"/>
        <path d="M5 7V5a3 3 0 016 0v2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
      </svg>
      <span>All checks run locally. No data sent.</span>
    </div>
  </div>
</div>`;
        }

        _buildSliderHTML() {
            return `
<div class="btp-slider-wrap">
  <p class="btp-ch-label">Slide to unlock →</p>
  <div class="btp-track" id="btp-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
    <div class="btp-track-fill" id="btp-fill"></div>
    <div class="btp-handle" id="btp-handle" tabindex="0" role="slider" aria-label="Drag to verify" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M9 18l6-6-6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
      </svg>
    </div>
  </div>
  <p class="btp-ch-hint">Drag the handle all the way to the right</p>
</div>`;
        }

        _buildMathHTML() {
            const a = rand(2, 15), b = rand(2, 15);
            this._mathAnswer = a + b;
            return `
<div class="btp-math-wrap">
  <p class="btp-ch-label">Solve the equation to continue</p>
  <div class="btp-equation">
    <span class="btp-num">${a}</span>
    <span class="btp-op">+</span>
    <span class="btp-num">${b}</span>
    <span class="btp-op">=</span>
    <input type="number" id="btp-math-input" class="btp-math-input"
           autocomplete="off" inputmode="numeric" placeholder="?" aria-label="Answer"
           min="0" max="99">
  </div>
  <button class="btp-btn" id="btp-math-submit" type="button">Verify</button>
  <p class="btp-ch-hint btp-math-err" id="btp-math-err" aria-live="polite"></p>
</div>`;
        }

        // ─── Challenge Wiring ─────────────────────────────────────────────────

        _wireSlider() {
            const track  = $('btp-track');
            const handle = $('btp-handle');
            const fill   = $('btp-fill');
            if (!track || !handle) return;

            let dragging = false, startX = 0, currentX = 0;
            const trackW  = () => track.getBoundingClientRect().width;
            const handleW = () => handle.getBoundingClientRect().width;

            const getProgress = (clientX) => {
                const rect = track.getBoundingClientRect();
                const raw  = clientX - rect.left - handleW() / 2;
                return clamp(raw / (rect.width - handleW()), 0, 1);
            };

            const setProgress = (p) => {
                const maxPx = trackW() - handleW();
                handle.style.transform = `translateX(${p * maxPx}px)`;
                fill.style.width = `${p * 100}%`;
                handle.setAttribute('aria-valuenow', Math.round(p * 100));
            };

            const onStart = (clientX) => {
                // Honeypot check
                if (($('btp-hp') || {}).value) { this._failChallenge(); return; }
                dragging = true;
                startX   = clientX;
                handle.classList.add('btp-dragging');
            };

            const onMove = (clientX) => {
                if (!dragging) return;
                setProgress(getProgress(clientX));
            };

            const onEnd = (clientX) => {
                if (!dragging) return;
                dragging = false;
                handle.classList.remove('btp-dragging');
                const p = getProgress(clientX);
                if (p >= 0.92) {
                    setProgress(1);
                    this._verifySuccess();
                } else {
                    setProgress(0);
                    handle.style.transition = 'transform 0.4s cubic-bezier(.4,0,.2,1)';
                    fill.style.transition   = 'width 0.4s cubic-bezier(.4,0,.2,1)';
                    setTimeout(() => {
                        handle.style.transition = '';
                        fill.style.transition   = '';
                    }, 400);
                }
            };

            // Mouse
            handle.addEventListener('mousedown',  (e) => { e.preventDefault(); onStart(e.clientX); });
            document.addEventListener('mousemove', (e) => onMove(e.clientX));
            document.addEventListener('mouseup',   (e) => onEnd(e.clientX));

            // Touch
            handle.addEventListener('touchstart',  (e) => { onStart(e.touches[0].clientX); }, { passive: true });
            document.addEventListener('touchmove',  (e) => { if (dragging) { e.preventDefault(); onMove(e.touches[0].clientX); } }, { passive: false });
            document.addEventListener('touchend',   (e) => onEnd(e.changedTouches[0].clientX));

            // Keyboard (accessibility)
            handle.addEventListener('keydown', (e) => {
                const p = parseFloat(handle.getAttribute('aria-valuenow')) / 100 || 0;
                if (e.key === 'ArrowRight') { setProgress(clamp(p + 0.05, 0, 1)); if (p + 0.05 >= 1) this._verifySuccess(); }
                if (e.key === 'ArrowLeft')  setProgress(clamp(p - 0.05, 0, 1));
            });
        }

        _wireMath() {
            const submit = $('btp-math-submit');
            const input  = $('btp-math-input');
            const err    = $('btp-math-err');
            if (!submit || !input) return;

            const check = () => {
                if (($('btp-hp') || {}).value) { this._failChallenge(); return; }
                const val = parseInt(input.value, 10);
                if (val === this._mathAnswer) {
                    input.classList.add('btp-correct');
                    submit.disabled = true;
                    setTimeout(() => this._verifySuccess(), 500);
                } else {
                    this._recordFail();
                    input.classList.add('btp-wrong');
                    err.textContent = 'Incorrect. Try again.';
                    setTimeout(() => {
                        input.classList.remove('btp-wrong');
                        input.value = '';
                        err.textContent = '';
                    }, 1000);
                }
            };

            submit.addEventListener('click', check);
            input.addEventListener('keydown', (e) => { if (e.key === 'Enter') check(); });
            input.focus();
        }

        // ─── Outcomes ─────────────────────────────────────────────────────────

        _verifySuccess(silent = false) {
            this._state.isVerified = true;
            this._saveSession();

            const overlay = $('btp-overlay');
            if (overlay && !silent) {
                const card = $('btp-card');
                if (card) {
                    card.classList.add('btp-success-anim');
                }
                setTimeout(() => {
                    overlay.style.opacity = '0';
                    setTimeout(() => overlay.remove(), 350);
                }, 700);
            } else if (overlay) {
                overlay.remove();
            }

            this._log('✓ Verified successfully.');
            if (typeof this.config.onVerified === 'function') {
                this.config.onVerified({ score: this._state.riskScore });
            }
        }

        _failChallenge() {
            this._recordFail();
            const overlay = $('btp-overlay');
            if (overlay) {
                const card = $('btp-card');
                if (card) card.classList.add('btp-shake');
                setTimeout(() => { if (card) card.classList.remove('btp-shake'); }, 600);
            }
        }

        _block(reason = 'Access denied.') {
            this._state.isBlocked = true;

            // Remove any existing overlay
            const old = $('btp-overlay');
            if (old) old.remove();

            const overlay = document.createElement('div');
            overlay.id = 'btp-overlay';
            overlay.innerHTML = `
<div class="btp-overlay-bg btp-block-bg"></div>
<div class="btp-wrap">
  <div class="btp-card btp-block-card btp-visible" id="btp-card" role="alertdialog" aria-live="assertive">
    <div class="btp-block-icon">
      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.5"/>
        <path d="M4.93 4.93l14.14 14.14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      </svg>
    </div>
    <h2 class="btp-block-title">Access Denied</h2>
    <p class="btp-block-msg">${this._escHTML(reason)}</p>
    <p class="btp-block-sub">If you believe this is an error, clear your cookies and try again.</p>
  </div>
</div>`;
            document.body.appendChild(overlay);
            this._log('✗ Blocked: ' + reason);

            if (typeof this.config.onBlocked === 'function') {
                this.config.onBlocked({ score: this._state.riskScore, reason });
            }
        }

        // ─── Utilities ────────────────────────────────────────────────────────

        _escHTML(str) {
            if (!str) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;');
        }

        _log(msg) {
            if (this.config.debugMode) console.log('%c[Boters+]%c ' + msg, 'color:#6366f1;font-weight:700', '');
        }

        /** Public API — force re-evaluate */
        recheck() {
            this._state.challengeShown = false;
            this._evaluate();
        }

        /** Public API — manual clear session */
        clearSession() {
            try {
                localStorage.removeItem(LS_KEY);
                localStorage.removeItem(LS_FAIL_KEY);
            } catch (_) {}
            this._state.isVerified = false;
        }

        /** Public API — get current risk report */
        getReport() {
            return {
                version: VERSION,
                riskScore: this._state.riskScore,
                riskReasons: [...this._state.riskReasons],
                isVerified: this._state.isVerified,
                isBlocked: this._state.isBlocked,
                touchDevice: this._state.touchDevice
            };
        }

        // ─── CSS ──────────────────────────────────────────────────────────────

        _injectCSS() {
            if ($('btp-styles')) return;
            const style = document.createElement('style');
            style.id = 'btp-styles';
            style.textContent = `
/* === Boters+ v2 Styles === */
#btp-overlay {
    position: fixed; inset: 0; z-index: 2147483647;
    display: flex; align-items: center; justify-content: center;
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    transition: opacity 0.35s ease;
}

.btp-overlay-bg {
    position: absolute; inset: 0;
    background: rgba(5, 5, 10, 0.72);
    backdrop-filter: blur(6px);
    -webkit-backdrop-filter: blur(6px);
}

.btp-block-bg { background: rgba(20, 0, 0, 0.82); }

.btp-wrap {
    position: relative; z-index: 1;
    width: 100%; padding: 16px;
    display: flex; justify-content: center;
}

.btp-card {
    background: #0f0f13;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 16px;
    padding: 28px 24px 20px;
    width: 100%; max-width: 380px;
    box-shadow: 0 24px 60px rgba(0,0,0,0.6), 0 0 0 1px rgba(99,102,241,0.12);
    opacity: 0;
    transform: scale(0.94) translateY(10px);
    transition: opacity 0.35s ease, transform 0.35s cubic-bezier(.4,0,.2,1);
}

.btp-card.btp-visible {
    opacity: 1; transform: scale(1) translateY(0);
}

.btp-brand {
    display: flex; align-items: center; gap: 12px; margin-bottom: 18px;
}

.btp-shield {
    width: 40px; height: 40px; flex-shrink: 0;
    background: linear-gradient(135deg, #4f46e5, #7c3aed);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    color: #fff; box-shadow: 0 4px 12px rgba(99,102,241,0.4);
}

.btp-shield svg { width: 22px; height: 22px; }

.btp-brand-text { display: flex; flex-direction: column; gap: 2px; }

.btp-title {
    font-size: 18px; font-weight: 700; color: #f4f4f6; letter-spacing: -0.3px;
}
.btp-title sup { font-size: 11px; vertical-align: super; opacity: 0.7; }

.btp-sub { font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.06em; }

.btp-divider {
    height: 1px; background: rgba(255,255,255,0.06); margin-bottom: 16px;
}

.btp-msg {
    font-size: 13.5px; color: #9ca3af; line-height: 1.6;
    margin-bottom: 20px;
}

/* Slider */
.btp-slider-wrap { display: flex; flex-direction: column; gap: 10px; }

.btp-ch-label {
    font-size: 13px; font-weight: 600; color: #e5e7eb; margin: 0 0 4px;
}

.btp-track {
    position: relative; height: 52px;
    background: #1a1a22;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 26px; overflow: hidden;
    cursor: pointer; user-select: none;
}

.btp-track-fill {
    position: absolute; left: 0; top: 0; bottom: 0;
    width: 0;
    background: linear-gradient(90deg, #4f46e5, #7c3aed);
    border-radius: 26px 0 0 26px;
    transition: background 0.3s;
}

.btp-handle {
    position: absolute; left: 0; top: 50%;
    transform: translateY(-50%);
    width: 48px; height: 44px;
    background: #fff;
    border-radius: 22px;
    display: flex; align-items: center; justify-content: center;
    color: #4f46e5;
    cursor: grab; box-shadow: 0 2px 8px rgba(0,0,0,0.4);
    transition: box-shadow 0.2s, background 0.2s;
    z-index: 2;
}

.btp-handle:focus-visible {
    outline: 2px solid #6366f1; outline-offset: 2px;
}

.btp-handle.btp-dragging { cursor: grabbing; box-shadow: 0 4px 16px rgba(99,102,241,0.5); }
.btp-handle svg { width: 20px; height: 20px; }

.btp-ch-hint { font-size: 11.5px; color: #6b7280; margin: 4px 0 0; text-align: center; }

/* Math challenge */
.btp-math-wrap { display: flex; flex-direction: column; gap: 14px; }

.btp-equation {
    display: flex; align-items: center; gap: 12px;
    justify-content: center; flex-wrap: wrap;
}

.btp-num {
    font-size: 32px; font-weight: 700; color: #f4f4f6;
    background: #1a1a22; border: 1px solid rgba(255,255,255,0.08);
    border-radius: 10px; padding: 8px 18px; min-width: 60px; text-align: center;
}

.btp-op { font-size: 28px; font-weight: 700; color: #6366f1; }

.btp-math-input {
    font-size: 28px; font-weight: 700; color: #f4f4f6;
    background: #1a1a22; border: 2px solid rgba(99,102,241,0.4);
    border-radius: 10px; padding: 6px 12px; width: 80px; text-align: center;
    outline: none; transition: border-color 0.2s, box-shadow 0.2s;
    /* Hide number spinners */
    -moz-appearance: textfield;
}
.btp-math-input::-webkit-inner-spin-button,
.btp-math-input::-webkit-outer-spin-button { -webkit-appearance: none; }
.btp-math-input:focus { border-color: #6366f1; box-shadow: 0 0 0 3px rgba(99,102,241,0.2); }
.btp-math-input.btp-correct { border-color: #10b981; box-shadow: 0 0 0 3px rgba(16,185,129,0.2); color: #10b981; }
.btp-math-input.btp-wrong   { border-color: #ef4444; box-shadow: 0 0 0 3px rgba(239,68,68,0.2); animation: btp-shake 0.3s; }

.btp-btn {
    background: linear-gradient(135deg, #4f46e5, #7c3aed);
    color: #fff; border: none; border-radius: 8px;
    padding: 12px; font-size: 14px; font-weight: 600; cursor: pointer;
    transition: opacity 0.2s, transform 0.15s;
}
.btp-btn:hover:not(:disabled) { opacity: 0.9; transform: translateY(-1px); }
.btp-btn:active { transform: translateY(0); }
.btp-btn:disabled { opacity: 0.5; cursor: not-allowed; }

.btp-math-err { color: #ef4444; font-size: 12px; text-align: center; min-height: 16px; margin: 0; }

/* Footer */
.btp-footer {
    display: flex; align-items: center; gap: 6px;
    margin-top: 18px; color: #4b5563; font-size: 11px;
}

.btp-lock { width: 12px; height: 12px; flex-shrink: 0; }

/* Block state */
.btp-block-card {
    text-align: center; max-width: 340px;
    border-color: rgba(239,68,68,0.2);
    box-shadow: 0 24px 60px rgba(0,0,0,0.7), 0 0 0 1px rgba(239,68,68,0.1);
}

.btp-block-icon {
    width: 56px; height: 56px; margin: 0 auto 16px;
    border-radius: 50%;
    background: rgba(239,68,68,0.1);
    border: 1px solid rgba(239,68,68,0.2);
    display: flex; align-items: center; justify-content: center;
    color: #ef4444;
}

.btp-block-icon svg { width: 28px; height: 28px; }
.btp-block-title { font-size: 20px; font-weight: 700; color: #f4f4f6; margin: 0 0 10px; }
.btp-block-msg   { font-size: 14px; color: #9ca3af; margin: 0 0 8px; line-height: 1.6; }
.btp-block-sub   { font-size: 12px; color: #4b5563; margin: 0; }

/* Animations */
@keyframes btp-shake {
    0%, 100% { transform: translateX(0); }
    25%       { transform: translateX(-6px); }
    75%       { transform: translateX(6px); }
}

.btp-shake { animation: btp-shake 0.45s cubic-bezier(.36,.07,.19,.97); }

.btp-success-anim {
    animation: btp-success 0.6s ease forwards;
}

@keyframes btp-success {
    0%   { border-color: rgba(16,185,129,0.2); box-shadow: 0 0 0 0 rgba(16,185,129,0.3); }
    50%  { border-color: rgba(16,185,129,0.5); box-shadow: 0 0 0 8px rgba(16,185,129,0.1); }
    100% { border-color: rgba(16,185,129,0.1); opacity: 0; }
}

@media (max-width: 400px) {
    .btp-card { padding: 20px 16px 16px; }
    .btp-num  { font-size: 26px; padding: 6px 12px; }
    .btp-op   { font-size: 22px; }
    .btp-math-input { font-size: 24px; width: 70px; }
}
            `;
            document.head.appendChild(style);
        }
    }

    // ─── Auto-initialize ───────────────────────────────────────────────────────
    // Usage: window.BotersPlus already has defaults.
    // Custom: new BotersPlus({ expiryDays: 7, debugMode: true, onVerified: () => console.log('Pass!') })
    global.BotersPlus = BotersPlus;

    // Default singleton
    global.BotersPlusClient = new BotersPlus({
        // debugMode: true, // Uncomment to see logs
    });

})(window);
