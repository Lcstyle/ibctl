// Idle sign-out for a logged-in dashboard page.
//
// The server ends a session after `dashboard.session_idle_minutes` with no user
// activity, and it does not count the page's own background polling as
// activity. So the browser has to tell it when the person is really here:
//
//  * It watches real input (mouse, keys, wheel, touch). Activity is kept in
//    memory and in localStorage, so every open tab shares one idea of "the
//    person was last here at T".
//  * While the person is active it sends `POST /api/session/touch` (the
//    heartbeat) about every max(15 s, idle / 4); the server counts that as
//    activity and refreshes the cookie. A 401 from it means the session ended.
//  * 30 s before the idle limit it shows a banner; any input hides it. At the
//    limit it posts the logout form and goes to the login page, which also
//    closes an open VNC websocket by leaving the page.
//  * A 401 from any fetch or htmx request means the session already ended
//    (idle on the server, or signed out in another tab): go to the login page.
//
// Configuration is two data attributes on the script tag: `data-idle-seconds`
// (0 turns everything off) and `data-root` (the proxy path prefix, may be
// empty). The decisions are small pure functions and `createController` takes
// its clock, storage, network and navigation as arguments, so node can run them.
(function (root) {
    'use strict';

    var MIN_HEARTBEAT_SECONDS = 15;
    var ACTIVITY_THROTTLE_MS = 1000;
    var BANNER_SECONDS = 30;
    var TICK_MS = 1000;
    var HEARTBEAT_RETRY_MS = 5000;
    var LOGOUT_GIVE_UP_MS = 3000;
    var ACTIVITY_KEY = 'ibctl.session.activity';
    var HEARTBEAT_KEY = 'ibctl.session.heartbeat';
    var TOUCH_PATH = '/api/session/touch';
    var LOGOUT_PATH = '/logout';
    // Input that means a person is there. `scroll` is left out on purpose: the
    // log viewer scrolls itself as lines arrive, and that must not keep a session
    // alive. A person scrolling does it with the wheel, the keys, a touch or the
    // mouse, all of which are listed.
    var ACTIVITY_EVENTS = ['mousemove', 'mousedown', 'keydown', 'wheel', 'touchstart', 'touchmove'];

    // --- decisions ---------------------------------------------------------

    function heartbeatEveryMs(idleSeconds) {
        return Math.max(MIN_HEARTBEAT_SECONDS, idleSeconds / 4) * 1000;
    }

    // Input is recorded at most once a second: mousemove fires hundreds of times.
    function shouldRecordActivity(now, lastRecorded) {
        return now - lastRecorded >= ACTIVITY_THROTTLE_MS;
    }

    // Send a heartbeat when there has been activity since the last one and the
    // last one is old enough. Checked on every input and on every tick, so
    // activity that arrives just after a heartbeat is still reported once the
    // interval is up, well before the server's idle limit.
    function shouldSendHeartbeat(now, lastActivity, lastHeartbeat, idleSeconds) {
        if (!(idleSeconds > 0)) {
            return false;
        }
        return lastActivity > lastHeartbeat && now - lastHeartbeat >= heartbeatEveryMs(idleSeconds);
    }

    // Whole seconds left before the idle limit; Infinity when it is off.
    function secondsUntilLogout(now, lastActivity, idleSeconds) {
        if (!(idleSeconds > 0)) {
            return Infinity;
        }
        return Math.max(0, Math.ceil(idleSeconds - (now - lastActivity) / 1000));
    }

    function shouldShowBanner(secondsLeft) {
        return secondsLeft > 0 && secondsLeft <= BANNER_SECONDS;
    }

    function bannerText(secondsLeft) {
        return 'Signing out in ' + secondsLeft + ' s because of inactivity. ' +
            'Move the mouse or press a key to stay signed in.';
    }

    // Chrome fires a mousemove when the page changes under a still pointer (an
    // htmx swap, say). Only a pointer that is somewhere new is a person.
    function pointerMoved(previous, x, y) {
        return !previous || previous.x !== x || previous.y !== y;
    }

    function trimRoot(rootPath) {
        return (rootPath || '').replace(/\/+$/, '');
    }

    function isLoginPage(pathname, rootPath) {
        return pathname === trimRoot(rootPath) + '/login';
    }

    // The login page URL, back to the current page, saying why. Mirrors what the
    // server redirects to: `<root>/login?next=/config&reason=idle`.
    function loginUrl(rootPath, reason, pathname, search) {
        var prefix = trimRoot(rootPath);
        var next = '';
        if (typeof pathname === 'string' && pathname.indexOf(prefix + '/') === 0) {
            next = pathname.slice(prefix.length) + (search || '');
        }
        var query = '';
        if (next && next !== '/' && next.indexOf('//') !== 0 && next.indexOf('/login') !== 0) {
            query = 'next=' + encodeURIComponent(next)
                .replace(/%2F/gi, '/').replace(/%3F/gi, '?').replace(/%3D/gi, '=') + '&';
        }
        return prefix + '/login?' + query + 'reason=' + encodeURIComponent(reason);
    }

    function asNumber(value) {
        var n = Number(value);
        return isFinite(n) ? n : 0;
    }

    // --- behaviour ---------------------------------------------------------
    //
    // env: now(), storage {get(key), set(key, value)}, fetch(url, options) ->
    // Promise<{status}>, navigate(url), setTimeout(fn, ms), location()
    // -> {pathname, search}, onLoginPage() -> bool, banner {show(text), hide()}.

    function createController(config, env) {
        var idle = config.idleSeconds;
        var rootPath = trimRoot(config.root);
        var started = env.now();
        var state = {
            activity: started,
            heartbeat: started, // loading the page was itself a navigation the server counted
            lastRecorded: started,
            sending: false,
            ending: false,
            bannerShown: false
        };
        env.storage.set(ACTIVITY_KEY, started);
        env.storage.set(HEARTBEAT_KEY, started);

        function lastActivity() {
            return Math.max(state.activity, asNumber(env.storage.get(ACTIVITY_KEY)));
        }

        function lastHeartbeat() {
            return Math.max(state.heartbeat, asNumber(env.storage.get(HEARTBEAT_KEY)));
        }

        function hideBanner() {
            if (state.bannerShown) {
                state.bannerShown = false;
                env.banner.hide();
            }
        }

        function goToLogin() {
            if (state.ending || env.onLoginPage()) {
                return;
            }
            state.ending = true;
            hideBanner();
            var where = env.location();
            env.navigate(loginUrl(rootPath, 'idle', where.pathname, where.search));
        }

        function logOut() {
            if (state.ending || env.onLoginPage()) {
                return;
            }
            state.ending = true;
            hideBanner();
            var where = env.location();
            var target = loginUrl(rootPath, 'idle', where.pathname, where.search);
            var left = false;
            function leave() {
                if (!left) {
                    left = true;
                    env.navigate(target);
                }
            }
            // Clear the cookies first, then leave; leave anyway if the server is slow.
            env.fetch(rootPath + LOGOUT_PATH, { method: 'POST', credentials: 'same-origin', redirect: 'manual' })
                .then(leave, leave);
            env.setTimeout(leave, LOGOUT_GIVE_UP_MS);
        }

        function maybeHeartbeat(now) {
            if (state.ending || state.sending ||
                !shouldSendHeartbeat(now, lastActivity(), lastHeartbeat(), idle)) {
                return;
            }
            state.sending = true;
            state.heartbeat = now;
            env.storage.set(HEARTBEAT_KEY, now); // claim it, so other tabs don't send the same one
            env.fetch(rootPath + TOUCH_PATH, { method: 'POST', credentials: 'same-origin' }).then(
                function (response) {
                    state.sending = false;
                    if (response && response.status === 401) {
                        goToLogin();
                    }
                },
                function () {
                    // Offline or the server is down: try again shortly.
                    state.sending = false;
                    var retryAt = now - heartbeatEveryMs(idle) + HEARTBEAT_RETRY_MS;
                    state.heartbeat = retryAt;
                    env.storage.set(HEARTBEAT_KEY, retryAt);
                }
            );
        }

        function noteActivity() {
            if (state.ending) {
                return;
            }
            var now = env.now();
            if (!shouldRecordActivity(now, state.lastRecorded)) {
                return;
            }
            state.lastRecorded = now;
            state.activity = now;
            env.storage.set(ACTIVITY_KEY, now);
            hideBanner();
            maybeHeartbeat(now);
        }

        function tick() {
            if (state.ending) {
                return;
            }
            var now = env.now();
            var left = secondsUntilLogout(now, lastActivity(), idle);
            if (left <= 0) {
                logOut();
                return;
            }
            if (shouldShowBanner(left)) {
                state.bannerShown = true;
                env.banner.show(bannerText(left));
            } else {
                hideBanner();
            }
            maybeHeartbeat(now);
        }

        return { noteActivity: noteActivity, tick: tick, handleUnauthorized: goToLogin, state: state };
    }

    // --- the page ------------------------------------------------------------

    function safeStorage() {
        var memory = {};
        return {
            get: function (key) {
                try {
                    return root.localStorage.getItem(key);
                } catch (e) {
                    return memory[key];
                }
            },
            set: function (key, value) {
                memory[key] = String(value);
                try {
                    root.localStorage.setItem(key, String(value));
                } catch (e) { /* storage blocked: this tab still times out on its own */ }
            }
        };
    }

    function pageBanner() {
        var box = null;
        var visual = null;

        function build() {
            var doc = root.document;
            box = doc.createElement('div');
            box.setAttribute('role', 'alert');
            box.style.cssText = 'position:fixed;left:50%;bottom:16px;transform:translateX(-50%);z-index:10000;' +
                'max-width:90vw;padding:8px 14px;background:#27272a;color:#e4e4e7;border:1px solid #52525b;' +
                'border-radius:6px;box-shadow:0 4px 16px rgba(0,0,0,.5);font:13px system-ui,sans-serif;';
            // Screen readers get one steady sentence; the ticking number is for eyes.
            var spoken = doc.createElement('span');
            spoken.style.cssText = 'position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);';
            spoken.textContent = 'You will be signed out soon because of inactivity. ' +
                'Move the mouse or press a key to stay signed in.';
            visual = doc.createElement('span');
            visual.setAttribute('aria-hidden', 'true');
            box.appendChild(spoken);
            box.appendChild(visual);
            doc.body.appendChild(box);
        }

        return {
            show: function (text) {
                if (!box) {
                    build();
                }
                visual.textContent = text;
                box.style.display = '';
            },
            hide: function () {
                if (box) {
                    box.style.display = 'none';
                }
            }
        };
    }

    function sameOrigin(input) {
        try {
            var target = typeof input === 'string' ? input : (input && input.url) || String(input);
            return new URL(target, root.location.href).origin === root.location.origin;
        } catch (e) {
            return false;
        }
    }

    function start(script) {
        var idle = parseInt(script.getAttribute('data-idle-seconds'), 10) || 0;
        var rootPath = script.getAttribute('data-root') || '';
        if (!(idle > 0) || isLoginPage(root.location.pathname, rootPath)) {
            return null;
        }
        var realFetch = root.fetch ? root.fetch.bind(root) : null;
        var env = {
            now: function () { return Date.now(); },
            storage: safeStorage(),
            fetch: realFetch,
            navigate: function (url) { root.location.assign(url); },
            setTimeout: function (fn, ms) { return root.setTimeout(fn, ms); },
            location: function () { return { pathname: root.location.pathname, search: root.location.search }; },
            onLoginPage: function () { return isLoginPage(root.location.pathname, rootPath); },
            banner: pageBanner()
        };
        if (!realFetch) {
            return null;
        }
        var controller = createController({ idleSeconds: idle, root: rootPath }, env);

        var pointer = null;
        function onInput(event) {
            if (event.type === 'mousemove') {
                var moved = pointerMoved(pointer, event.screenX, event.screenY);
                pointer = { x: event.screenX, y: event.screenY };
                if (!moved) {
                    return;
                }
            }
            controller.noteActivity();
        }
        ACTIVITY_EVENTS.forEach(function (name) {
            root.addEventListener(name, onInput, { capture: true, passive: true });
        });
        root.setInterval(controller.tick, TICK_MS);
        root.document.addEventListener('visibilitychange', controller.tick);
        root.addEventListener('pageshow', controller.tick);
        root.addEventListener('storage', function (event) {
            if (event.key === ACTIVITY_KEY) {
                controller.tick();
            }
        });

        // Any request the page makes that comes back 401 means the session is over.
        root.fetch = function (input) {
            var result = realFetch.apply(root, arguments);
            result.then(function (response) {
                if (response && response.status === 401 && sameOrigin(input)) {
                    controller.handleUnauthorized();
                }
            }, function () { /* the caller sees the failure */ });
            return result;
        };
        root.document.addEventListener('htmx:responseError', function (event) {
            var xhr = event.detail && event.detail.xhr;
            if (xhr && xhr.status === 401) {
                controller.handleUnauthorized();
            }
        });
        return controller;
    }

    var Session = {
        heartbeatEveryMs: heartbeatEveryMs,
        shouldRecordActivity: shouldRecordActivity,
        shouldSendHeartbeat: shouldSendHeartbeat,
        secondsUntilLogout: secondsUntilLogout,
        shouldShowBanner: shouldShowBanner,
        bannerText: bannerText,
        pointerMoved: pointerMoved,
        isLoginPage: isLoginPage,
        loginUrl: loginUrl,
        createController: createController,
        keys: { activity: ACTIVITY_KEY, heartbeat: HEARTBEAT_KEY },
        events: ACTIVITY_EVENTS
    };

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = Session;
    } else {
        root.IbctlSession = Session;
        if (root.document && root.document.currentScript) {
            start(root.document.currentScript);
        }
    }
})(typeof window !== 'undefined' ? window : this);
