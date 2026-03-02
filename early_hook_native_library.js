'use strict';

/**
 * waitForLib(name, callback)
 *
 * Deterministically detects when a native library is fully loaded by hooking
 * two internal linker functions: do_dlopen and call_constructor.
 *
 * Android's linker loads a .so in two phases:
 *   1. do_dlopen        — maps the library into memory and resolves symbols
 *   2. call_constructor — runs .init/.init_array (C++ static initializers, etc.)
 *
 * We hook do_dlopen.onLeave to detect when our target library is opening,
 * then attach call_constructor at that point so it only fires for our target.
 * The callback is invoked after call_constructor completes, meaning the library
 * is fully initialized and all exports are safe to hook.
 *
 * The callback is deferred via setImmediate to escape the linker thread's
 * instrumentation lock before calling Interceptor.attach inside it.
 * When Frida executes a hook, it holds an internal lock on that thread to
 * safely patch memory. Any attempt to call Interceptor.attach from within
 * that same hook will try to acquire the same lock, causing a deadlock.
 * setImmediate schedules the callback on the next tick of Frida's JS event
 * loop, by which point the linker thread has exited the hook and released
 * the lock, making it safe to attach new interceptors.
 *
 * Throws if the linker or required symbols can't be resolved.
 * Instead of using x0 directly, we use frida built in so it's working in different archs
 *
 * @param {string}   name      - Library name, e.g. 'xxxxx.so'
 * @param {function} callback  - Called with the Module object once loaded
 */
function waitForLib(name, callback) {
    const already = Process.findModuleByName(name);
    if (already) { callback(already); return; }

    const linker = Process.findModuleByName('linker64') ?? Process.findModuleByName('linker');
    if (!linker) return;

    let do_dlopen = null, call_ctor = null;
    linker.enumerateSymbols().forEach(s => {
        if (s.name.includes('do_dlopen'))        do_dlopen = s.address;
        if (s.name.includes('call_constructor')) call_ctor  = s.address;
    });

    if (!do_dlopen) return;

    let ctorListener = null, done = false;
    
    Interceptor.attach(do_dlopen, {
        onEnter(args) {
            try {
                // Safely read the library path from args[0]
                if (args[0].isNull()) return;
                const libPath = args[0].readCString();
                this._match = !!(libPath && libPath.includes(name));
            } catch (e) {
                this._match = false;
            }
        },
        onLeave() {
            if (!this._match || ctorListener || !call_ctor) return;
            ctorListener = Interceptor.attach(call_ctor, {
                onEnter() {
                    if (done) return;
                    const mod = Process.findModuleByName(name);
                    if (!mod) return;
                    done = true;
                    ctorListener.detach();
                    setImmediate(() => callback(mod));
                }
            });
        }
    });
}

// ─── Usage example ───────────────────────────────────────────────────────────

waitForLib('xxxx.so', lib => {
  console.log(`[+] xxxx.so @ ${lib.base}`);

});
