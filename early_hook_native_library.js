/**
* Deterministically detects when a native library is fully loaded by hooking
 * two internal linker functions: do_dlopen and call_constructor.
 *
 * Android's linker loads a .so in two phases:
 *   1. do_dlopen   — maps the library into memory and resolves symbols
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
 * Symbol resolution tries enumerateSymbols first (full debug symbol table)
 * and falls back to enumerateExports if the linker simbols are stripped. Symbols
 * include all internal/debug info while exports only contain what the linker
 * intentionally exposes to other libraries. On stock Android both work. If both fail
 * the function throws immediately so you know rather than getting a silent hang.
 *
 **/

function waitForLib(name, callback) {
  const already = Process.findModuleByName(name);
  if (already) {
    callback(already);
    return;
  }

  const linker = Process.findModuleByName('linker64') ?? Process.findModuleByName('linker');
  if (!linker) throw new Error('[waitForLib] linker not found');

  let do_dlopen = null;
  let call_ctor = null;

  linker.enumerateSymbols().forEach(sym => {
    if (sym.name.indexOf('do_dlopen')        >= 0) do_dlopen = sym.address;
    if (sym.name.indexOf('call_constructor') >= 0) call_ctor  = sym.address;
  });

  // Fallback to exports if symbols are stripped
  if (!do_dlopen || !call_ctor) {
    console.log('[waitForLib] symbols incomplete, trying exports...');
    linker.enumerateExports().forEach(exp => {
      if (!do_dlopen && exp.name.indexOf('do_dlopen')        >= 0) do_dlopen = exp.address;
      if (!call_ctor  && exp.name.indexOf('call_constructor') >= 0) call_ctor  = exp.address;
    });
  }

  if (!do_dlopen) throw new Error('[waitForLib] do_dlopen not found in linker symbols');
  if (!call_ctor)  throw new Error('[waitForLib] call_constructor not found in linker symbols');

  let ctorListener = null;
  let done         = false;

  Interceptor.attach(do_dlopen, {
    onEnter() {
      const path = this.context.x0.readCString();
      this._match = !!(path && path.indexOf(name) >= 0);
    },
    onLeave() {
      if (!this._match || ctorListener) return;
      // do_dlopen has fully returned — safe to attach a new interceptor
      ctorListener = Interceptor.attach(call_ctor, {
        onEnter() {
          if (done) return;
          const mod = Process.findModuleByName(name);
          if (!mod) return;
          done = true;
          ctorListener.detach();
          console.log(`[waitForLib] ${name} fully loaded @ ${mod.base}`);
          setImmediate(() => callback(mod));
        }
      });
    }
  });


// example

waitForLib('xxxx.so', lib => {
  console.log(`[+] xxx.so @ ${lib.base}`);

});
