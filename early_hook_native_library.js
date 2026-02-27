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
