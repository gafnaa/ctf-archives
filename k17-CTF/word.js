var Module = typeof Module != "undefined" ? Module : {};

var ENVIRONMENT_IS_WEB = typeof window == "object";
var ENVIRONMENT_IS_WORKER = typeof importScripts == "function";
var ENVIRONMENT_IS_NODE =
  typeof process == "object" &&
  typeof process.versions == "object" &&
  typeof process.versions.node == "string" &&
  process.type != "renderer";
var ENVIRONMENT_IS_SHELL =
  !ENVIRONMENT_IS_WEB && !ENVIRONMENT_IS_NODE && !ENVIRONMENT_IS_WORKER;

if (ENVIRONMENT_IS_NODE) {
}

var moduleOverrides = Object.assign({}, Module);

var arguments_ = [];
var thisProgram = "./this.program";
var quit_ = (status, toThrow) => {
  throw toThrow;
};

var scriptDirectory = "";
function locateFile(path) {
  if (Module["locateFile"]) {
    return Module["locateFile"](path, scriptDirectory);
  }
  return scriptDirectory + path;
}

var readAsync, readBinary;

if (ENVIRONMENT_IS_NODE) {
  if (
    typeof process == "undefined" ||
    !process.release ||
    process.release.name !== "node"
  )
    throw new Error(
      "not compiled for this environment (did you build to HTML and try to run it not on the web, or set ENVIRONMENT to something - like node - and run it someplace else - like on the web?)"
    );

  var nodeVersion = process.versions.node;
  var numericVersion = nodeVersion.split(".").slice(0, 3);
  numericVersion =
    numericVersion[0] * 10000 +
    numericVersion[1] * 100 +
    numericVersion[2].split("-")[0] * 1;
  var minVersion = 160000;
  if (numericVersion < 160000) {
    throw new Error(
      "This emscripten-generated code requires node v16.0.0 (detected v" +
        nodeVersion +
        ")"
    );
  }

  var fs = require("fs");
  var nodePath = require("path");

  scriptDirectory = __dirname + "/";

  readBinary = (filename) => {
    filename = isFileURI(filename)
      ? new URL(filename)
      : nodePath.normalize(filename);
    var ret = fs.readFileSync(filename);
    assert(ret.buffer);
    return ret;
  };

  readAsync = (filename, binary = true) => {
    filename = isFileURI(filename)
      ? new URL(filename)
      : nodePath.normalize(filename);
    return new Promise((resolve, reject) => {
      fs.readFile(filename, binary ? undefined : "utf8", (err, data) => {
        if (err) reject(err);
        else resolve(binary ? data.buffer : data);
      });
    });
  };
  if (!Module["thisProgram"] && process.argv.length > 1) {
    thisProgram = process.argv[1].replace(/\\/g, "/");
  }

  arguments_ = process.argv.slice(2);

  if (typeof module != "undefined") {
    module["exports"] = Module;
  }

  quit_ = (status, toThrow) => {
    process.exitCode = status;
    throw toThrow;
  };
} else if (ENVIRONMENT_IS_SHELL) {
  if (
    (typeof process == "object" && typeof require === "function") ||
    typeof window == "object" ||
    typeof importScripts == "function"
  )
    throw new Error(
      "not compiled for this environment (did you build to HTML and try to run it not on the web, or set ENVIRONMENT to something - like node - and run it someplace else - like on the web?)"
    );
} else if (ENVIRONMENT_IS_WEB || ENVIRONMENT_IS_WORKER) {
  if (ENVIRONMENT_IS_WORKER) {
    scriptDirectory = self.location.href;
  } else if (typeof document != "undefined" && document.currentScript) {
    scriptDirectory = document.currentScript.src;
  }
  if (scriptDirectory.startsWith("blob:")) {
    scriptDirectory = "";
  } else {
    scriptDirectory = scriptDirectory.substr(
      0,
      scriptDirectory.replace(/[?#].*/, "").lastIndexOf("/") + 1
    );
  }

  if (!(typeof window == "object" || typeof importScripts == "function"))
    throw new Error(
      "not compiled for this environment (did you build to HTML and try to run it not on the web, or set ENVIRONMENT to something - like node - and run it someplace else - like on the web?)"
    );

  {
    if (ENVIRONMENT_IS_WORKER) {
      readBinary = (url) => {
        var xhr = new XMLHttpRequest();
        xhr.open("GET", url, false);
        xhr.responseType = "arraybuffer";
        xhr.send(null);
        return new Uint8Array(/** @type{!ArrayBuffer} */ (xhr.response));
      };
    }

    readAsync = (url) => {
      if (isFileURI(url)) {
        return new Promise((resolve, reject) => {
          var xhr = new XMLHttpRequest();
          xhr.open("GET", url, true);
          xhr.responseType = "arraybuffer";
          xhr.onload = () => {
            if (xhr.status == 200 || (xhr.status == 0 && xhr.response)) {
              resolve(xhr.response);
              return;
            }
            reject(xhr.status);
          };
          xhr.onerror = reject;
          xhr.send(null);
        });
      }
      return fetch(url, { credentials: "same-origin" }).then((response) => {
        if (response.ok) {
          return response.arrayBuffer();
        }
        return Promise.reject(
          new Error(response.status + " : " + response.url)
        );
      });
    };
  }
} else {
  throw new Error("environment detection error");
}

var out = Module["print"] || console.log.bind(console);
var err = Module["printErr"] || console.error.bind(console);

Object.assign(Module, moduleOverrides);
moduleOverrides = null;
checkIncomingModuleAPI();

if (Module["arguments"]) arguments_ = Module["arguments"];
legacyModuleProp("arguments", "arguments_");

if (Module["thisProgram"]) thisProgram = Module["thisProgram"];
legacyModuleProp("thisProgram", "thisProgram");

assert(
  typeof Module["memoryInitializerPrefixURL"] == "undefined",
  "Module.memoryInitializerPrefixURL option was removed, use Module.locateFile instead"
);
assert(
  typeof Module["pthreadMainPrefixURL"] == "undefined",
  "Module.pthreadMainPrefixURL option was removed, use Module.locateFile instead"
);
assert(
  typeof Module["cdInitializerPrefixURL"] == "undefined",
  "Module.cdInitializerPrefixURL option was removed, use Module.locateFile instead"
);
assert(
  typeof Module["filePackagePrefixURL"] == "undefined",
  "Module.filePackagePrefixURL option was removed, use Module.locateFile instead"
);
assert(typeof Module["read"] == "undefined", "Module.read option was removed");
assert(
  typeof Module["readAsync"] == "undefined",
  "Module.readAsync option was removed (modify readAsync in JS)"
);
assert(
  typeof Module["readBinary"] == "undefined",
  "Module.readBinary option was removed (modify readBinary in JS)"
);
assert(
  typeof Module["setWindowTitle"] == "undefined",
  "Module.setWindowTitle option was removed (modify emscripten_set_window_title in JS)"
);
assert(
  typeof Module["TOTAL_MEMORY"] == "undefined",
  "Module.TOTAL_MEMORY has been renamed Module.INITIAL_MEMORY"
);
legacyModuleProp("asm", "wasmExports");
legacyModuleProp("readAsync", "readAsync");
legacyModuleProp("readBinary", "readBinary");
legacyModuleProp("setWindowTitle", "setWindowTitle");
var IDBFS = "IDBFS is no longer included by default; build with -lidbfs.js";
var PROXYFS =
  "PROXYFS is no longer included by default; build with -lproxyfs.js";
var WORKERFS =
  "WORKERFS is no longer included by default; build with -lworkerfs.js";
var FETCHFS =
  "FETCHFS is no longer included by default; build with -lfetchfs.js";
var ICASEFS =
  "ICASEFS is no longer included by default; build with -licasefs.js";
var JSFILEFS =
  "JSFILEFS is no longer included by default; build with -ljsfilefs.js";
var OPFS = "OPFS is no longer included by default; build with -lopfs.js";

var NODEFS = "NODEFS is no longer included by default; build with -lnodefs.js";

assert(
  !ENVIRONMENT_IS_SHELL,
  "shell environment detected but not enabled at build time.  Add `shell` to `-sENVIRONMENT` to enable."
);

var wasmBinary = Module["wasmBinary"];
legacyModuleProp("wasmBinary", "wasmBinary");

if (typeof WebAssembly != "object") {
  err("no native wasm support detected");
}

var wasmMemory;

var ABORT = false;

var EXITSTATUS;

function assert(condition, text) {
  if (!condition) {
    abort("Assertion failed" + (text ? ": " + text : ""));
  }
}

function _malloc() {
  abort(
    "malloc() called but not included in the build - add `_malloc` to EXPORTED_FUNCTIONS"
  );
}
function _free() {
  abort(
    "free() called but not included in the build - add `_free` to EXPORTED_FUNCTIONS"
  );
}

var HEAP, HEAP8, HEAPU8, HEAP16, HEAPU16, HEAP32, HEAPU32, HEAPF32, HEAPF64;

function updateMemoryViews() {
  var b = wasmMemory.buffer;
  Module["HEAP8"] = HEAP8 = new Int8Array(b);
  Module["HEAP16"] = HEAP16 = new Int16Array(b);
  Module["HEAPU8"] = HEAPU8 = new Uint8Array(b);
  Module["HEAPU16"] = HEAPU16 = new Uint16Array(b);
  Module["HEAP32"] = HEAP32 = new Int32Array(b);
  Module["HEAPU32"] = HEAPU32 = new Uint32Array(b);
  Module["HEAPF32"] = HEAPF32 = new Float32Array(b);
  Module["HEAPF64"] = HEAPF64 = new Float64Array(b);
}

assert(
  !Module["STACK_SIZE"],
  "STACK_SIZE can no longer be set at runtime.  Use -sSTACK_SIZE at link time"
);

assert(
  typeof Int32Array != "undefined" &&
    typeof Float64Array !== "undefined" &&
    Int32Array.prototype.subarray != undefined &&
    Int32Array.prototype.set != undefined,
  "JS engine does not provide full typed array support"
);

assert(
  !Module["wasmMemory"],
  "Use of `wasmMemory` detected.  Use -sIMPORTED_MEMORY to define wasmMemory externally"
);
assert(
  !Module["INITIAL_MEMORY"],
  "Detected runtime INITIAL_MEMORY setting.  Use -sIMPORTED_MEMORY to define wasmMemory dynamically"
);

function writeStackCookie() {
  var max = _emscripten_stack_get_end();
  assert((max & 3) == 0);
  if (max == 0) {
    max += 4;
  }
  HEAPU32[max >> 2] = 0x02135467;
  HEAPU32[(max + 4) >> 2] = 0x89bacdfe;
  HEAPU32[0 >> 2] = 1668509029;
}

function checkStackCookie() {
  if (ABORT) return;
  var max = _emscripten_stack_get_end();
  if (max == 0) {
    max += 4;
  }
  var cookie1 = HEAPU32[max >> 2];
  var cookie2 = HEAPU32[(max + 4) >> 2];
  if (cookie1 != 0x02135467 || cookie2 != 0x89bacdfe) {
    abort(
      `Stack overflow! Stack cookie has been overwritten at ${ptrToString(
        max
      )}, expected hex dwords 0x89BACDFE and 0x2135467, but received ${ptrToString(
        cookie2
      )} ${ptrToString(cookie1)}`
    );
  }
  if (HEAPU32[0 >> 2] != 0x63736d65) {
    abort(
      "Runtime error: The application has corrupted its heap memory area (address zero)!"
    );
  }
}
var __ATPRERUN__ = [];
var __ATINIT__ = [];
var __ATEXIT__ = [];
var __ATPOSTRUN__ = [];

var runtimeInitialized = false;

function preRun() {
  var preRuns = Module["preRun"];
  if (preRuns) {
    if (typeof preRuns == "function") preRuns = [preRuns];
    preRuns.forEach(addOnPreRun);
  }
  callRuntimeCallbacks(__ATPRERUN__);
}

function initRuntime() {
  assert(!runtimeInitialized);
  runtimeInitialized = true;

  checkStackCookie();

  callRuntimeCallbacks(__ATINIT__);
}

function postRun() {
  checkStackCookie();

  var postRuns = Module["postRun"];
  if (postRuns) {
    if (typeof postRuns == "function") postRuns = [postRuns];
    postRuns.forEach(addOnPostRun);
  }

  callRuntimeCallbacks(__ATPOSTRUN__);
}

function addOnPreRun(cb) {
  __ATPRERUN__.unshift(cb);
}

function addOnInit(cb) {
  __ATINIT__.unshift(cb);
}

function addOnExit(cb) {}

function addOnPostRun(cb) {
  __ATPOSTRUN__.unshift(cb);
}

assert(
  Math.imul,
  "This browser does not support Math.imul(), build with LEGACY_VM_SUPPORT or POLYFILL_OLD_MATH_FUNCTIONS to add in a polyfill"
);
assert(
  Math.fround,
  "This browser does not support Math.fround(), build with LEGACY_VM_SUPPORT or POLYFILL_OLD_MATH_FUNCTIONS to add in a polyfill"
);
assert(
  Math.clz32,
  "This browser does not support Math.clz32(), build with LEGACY_VM_SUPPORT or POLYFILL_OLD_MATH_FUNCTIONS to add in a polyfill"
);
assert(
  Math.trunc,
  "This browser does not support Math.trunc(), build with LEGACY_VM_SUPPORT or POLYFILL_OLD_MATH_FUNCTIONS to add in a polyfill"
);
var runDependencies = 0;
var runDependencyWatcher = null;
var dependenciesFulfilled = null;
var runDependencyTracking = {};

function getUniqueRunDependency(id) {
  var orig = id;
  while (1) {
    if (!runDependencyTracking[id]) return id;
    id = orig + Math.random();
  }
}

function addRunDependency(id) {
  runDependencies++;

  Module["monitorRunDependencies"]?.(runDependencies);

  if (id) {
    assert(!runDependencyTracking[id]);
    runDependencyTracking[id] = 1;
    if (runDependencyWatcher === null && typeof setInterval != "undefined") {
      runDependencyWatcher = setInterval(() => {
        if (ABORT) {
          clearInterval(runDependencyWatcher);
          runDependencyWatcher = null;
          return;
        }
        var shown = false;
        for (var dep in runDependencyTracking) {
          if (!shown) {
            shown = true;
            err("still waiting on run dependencies:");
          }
          err(`dependency: ${dep}`);
        }
        if (shown) {
          err("(end of list)");
        }
      }, 10000);
    }
  } else {
    err("warning: run dependency added without ID");
  }
}

function removeRunDependency(id) {
  runDependencies--;

  Module["monitorRunDependencies"]?.(runDependencies);

  if (id) {
    assert(runDependencyTracking[id]);
    delete runDependencyTracking[id];
  } else {
    err("warning: run dependency removed without ID");
  }
  if (runDependencies == 0) {
    if (runDependencyWatcher !== null) {
      clearInterval(runDependencyWatcher);
      runDependencyWatcher = null;
    }
    if (dependenciesFulfilled) {
      var callback = dependenciesFulfilled;
      dependenciesFulfilled = null;
      callback();
    }
  }
}

function abort(what) {
  Module["onAbort"]?.(what);

  what = "Aborted(" + what + ")";
  err(what);

  ABORT = true;

  var e = new WebAssembly.RuntimeError(what);

  throw e;
}

var FS = {
  error() {
    abort(
      "Filesystem support (FS) was not included. The problem is that you are using files from JS, but files were not used from C/C++, so filesystem support was not auto-included. You can force-include filesystem support with -sFORCE_FILESYSTEM"
    );
  },
  init() {
    FS.error();
  },
  createDataFile() {
    FS.error();
  },
  createPreloadedFile() {
    FS.error();
  },
  createLazyFile() {
    FS.error();
  },
  open() {
    FS.error();
  },
  mkdev() {
    FS.error();
  },
  registerDevice() {
    FS.error();
  },
  analyzePath() {
    FS.error();
  },

  ErrnoError() {
    FS.error();
  },
};
Module["FS_createDataFile"] = FS.createDataFile;
Module["FS_createPreloadedFile"] = FS.createPreloadedFile;

var dataURIPrefix = "data:application/octet-stream;base64,";

var isDataURI = (filename) => filename.startsWith(dataURIPrefix);

var isFileURI = (filename) => filename.startsWith("file://");
function createExportWrapper(name, nargs) {
  return (...args) => {
    assert(
      runtimeInitialized,
      `native function \`${name}\` called before runtime initialization`
    );
    var f = wasmExports[name];
    assert(f, `exported native function \`${name}\` not found`);
    assert(
      args.length <= nargs,
      `native function \`${name}\` called with ${args.length} args but expects ${nargs}`
    );
    return f(...args);
  };
}

function findWasmBinary() {
  var f = "words.wasm";
  if (!isDataURI(f)) {
    return locateFile(f);
  }
  return f;
}

var wasmBinaryFile;

function getBinarySync(file) {
  if (file == wasmBinaryFile && wasmBinary) {
    return new Uint8Array(wasmBinary);
  }
  if (readBinary) {
    return readBinary(file);
  }
  throw "both async and sync fetching of the wasm failed";
}

function getBinaryPromise(binaryFile) {
  if (!wasmBinary) {
    return readAsync(binaryFile).then(
      (response) => new Uint8Array(/** @type{!ArrayBuffer} */ (response)),
      () => getBinarySync(binaryFile)
    );
  }

  return Promise.resolve().then(() => getBinarySync(binaryFile));
}

function instantiateArrayBuffer(binaryFile, imports, receiver) {
  return getBinaryPromise(binaryFile)
    .then((binary) => {
      return WebAssembly.instantiate(binary, imports);
    })
    .then(receiver, (reason) => {
      err(`failed to asynchronously prepare wasm: ${reason}`);

      if (isFileURI(wasmBinaryFile)) {
        err(
          `warning: Loading from a file URI (${wasmBinaryFile}) is not supported in most browsers. See https://emscripten.org/docs/getting_started/FAQ.html#how-do-i-run-a-local-webserver-for-testing-why-does-my-program-stall-in-downloading-or-preparing`
        );
      }
      abort(reason);
    });
}

function instantiateAsync(binary, binaryFile, imports, callback) {
  if (
    !binary &&
    typeof WebAssembly.instantiateStreaming == "function" &&
    !isDataURI(binaryFile) &&
    !isFileURI(binaryFile) &&
    !ENVIRONMENT_IS_NODE &&
    typeof fetch == "function"
  ) {
    return fetch(binaryFile, { credentials: "same-origin" }).then(
      (response) => {
        /** @suppress {checkTypes} */
        var result = WebAssembly.instantiateStreaming(response, imports);

        return result.then(callback, function (reason) {
          err(`wasm streaming compile failed: ${reason}`);
          err("falling back to ArrayBuffer instantiation");
          return instantiateArrayBuffer(binaryFile, imports, callback);
        });
      }
    );
  }
  return instantiateArrayBuffer(binaryFile, imports, callback);
}

function getWasmImports() {
  return {
    env: wasmImports,
    wasi_snapshot_preview1: wasmImports,
  };
}

function createWasm() {
  var info = getWasmImports();
  function receiveInstance(instance, module) {
    wasmExports = instance.exports;

    wasmMemory = wasmExports["memory"];

    assert(wasmMemory, "memory not found in wasm exports");
    updateMemoryViews();

    addOnInit(wasmExports["__wasm_call_ctors"]);

    removeRunDependency("wasm-instantiate");
    return wasmExports;
  }
  addRunDependency("wasm-instantiate");

  var trueModule = Module;
  function receiveInstantiationResult(result) {
    assert(
      Module === trueModule,
      "the Module object should not be replaced during async compilation - perhaps the order of HTML elements is wrong?"
    );
    trueModule = null;
    receiveInstance(result["instance"]);
  }

  if (Module["instantiateWasm"]) {
    try {
      return Module["instantiateWasm"](info, receiveInstance);
    } catch (e) {
      err(`Module.instantiateWasm callback failed with error: ${e}`);
      return false;
    }
  }

  wasmBinaryFile ??= findWasmBinary();

  instantiateAsync(
    wasmBinary,
    wasmBinaryFile,
    info,
    receiveInstantiationResult
  );
  return {};
}

var tempDouble;
var tempI64;

(() => {
  var h16 = new Int16Array(1);
  var h8 = new Int8Array(h16.buffer);
  h16[0] = 0x6373;
  if (h8[0] !== 0x73 || h8[1] !== 0x63)
    throw "Runtime error: expected the system to be little-endian! (Run with -sSUPPORT_BIG_ENDIAN to bypass)";
})();

if (Module["ENVIRONMENT"]) {
  throw new Error(
    "Module.ENVIRONMENT has been deprecated. To force the environment, use the ENVIRONMENT compile-time option (for example, -sENVIRONMENT=web or -sENVIRONMENT=node)"
  );
}

function legacyModuleProp(prop, newName, incoming = true) {
  if (!Object.getOwnPropertyDescriptor(Module, prop)) {
    Object.defineProperty(Module, prop, {
      configurable: true,
      get() {
        let extra = incoming
          ? " (the initial value can be provided on Module, but after startup the value is only looked for on a local variable of that name)"
          : "";
        abort(`\`Module.${prop}\` has been replaced by \`${newName}\`` + extra);
      },
    });
  }
}

function ignoredModuleProp(prop) {
  if (Object.getOwnPropertyDescriptor(Module, prop)) {
    abort(
      `\`Module.${prop}\` was supplied but \`${prop}\` not included in INCOMING_MODULE_JS_API`
    );
  }
}

function isExportedByForceFilesystem(name) {
  return (
    name === "FS_createPath" ||
    name === "FS_createDataFile" ||
    name === "FS_createPreloadedFile" ||
    name === "FS_unlink" ||
    name === "addRunDependency" ||
    name === "FS_createLazyFile" ||
    name === "FS_createDevice" ||
    name === "removeRunDependency"
  );
}

function hookGlobalSymbolAccess(sym, func) {
  if (
    typeof globalThis != "undefined" &&
    !Object.getOwnPropertyDescriptor(globalThis, sym)
  ) {
    Object.defineProperty(globalThis, sym, {
      configurable: true,
      get() {
        func();
        return undefined;
      },
    });
  }
}

function missingGlobal(sym, msg) {
  hookGlobalSymbolAccess(sym, () => {
    warnOnce(`\`${sym}\` is not longer defined by emscripten. ${msg}`);
  });
}

missingGlobal("buffer", "Please use HEAP8.buffer or wasmMemory.buffer");
missingGlobal("asm", "Please use wasmExports instead");

function missingLibrarySymbol(sym) {
  hookGlobalSymbolAccess(sym, () => {
    var msg = `\`${sym}\` is a library symbol and not included by default; add it to your library.js __deps or to DEFAULT_LIBRARY_FUNCS_TO_INCLUDE on the command line`;
    var librarySymbol = sym;
    if (!librarySymbol.startsWith("_")) {
      librarySymbol = "$" + sym;
    }
    msg += ` (e.g. -sDEFAULT_LIBRARY_FUNCS_TO_INCLUDE='${librarySymbol}')`;
    if (isExportedByForceFilesystem(sym)) {
      msg +=
        ". Alternatively, forcing filesystem support (-sFORCE_FILESYSTEM) can export this for you";
    }
    warnOnce(msg);
  });

  unexportedRuntimeSymbol(sym);
}

function unexportedRuntimeSymbol(sym) {
  if (!Object.getOwnPropertyDescriptor(Module, sym)) {
    Object.defineProperty(Module, sym, {
      configurable: true,
      get() {
        var msg = `'${sym}' was not exported. add it to EXPORTED_RUNTIME_METHODS (see the Emscripten FAQ)`;
        if (isExportedByForceFilesystem(sym)) {
          msg +=
            ". Alternatively, forcing filesystem support (-sFORCE_FILESYSTEM) can export this for you";
        }
        abort(msg);
      },
    });
  }
}

function dbg(...args) {
  console.warn(...args);
}

function ExitStatus(status) {
  this.name = "ExitStatus";
  this.message = `Program terminated with exit(${status})`;
  this.status = status;
}

var callRuntimeCallbacks = (callbacks) => {
  callbacks.forEach((f) => f(Module));
};

function getValue(ptr, type = "i8") {
  if (type.endsWith("*")) type = "*";
  switch (type) {
    case "i1":
      return HEAP8[ptr];
    case "i8":
      return HEAP8[ptr];
    case "i16":
      return HEAP16[ptr >> 1];
    case "i32":
      return HEAP32[ptr >> 2];
    case "i64":
      abort("to do getValue(i64) use WASM_BIGINT");
    case "float":
      return HEAPF32[ptr >> 2];
    case "double":
      return HEAPF64[ptr >> 3];
    case "*":
      return HEAPU32[ptr >> 2];
    default:
      abort(`invalid type for getValue: ${type}`);
  }
}

var noExitRuntime = Module["noExitRuntime"] || true;

var ptrToString = (ptr) => {
  assert(typeof ptr === "number");
  ptr >>>= 0;
  return "0x" + ptr.toString(16).padStart(8, "0");
};

function setValue(ptr, value, type = "i8") {
  if (type.endsWith("*")) type = "*";
  switch (type) {
    case "i1":
      HEAP8[ptr] = value;
      break;
    case "i8":
      HEAP8[ptr] = value;
      break;
    case "i16":
      HEAP16[ptr >> 1] = value;
      break;
    case "i32":
      HEAP32[ptr >> 2] = value;
      break;
    case "i64":
      abort("to do setValue(i64) use WASM_BIGINT");
    case "float":
      HEAPF32[ptr >> 2] = value;
      break;
    case "double":
      HEAPF64[ptr >> 3] = value;
      break;
    case "*":
      HEAPU32[ptr >> 2] = value;
      break;
    default:
      abort(`invalid type for setValue: ${type}`);
  }
}

var stackRestore = (val) => __emscripten_stack_restore(val);

var stackSave = () => _emscripten_stack_get_current();

var warnOnce = (text) => {
  warnOnce.shown ||= {};
  if (!warnOnce.shown[text]) {
    warnOnce.shown[text] = 1;
    if (ENVIRONMENT_IS_NODE) text = "warning: " + text;
    err(text);
  }
};

var getCFunc = (ident) => {
  var func = Module["_" + ident];
  assert(
    func,
    "Cannot call unknown function " + ident + ", make sure it is exported"
  );
  return func;
};

var writeArrayToMemory = (array, buffer) => {
  assert(
    array.length >= 0,
    "writeArrayToMemory array must have a length (should be an array or typed array)"
  );
  HEAP8.set(array, buffer);
};

var lengthBytesUTF8 = (str) => {
  var len = 0;
  for (var i = 0; i < str.length; ++i) {
    var c = str.charCodeAt(i);
    if (c <= 0x7f) {
      len++;
    } else if (c <= 0x7ff) {
      len += 2;
    } else if (c >= 0xd800 && c <= 0xdfff) {
      len += 4;
      ++i;
    } else {
      len += 3;
    }
  }
  return len;
};

var stringToUTF8Array = (str, heap, outIdx, maxBytesToWrite) => {
  assert(
    typeof str === "string",
    `stringToUTF8Array expects a string (got ${typeof str})`
  );
  if (!(maxBytesToWrite > 0)) return 0;

  var startIdx = outIdx;
  var endIdx = outIdx + maxBytesToWrite - 1;
  for (var i = 0; i < str.length; ++i) {
    var u = str.charCodeAt(i);
    if (u >= 0xd800 && u <= 0xdfff) {
      var u1 = str.charCodeAt(++i);
      u = (0x10000 + ((u & 0x3ff) << 10)) | (u1 & 0x3ff);
    }
    if (u <= 0x7f) {
      if (outIdx >= endIdx) break;
      heap[outIdx++] = u;
    } else if (u <= 0x7ff) {
      if (outIdx + 1 >= endIdx) break;
      heap[outIdx++] = 0xc0 | (u >> 6);
      heap[outIdx++] = 0x80 | (u & 63);
    } else if (u <= 0xffff) {
      if (outIdx + 2 >= endIdx) break;
      heap[outIdx++] = 0xe0 | (u >> 12);
      heap[outIdx++] = 0x80 | ((u >> 6) & 63);
      heap[outIdx++] = 0x80 | (u & 63);
    } else {
      if (outIdx + 3 >= endIdx) break;
      if (u > 0x10ffff)
        warnOnce(
          "Invalid Unicode code point " +
            ptrToString(u) +
            " encountered when serializing a JS string to a UTF-8 string in wasm memory! (Valid unicode code points should be in range 0-0x10FFFF)."
        );
      heap[outIdx++] = 0xf0 | (u >> 18);
      heap[outIdx++] = 0x80 | ((u >> 12) & 63);
      heap[outIdx++] = 0x80 | ((u >> 6) & 63);
      heap[outIdx++] = 0x80 | (u & 63);
    }
  }
  heap[outIdx] = 0;
  return outIdx - startIdx;
};
var stringToUTF8 = (str, outPtr, maxBytesToWrite) => {
  assert(
    typeof maxBytesToWrite == "number",
    "stringToUTF8(str, outPtr, maxBytesToWrite) is missing the third parameter that specifies the length of the output buffer!"
  );
  return stringToUTF8Array(str, HEAPU8, outPtr, maxBytesToWrite);
};

var stackAlloc = (sz) => __emscripten_stack_alloc(sz);
var stringToUTF8OnStack = (str) => {
  var size = lengthBytesUTF8(str) + 1;
  var ret = stackAlloc(size);
  stringToUTF8(str, ret, size);
  return ret;
};

var UTF8Decoder =
  typeof TextDecoder != "undefined" ? new TextDecoder() : undefined;

var UTF8ArrayToString = (heapOrArray, idx = 0, maxBytesToRead = NaN) => {
  var endIdx = idx + maxBytesToRead;
  var endPtr = idx;
  while (heapOrArray[endPtr] && !(endPtr >= endIdx)) ++endPtr;

  if (endPtr - idx > 16 && heapOrArray.buffer && UTF8Decoder) {
    return UTF8Decoder.decode(heapOrArray.subarray(idx, endPtr));
  }
  var str = "";
  while (idx < endPtr) {
    var u0 = heapOrArray[idx++];
    if (!(u0 & 0x80)) {
      str += String.fromCharCode(u0);
      continue;
    }
    var u1 = heapOrArray[idx++] & 63;
    if ((u0 & 0xe0) == 0xc0) {
      str += String.fromCharCode(((u0 & 31) << 6) | u1);
      continue;
    }
    var u2 = heapOrArray[idx++] & 63;
    if ((u0 & 0xf0) == 0xe0) {
      u0 = ((u0 & 15) << 12) | (u1 << 6) | u2;
    } else {
      if ((u0 & 0xf8) != 0xf0)
        warnOnce(
          "Invalid UTF-8 leading byte " +
            ptrToString(u0) +
            " encountered when deserializing a UTF-8 string in wasm memory to a JS string!"
        );
      u0 =
        ((u0 & 7) << 18) | (u1 << 12) | (u2 << 6) | (heapOrArray[idx++] & 63);
    }

    if (u0 < 0x10000) {
      str += String.fromCharCode(u0);
    } else {
      var ch = u0 - 0x10000;
      str += String.fromCharCode(0xd800 | (ch >> 10), 0xdc00 | (ch & 0x3ff));
    }
  }
  return str;
};

var UTF8ToString = (ptr, maxBytesToRead) => {
  assert(
    typeof ptr == "number",
    `UTF8ToString expects a number (got ${typeof ptr})`
  );
  return ptr ? UTF8ArrayToString(HEAPU8, ptr, maxBytesToRead) : "";
};

function ccall(ident, returnType, argTypes, args, opts) {
  var toC = {
    string: (str) => {
      var ret = 0;
      if (str !== null && str !== undefined && str !== 0) {
        ret = stringToUTF8OnStack(str);
      }
      return ret;
    },
    array: (arr) => {
      var ret = stackAlloc(arr.length);
      writeArrayToMemory(arr, ret);
      return ret;
    },
  };

  function convertReturnValue(ret) {
    if (returnType === "string") {
      return UTF8ToString(ret);
    }
    if (returnType === "boolean") return Boolean(ret);
    return ret;
  }

  var func = getCFunc(ident);
  var cArgs = [];
  var stack = 0;
  assert(returnType !== "array", 'Return type should not be "array".');
  if (args) {
    for (var i = 0; i < args.length; i++) {
      var converter = toC[argTypes[i]];
      if (converter) {
        if (stack === 0) stack = stackSave();
        cArgs[i] = converter(args[i]);
      } else {
        cArgs[i] = args[i];
      }
    }
  }
  var ret = func(...cArgs);
  function onDone(ret) {
    if (stack !== 0) stackRestore(stack);
    return convertReturnValue(ret);
  }

  ret = onDone(ret);
  return ret;
}
function checkIncomingModuleAPI() {
  ignoredModuleProp("fetchSettings");
}
var wasmImports = {};
var wasmExports = createWasm();
var ___wasm_call_ctors = createExportWrapper("__wasm_call_ctors", 0);
var _get_word = (Module["_get_word"] = createExportWrapper("get_word", 2));
var _fflush = createExportWrapper("fflush", 1);
var __emscripten_tempret_set = createExportWrapper(
  "_emscripten_tempret_set",
  1
);
var __emscripten_tempret_get = createExportWrapper(
  "_emscripten_tempret_get",
  0
);
var _emscripten_stack_init = () =>
  (_emscripten_stack_init = wasmExports["emscripten_stack_init"])();
var _emscripten_stack_get_free = () =>
  (_emscripten_stack_get_free = wasmExports["emscripten_stack_get_free"])();
var _emscripten_stack_get_base = () =>
  (_emscripten_stack_get_base = wasmExports["emscripten_stack_get_base"])();
var _emscripten_stack_get_end = () =>
  (_emscripten_stack_get_end = wasmExports["emscripten_stack_get_end"])();
var __emscripten_stack_restore = (a0) =>
  (__emscripten_stack_restore = wasmExports["_emscripten_stack_restore"])(a0);
var __emscripten_stack_alloc = (a0) =>
  (__emscripten_stack_alloc = wasmExports["_emscripten_stack_alloc"])(a0);
var _emscripten_stack_get_current = () =>
  (_emscripten_stack_get_current =
    wasmExports["emscripten_stack_get_current"])();

Module["ccall"] = ccall;
var missingLibrarySymbols = [
  "writeI53ToI64",
  "writeI53ToI64Clamped",
  "writeI53ToI64Signaling",
  "writeI53ToU64Clamped",
  "writeI53ToU64Signaling",
  "readI53FromI64",
  "readI53FromU64",
  "convertI32PairToI53",
  "convertI32PairToI53Checked",
  "convertU32PairToI53",
  "getTempRet0",
  "setTempRet0",
  "zeroMemory",
  "exitJS",
  "getHeapMax",
  "abortOnCannotGrowMemory",
  "growMemory",
  "strError",
  "inetPton4",
  "inetNtop4",
  "inetPton6",
  "inetNtop6",
  "readSockaddr",
  "writeSockaddr",
  "initRandomFill",
  "randomFill",
  "emscriptenLog",
  "readEmAsmArgs",
  "jstoi_q",
  "getExecutableName",
  "listenOnce",
  "autoResumeAudioContext",
  "dynCallLegacy",
  "getDynCaller",
  "dynCall",
  "handleException",
  "keepRuntimeAlive",
  "runtimeKeepalivePush",
  "runtimeKeepalivePop",
  "callUserCallback",
  "maybeExit",
  "asmjsMangle",
  "asyncLoad",
  "alignMemory",
  "mmapAlloc",
  "HandleAllocator",
  "getNativeTypeSize",
  "STACK_SIZE",
  "STACK_ALIGN",
  "POINTER_SIZE",
  "ASSERTIONS",
  "cwrap",
  "uleb128Encode",
  "sigToWasmTypes",
  "generateFuncType",
  "convertJsFunctionToWasm",
  "getEmptyTableSlot",
  "updateTableMap",
  "getFunctionAddress",
  "addFunction",
  "removeFunction",
  "reallyNegative",
  "unSign",
  "strLen",
  "reSign",
  "formatString",
  "intArrayFromString",
  "intArrayToString",
  "AsciiToString",
  "stringToAscii",
  "UTF16ToString",
  "stringToUTF16",
  "lengthBytesUTF16",
  "UTF32ToString",
  "stringToUTF32",
  "lengthBytesUTF32",
  "stringToNewUTF8",
  "registerKeyEventCallback",
  "maybeCStringToJsString",
  "findEventTarget",
  "getBoundingClientRect",
  "fillMouseEventData",
  "registerMouseEventCallback",
  "registerWheelEventCallback",
  "registerUiEventCallback",
  "registerFocusEventCallback",
  "fillDeviceOrientationEventData",
  "registerDeviceOrientationEventCallback",
  "fillDeviceMotionEventData",
  "registerDeviceMotionEventCallback",
  "screenOrientation",
  "fillOrientationChangeEventData",
  "registerOrientationChangeEventCallback",
  "fillFullscreenChangeEventData",
  "registerFullscreenChangeEventCallback",
  "JSEvents_requestFullscreen",
  "JSEvents_resizeCanvasForFullscreen",
  "registerRestoreOldStyle",
  "hideEverythingExceptGivenElement",
  "restoreHiddenElements",
  "setLetterbox",
  "softFullscreenResizeWebGLRenderTarget",
  "doRequestFullscreen",
  "fillPointerlockChangeEventData",
  "registerPointerlockChangeEventCallback",
  "registerPointerlockErrorEventCallback",
  "requestPointerLock",
  "fillVisibilityChangeEventData",
  "registerVisibilityChangeEventCallback",
  "registerTouchEventCallback",
  "fillGamepadEventData",
  "registerGamepadEventCallback",
  "registerBeforeUnloadEventCallback",
  "fillBatteryEventData",
  "battery",
  "registerBatteryEventCallback",
  "setCanvasElementSize",
  "getCanvasElementSize",
  "jsStackTrace",
  "getCallstack",
  "convertPCtoSourceLocation",
  "getEnvStrings",
  "checkWasiClock",
  "flush_NO_FILESYSTEM",
  "wasiRightsToMuslOFlags",
  "wasiOFlagsToMuslOFlags",
  "createDyncallWrapper",
  "safeSetTimeout",
  "setImmediateWrapped",
  "clearImmediateWrapped",
  "polyfillSetImmediate",
  "registerPostMainLoop",
  "registerPreMainLoop",
  "getPromise",
  "makePromise",
  "idsToPromises",
  "makePromiseCallback",
  "ExceptionInfo",
  "findMatchingCatch",
  "Browser_asyncPrepareDataCounter",
  "safeRequestAnimationFrame",
  "isLeapYear",
  "ydayFromDate",
  "arraySum",
  "addDays",
  "getSocketFromFD",
  "getSocketAddress",
  "FS_createPreloadedFile",
  "FS_modeStringToFlags",
  "FS_getMode",
  "FS_stdin_getChar",
  "FS_unlink",
  "FS_createDataFile",
  "FS_mkdirTree",
  "_setNetworkCallback",
  "heapObjectForWebGLType",
  "toTypedArrayIndex",
  "webgl_enable_ANGLE_instanced_arrays",
  "webgl_enable_OES_vertex_array_object",
  "webgl_enable_WEBGL_draw_buffers",
  "webgl_enable_WEBGL_multi_draw",
  "webgl_enable_EXT_polygon_offset_clamp",
  "webgl_enable_EXT_clip_control",
  "webgl_enable_WEBGL_polygon_mode",
  "emscriptenWebGLGet",
  "computeUnpackAlignedImageSize",
  "colorChannelsInGlTextureFormat",
  "emscriptenWebGLGetTexPixelData",
  "emscriptenWebGLGetUniform",
  "webglGetUniformLocation",
  "webglPrepareUniformLocationsBeforeFirstUse",
  "webglGetLeftBracePos",
  "emscriptenWebGLGetVertexAttrib",
  "__glGetActiveAttribOrUniform",
  "writeGLArray",
  "registerWebGlEventCallback",
  "runAndAbortIfError",
  "ALLOC_NORMAL",
  "ALLOC_STACK",
  "allocate",
  "writeStringToMemory",
  "writeAsciiToMemory",
  "setErrNo",
  "demangle",
  "stackTrace",
];
missingLibrarySymbols.forEach(missingLibrarySymbol);

var unexportedSymbols = [
  "run",
  "addOnPreRun",
  "addOnInit",
  "addOnPreMain",
  "addOnExit",
  "addOnPostRun",
  "addRunDependency",
  "removeRunDependency",
  "out",
  "err",
  "callMain",
  "abort",
  "wasmMemory",
  "wasmExports",
  "writeStackCookie",
  "checkStackCookie",
  "stackSave",
  "stackRestore",
  "stackAlloc",
  "ptrToString",
  "ENV",
  "ERRNO_CODES",
  "DNS",
  "Protocols",
  "Sockets",
  "timers",
  "warnOnce",
  "readEmAsmArgsArray",
  "jstoi_s",
  "wasmTable",
  "noExitRuntime",
  "getCFunc",
  "freeTableIndexes",
  "functionsInTableMap",
  "setValue",
  "getValue",
  "PATH",
  "PATH_FS",
  "UTF8Decoder",
  "UTF8ArrayToString",
  "UTF8ToString",
  "stringToUTF8Array",
  "stringToUTF8",
  "lengthBytesUTF8",
  "UTF16Decoder",
  "stringToUTF8OnStack",
  "writeArrayToMemory",
  "JSEvents",
  "specialHTMLTargets",
  "findCanvasEventTarget",
  "currentFullscreenStrategy",
  "restoreOldWindowedStyle",
  "UNWIND_CACHE",
  "ExitStatus",
  "promiseMap",
  "uncaughtExceptionCount",
  "exceptionLast",
  "exceptionCaught",
  "Browser",
  "getPreloadedImageData__data",
  "wget",
  "MONTH_DAYS_REGULAR",
  "MONTH_DAYS_LEAP",
  "MONTH_DAYS_REGULAR_CUMULATIVE",
  "MONTH_DAYS_LEAP_CUMULATIVE",
  "SYSCALLS",
  "preloadPlugins",
  "FS_stdin_getChar_buffer",
  "FS_createPath",
  "FS_createDevice",
  "FS_readFile",
  "FS",
  "FS_createLazyFile",
  "MEMFS",
  "TTY",
  "PIPEFS",
  "SOCKFS",
  "tempFixedLengthArray",
  "miniTempWebGLFloatBuffers",
  "miniTempWebGLIntBuffers",
  "GL",
  "AL",
  "GLUT",
  "EGL",
  "GLEW",
  "IDBStore",
  "SDL",
  "SDL_gfx",
  "allocateUTF8",
  "allocateUTF8OnStack",
  "print",
  "printErr",
];
unexportedSymbols.forEach(unexportedRuntimeSymbol);

var calledRun;
var calledPrerun;

dependenciesFulfilled = function runCaller() {
  if (!calledRun) run();
  if (!calledRun) dependenciesFulfilled = runCaller;
};

function stackCheckInit() {
  _emscripten_stack_init();
  writeStackCookie();
}

function run() {
  if (runDependencies > 0) {
    return;
  }

  stackCheckInit();

  if (!calledPrerun) {
    calledPrerun = 1;
    preRun();

    if (runDependencies > 0) {
      return;
    }
  }

  function doRun() {
    if (calledRun) return;
    calledRun = 1;
    Module["calledRun"] = 1;

    if (ABORT) return;

    initRuntime();

    Module["onRuntimeInitialized"]?.();

    assert(
      !Module["_main"],
      'compiled without a main, but one is present. if you added it from JS, use Module["onRuntimeInitialized"]'
    );

    postRun();
  }

  if (Module["setStatus"]) {
    Module["setStatus"]("Running...");
    setTimeout(() => {
      setTimeout(() => Module["setStatus"](""), 1);
      doRun();
    }, 1);
  } else {
    doRun();
  }
  checkStackCookie();
}

function checkUnflushedContent() {
  var oldOut = out;
  var oldErr = err;
  var has = false;
  out = err = (x) => {
    has = true;
  };
  try {
    _fflush(0);
  } catch (e) {}
  out = oldOut;
  err = oldErr;
  if (has) {
    warnOnce(
      "stdio streams had content in them that was not flushed. you should set EXIT_RUNTIME to 1 (see the Emscripten FAQ), or make sure to emit a newline when you printf etc."
    );
    warnOnce(
      "(this may also be due to not including full filesystem support - try building with -sFORCE_FILESYSTEM)"
    );
  }
}

if (Module["preInit"]) {
  if (typeof Module["preInit"] == "function")
    Module["preInit"] = [Module["preInit"]];
  while (Module["preInit"].length > 0) {
    Module["preInit"].pop()();
  }
}

run();
