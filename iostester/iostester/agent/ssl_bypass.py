"""Universal iOS SSL Pinning Bypass (Frida 17+) Script.

Embedded directly into the toolkit to eliminate external file dependencies.
Handles Security.framework (iOS 12+ SecTrustEvaluateWithError, legacy SecTrustEvaluate)
and libboringssl.dylib (SSL_set_custom_verify callback replacement).
"""

SSL_BYPASS_SCRIPT = r"""
function getExport(modName, funcName) {
  try {
    var mod = Process.getModuleByName(modName);
    return mod.findExportByName(funcName);
  } catch (e) {
    try {
      var mod2 = Process.findModuleByName(modName);
      if (mod2) return mod2.findExportByName(funcName);
    } catch (e2) {}
  }
  return null;
}

// 1. SecTrustEvaluateWithError (Security.framework)
try {
  var pSecTrustEvaluateWithError = getExport("Security", "SecTrustEvaluateWithError");
  if (pSecTrustEvaluateWithError) {
    Interceptor.attach(pSecTrustEvaluateWithError, {
      onEnter: function (args) {
        this.errorPtr = args[1];
      },
      onLeave: function (retval) {
        if (this.errorPtr && !this.errorPtr.isNull()) {
          this.errorPtr.writePointer(NULL);
        }
        retval.replace(ptr(1));
      }
    });
  }
} catch (e) {}

// 2. SecTrustEvaluate (Security.framework)
try {
  var pSecTrustEvaluate = getExport("Security", "SecTrustEvaluate");
  if (pSecTrustEvaluate) {
    Interceptor.attach(pSecTrustEvaluate, {
      onEnter: function (args) {
        this.resultPtr = args[1];
      },
      onLeave: function (retval) {
        if (this.resultPtr && !this.resultPtr.isNull()) {
          this.resultPtr.writeU32(1);
        }
        retval.replace(ptr(0));
      }
    });
  }
} catch (e) {}

// 3. SecTrustGetTrustResult (Security.framework)
try {
  var pSecTrustGetTrustResult = getExport("Security", "SecTrustGetTrustResult");
  if (pSecTrustGetTrustResult) {
    Interceptor.attach(pSecTrustGetTrustResult, {
      onEnter: function (args) {
        this.resultPtr = args[1];
      },
      onLeave: function (retval) {
        if (this.resultPtr && !this.resultPtr.isNull()) {
          this.resultPtr.writeU32(1);
        }
        retval.replace(ptr(0));
      }
    });
  }
} catch (e) {}

// 4. BoringSSL custom verify
try {
  var pSetCustomVerify = getExport("libboringssl.dylib", "SSL_set_custom_verify");
  if (pSetCustomVerify) {
    var replacedCallbacks = {};
    Interceptor.attach(pSetCustomVerify, {
      onEnter: function (args) {
        var callbackPtr = args[2];
        var key = callbackPtr.toString();
        if (!callbackPtr.isNull() && !replacedCallbacks[key]) {
          try {
            Interceptor.replace(callbackPtr, new NativeCallback(function (ssl, out_alert) {
              return 0; // ssl_verify_ok
            }, 'int', ['pointer', 'pointer']));
            replacedCallbacks[key] = true;
          } catch (err) {}
        }
      }
    });
  }
} catch (e) {}
"""
