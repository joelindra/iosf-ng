/*
 * iostester TLS interceptor agent
 * ---------------------------------
 * Runs inside the target iOS app (via frida spawn/attach, or via an injected
 * Frida Gadget on non-jailbroken devices).
 *
 * Plaintext capture strategy
 * --------------------------
 * On iOS, all TLS connections created through high level APIs (NSURLSession,
 * Network.framework, WebKit/CFNetwork) terminate in Apple's BoringSSL
 * (libboringssl.dylib). Hooking SSL_write/SSL_read at that layer yields HTTP
 * plaintext *above* TLS - so certificate pinning, ATS, and proxy restrictions
 * are irrelevant to capture. Captured traffic is matched back to the SNI host
 * through SSL_set_tlsext_host_name and to the socket peer through
 * SSL_set_bio + BIO_set_fd.
 *
 * Messages are emitted as JSON strings (send(JSON.stringify(...))) so binary
 * bodies can be hex encoded and large payloads streamed in slices.
 *
 * Verified on: iPhone (iOS 16.7.16), Frida 17.19, MyTsel staging app.
 * Frida 17 removed the static Module.findExportByName - instance APIs used.
 */

(function () {
  "use strict";

  var CFG = JSON.parse('__CFG__' || '{}');
  var MAX_SLICE = CFG.maxSlice || 262144;     // hex chars per message (~128 KiB body)
  var INCLUDE_BODY = CFG.captureBody !== false;
  var FILTER = (CFG.hosts || []).map(function (h) { return h.toLowerCase(); });

  var stats = { write: 0, read: 0, conns: 0, opens: 0, drops: 0, bytes_up: 0, bytes_down: 0 };
  var sslBio = {};       // ssl ptr -> {rbio, wbio}
  var bioFd = {};        // bio ptr -> fd
  var fdPeer = {};       // fd -> "ip:port"
  var sslHost = {};      // ssl ptr -> sni
  var sslConn = {};      // ssl ptr -> conn id (opened lazily)
  var nextConn = 1;
  var seq = 0;

  function nowMs() {
    return Date.now();
  }

  function hexOf(ptr, n) {
    try {
      return bytesToHex(new Uint8Array(ptr.readByteArray(n)));
    } catch (e) {
      return "";
    }
  }

  var HEX = "0123456789abcdef";
  function bytesToHex(u8) {
    var out = "";
    for (var i = 0; i < u8.length; i++) {
      out += HEX[(u8[i] >> 4) & 0xf] + HEX[u8[i] & 0xf];
    }
    return out;
  }

  function emit(obj) {
    try {
      send(JSON.stringify(obj));
    } catch (e) { /* never throw from a hook */ }
  }

  function modExport(modName, names) {
    var m;
    try {
      m = Process.getModuleByName(modName);
    } catch (e) {
      return null;
    }
    for (var i = 0; i < names.length; i++) {
      try {
        var p = m.findExportByName(names[i]);
        if (p) return p;
      } catch (e) { /* continue */ }
    }
    return null;
  }

  function hookFirst(modName, names, cb) {
    var p = modExport(modName, names);
    if (!p) {
      emit({ t: "agent", kind: "hook_missing", mod: modName, names: names });
      return false;
    }
    Interceptor.attach(p, cb);
    return true;
  }

  function sockaddr(ptr) {
    try {
      var fam = ptr.readU8();
      var port = (ptr.add(2).readU8() << 8) | ptr.add(3).readU8();
      if (fam === 2) {
        var b = new Uint8Array(ptr.add(4).readByteArray(4));
        return b[0] + "." + b[1] + "." + b[2] + "." + b[3] + ":" + port;
      }
      if (fam === 30) {
        var b6 = new Uint8Array(ptr.add(8).readByteArray(16));
        var parts = [];
        for (var i = 0; i < 8; i++) parts.push(((b6[i * 2] << 8) | b6[i * 2 + 1]).toString(16));
        return "[" + parts.join(":") + "]:" + port;
      }
      return "fam" + fam + ":" + port;
    } catch (e) {
      return null;
    }
  }

  function hostAllowed(host) {
    if (!FILTER.length) return true;
    if (!host) return true; // allow until SNI known
    host = host.toLowerCase();
    for (var i = 0; i < FILTER.length; i++) {
      var f = FILTER[i];
      if (f.charAt(0) === "*") {
        if (host.slice(-(f.length - 1)) === f.slice(1)) return true;
      } else if (host === f || host.indexOf(f + ":") === 0) {
        return true;
      }
    }
    return false;
  }

  function ensureConn(ssl) {
    var id = sslConn[ssl];
    if (id) return id;
    id = "c" + nextConn++;
    sslConn[ssl] = id;
    var map = sslBio[ssl] || {};
    var fd = bioFd[map.wbio] !== undefined ? bioFd[map.wbio]
           : (bioFd[map.rbio] !== undefined ? bioFd[map.rbio] : null);
    stats.opens++;
    emit({
      t: "conn_open",
      conn: id,
      fd: fd,
      peer: fd !== null ? (fdPeer[fd] || null) : null,
      host: sslHost[ssl] || null,
      ts: nowMs()
    });
    return id;
  }

  function peerForSsl(ssl) {
    var map = sslBio[ssl] || {};
    var fd = bioFd[map.wbio] !== undefined ? bioFd[map.wbio]
           : (bioFd[map.rbio] !== undefined ? bioFd[map.rbio] : null);
    return fd !== null && fd !== undefined ? (fdPeer[fd] || null) : null;
  }

  function emitData(dir, ssl, ptr, n) {
    if (!INCLUDE_BODY || n <= 0) return;
    var host = sslHost[ssl] || null;
    if (!hostAllowed(host)) {
      stats.drops++;
      return;
    }
    var conn = ensureConn(ssl);
    var peer = peerForSsl(ssl);
    var remaining = n;
    var off = 0;
    var first = true;
    while (remaining > 0) {
      // hex chars -> bytes = chars/2
      var take = Math.min(remaining, MAX_SLICE / 2);
      var hex = hexOf(ptr.add(off), take);
      if (!hex) break;
      emit({
        t: "data",
        dir: dir,
        conn: conn,
        host: host,
        peer: peer,
        ts: nowMs(),
        seq: seq++,
        first: first,
        last: remaining - take <= 0,
        hex: hex
      });
      first = false;
      off += take;
      remaining -= take;
    }
  }

  // ---- hooks -----------------------------------------------------------
  hookFirst("libboringssl.dylib", ["SSL_set_tlsext_host_name"], {
    onEnter: function (args) {
      try {
        var host = args[1].readUtf8String();
        sslHost[args[0].toString()] = host;
      } catch (e) {}
    }
  });

  hookFirst("libboringssl.dylib", ["SSL_set_bio"], {
    onEnter: function (args) {
      sslBio[args[0].toString()] = { rbio: args[1].toString(), wbio: args[2].toString() };
    }
  });

  hookFirst("libboringssl.dylib", ["BIO_set_fd"], {
    onEnter: function (args) {
      try {
        bioFd[args[0].toString()] = args[1].toInt32();
      } catch (e) {}
    }
  });

  hookFirst("libsystem_c.dylib", ["connect"], {
    onEnter: function (args) {
      try {
        fdPeer[args[0].toInt32()] = sockaddr(args[1]);
        stats.conns++;
      } catch (e) {}
    }
  });

  hookFirst("libboringssl.dylib", ["SSL_write"], {
    onEnter: function (args) {
      stats.write++;
      try {
        var n = args[2].toInt32();
        stats.bytes_up += n;
        emitData("up", args[0].toString(), args[1], n);
      } catch (e) {}
    }
  });

  hookFirst("libboringssl.dylib", ["SSL_read"], {
    onEnter: function (args) {
      this.ssl = args[0].toString();
      this.buf = args[1];
      this.max = args[2].toInt32();
    },
    onLeave: function (retval) {
      var n = retval.toInt32();
      stats.read++;
      if (n <= 0) return;
      try {
        stats.bytes_down += n;
        emitData("down", this.ssl, this.buf, n);
      } catch (e) {}
    }
  });

  // ---- SSL Pinning Bypass Hooks (Security.framework & BoringSSL) ----
  try {
    var pSecTrustEvaluateWithError = modExport("Security", ["SecTrustEvaluateWithError"]);
    if (pSecTrustEvaluateWithError) {
      Interceptor.attach(pSecTrustEvaluateWithError, {
        onEnter: function (args) { this.errPtr = args[1]; },
        onLeave: function (retval) {
          if (this.errPtr && !this.errPtr.isNull()) this.errPtr.writePointer(NULL);
          retval.replace(ptr(1));
        }
      });
    }
  } catch (e) {}

  try {
    var pSecTrustEvaluate = modExport("Security", ["SecTrustEvaluate"]);
    if (pSecTrustEvaluate) {
      Interceptor.attach(pSecTrustEvaluate, {
        onEnter: function (args) { this.resPtr = args[1]; },
        onLeave: function (retval) {
          if (this.resPtr && !this.resPtr.isNull()) this.resPtr.writeU32(1);
          retval.replace(ptr(0));
        }
      });
    }
  } catch (e) {}

  try {
    var pSecTrustGetTrustResult = modExport("Security", ["SecTrustGetTrustResult"]);
    if (pSecTrustGetTrustResult) {
      Interceptor.attach(pSecTrustGetTrustResult, {
        onEnter: function (args) { this.resPtr = args[1]; },
        onLeave: function (retval) {
          if (this.resPtr && !this.resPtr.isNull()) this.resPtr.writeU32(1);
          retval.replace(ptr(0));
        }
      });
    }
  } catch (e) {}

  try {
    var pCustomVerify = modExport("libboringssl.dylib", ["SSL_set_custom_verify"]);
    if (pCustomVerify) {
      var replacedCb = {};
      Interceptor.attach(pCustomVerify, {
        onEnter: function (args) {
          var cb = args[2];
          var key = cb.toString();
          if (!cb.isNull() && !replacedCb[key]) {
            try {
              Interceptor.replace(cb, new NativeCallback(function (ssl, alert) {
                return 0; // ssl_verify_ok
              }, 'int', ['pointer', 'pointer']));
              replacedCb[key] = true;
            } catch (err) {}
          }
        }
      });
    }
  } catch (e) {}

  // Optional: capture DNS host resolution (helps map IPs to hostnames)
  try {
    var ga = modExport("libsystem_info.dylib", ["getaddrinfo"]);
    if (ga) {
      Interceptor.attach(ga, {
        onEnter: function (args) {
          try { this.node = args[0].isNull() ? null : args[0].readUtf8String(); } catch (e) { this.node = null; }
        },
        onLeave: function (retval) {
          if (this.node && retval.toInt32() === 0) {
            emit({ t: "dns", host: this.node, ts: nowMs() });
          }
        }
      });
    }
  } catch (e) {}

  emit({ t: "agent", kind: "ready", pid: Process.id, arch: Process.arch, ts: nowMs() });

  // Periodic stats heartbeat
  setInterval(function () {
    emit({ t: "stats", ts: nowMs(), stats: stats });
  }, 10000);
})();
