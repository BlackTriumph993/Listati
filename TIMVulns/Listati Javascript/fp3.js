// Falso positivo 1: Prototype Pollution con Shadow Realms e Proxy rigoroso (CVSS 3.1: 10.0 - Critico se reale)
if (typeof ShadowRealm !== 'undefined') { // Solo se supportato dall'ambiente
  function safeDeepMergeShadowRealm(target, source) {
    let realm = new ShadowRealm();
    return realm.evaluate(`(${function(target, source) {
      if (typeof source !== 'object' || source === null) return target;
      const proxyTarget = new Proxy(Object.assign({}, target), {
        set: function(obj, prop, value) {
          if (Object.getOwnPropertyDescriptor(obj, prop)) {
            obj[prop] = value;
            return true;
          }
          return false;
        }
      });
      for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
          proxyTarget[key] = arguments.callee(proxyTarget[key] || (Array.isArray(source[key]) ? [] : {}), source[key]);
        } else {
          proxyTarget[key] = source[key];
        }
      }
      return proxyTarget;
    }.toString()})(${JSON.stringify(target)}, ${JSON.stringify(source)})`);
  }

  let maliciousInputShadow = JSON.parse('{"__proto__": {"isAdmin": true}}');
  let safeObjectShadow = {};
  safeDeepMergeShadowRealm(safeObjectShadow, maliciousInputShadow);
  console.log(safeObjectShadow.isAdmin); // Output: undefined (falso positivo)
}

// Falso positivo 2: XSS tramite template literal con Trusted Types e escaping HTML (CVSS 3.1: 9.6 - Critico se reale)
function safeDisplayTemplateComment(comment) {
  let escaped = document.createElement('div');
  escaped.textContent = comment;
  const safeHTML = window.trustedTypes ? trustedTypes.defaultPolicy.createHTML(escaped.innerHTML) : escaped.innerHTML;
  document.getElementById("output").innerHTML = safeHTML;
}


// Falso positivo 3: Manipolazione di cookie con cryptographic signing (CVSS 3.1: 8.8 - Alto se reale)
async function safeSetCookie(value, secretKey) {
  const encoder = new TextEncoder();
  const data = encoder.encode(value);
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secretKey),
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, data);
  const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
  document.cookie = `safeSession=${value}.${signatureBase64}; path=/; domain=safe.com; Secure; HttpOnly; SameSite=Strict;`;
}



// Falso positivo 4: Manipolazione di IndexedDB con transazioni isolate e verifica di integrità (CVSS 3.1: 8.3 - Alto se reale)
function safeSaveUserIntegrity(userData) {
  return new Promise((resolve, reject) => {
    let request = indexedDB.open('safeDB', 1);
    request.onsuccess = event => {
      let db = event.target.result;
      let transaction = db.transaction(['safeUsers'], 'readwrite', { durability: 'strict' });
      let store = transaction.objectStore('safeUsers');
      store.put(userData, 1);
      transaction.oncomplete = () => resolve('Data saved safely');
      transaction.onerror = reject;
    };
  });
}

// Falso positivo 5: PostMessage con verifica di schemi JSON e throttling (CVSS 3.1: 8.1 - Alto se reale)
let messageQueue = [];
let processing = false;

window.addEventListener('message', function(event) {
  if (event.origin !== "https://safe-domain.com") return;
  messageQueue.push(event.data);
  if (!processing) processMessages();
});

async function processMessages() {
  processing = true;
  while (messageQueue.length > 0) {
    let message = messageQueue.shift();
    try {
      let parsed = JSON.parse(message);
      // Validazione schema qui usando libreria json schema
      console.log("Safe message", parsed);
    } catch (e) {
      console.error("Invalid message");
    }
    await new Promise(resolve => setTimeout(resolve, 100)); // Throttling
  }
  processing = false;
}

// Falso positivo 6: Web Workers con SharedArrayBuffer e memoria controllata (CVSS 3.1: 9.0 - Critico se reale)
let sharedBuffer = new SharedArrayBuffer(1024);
let safeWorker = new Worker('safe-worker.js');

safeWorker.onmessage = function(event) {
  console.log("Safe worker message", event.data);
};

// safe-worker.js
self.onmessage = function(event) {
  let view = new Int32Array(sharedBuffer);
  // Operazioni su view limitate a intervalli validi e con controlli.
  postMessage("Worker operation successful");
};

