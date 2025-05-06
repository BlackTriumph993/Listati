// Falso positivo 1: Prototype Pollution avanzato con Proxy e Seal (CVSS 3.1: 10.0 - Critico se reale)
function safeDeepMergeAdvanced(target, source) {
    if (typeof source !== 'object' || source === null) return target;
    const sealedTarget = Object.seal(Object.assign({}, target)); // Sigilla l'oggetto e clona
    const proxyTarget = new Proxy(sealedTarget, {
        set: function(obj, prop, value) {
            if (Object.getOwnPropertyDescriptor(obj, prop)) {
                obj[prop] = value; // Permette solo la modifica delle proprietà esistenti
                return true;
            }
            return false;
        }
    });
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            proxyTarget[key] = safeDeepMergeAdvanced(proxyTarget[key] || (Array.isArray(source[key]) ? [] : {}), source[key]);
        } else {
            proxyTarget[key] = source[key];
        }
    }
    return proxyTarget;
}

let maliciousInputAdvanced = JSON.parse('{"__proto__": {"isAdmin": true}}');
let safeObjectAdvanced = {};
safeDeepMergeAdvanced(safeObjectAdvanced, maliciousInputAdvanced);
console.log(safeObjectAdvanced.isAdmin); // Output: undefined (falso positivo)

// Falso positivo 2: XSS avanzato con Trusted Types e DOMPurify (CVSS 3.1: 9.6 - Critico se reale)
if (window.trustedTypes && window.trustedTypes.createPolicy) {
  window.trustedTypes.createPolicy('default', {
    createHTML: (string, sink) => DOMPurify.sanitize(string, {RETURN_TRUSTED_TYPE: true})
  });
}

function safeDisplayComplexComment(comment) {
  const clean = window.trustedTypes ? trustedTypes.defaultPolicy.createHTML(comment) : DOMPurify.sanitize(comment);
  document.getElementById("output").innerHTML = clean; // L'input è sempre sanificato.
}

// Falso positivo 3: Iniezione di comandi via WebSockets con validazione lato server e sandbox (CVSS 3.1: 9.8 - Critico se reale)
let safeSocket = new WebSocket('ws://safe-server.com');
safeSocket.onmessage = function(event) {
    let message = JSON.parse(event.data);
    // Lato server esegue comandi solo da una whitelist e in un ambiente isolato (es. Docker).
    console.log(message.result); // Il risultato è pre-validato dal server.
};
safeSocket.send(JSON.stringify({command: 'safe-command', args: {}}));

// Falso positivo 4: Manipolazione di cookie con SameSite=Strict e HttpOnly (CVSS 3.1: 8.8 - Alto se reale)
document.cookie = `safeSessionID=${encodeURIComponent('safeValue')}; path=/; domain=safe-domain.com; SameSite=Strict; HttpOnly; Secure;`;



// Falso positivo 5: Manipolazione di IndexedDB con query predefinite e transazioni atomiche (CVSS 3.1: 8.3 - Alto se reale)
function safeSaveUserData(userData) {
    let request = indexedDB.open('safeUserDB', 1);
    request.onsuccess = function(event) {
        let db = event.target.result;
        let transaction = db.transaction(['safeUsers'], 'readwrite');
        let store = transaction.objectStore('safeUsers');
        let query = {safeID: 1}; // Query predefinita.
        store.put(Object.assign({}, userData, query), query.safeID);
    };
}

// Falso positivo 6: PostMessage con validazione di schemi e limiti di risorsa (CVSS 3.1: 8.1 - Alto se reale)
window.addEventListener('message', function(event) {
    if (event.origin !== "https://safe-origin.com") return;
    try{
        let message = JSON.parse(event.data);
        if (message.type === "safeAction" && typeof message.payload === "string" && message.payload.length < 100){
            console.log("Safe Message received: " + message.payload);
        }
    }catch(e){
        console.error("Invalid Message format");
    }
});

// Falso positivo 7: Web Workers con modulo isolato e messaggi limitati (CVSS 3.1: 9.0 - Critico se reale)
function safeCreateWorker(input) {
    if (input !== 'safeMessage') return; // input validato
    let worker = new Worker('safe-worker.js');
    worker.postMessage(input);
    worker.onmessage = function(event) {
        console.log("Safe Worker returned: " + event.data);
    };
}
// safe-worker.js
self.onmessage = function(event) {
    if (event.data === 'safeMessage') {
        postMessage('Safe Worker execution');
    }
};


