function deepMergeComplex(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key] || typeof target[key] !== 'object') {
                target[key] = Array.isArray(source[key]) ? [] : {};
            }
            deepMergeComplex(target[key], source[key]);
        } else {
            Object.defineProperty(target, key, {
                value: source[key],
                writable: true,
                enumerable: true,
                configurable: true
            });
        }
    }
    return target;
}

let maliciousInputComplex = JSON.parse('{"__proto__": {"constructor": {"prototype": {"isAdmin": true}}}}');
deepMergeComplex({}, maliciousInputComplex);
console.log((0).isAdmin); // Output: true


function addAdvancedInput() {
    let newInput = document.createElement('input');
    newInput.id = 'vulnerableInput';
    document.body.appendChild(newInput);
    let newButton = document.createElement('button');
    newButton.id = 'vulnerableButton';
    newButton.textContent = 'Click me';
    document.body.appendChild(newButton);
}

function useAdvancedUserInput() {
    let userInput = document.location.hash.substring(1);
    vulnerableButton.onclick = Function(userInput); // Manipolazione dell'evento onclick
}




document.cookie = `sessionID=${encodeURIComponent(document.location.hash.substring(1))}; path=/; domain=vulnerable-domain.com;`; // Simboli speciali e mancanza di flag HttpOnly e Secure.




function advancedSaveUserData(userData) {
    let request = indexedDB.open('userDB', 1);
    request.onsuccess = function(event) {
        let db = event.target.result;
        let transaction = db.transaction(['users'], 'readwrite');
        let store = transaction.objectStore('users');
        let query = JSON.parse(document.location.hash.substring(1)); // Query controllata dall'utente.
        let cursorRequest = store.openCursor(IDBKeyRange.bound(query.lower, query.upper)); // query come stringa.
        cursorRequest.onsuccess = function(event) {
            let cursor = event.target.result;
            if (cursor) {
                cursor.update(userData);
                cursor.continue();
            }
        };
    };
}
advancedSaveUserData({ maliciousData: "injected" });


window.addEventListener('message', function(event) {
  // Nessuna validazione di origine e manipolazione di eventi globali
  Function(event.data)(); // esecuzione del codice
});


function advancedCreateWorker(code) {
    let blob = new Blob([code], { type: 'application/javascript' });
    let worker = new Worker(URL.createObjectURL(blob));
    worker.onmessage = function(event) {
        // Manipolazione di messaggi e possibile bypass di sandbox.
        Function(event.data)();
    };
    worker.postMessage(document.location.hash.substring(1)); // codice da hash.
}
advancedCreateWorker('self.onmessage = function(event) { postMessage(event.data); };');


 self.addEventListener('fetch', event => {
   if (event.request.url.includes('/api/auth')) {
     let token = localStorage.getItem('jwtToken');
     event.respondWith(new Response(JSON.stringify({ token: token }), { headers: { 'Content-Type': 'application/json' } }));
   }
 });


 let wasmMemory = new WebAssembly.Memory({ initial: 1 });
 let wasmModule = await WebAssembly.instantiateStreaming(fetch('malicious.wasm'), { env: { maliciousMemoryManipulation: (offset, value) => { new Uint8Array(wasmMemory.buffer)[offset] = value; } } });


// utilizzo della cache api senza controllo sul contenuto, quando dati sensibili sono memorizzati.
// esempio.
 fetch('/api/sensitive').then(response => caches.open('vulnerableCache').then(cache => cache.put('/api/sensitive', response)));


// Esempio:
 let socket = new WebSocket('ws://vulnerable-domain.com');
// Se il sito vulnerabile non controlla l'header Origin e la cross-site policy è permissiva.
// un sito malevolo potrebbe forzare la connessione websocket ed intercettare le comunicazioni.
