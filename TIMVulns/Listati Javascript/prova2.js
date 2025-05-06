// 1. Prototype Pollution (CVSS 3.1: 9.8 - Critico)
function deepMerge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

let maliciousInput = JSON.parse('{"__proto__": {"polluted": true}}');
deepMerge({}, maliciousInput);
console.log({}.polluted); // Output: true

// 2. DOM clobbering + XSS (CVSS 3.1: 9.6 - Critico)
function addInput() {
    let newInput = document.createElement('input');
    newInput.id = 'vulnerableInput';
    document.body.appendChild(newInput);
}

function useUserInput() {
    let userInput = document.location.hash.substring(1); // Input da hash URL
    vulnerableInput.value = userInput;
    let newScript = document.createElement('script');
    newScript.textContent = vulnerableInput.value;
    document.body.appendChild(newScript);
}

// 3. Iniezione di comandi lato server via WebSocket (CVSS 3.1: 9.8 - Critico)
let socket = new WebSocket('ws://vulnerable-server.com');
socket.onmessage = function(event) {
    // Il server esegue eval() sul dato ricevuto
    console.log(event.data);
};
socket.send('os.execute("rm -rf /")'); // Iniezione di comando arbitrario.

// 4. Manipolazione di cookie non sicura (CVSS 3.1: 7.5 - Alto)
document.cookie = `sessionID=${document.location.hash.substring(1)}`; // Cookie da hash URL.


// 5. Manipolazione non sicura di IndexedDB (CVSS 3.1: 6.5 - Medio)
function saveUserData(userData) {
    let request = indexedDB.open('userDB', 1);
    request.onsuccess = function(event) {
        let db = event.target.result;
        let transaction = db.transaction(['users'], 'readwrite');
        let store = transaction.objectStore('users');
        store.put(userData, 1); // UserData controllato dall'utente.
    };
}
saveUserData(JSON.parse(document.location.hash.substring(1))); // Hash URL usato come input diretto.

// 6. PostMessage senza validazione di origin (CVSS 3.1: 5.3 - Medio)
window.addEventListener('message', function(event) {
  // Nessuna validazione di origin
  eval(event.data);
});

// 7. Utilizzo non sicuro di Web Workers (CVSS 3.1: 7.5 - Alto)
function createWorker(code){
    let blob = new Blob([code], {type:'application/javascript'});
    let worker = new Worker(URL.createObjectURL(blob));
    worker.onmessage = function(event) {
        console.log("Worker returned: "+ event.data);
    };
    worker.onerror = function(error){
        console.log("Worker error: " + error.message);
    }
    worker.postMessage('start');
}

createWorker(document.location.hash.substring(1)); // codice worker non validato.


//8. URL.createObjectURL senza revoca. (CVSS 3.1: 5.3 Medio)
let file = new Blob(["test"], { type: 'text/plain' });
let url = URL.createObjectURL(file); // url non revocato.

//9. utilizzo di document.write. (CVSS 3.1: 6.1 Medio)
document.write(document.location.hash.substring(1));
