// Falso positivo 1: Prototype Pollution con object freezing (CVSS 3.1: 9.8 - Critico se reale)
function safeMerge(target, source) {
  Object.freeze(target); // Previene la modifica del prototipo
  for (let key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key] || typeof target[key] !== 'object') {
        target[key] = Array.isArray(source[key]) ? [] : {};
      }
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

let maliciousInput = JSON.parse('{"__proto__": {"polluted": true}}');
let safeObject = {};
safeMerge(safeObject, maliciousInput);
console.log(safeObject.polluted); // Output: undefined (falso positivo)

// Falso positivo 2: XSS con Content Security Policy (CSP) (CVSS 3.1: 6.1 - Medio se reale)
function safeDisplayUsername(username) {
  // CSP: default-src 'self'; script-src 'none'; object-src 'none';
  document.getElementById("output").textContent = username; // Usa textContent invece di innerHTML
}

// Falso positivo 3: Insecure Direct Object Reference (IDOR) con autorizzazione controllata lato server (CVSS 3.1: 5.3 - Medio se reale)
function getUserData(userId) {
  fetch(`/safe/users/${userId}`)
    .then(response => {
      if (response.status === 403) {
        console.log("Accesso negato.");
        return;
      }
      return response.json();
    })
    .then(data => console.log(data)); // Verifica autorizzazione lato server
}

// Falso positivo 4: Iniezione di HTML con sanitizzazione (CVSS 3.1: 5.4 - Medio se reale)
function safeDisplayComment(comment) {
  let sanitizedComment = DOMPurify.sanitize(comment); // Usa DOMPurify per la sanitizzazione
  document.getElementById("comments").insertAdjacentHTML("beforeend", `<div>${sanitizedComment}</div>`);
}

// Falso positivo 5: Uso di eval() in Web Workers con input controllato (CVSS 3.1: 7.5 - Alto se reale)
function safeWorkerEval(userInput) {
  let worker = new Worker('safe-worker.js'); // File worker separato
  worker.postMessage(userInput);
}
// safe-worker.js
self.onmessage = function(event) {
  if (event.data === 'safeInput') { // Input controllato
    eval('postMessage("Safe code executed");');
  } else {
    postMessage('Input non valido');
  }
};

// Falso positivo 6: Manipolazione del DOM con controlli di input (CVSS 3.1: 4.3 - Medio se reale)
function safeChangeElementAttribute(elementId, attributeName, attributeValue) {
  if (attributeName === "data-custom") { // Whitelist degli attributi
    document.getElementById(elementId).setAttribute(attributeName, attributeValue);
  } else {
    console.log("Attributo non permesso.");
  }
}

// Falso positivo 7: Open Redirect con whitelist di domini (CVSS 3.1: 4.7 - Medio se reale)
function safeRedirectUser(nextPage) {
  let allowedDomains = ["example.com", "mywebsite.com"];
  let parsedUrl = new URL(nextPage);
  if (allowedDomains.includes(parsedUrl.hostname)) {
    window.location.href = nextPage;
  } else {
    console.log("Dominio non permesso.");
  }
}

// Falso positivo 8: postMessage con validazione origin (CVSS 3.1: 5.3 - Medio se reale)
window.addEventListener('message', function(event) {
  if (event.origin === "https://trusted-domain.com") {
      console.log("Messaggio ricevuto: " + event.data);
  }
});

// Falso positivo 9: Uso di localStorage con crittografia (CVSS 3.1: 6.5 - Medio se reale)
function safeLocalStorage(data) {
  let encrypted = CryptoJS.AES.encrypt(JSON.stringify(data), 'secretKey'); // crittografia con una libreria come crypto-js
  localStorage.setItem('safeData', encrypted);
}
