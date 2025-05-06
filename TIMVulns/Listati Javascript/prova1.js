// 1. Iniezione di codice (Eval) (CVSS 3.1: 9.8 - Critico)
function executeCode(userInput) {
  eval(userInput); // Esecuzione di codice arbitrario da input utente
}

// 2. Cross-Site Scripting (XSS) (CVSS 3.1: 6.1 - Medio)
function displayUsername(username) {
  document.getElementById("output").innerHTML = username; // Output non sanificato
}

// 3. Insecure Direct Object Reference (IDOR) (CVSS 3.1: 5.3 - Medio)
function getUserData(userId) {
  fetch(`/users/${userId}`) // UserId direttamente da input utente
    .then(response => response.json())
    .then(data => console.log(data));
}

// 4. Iniezione di HTML (CVSS 3.1: 5.4 - Medio)
function displayComment(comment) {
  document.getElementById("comments").insertAdjacentHTML("beforeend", `<div>${comment}</div>`); // Possibile iniezione HTML
}


// 5. Manipolazione del DOM non sicura (CVSS 3.1: 4.3 - Medio)
function changeElementAttribute(elementId, attributeName, attributeValue) {
  document.getElementById(elementId)[attributeName] = attributeValue; // Potenziale per alterare il comportamento della pagina in modo imprevisto.
}

// 6. Uso di innerHTML con contenuto generato dinamicamente (CVSS 3.1: 6.1 - Medio)
function updateContent(content) {
  document.getElementById("content-area").innerHTML = content; // Possibilità di iniezione XSS.
}

// 7. Open Redirect (CVSS 3.1: 4.7 - Medio)
function redirectUser(nextPage) {
  window.location.href = nextPage; // Reindirizzamento a URL fornita dall'utente.
}

// 9. Informazioni sensibili nell'URL (CVSS 3.1: 5.3 - Medio)
// La trasmissione di parametri sensibili (come password)
// direttamente nell'URL dovrebbe essere evitata.
// Esempio:
//8 fetch(`/api/login?username=${username}&password=${password}`)

// 9. Uso di postMessage non sicuro (CVSS 3.1: 5.3 - Medio)
window.addEventListener('message', function(event) {
  // Manca la validazione dell'origin
  console.log("Messaggio ricevuto: " + event.data);
  // Gestisce i dati senza controllarne la fonte
});
