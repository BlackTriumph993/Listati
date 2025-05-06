
function executeCode(userInput) {
  eval(userInput); // Esecuzione di codice arbitrario da input utente
}


function displayUsername(username) {
  document.getElementById("output").innerHTML = username; // Output non sanificato
}


function getUserData(userId) {
  fetch(`/users/${userId}`) // UserId direttamente da input utente
    .then(response => response.json())
    .then(data => console.log(data));
}


function displayComment(comment) {
  document.getElementById("comments").insertAdjacentHTML("beforeend", `<div>${comment}</div>`); // Possibile iniezione HTML
}



function changeElementAttribute(elementId, attributeName, attributeValue) {
  document.getElementById(elementId)[attributeName] = attributeValue; // Potenziale per alterare il comportamento della pagina in modo imprevisto.
}


function updateContent(content) {
  document.getElementById("content-area").innerHTML = content; // Possibilità di iniezione XSS.
}


function redirectUser(nextPage) {
  window.location.href = nextPage; // Reindirizzamento a URL fornita dall'utente.
}


// La trasmissione di parametri sensibili (come password)
// direttamente nell'URL dovrebbe essere evitata.
// Esempio:
//8 fetch(`/api/login?username=${username}&password=${password}`)


window.addEventListener('message', function(event) {
  // Manca la validazione dell'origin
  console.log("Messaggio ricevuto: " + event.data);
  // Gestisce i dati senza controllarne la fonte
});
