const messageInput = document.querySelector('#messageInput');
const encryptButton = document.querySelector('#encryptButton');
const decryptButton = document.querySelector('#decryptButton');
const plaintextOutput = document.querySelector('#plaintextOutput');
const ciphertextOutput = document.querySelector('#ciphertextOutput');
const decryptedOutput = document.querySelector('#decryptedOutput');
const resultCard = document.querySelector('#resultCard');
const attackerCopy = document.querySelector('#attackerCopy');
const plaintextCard = document.querySelector('#plaintextCard');
const keyCard = document.querySelector('#keyCard');
const ciphertextCard = document.querySelector('#ciphertextCard');

let aesKey;
let initializationVector;
let encryptedPacket;

function bytesToBase64(bytes) {
  let binary = '';
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return window.btoa(binary);
}

function wait(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

function clearJourneyState() {
  [plaintextCard, keyCard, ciphertextCard].forEach((card) => {
    card.classList.remove('active', 'revealed');
  });
}

async function encryptMessage() {
  const message = messageInput.value.trim();

  if (!message) {
    messageInput.focus();
    messageInput.placeholder = 'Please enter a message first';
    return;
  }

  if (!window.crypto?.subtle) {
    ciphertextOutput.textContent = 'Secure browser context required';
    attackerCopy.textContent = 'Open this site with VS Code Live Server or another localhost server, then try again.';
    return;
  }

  encryptButton.disabled = true;
  decryptButton.disabled = true;
  resultCard.hidden = true;
  clearJourneyState();
  plaintextOutput.textContent = message;
  ciphertextOutput.textContent = 'Transforming…';
  attackerCopy.textContent = 'The attacker sees only scrambled data, not the readable message.';

  plaintextCard.classList.add('active');
  await wait(550);
  plaintextCard.classList.remove('active');
  plaintextCard.classList.add('revealed');
  keyCard.classList.add('active');
  await wait(700);
  keyCard.classList.remove('active');
  keyCard.classList.add('revealed');
  ciphertextCard.classList.add('active');

  // AES-GCM is authenticated encryption. The browser generates a new 256-bit key
  // and a unique 96-bit initialization vector each time the user encrypts.
  aesKey = await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  initializationVector = window.crypto.getRandomValues(new Uint8Array(12));
  const plaintextBytes = new TextEncoder().encode(message);
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: initializationVector },
    aesKey,
    plaintextBytes,
  );
  encryptedPacket = new Uint8Array(encryptedBuffer);
  ciphertextOutput.textContent = bytesToBase64(encryptedPacket);
  await wait(550);
  ciphertextCard.classList.remove('active');
  ciphertextCard.classList.add('revealed');
  attackerCopy.textContent = 'The intercepted text is unreadable without the matching secret key.';
  decryptButton.disabled = false;
  encryptButton.disabled = false;
}

async function decryptMessage() {
  if (!encryptedPacket) return;

  decryptButton.disabled = true;
  ciphertextCard.classList.add('active');
  await wait(450);
  keyCard.classList.add('active');
  await wait(550);
  ciphertextCard.classList.remove('active');
  keyCard.classList.remove('active');
  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: initializationVector },
    aesKey,
    encryptedPacket,
  );
  decryptedOutput.textContent = new TextDecoder().decode(decryptedBuffer);
  resultCard.hidden = false;
  resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

encryptButton.addEventListener('click', encryptMessage);
decryptButton.addEventListener('click', decryptMessage);
messageInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') encryptMessage();
});
