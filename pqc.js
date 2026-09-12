const ml_kem768 = globalThis.QuantumShieldMLKEM?.ml_kem768;

const messageInput = document.querySelector('#pqcMessage');
const encryptButton = document.querySelector('#pqcEncryptButton');
const decryptButton = document.querySelector('#pqcDecryptButton');
const cipherPanel = document.querySelector('#pqcCipherPanel');
const ciphertextOutput = document.querySelector('#pqcCiphertext');
const decryptedOutput = document.querySelector('#pqcDecrypted');

const stepCards = [
  document.querySelector('#pqcStepOne'),
  document.querySelector('#pqcStepTwo'),
  document.querySelector('#pqcStepThree'),
  document.querySelector('#pqcStepFour'),
];
const keyStatus = document.querySelector('#pqcKeyStatus');
const kemStatus = document.querySelector('#pqcKemStatus');
const secretStatus = document.querySelector('#pqcSecretStatus');
const cipherStatus = document.querySelector('#pqcCipherStatus');

let sessionKey;
let initializationVector;
let encryptedPacket;

const wait = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

function sameBytes(first, second) {
  if (first.length !== second.length) return false;
  return first.every((value, index) => value === second[index]);
}

function bytesToBase64(bytes) {
  let binary = '';
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return window.btoa(binary);
}

function resetDemo() {
  stepCards.forEach((card) => card.classList.remove('active', 'complete', 'failed'));
  keyStatus.textContent = 'Waiting to generate a post-quantum key pair.';
  kemStatus.textContent = 'Waiting for encapsulation.';
  secretStatus.textContent = 'Waiting for Alice to verify the secret.';
  cipherStatus.textContent = 'Waiting for encryption.';
  cipherPanel.hidden = true;
  decryptedOutput.textContent = '';
  decryptButton.disabled = true;
}

async function encryptWithPostQuantumKey() {
  const message = messageInput.value.trim();
  if (!message) {
    messageInput.focus();
    messageInput.placeholder = 'Enter a message first';
    return;
  }
  if (!ml_kem768) {
    cipherStatus.textContent = 'The ML-KEM library did not load. Refresh this page, then try again.';
    stepCards[0].classList.add('failed');
    return;
  }
  if (!window.crypto?.subtle) {
    cipherStatus.textContent = 'A secure browser context is required. Open the deployed HTTPS website and try again.';
    stepCards[3].classList.add('failed');
    return;
  }

  encryptButton.disabled = true;
  resetDemo();

  try {
    stepCards[0].classList.add('active');
    keyStatus.textContent = 'Generating Alice’s ML-KEM-768 public and secret key pair…';
    const aliceKeys = ml_kem768.keygen();
    await wait(260);
    keyStatus.textContent = `Complete. Public key: ${aliceKeys.publicKey.length.toLocaleString()} bytes; secret key: ${aliceKeys.secretKey.length.toLocaleString()} bytes.`;
    stepCards[0].classList.replace('active', 'complete');

    stepCards[1].classList.add('active');
    kemStatus.textContent = 'Bob encapsulates a shared secret to Alice’s public key…';
    const bobResult = ml_kem768.encapsulate(aliceKeys.publicKey);
    await wait(260);
    kemStatus.textContent = `Complete. ML-KEM ciphertext: ${bobResult.cipherText.length.toLocaleString()} bytes; Bob keeps the 32-byte secret.`;
    stepCards[1].classList.replace('active', 'complete');

    stepCards[2].classList.add('active');
    secretStatus.textContent = 'Alice decapsulates Bob’s ciphertext using her secret key…';
    const aliceSharedSecret = ml_kem768.decapsulate(bobResult.cipherText, aliceKeys.secretKey);
    if (!sameBytes(aliceSharedSecret, bobResult.sharedSecret)) throw new Error('Shared secrets do not match.');
    sessionKey = await window.crypto.subtle.importKey(
      'raw',
      aliceSharedSecret,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt'],
    );
    await wait(260);
    secretStatus.textContent = 'Verified: Alice and Bob share the same secret. It is imported as a 256-bit AES-GCM key.';
    stepCards[2].classList.replace('active', 'complete');

    stepCards[3].classList.add('active');
    cipherStatus.textContent = 'Encrypting the message with AES-256-GCM…';
    initializationVector = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: initializationVector },
      sessionKey,
      new TextEncoder().encode(message),
    );
    encryptedPacket = new Uint8Array(encryptedBuffer);
    await wait(260);
    cipherStatus.textContent = `Complete. The encrypted data includes AES-GCM authentication protection.`;
    stepCards[3].classList.replace('active', 'complete');

    ciphertextOutput.textContent = bytesToBase64(encryptedPacket);
    cipherPanel.hidden = false;
    decryptButton.disabled = false;
  } catch (error) {
    stepCards.find((card) => card.classList.contains('active'))?.classList.replace('active', 'failed');
    cipherStatus.textContent = `Demo could not complete: ${error.message}`;
  } finally {
    encryptButton.disabled = false;
  }
}

async function decryptAsAlice() {
  if (!sessionKey || !encryptedPacket) return;
  decryptButton.disabled = true;
  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: initializationVector },
    sessionKey,
    encryptedPacket,
  );
  decryptedOutput.textContent = `Alice successfully restored: “${new TextDecoder().decode(decryptedBuffer)}”`;
}

encryptButton.addEventListener('click', encryptWithPostQuantumKey);
decryptButton.addEventListener('click', decryptAsAlice);
messageInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') encryptWithPostQuantumKey();
});
