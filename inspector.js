const mlKem = globalThis.QuantumShieldMLKEM?.ml_kem768;
const runButton = document.querySelector('#runInspectorButton');
const messageInput = document.querySelector('#inspectorMessage');
const inspectorError = document.querySelector('#inspectorError');
const traceResult = document.querySelector('#traceResult');
const traceResultText = document.querySelector('#traceResultText');

const values = {
  alicePublicKey: document.querySelector('#alicePublicKey'),
  aliceSecretFingerprint: document.querySelector('#aliceSecretFingerprint'),
  bobSecretFingerprint: document.querySelector('#bobSecretFingerprint'),
  secretMatch: document.querySelector('#secretMatch'),
  payloadMatch: document.querySelector('#payloadMatch'),
  publicKeyPacket: document.querySelector('#publicKeyPacketValue'),
  kemPacket: document.querySelector('#kemPacketValue'),
  dataPacket: document.querySelector('#dataPacketValue'),
  traceOne: document.querySelector('#traceOneText'),
  traceTwo: document.querySelector('#traceTwoText'),
  traceThree: document.querySelector('#traceThreeText'),
  traceFour: document.querySelector('#traceFourText'),
};

const traceCards = [
  document.querySelector('#traceOne'),
  document.querySelector('#traceTwo'),
  document.querySelector('#traceThree'),
  document.querySelector('#traceFour'),
];
const partyCards = [document.querySelector('#aliceCard'), document.querySelector('#channelCard'), document.querySelector('#bobCard')];
const wait = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

function bytesMatch(first, second) {
  return first.length === second.length && first.every((value, index) => value === second[index]);
}

function bytesToBase64(bytes) {
  let binary = '';
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return window.btoa(binary);
}

function shortFingerprint(fingerprint) {
  return `${fingerprint.slice(0, 16)}…${fingerprint.slice(-8)}`;
}

async function fingerprint(bytes) {
  const digest = new Uint8Array(await window.crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function setTraceState(index, state) {
  traceCards[index].classList.remove('active', 'complete', 'failed');
  traceCards[index].classList.add(state);
}

function resetTrace() {
  inspectorError.textContent = '';
  traceResult.hidden = true;
  traceCards.forEach((card) => card.classList.remove('active', 'complete', 'failed'));
  partyCards.forEach((card) => card.classList.remove('protocol-active', 'protocol-complete'));
  values.alicePublicKey.textContent = 'Waiting';
  values.aliceSecretFingerprint.textContent = 'Waiting';
  values.bobSecretFingerprint.textContent = 'Waiting';
  values.secretMatch.textContent = 'Waiting';
  values.payloadMatch.textContent = 'Waiting';
  values.publicKeyPacket.textContent = 'Waiting';
  values.kemPacket.textContent = 'Waiting';
  values.dataPacket.textContent = 'Waiting';
  values.traceOne.textContent = 'Alice has not generated a key pair yet.';
  values.traceTwo.textContent = 'Bob has not established a secret yet.';
  values.traceThree.textContent = 'Alice has not recovered Bob’s secret yet.';
  values.traceFour.textContent = 'The payload is waiting for a verified shared secret.';
}

async function runProtocolTrace() {
  const message = messageInput.value.trim();
  if (!message) {
    messageInput.focus();
    messageInput.placeholder = 'Enter data for Alice to protect';
    return;
  }
  if (!mlKem) {
    inspectorError.textContent = 'The ML-KEM library did not load. Refresh this page and try again.';
    return;
  }
  if (!window.crypto?.subtle) {
    inspectorError.textContent = 'This browser needs a secure context for Web Crypto. Use the deployed HTTPS website or refresh the local page.';
    return;
  }

  runButton.disabled = true;
  resetTrace();

  try {
    partyCards[0].classList.add('protocol-active');
    setTraceState(0, 'active');
    values.traceOne.textContent = 'Generating a fresh ML-KEM-768 key pair inside Alice’s browser session…';
    const alice = mlKem.keygen();
    const publicKeyFingerprint = await fingerprint(alice.publicKey);
    const secretKeyFingerprint = await fingerprint(alice.secretKey);
    values.alicePublicKey.textContent = `${alice.publicKey.length.toLocaleString()} bytes · SHA-256 ${shortFingerprint(publicKeyFingerprint)}`;
    values.aliceSecretFingerprint.textContent = `Private fingerprint ${shortFingerprint(secretKeyFingerprint)}`;
    values.publicKeyPacket.textContent = `${alice.publicKey.length.toLocaleString()} B · SHA-256 ${shortFingerprint(publicKeyFingerprint)}`;
    values.traceOne.textContent = `Complete: public key = ${alice.publicKey.length.toLocaleString()} bytes; private key remains on Alice’s device.`;
    partyCards[0].classList.replace('protocol-active', 'protocol-complete');
    setTraceState(0, 'complete');
    await wait(260);

    partyCards[1].classList.add('protocol-active');
    setTraceState(1, 'active');
    values.traceTwo.textContent = 'Bob encapsulates a new shared secret to Alice’s public key…';
    const bob = mlKem.encapsulate(alice.publicKey);
    const bobFingerprint = await fingerprint(bob.sharedSecret);
    const kemCipherFingerprint = await fingerprint(bob.cipherText);
    values.bobSecretFingerprint.textContent = `SHA-256 ${shortFingerprint(bobFingerprint)}`;
    values.kemPacket.textContent = `${bob.cipherText.length.toLocaleString()} B · SHA-256 ${shortFingerprint(kemCipherFingerprint)}`;
    values.traceTwo.textContent = `Complete: Bob keeps a 32-byte shared secret and sends only the ${bob.cipherText.length.toLocaleString()}-byte ML-KEM ciphertext.`;
    setTraceState(1, 'complete');
    await wait(260);

    partyCards[0].classList.add('protocol-active');
    partyCards[2].classList.add('protocol-active');
    setTraceState(2, 'active');
    values.traceThree.textContent = 'Alice decapsulates the ML-KEM ciphertext with her private key…';
    const aliceSecret = mlKem.decapsulate(bob.cipherText, alice.secretKey);
    const aliceFingerprint = await fingerprint(aliceSecret);
    const matched = bytesMatch(aliceSecret, bob.sharedSecret);
    if (!matched) throw new Error('Alice and Bob did not derive the same shared secret.');
    values.aliceSecretFingerprint.textContent = `Shared-secret SHA-256 ${shortFingerprint(aliceFingerprint)}`;
    values.secretMatch.innerHTML = '<span class="status-good">Match ✓</span>';
    values.traceThree.textContent = 'Verified: Alice and Bob derived the same 32-byte secret without transmitting it in plaintext.';
    partyCards[0].classList.replace('protocol-active', 'protocol-complete');
    partyCards[1].classList.replace('protocol-active', 'protocol-complete');
    partyCards[2].classList.replace('protocol-active', 'protocol-complete');
    setTraceState(2, 'complete');
    await wait(260);

    setTraceState(3, 'active');
    values.traceFour.textContent = 'Importing the shared secret as AES-256-GCM key material and encrypting Alice’s payload…';
    const aliceAesKey = await window.crypto.subtle.importKey('raw', aliceSecret, { name: 'AES-GCM' }, false, ['encrypt']);
    const bobAesKey = await window.crypto.subtle.importKey('raw', bob.sharedSecret, { name: 'AES-GCM' }, false, ['decrypt']);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedBuffer = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aliceAesKey, new TextEncoder().encode(message));
    const ciphertext = new Uint8Array(encryptedBuffer);
    const restoredBuffer = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, bobAesKey, ciphertext);
    const restoredMessage = new TextDecoder().decode(restoredBuffer);
    if (restoredMessage !== message) throw new Error('Bob could not restore the original payload.');
    const payloadFingerprint = await fingerprint(ciphertext);
    values.dataPacket.textContent = `IV 12 B + payload ${ciphertext.length} B · SHA-256 ${shortFingerprint(payloadFingerprint)}`;
    values.payloadMatch.innerHTML = '<span class="status-good">Restored ✓</span>';
    values.traceFour.textContent = `Complete: AES-GCM encrypted ${message.length} characters; Bob decrypted and authenticated the payload successfully.`;
    setTraceState(3, 'complete');

    traceResultText.textContent = `Shared-secret fingerprints match, and Bob restored “${restoredMessage}”. The public channel carried only public key material, ML-KEM ciphertext, IV, and AES ciphertext.`;
    traceResult.hidden = false;
  } catch (error) {
    const activeCard = traceCards.find((card) => card.classList.contains('active'));
    activeCard?.classList.replace('active', 'failed');
    inspectorError.textContent = `Trace stopped: ${error.message}`;
  } finally {
    runButton.disabled = false;
  }
}

runButton.addEventListener('click', runProtocolTrace);
messageInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') runProtocolTrace();
});
