const mlKem = globalThis.QuantumShieldMLKEM?.ml_kem768;
const createBobKeysButton = document.querySelector('#createBobKeys');
const sendMessageButton = document.querySelector('#sendSecureMessage');
const decryptMessageButton = document.querySelector('#decryptSecureMessage');
const messageInput = document.querySelector('#channelMessage');
const channelSession = document.querySelector('#channelSession');
const aliceStatus = document.querySelector('#aliceStatus');
const bobStatus = document.querySelector('#bobStatus');
const packetSummary = document.querySelector('#packetSummary');
const packetInspection = document.querySelector('#packetInspection');
const packetJson = document.querySelector('#packetJson');
const inboxItem = document.querySelector('#inboxItem');
const receivedMessage = document.querySelector('#receivedMessage');
const receivedText = document.querySelector('#receivedText');
const channelResult = document.querySelector('#channelResult');
const channelResultText = document.querySelector('#channelResultText');
const alicePanel = document.querySelector('#alicePanel');
const bobPanel = document.querySelector('#bobPanel');
const transitPanel = document.querySelector('#transitPanel');

let bobKeys;
let encryptedPacket;

const wait = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

function bytesToBase64(bytes) {
  let binary = '';
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return window.btoa(binary);
}

function abbreviated(value, start = 20, end = 12) {
  return `${value.slice(0, start)}…${value.slice(-end)}`;
}

function resetMessageState() {
  encryptedPacket = undefined;
  sendMessageButton.disabled = !bobKeys;
  decryptMessageButton.disabled = true;
  packetSummary.textContent = 'No packet transmitted yet.';
  packetInspection.hidden = true;
  inboxItem.innerHTML = '<span>◌</span><p>No encrypted message received.</p>';
  receivedMessage.hidden = true;
  channelResult.hidden = true;
  aliceStatus.textContent = bobKeys ? 'Bob’s public key is ready. Encrypt a message whenever you are ready.' : 'Waiting for Bob’s public key.';
  bobStatus.textContent = bobKeys ? 'Bob’s private key is ready and remains only in this browser session.' : 'Bob’s private key stays local.';
}

async function createBobKeys() {
  if (!mlKem || !window.crypto?.subtle) {
    channelSession.textContent = 'Cryptographic support did not load. Refresh the page and try again.';
    return;
  }
  createBobKeysButton.disabled = true;
  channelSession.textContent = 'Generating a fresh ML-KEM-768 key pair for Bob…';
  await wait(220);
  bobKeys = mlKem.keygen();
  const publicKeyFingerprint = new Uint8Array(await window.crypto.subtle.digest('SHA-256', bobKeys.publicKey));
  const fingerprint = Array.from(publicKeyFingerprint, (byte) => byte.toString(16).padStart(2, '0')).join('');
  channelSession.innerHTML = `<span class="status-good">Session ready ✓</span> Bob’s public key: ${bobKeys.publicKey.length.toLocaleString()} bytes · SHA-256 ${abbreviated(fingerprint)}. His ${bobKeys.secretKey.length.toLocaleString()}-byte private key remains local.`;
  createBobKeysButton.textContent = 'Create a fresh Bob session ↻';
  createBobKeysButton.disabled = false;
  resetMessageState();
}

async function sendEncryptedMessage() {
  const message = messageInput.value.trim();
  if (!bobKeys) return;
  if (!message) {
    messageInput.focus();
    messageInput.placeholder = 'Write a message for Bob first';
    return;
  }
  sendMessageButton.disabled = true;
  decryptMessageButton.disabled = true;
  receivedMessage.hidden = true;
  channelResult.hidden = true;
  alicePanel.classList.add('channel-active');
  aliceStatus.textContent = 'Alice is using Bob’s public key to establish a new post-quantum session secret…';

  try {
    const aliceResult = mlKem.encapsulate(bobKeys.publicKey);
    const aliceAesKey = await window.crypto.subtle.importKey('raw', aliceResult.sharedSecret, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aliceAesKey,
      new TextEncoder().encode(message),
    );
    encryptedPacket = {
      version: 'QuantumShield-PQC-1',
      kem: 'ML-KEM-768',
      cipher: 'AES-256-GCM',
      kemCiphertext: aliceResult.cipherText,
      iv,
      ciphertext: new Uint8Array(encryptedBuffer),
    };
    await wait(280);
    const transportPacket = {
      version: encryptedPacket.version,
      kem: encryptedPacket.kem,
      cipher: encryptedPacket.cipher,
      kemCiphertextBase64: bytesToBase64(encryptedPacket.kemCiphertext),
      ivBase64: bytesToBase64(encryptedPacket.iv),
      ciphertextBase64: bytesToBase64(encryptedPacket.ciphertext),
    };
    packetSummary.innerHTML = `<span class="status-good">Encrypted packet transmitted ✓</span><br />ML-KEM ciphertext: ${encryptedPacket.kemCiphertext.length.toLocaleString()} B · AES payload: ${encryptedPacket.ciphertext.length} B`;
    packetJson.textContent = JSON.stringify({
      ...transportPacket,
      kemCiphertextBase64: abbreviated(transportPacket.kemCiphertextBase64),
      ciphertextBase64: abbreviated(transportPacket.ciphertextBase64),
    }, null, 2);
    packetInspection.hidden = false;
    inboxItem.innerHTML = `<span class="inbox-dot">●</span><p><strong>1 encrypted message received</strong><br />ML-KEM ciphertext + AES-GCM payload</p>`;
    aliceStatus.textContent = 'Sent. Alice transmitted encrypted packet data; no plaintext or Bob private key crossed the channel.';
    bobStatus.textContent = 'Encrypted packet received. Bob can now decapsulate and decrypt it locally.';
    alicePanel.classList.replace('channel-active', 'channel-complete');
    transitPanel.classList.add('channel-complete');
    decryptMessageButton.disabled = false;
  } catch (error) {
    alicePanel.classList.replace('channel-active', 'channel-failed');
    aliceStatus.textContent = `Encryption failed: ${error.message}`;
  } finally {
    sendMessageButton.disabled = false;
  }
}

async function decryptMessageAsBob() {
  if (!encryptedPacket || !bobKeys) return;
  decryptMessageButton.disabled = true;
  bobPanel.classList.add('channel-active');
  bobStatus.textContent = 'Bob is decapsulating the ML-KEM ciphertext with his locally held private key…';

  try {
    const bobSharedSecret = mlKem.decapsulate(encryptedPacket.kemCiphertext, bobKeys.secretKey);
    const bobAesKey = await window.crypto.subtle.importKey('raw', bobSharedSecret, { name: 'AES-GCM' }, false, ['decrypt']);
    const plaintextBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: encryptedPacket.iv },
      bobAesKey,
      encryptedPacket.ciphertext,
    );
    const plaintext = new TextDecoder().decode(plaintextBuffer);
    await wait(260);
    receivedText.textContent = plaintext;
    receivedMessage.hidden = false;
    bobStatus.textContent = 'Success. Bob derived the session key locally and restored the authenticated message.';
    bobPanel.classList.replace('channel-active', 'channel-complete');
    channelResultText.textContent = 'Alice encrypted with ML-KEM-768-established AES key. Bob decrypted with his local ML-KEM private key. The public channel carried ciphertext only.';
    channelResult.hidden = false;
  } catch (error) {
    bobPanel.classList.replace('channel-active', 'channel-failed');
    bobStatus.textContent = `Decryption failed: ${error.message}`;
  }
}

createBobKeysButton.addEventListener('click', createBobKeys);
sendMessageButton.addEventListener('click', sendEncryptedMessage);
decryptMessageButton.addEventListener('click', decryptMessageAsBob);
