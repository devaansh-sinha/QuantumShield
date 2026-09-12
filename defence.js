(() => {
  const mlKem = globalThis.QuantumShieldMLKEM?.ml_kem768;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const $ = (selector) => document.querySelector(selector);

  const createKeysButton = $('#defCreateKeysButton');
  const sealButton = $('#defSealButton');
  const openUploadButton = $('#defOpenUploadButton');
  const openLatestButton = $('#defOpenLatestButton');
  const interceptButton = $('#defInterceptButton');
  const tamperButton = $('#defTamperButton');
  const replayButton = $('#defReplayButton');
  const impersonationButton = $('#defImpersonationButton');

  const recipientNameInput = $('#defRecipientName');
  const recipientPublicKeyInput = $('#defRecipientPublicKeyInput');
  const messageInput = $('#defMessage');
  const attachmentInput = $('#defAttachment');
  const packetInput = $('#defPacketInput');
  const recoveryKeyInput = $('#defRecoveryKeyInput');
  const trustKeyInput = $('#defTrustKeyInput');

  const keyStatus = $('#defKeyStatus');
  const publicKeyStatus = $('#defPublicKeyStatus');
  const attachmentStatus = $('#defAttachmentStatus');
  const receiverStatus = $('#defReceiverStatus');
  const consoleOutput = $('#defConsole');
  const attackOutput = $('#defAttackOutput');
  const keyDownloads = $('#defKeyDownloads');
  const packagePanel = $('#defPackagePanel');
  const transitPanel = $('#defTransitPanel');
  const resultPanel = $('#defResultPanel');
  const attackLab = $('#defAttackLab');
  const recoveredAttachment = $('#defRecoveredAttachment');
  const resultHeading = $('#defResultHeading');
  const resultText = $('#defResultText');
  const recoveredFileName = $('#defRecoveredFileName');
  const transportPreview = $('#defTransportPreview');

  const keyCard = $('#defKeyCard');
  const sealCard = $('#defSealCard');
  const transitCard = $('#defTransitCard');
  const openCard = $('#defOpenCard');
  const traceKey = $('#defTraceKey');
  const traceKem = $('#defTraceKem');
  const traceAes = $('#defTraceAes');
  const traceOrigin = $('#defTraceOrigin');
  const traceDefence = $('#defTraceDefence');

  const MAX_FILE_BYTES = 10 * 1024 * 1024;
  const MAX_KEY_BYTES = 150 * 1024;
  const PACKET_FORMAT = 'DefenceGuard-Packet-1';
  const PUBLIC_KEY_FORMAT = 'DefenceGuard-Field-Public-1';
  const PRIVATE_KEY_FORMAT = 'DefenceGuard-Field-Private-1';
  const TRUST_KEY_FORMAT = 'DefenceGuard-Command-Trust-1';
  const replayRegistry = new Set();

  let localRecipient;
  let recipientPublicBundle;
  let commandSigning;
  let commandTrustBundle;
  let latestPacket;
  let latestPayload;
  let recoveredFile;

  function setState(element, state) {
    element.classList.remove('active', 'complete', 'failed', 'blocked');
    if (state) element.classList.add(state);
  }

  function setTrace(element, state, message) {
    setState(element, state);
    element.querySelector('code').textContent = message;
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} bytes`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  function bytesToBase64(bytes) {
    const chunkSize = 0x8000;
    let result = '';
    for (let offset = 0; offset < bytes.length; offset += chunkSize) result += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
    return window.btoa(result);
  }

  function base64ToBytes(value) {
    if (typeof value !== 'string') throw new Error('Expected base64-encoded data.');
    const binary = window.atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    return bytes;
  }

  function safeName(value, fallback) {
    const cleaned = String(value || fallback).replace(/[\\/:*?"<>|]/g, '_').replace(/\s+/g, ' ').trim();
    return cleaned || fallback;
  }

  function keyStem(value) {
    return safeName(value, 'field-unit').toLowerCase().replace(/\s+/g, '-');
  }

  function randomId() {
    if (window.crypto.randomUUID) return window.crypto.randomUUID();
    const values = window.crypto.getRandomValues(new Uint32Array(4));
    return Array.from(values, (value) => value.toString(16).padStart(8, '0')).join('-');
  }

  function short(value, start = 12, end = 8) {
    return value.length > start + end ? `${value.slice(0, start)}…${value.slice(-end)}` : value;
  }

  async function sha256(value) {
    const bytes = typeof value === 'string' ? encoder.encode(value) : value;
    const digest = await window.crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  function download(data, name, type) {
    const blob = data instanceof Blob ? data : new Blob([data], { type });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = name;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1200);
  }

  function ensureSupport() {
    if (!mlKem) throw new Error('ML-KEM did not load. Refresh and try again.');
    if (!window.crypto?.subtle) throw new Error('Web Crypto is unavailable. Use a current browser on the deployed HTTPS site.');
  }

  function signatureRecord(packet) {
    return JSON.stringify({
      format: packet.format,
      version: packet.version,
      kem: packet.kem,
      cipher: packet.cipher,
      sender: packet.sender,
      senderKeyId: packet.senderKeyId,
      recipient: packet.recipient,
      recipientKeyId: packet.recipientKeyId,
      packetId: packet.packetId,
      sequence: packet.sequence,
      issuedAt: packet.issuedAt,
      expiresAt: packet.expiresAt,
      kemCiphertextBase64: packet.kemCiphertextBase64,
      ivBase64: packet.ivBase64,
      ciphertextBase64: packet.ciphertextBase64,
    });
  }

  function validatePublicBundle(bundle) {
    if (!bundle || bundle.format !== PUBLIC_KEY_FORMAT || bundle.kem !== 'ML-KEM-768' || typeof bundle.publicKeyBase64 !== 'string' || typeof bundle.keyId !== 'string') {
      throw new Error('This is not a valid DefenceGuard field-unit public key (.dpk).');
    }
  }

  function validatePrivateBundle(bundle) {
    if (!bundle || bundle.format !== PRIVATE_KEY_FORMAT || bundle.kem !== 'ML-KEM-768' || typeof bundle.secretKeyBase64 !== 'string' || typeof bundle.keyId !== 'string') {
      throw new Error('This is not a valid DefenceGuard field-unit private key (.dsk).');
    }
  }

  function validateTrustBundle(bundle) {
    if (!bundle || bundle.format !== TRUST_KEY_FORMAT || bundle.signature !== 'ECDSA-P-256 (learning prototype)' || !bundle.publicJwk || typeof bundle.senderKeyId !== 'string') {
      throw new Error('This is not a valid trusted command key (.dtrust).');
    }
  }

  function validatePacket(packet) {
    if (!packet || packet.format !== PACKET_FORMAT || packet.kem !== 'ML-KEM-768' || packet.cipher !== 'AES-256-GCM') {
      throw new Error('This is not a valid DefenceGuard protected packet (.dguard).');
    }
    const required = ['recipientKeyId', 'senderKeyId', 'packetId', 'issuedAt', 'expiresAt', 'kemCiphertextBase64', 'ivBase64', 'ciphertextBase64', 'signatureBase64'];
    if (required.some((field) => typeof packet[field] !== 'string')) throw new Error('The protected packet is missing security fields.');
  }

  function updateSealState() {
    sealButton.disabled = !recipientPublicBundle;
  }

  function updateUploadState() {
    openUploadButton.disabled = !(packetInput.files?.[0] && recoveryKeyInput.files?.[0] && trustKeyInput.files?.[0]);
  }

  function showResult(title, message, file) {
    resultPanel.hidden = false;
    resultHeading.textContent = title;
    resultText.textContent = message;
    recoveredAttachment.hidden = !file;
    if (file) {
      recoveredFile = file;
      recoveredFileName.textContent = `${file.name} · ${formatBytes(file.bytes.length)}`;
    }
  }

  function renderTransport(packet) {
    const preview = {
      format: packet.format,
      recipient: packet.recipient,
      packetId: short(packet.packetId),
      issuedAt: packet.issuedAt,
      expiresAt: packet.expiresAt,
      kem: packet.kem,
      cipher: packet.cipher,
      senderSignature: 'present',
      kemCiphertextBase64: short(packet.kemCiphertextBase64, 18, 10),
      ciphertextBase64: short(packet.ciphertextBase64, 18, 10),
      privateRecoveryKey: 'never included',
      plaintextMessage: 'never included',
      plaintextAttachment: 'never included',
    };
    transportPreview.textContent = JSON.stringify(preview, null, 2);
  }

  async function createFieldUnitKeys() {
    try {
      ensureSupport();
      createKeysButton.disabled = true;
      setState(keyCard, 'active');
      setTrace(traceKey, 'active', 'Generating ML-KEM-768 public/private key pair locally…');
      keyStatus.textContent = 'Generating a fresh ML-KEM-768 key pair locally…';
      consoleOutput.textContent = 'FIELD UNIT: creating post-quantum key material. The private recovery key will remain on this device unless the user explicitly downloads it.';

      const keyPair = mlKem.keygen();
      const label = (recipientNameInput.value || 'Field Unit').trim().slice(0, 48) || 'Field Unit';
      const keyId = randomId();
      const createdAt = new Date().toISOString();
      const publicFingerprint = await sha256(keyPair.publicKey);
      const publicBundle = { format: PUBLIC_KEY_FORMAT, version: 1, kem: 'ML-KEM-768', recipient: label, keyId, createdAt, publicFingerprint, publicKeyBase64: bytesToBase64(keyPair.publicKey) };
      const privateBundle = { format: PRIVATE_KEY_FORMAT, version: 1, kem: 'ML-KEM-768', recipient: label, keyId, createdAt, secretKeyBase64: bytesToBase64(keyPair.secretKey) };
      keyPair.publicKey.fill(0);
      localRecipient = { publicBundle, privateBundle, secretKey: keyPair.secretKey };
      recipientPublicBundle = publicBundle;
      keyStatus.textContent = `Key set ready for ${label}. Public fingerprint: ${short(publicFingerprint, 16, 8)}`;
      publicKeyStatus.textContent = `Using the locally created public key for ${label}. A command centre could instead upload the downloaded .dpk file.`;
      keyDownloads.hidden = false;
      setState(keyCard, 'complete');
      setState(sealCard, 'active');
      setTrace(traceKey, 'complete', `Public fingerprint: ${short(publicFingerprint, 16, 8)} · private key stays local`);
      consoleOutput.textContent = `FIELD UNIT KEY SET READY ✓\nPublic key fingerprint: ${short(publicFingerprint, 16, 8)}\n\nShare only the .dpk public key with the command centre. Keep the matching .dsk recovery key private.`;
      updateSealState();
    } catch (error) {
      setState(keyCard, 'failed');
      setTrace(traceKey, 'failed', `Key setup failed: ${error.message}`);
      keyStatus.textContent = `Key setup failed: ${error.message}`;
      consoleOutput.textContent = `FIELD UNIT KEY SETUP FAILED: ${error.message}`;
    } finally {
      createKeysButton.disabled = false;
    }
  }

  async function loadPublicBundle() {
    const file = recipientPublicKeyInput.files?.[0];
    if (!file) {
      recipientPublicBundle = localRecipient?.publicBundle;
      publicKeyStatus.textContent = localRecipient ? `Using locally created public key for ${localRecipient.publicBundle.recipient}.` : 'Create local keys above or upload a field unit’s public key.';
      updateSealState();
      return;
    }
    try {
      if (file.size > MAX_KEY_BYTES) throw new Error('The uploaded public key file is unexpectedly large.');
      const bundle = JSON.parse(await file.text());
      validatePublicBundle(bundle);
      const material = base64ToBytes(bundle.publicKeyBase64);
      if (!material.length) throw new Error('The public key contains no key material.');
      material.fill(0);
      recipientPublicBundle = bundle;
      publicKeyStatus.textContent = `Loaded public key for ${bundle.recipient}. It can seal a package but cannot open one.`;
      updateSealState();
    } catch (error) {
      recipientPublicBundle = localRecipient?.publicBundle;
      publicKeyStatus.textContent = `Could not use uploaded public key: ${error.message}`;
      updateSealState();
    }
  }

  async function ensureCommandTrust() {
    if (commandSigning && commandTrustBundle) return;
    commandSigning = await window.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const publicJwk = await window.crypto.subtle.exportKey('jwk', commandSigning.publicKey);
    const fingerprint = await sha256(JSON.stringify(publicJwk));
    commandTrustBundle = {
      format: TRUST_KEY_FORMAT,
      version: 1,
      signature: 'ECDSA-P-256 (learning prototype)',
      sender: 'Fictional Defence Command Centre',
      senderKeyId: randomId(),
      publicFingerprint: fingerprint,
      publicJwk,
      note: 'This is a demo trust key. Production systems need post-quantum ML-DSA signatures and authenticated provisioning.',
    };
  }

  async function buildPayload() {
    const message = messageInput.value.trim();
    const attachment = attachmentInput.files?.[0];
    if (!message && !attachment) throw new Error('Write a message, choose an attachment, or provide both.');
    if (attachment && attachment.size > MAX_FILE_BYTES) throw new Error('This local prototype accepts attachments up to 10 MB.');
    let attachmentRecord;
    if (attachment) {
      const bytes = new Uint8Array(await attachment.arrayBuffer());
      attachmentRecord = { name: safeName(attachment.name, 'attachment.bin'), type: attachment.type || 'application/octet-stream', base64: bytesToBase64(bytes) };
      bytes.fill(0);
    }
    return { version: 1, message, attachment: attachmentRecord || null };
  }

  async function sealPacket() {
    let publicKey;
    let sharedSecret;
    let kemCiphertext;
    try {
      ensureSupport();
      validatePublicBundle(recipientPublicBundle);
      sealButton.disabled = true;
      setState(sealCard, 'active');
      setTrace(traceKem, 'active', 'Encapsulating a fresh ML-KEM-768 secret to the field-unit public key…');
      setTrace(traceAes, 'active', 'Preparing encrypted message and optional attachment…');
      setTrace(traceOrigin, 'active', 'Creating command-centre signing identity for this demo session…');
      consoleOutput.textContent = 'COMMAND CENTRE: preparing a unique protected packet. The message and optional attachment will be encrypted locally before anything is downloaded.';

      latestPayload = await buildPayload();
      publicKey = base64ToBytes(recipientPublicBundle.publicKeyBase64);
      const kemResult = mlKem.encapsulate(publicKey);
      sharedSecret = kemResult.sharedSecret;
      kemCiphertext = kemResult.cipherText;
      const aesKey = await window.crypto.subtle.importKey('raw', sharedSecret, { name: 'AES-GCM' }, false, ['encrypt']);
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encryptedBuffer = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encoder.encode(JSON.stringify(latestPayload)));

      await ensureCommandTrust();
      const now = new Date();
      const expires = new Date(now.getTime() + (30 * 60 * 1000));
      const draft = {
        format: PACKET_FORMAT,
        version: 1,
        kem: 'ML-KEM-768',
        cipher: 'AES-256-GCM',
        sender: 'Fictional Defence Command Centre',
        senderKeyId: commandTrustBundle.senderKeyId,
        recipient: recipientPublicBundle.recipient,
        recipientKeyId: recipientPublicBundle.keyId,
        packetId: randomId(),
        sequence: `EX-${now.getUTCFullYear()}-${String(now.getTime()).slice(-6)}`,
        issuedAt: now.toISOString(),
        expiresAt: expires.toISOString(),
        kemCiphertextBase64: bytesToBase64(kemCiphertext),
        ivBase64: bytesToBase64(iv),
        ciphertextBase64: bytesToBase64(new Uint8Array(encryptedBuffer)),
      };
      const signature = new Uint8Array(await window.crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, commandSigning.privateKey, encoder.encode(signatureRecord(draft))));
      latestPacket = { ...draft, signatureBase64: bytesToBase64(signature) };

      $('#defPacketId').textContent = short(latestPacket.packetId, 16, 8);
      $('#defKemSize').textContent = formatBytes(kemCiphertext.length);
      $('#defCipherSize').textContent = formatBytes(base64ToBytes(latestPacket.ciphertextBase64).length);
      $('#defExpiry').textContent = '30 minutes + single-use packet ID';
      renderTransport(latestPacket);
      packagePanel.hidden = false;
      transitPanel.hidden = false;
      attackLab.hidden = false;
      openLatestButton.disabled = !(localRecipient && localRecipient.privateBundle.keyId === latestPacket.recipientKeyId);
      setState(sealCard, 'complete');
      setState(transitCard, 'complete');
      setState(openCard, 'active');
      setTrace(traceKem, 'complete', `ML-KEM ciphertext: ${formatBytes(kemCiphertext.length)} · fresh shared secret established`);
      setTrace(traceAes, 'complete', `AES-256-GCM authenticated ciphertext: ${formatBytes(base64ToBytes(latestPacket.ciphertextBase64).length)}`);
      setTrace(traceOrigin, 'complete', `Command signature present · trusted key ${short(commandTrustBundle.publicFingerprint, 16, 8)}`);
      consoleOutput.textContent = `PACKET SEALED ✓\nRecipient: ${latestPacket.recipient}\nPacket ID: ${latestPacket.packetId}\nExpiry: ${latestPacket.expiresAt}\n\nML-KEM established a one-time 256-bit secret. AES-256-GCM encrypted the message${latestPayload.attachment ? ' and attachment' : ''}. The downloadable package contains ciphertext only.`;
      attackOutput.textContent = 'Ready. Test what an interceptor, modifier, replay attacker, or unauthorised sender can do with this local demo packet.';
    } catch (error) {
      setState(sealCard, 'failed');
      setTrace(traceKem, 'failed', `Packet sealing failed: ${error.message}`);
      consoleOutput.textContent = `PACKET SEALING FAILED: ${error.message}`;
    } finally {
      publicKey?.fill(0);
      sharedSecret?.fill(0);
      kemCiphertext?.fill(0);
      updateSealState();
    }
  }

  async function decryptAndVerify(packet, privateBundle, trustBundle, seenPackets = replayRegistry) {
    let secretKey;
    let sharedSecret;
    let kemCiphertext;
    try {
      validatePacket(packet);
      validatePrivateBundle(privateBundle);
      validateTrustBundle(trustBundle);
      if (packet.recipientKeyId !== privateBundle.keyId) throw new Error('This private recovery key does not match the packet recipient.');
      if (packet.senderKeyId !== trustBundle.senderKeyId) throw new Error('Sender is not in this field unit’s trusted command registry.');
      if (Date.parse(packet.expiresAt) <= Date.now()) throw new Error('Packet rejected: its authorised validity window has expired.');
      if (seenPackets.has(packet.packetId)) throw new Error('Replay detected: this packet ID has already been accepted by the field unit.');

      const trustedPublicKey = await window.crypto.subtle.importKey('jwk', trustBundle.publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      const signatureOk = await window.crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, trustedPublicKey, base64ToBytes(packet.signatureBase64), encoder.encode(signatureRecord(packet)));
      if (!signatureOk) throw new Error('Packet rejected: the command-origin signature is invalid or package metadata was modified.');

      kemCiphertext = base64ToBytes(packet.kemCiphertextBase64);
      secretKey = base64ToBytes(privateBundle.secretKeyBase64);
      sharedSecret = mlKem.decapsulate(kemCiphertext, secretKey);
      const aesKey = await window.crypto.subtle.importKey('raw', sharedSecret, { name: 'AES-GCM' }, false, ['decrypt']);
      const iv = base64ToBytes(packet.ivBase64);
      if (iv.length !== 12) throw new Error('Packet rejected: invalid AES-GCM nonce.');
      const plaintext = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, base64ToBytes(packet.ciphertextBase64));
      const payload = JSON.parse(decoder.decode(plaintext));
      if (!payload || typeof payload.message !== 'string') throw new Error('Packet payload failed the expected structure check.');
      seenPackets.add(packet.packetId);
      return payload;
    } finally {
      secretKey?.fill(0);
      sharedSecret?.fill(0);
      kemCiphertext?.fill(0);
    }
  }

  function makeRecoveredFile(payload) {
    if (!payload.attachment) return undefined;
    const bytes = base64ToBytes(payload.attachment.base64);
    return { name: safeName(payload.attachment.name, 'recovered-file'), type: payload.attachment.type || 'application/octet-stream', bytes };
  }

  async function openPacket(packet, privateBundle, trustBundle, sourceLabel) {
    try {
      setState(openCard, 'active');
      setTrace(traceOrigin, 'active', 'Checking trusted command identity, packet signature, expiry, and replay status…');
      setTrace(traceDefence, 'active', 'Attempting to decapsulate and decrypt only after origin checks pass…');
      receiverStatus.textContent = `Verifying ${sourceLabel}…`;
      consoleOutput.textContent = `FIELD UNIT: checking sender trust, signature, packet expiry, and replay state before decrypting ${sourceLabel}.`;
      const payload = await decryptAndVerify(packet, privateBundle, trustBundle);
      const attachment = makeRecoveredFile(payload);
      setState(openCard, 'complete');
      setTrace(traceOrigin, 'complete', 'Trusted command key and packet signature verified ✓');
      setTrace(traceDefence, 'complete', 'Fresh packet accepted once; modified, replayed, and unknown-sender packets are rejected');
      receiverStatus.textContent = 'Packet accepted. Signature, expiry, replay status, and AES-GCM authentication all passed.';
      showResult('Field unit accepted the protected packet', payload.message || 'The packet carried an attachment without a message.', attachment);
      consoleOutput.textContent = `FIELD UNIT ACCEPTED PACKET ✓\nSender identity: verified\nPacket freshness: verified\nAES-GCM integrity: verified\n\nDecrypted message: ${payload.message || '(no message text)'}${attachment ? `\nRecovered attachment: ${attachment.name}` : ''}`;
    } catch (error) {
      setState(openCard, 'failed');
      setTrace(traceOrigin, 'failed', `Receiver rejected packet: ${error.message}`);
      setTrace(traceDefence, 'failed', 'No command data was trusted or displayed');
      receiverStatus.textContent = `Packet rejected: ${error.message}`;
      showResult('Field unit rejected the packet', error.message);
      consoleOutput.textContent = `FIELD UNIT REJECTED PACKET ✕\nReason: ${error.message}\n\nNo decrypted command or attachment is trusted.`;
    }
  }

  async function openLatestPacket() {
    if (!latestPacket || !localRecipient || !commandTrustBundle) return;
    await openPacket(latestPacket, localRecipient.privateBundle, commandTrustBundle, 'latest local demo packet');
  }

  async function openUploadedPacket() {
    try {
      const [packetFile, recoveryFile, trustFile] = [packetInput.files?.[0], recoveryKeyInput.files?.[0], trustKeyInput.files?.[0]];
      if (!packetFile || !recoveryFile || !trustFile) throw new Error('Upload the .dguard packet, matching .dsk key, and trusted .dtrust command key.');
      if (packetFile.size > MAX_FILE_BYTES * 2 || recoveryFile.size > MAX_KEY_BYTES || trustFile.size > MAX_KEY_BYTES) throw new Error('One uploaded file exceeds this local prototype’s size limit.');
      const packet = JSON.parse(await packetFile.text());
      const privateBundle = JSON.parse(await recoveryFile.text());
      const trustBundle = JSON.parse(await trustFile.text());
      await openPacket(packet, privateBundle, trustBundle, 'uploaded protected packet');
    } catch (error) {
      receiverStatus.textContent = `Could not open uploaded packet: ${error.message}`;
      showResult('Field unit rejected the upload', error.message);
    }
  }

  async function runInterceptTest() {
    if (!latestPacket) return;
    setState(transitCard, 'active');
    attackOutput.innerHTML = '<strong>INTERCEPTION RESULT ✓</strong><p>The attacker can view the packet ID, expiry, ML-KEM ciphertext, IV, and AES-GCM ciphertext. The message, attachment, AES key, and private recovery key are absent. Knowing the public key does not decrypt the package.</p>';
    setState(transitCard, 'complete');
    setTrace(traceDefence, 'complete', 'Intercepted transport packet exposes ciphertext metadata only');
    consoleOutput.textContent = 'INTERCEPTION TEST ✓\nThe public network copy contains public metadata and encrypted bytes. No plaintext command, attachment, AES key, or field-unit private key is present.';
  }

  async function runTamperTest() {
    if (!latestPacket || !localRecipient || !commandTrustBundle) return;
    try {
      setTrace(traceDefence, 'active', 'Attacker flips one byte in encrypted payload; receiver checks signature before decryption…');
      const alteredBytes = base64ToBytes(latestPacket.ciphertextBase64);
      alteredBytes[Math.floor(alteredBytes.length / 2)] ^= 1;
      const altered = { ...latestPacket, ciphertextBase64: bytesToBase64(alteredBytes) };
      alteredBytes.fill(0);
      const isolatedRegistry = new Set();
      try {
        await decryptAndVerify(altered, localRecipient.privateBundle, commandTrustBundle, isolatedRegistry);
        throw new Error('Unexpected acceptance. Refresh before using this result.');
      } catch (error) {
        if (error.message.startsWith('Unexpected')) throw error;
        attackOutput.innerHTML = `<strong>TAMPER REJECTED ✓</strong><p>${error.message} The receiver refuses it before displaying the altered command.</p>`;
        setTrace(traceDefence, 'complete', 'Modified ciphertext changed the signed packet; receiver rejected it before use');
        consoleOutput.textContent = `TAMPER TEST ✓\nOne ciphertext byte was modified locally. Result: ${error.message}\n\nThe field unit does not accept or display modified command data.`;
      }
    } catch (error) {
      attackOutput.textContent = `Tamper test could not run: ${error.message}`;
    }
  }

  async function runReplayTest() {
    if (!latestPacket || !localRecipient || !commandTrustBundle) return;
    try {
      const testRegistry = new Set();
      await decryptAndVerify(latestPacket, localRecipient.privateBundle, commandTrustBundle, testRegistry);
      try {
        await decryptAndVerify(latestPacket, localRecipient.privateBundle, commandTrustBundle, testRegistry);
        throw new Error('Unexpected acceptance. Refresh before using this result.');
      } catch (error) {
        if (error.message.startsWith('Unexpected')) throw error;
        attackOutput.innerHTML = `<strong>REPLAY REJECTED ✓</strong><p>First delivery is accepted in the isolated test. A second copy with the same packet ID is rejected: ${error.message}</p>`;
        setTrace(traceDefence, 'complete', 'Receiver replay registry blocks a reused packet ID');
        consoleOutput.textContent = `REPLAY TEST ✓\nFirst valid packet delivery: accepted.\nSecond copy with identical packet ID: rejected.\n\nResult: ${error.message}`;
      }
    } catch (error) {
      attackOutput.textContent = `Replay test could not run: ${error.message}`;
    }
  }

  async function runImpersonationTest() {
    if (!latestPacket || !localRecipient || !commandTrustBundle) return;
    try {
      const forged = { ...latestPacket, senderKeyId: `UNTRUSTED-${randomId()}` };
      const testRegistry = new Set();
      try {
        await decryptAndVerify(forged, localRecipient.privateBundle, commandTrustBundle, testRegistry);
        throw new Error('Unexpected acceptance. Refresh before using this result.');
      } catch (error) {
        if (error.message.startsWith('Unexpected')) throw error;
        attackOutput.innerHTML = `<strong>IMPERSONATION REJECTED ✓</strong><p>${error.message} A packet must match the pre-trusted command signing key before the field unit attempts decryption.</p>`;
        setTrace(traceDefence, 'complete', 'Unknown sender key was rejected by trusted-sender registry');
        consoleOutput.textContent = `IMPERSONATION TEST ✓\nAttacker packet claimed an untrusted sender key ID.\nResult: ${error.message}`;
      }
    } catch (error) {
      attackOutput.textContent = `Impersonation test could not run: ${error.message}`;
    }
  }

  recipientPublicKeyInput.addEventListener('change', loadPublicBundle);
  attachmentInput.addEventListener('change', () => {
    const file = attachmentInput.files?.[0];
    attachmentStatus.textContent = file ? `${safeName(file.name, 'attachment')} · ${formatBytes(file.size)}` : 'No attachment selected.';
  });
  packetInput.addEventListener('change', updateUploadState);
  recoveryKeyInput.addEventListener('change', updateUploadState);
  trustKeyInput.addEventListener('change', updateUploadState);
  createKeysButton.addEventListener('click', createFieldUnitKeys);
  sealButton.addEventListener('click', sealPacket);
  openLatestButton.addEventListener('click', openLatestPacket);
  openUploadButton.addEventListener('click', openUploadedPacket);
  interceptButton.addEventListener('click', runInterceptTest);
  tamperButton.addEventListener('click', runTamperTest);
  replayButton.addEventListener('click', runReplayTest);
  impersonationButton.addEventListener('click', runImpersonationTest);

  $('#defDownloadPublicKeyButton').addEventListener('click', () => {
    if (localRecipient) download(JSON.stringify(localRecipient.publicBundle, null, 2), `${keyStem(localRecipient.publicBundle.recipient)}-public.dpk`, 'application/json');
  });
  $('#defDownloadPrivateKeyButton').addEventListener('click', () => {
    if (localRecipient) download(JSON.stringify(localRecipient.privateBundle, null, 2), `${keyStem(localRecipient.privateBundle.recipient)}-private.dsk`, 'application/json');
  });
  $('#defDownloadPacketButton').addEventListener('click', () => {
    if (latestPacket) download(JSON.stringify(latestPacket, null, 2), `defenceguard-${latestPacket.packetId.slice(0, 8)}.dguard`, 'application/json');
  });
  $('#defDownloadTrustButton').addEventListener('click', () => {
    if (commandTrustBundle) download(JSON.stringify(commandTrustBundle, null, 2), 'fictional-command-centre.dtrust', 'application/json');
  });
  $('#defDownloadRecoveredButton').addEventListener('click', () => {
    if (recoveredFile) download(new Blob([recoveredFile.bytes], { type: recoveredFile.type }), recoveredFile.name, recoveredFile.type);
  });
})();
