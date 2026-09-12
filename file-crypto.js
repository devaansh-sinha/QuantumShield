(() => {
  const mlKem = globalThis.QuantumShieldMLKEM?.ml_kem768;
  const recipientNameInput = document.querySelector('#pqcRecipientName');
  const generateRecipientKeysButton = document.querySelector('#pqcGenerateRecipientKeysButton');
  const recipientKeyStatus = document.querySelector('#pqcRecipientKeyStatus');
  const recipientKeyDownloads = document.querySelector('#pqcRecipientKeyDownloads');
  const downloadPublicKeyButton = document.querySelector('#pqcDownloadPublicKeyButton');
  const downloadPrivateKeyButton = document.querySelector('#pqcDownloadPrivateKeyButton');
  const recipientPublicKeyInput = document.querySelector('#pqcRecipientPublicKeyInput');
  const recipientPublicKeyStatus = document.querySelector('#pqcRecipientPublicKeyStatus');
  const fileInput = document.querySelector('#pqcFileInput');
  const encryptButton = document.querySelector('#pqcFileEncryptButton');
  const encryptedPackageInput = document.querySelector('#pqcEncryptedPackageInput');
  const recoveryKeyInput = document.querySelector('#pqcRecoveryKeyInput');
  const decryptButton = document.querySelector('#pqcFileDecryptButton');
  const selectionOutput = document.querySelector('#pqcFileSelection');
  const resultPanel = document.querySelector('#pqcFileResult');
  const statusOutput = document.querySelector('#pqcFileStatus');
  const downloads = document.querySelector('#pqcFileDownloads');
  const downloadPackageButton = document.querySelector('#pqcDownloadPackageButton');
  const inspectionPanel = document.querySelector('#pqcFileInspection');
  const packetRecipient = document.querySelector('#pqcFilePacketRecipient');
  const packetKem = document.querySelector('#pqcFilePacketKem');
  const packetIv = document.querySelector('#pqcFilePacketIv');
  const packetCiphertext = document.querySelector('#pqcFilePacketCiphertext');
  const tamperButton = document.querySelector('#pqcTamperButton');
  const tamperStatus = document.querySelector('#pqcTamperStatus');
  const downloadTamperedButton = document.querySelector('#pqcDownloadTamperedButton');

  const MAX_FILE_BYTES = 10 * 1024 * 1024;
  const MAX_KEY_FILE_BYTES = 100 * 1024;
  const PACKAGE_FORMAT = 'QuantumShield-File-2';
  const PUBLIC_KEY_FORMAT = 'QuantumShield-Public-Key-1';
  const RECOVERY_KEY_FORMAT = 'QuantumShield-Recovery-Key-1';
  let latestPackage;
  let latestTamperedPackage;
  let generatedRecipient;
  let recipientPublicBundle;

  function bytesToBase64(bytes) {
    const chunkSize = 0x8000;
    let binary = '';
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
    }
    return window.btoa(binary);
  }

  function base64ToBytes(value) {
    if (typeof value !== 'string') throw new Error('Expected Base64 data.');
    const binary = window.atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    return bytes;
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} bytes`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  function safeDownloadName(name, fallback) {
    const cleaned = (name || fallback).replace(/[\\/:*?"<>|]/g, '_').replace(/\s+/g, ' ').trim();
    return cleaned || fallback;
  }

  function fileStem(name) {
    return safeDownloadName(name, 'protected-file').replace(/\.[^.]+$/, '') || 'protected-file';
  }

  function keyStem(name) {
    return safeDownloadName(name, 'recipient').replace(/\s+/g, '-').toLowerCase();
  }

  function createKeyId() {
    if (window.crypto.randomUUID) return window.crypto.randomUUID();
    const values = window.crypto.getRandomValues(new Uint32Array(4));
    return Array.from(values, (value) => value.toString(16).padStart(8, '0')).join('-');
  }

  function downloadFile(data, filename, type) {
    const blob = data instanceof Blob ? data : new Blob([data], { type });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function showResult(message, canDownload = false) {
    resultPanel.hidden = false;
    statusOutput.textContent = message;
    downloads.hidden = !canDownload;
  }

  function ensureCryptoSupport() {
    if (!mlKem) throw new Error('The ML-KEM library did not load. Refresh the page and try again.');
    if (!window.crypto?.subtle) throw new Error('This browser does not provide Web Crypto. Use the deployed HTTPS site and try again.');
  }

  function validateSelectedFile(file) {
    if (!file) throw new Error('Choose a file first.');
    if (file.size === 0) throw new Error('Choose a file that is not empty.');
    if (file.size > MAX_FILE_BYTES) throw new Error('This local prototype accepts files up to 10 MB.');
  }

  function validatePublicKey(publicKey) {
    if (!publicKey || typeof publicKey !== 'object') throw new Error('The public key is not valid JSON.');
    if (publicKey.format !== PUBLIC_KEY_FORMAT || publicKey.kem !== 'ML-KEM-768' || typeof publicKey.publicKeyBase64 !== 'string' || typeof publicKey.keyId !== 'string') {
      throw new Error('This is not a QuantumShield ML-KEM-768 public key (.qpk).');
    }
  }

  function validatePackage(packet) {
    if (!packet || typeof packet !== 'object') throw new Error('The encrypted package is not valid JSON.');
    if (packet.format !== PACKAGE_FORMAT || packet.kem !== 'ML-KEM-768' || packet.cipher !== 'AES-256-GCM') {
      throw new Error('This is not a QuantumShield ML-KEM-768 + AES-256-GCM file package.');
    }
    if (typeof packet.originalName !== 'string' || typeof packet.keyId !== 'string' || typeof packet.kemCiphertextBase64 !== 'string' || typeof packet.ivBase64 !== 'string' || typeof packet.ciphertextBase64 !== 'string') {
      throw new Error('The encrypted package is missing required fields.');
    }
  }

  function validateRecoveryKey(recoveryKey) {
    if (!recoveryKey || typeof recoveryKey !== 'object') throw new Error('The private recovery key is not valid JSON.');
    if (recoveryKey.format !== RECOVERY_KEY_FORMAT || recoveryKey.kem !== 'ML-KEM-768' || typeof recoveryKey.secretKeyBase64 !== 'string' || typeof recoveryKey.keyId !== 'string') {
      throw new Error('This is not a QuantumShield ML-KEM-768 private recovery key (.qsk).');
    }
  }

  function updateEncryptState() {
    encryptButton.disabled = !fileInput.files?.[0] || !recipientPublicBundle;
  }

  function updateDecryptState() {
    decryptButton.disabled = !encryptedPackageInput.files?.[0] || !recoveryKeyInput.files?.[0];
  }

  function clearTamperedPackage() {
    latestTamperedPackage = undefined;
    downloadTamperedButton.hidden = true;
    downloadTamperedButton.disabled = true;
  }

  function populatePacketInspection(packet) {
    try {
      packetRecipient.textContent = packet.recipient || 'Named recipient';
      packetKem.textContent = `${formatBytes(base64ToBytes(packet.kemCiphertextBase64).length)} encapsulated key material`;
      packetIv.textContent = `${base64ToBytes(packet.ivBase64).length} bytes — public AES-GCM nonce`;
      packetCiphertext.textContent = `${formatBytes(base64ToBytes(packet.ciphertextBase64).length)} authenticated ciphertext`;
      inspectionPanel.hidden = false;
    } catch {
      inspectionPanel.hidden = true;
    }
  }

  function updateTamperAvailability(packet, preserveStatus = false) {
    const matchesLocalRecipient = Boolean(generatedRecipient && packet && generatedRecipient.privateBundle.keyId === packet.keyId);
    tamperButton.disabled = !matchesLocalRecipient;
    if (!matchesLocalRecipient) clearTamperedPackage();
    if (!preserveStatus) {
      tamperStatus.textContent = matchesLocalRecipient
        ? 'Ready: this demo has the matching private key only in this browser tab. The test will flip one encrypted byte.'
        : 'The package is ready to share. Create recipient keys in this tab, then encrypt for that recipient to run the local tamper test.';
    }
  }

  async function generateRecipientKeys() {
    try {
      ensureCryptoSupport();
      generateRecipientKeysButton.disabled = true;
      recipientKeyStatus.textContent = 'Generating an ML-KEM-768 key pair locally…';

      const recipient = (recipientNameInput.value || 'Recipient').trim().slice(0, 40) || 'Recipient';
      const keyPair = mlKem.keygen();
      const createdAt = new Date().toISOString();
      const keyId = createKeyId();
      const publicBundle = {
        format: PUBLIC_KEY_FORMAT,
        version: 1,
        kem: 'ML-KEM-768',
        recipient,
        keyId,
        createdAt,
        publicKeyBase64: bytesToBase64(keyPair.publicKey),
      };
      const privateBundle = {
        format: RECOVERY_KEY_FORMAT,
        version: 1,
        kem: 'ML-KEM-768',
        recipient,
        keyId,
        createdAt,
        secretKeyBase64: bytesToBase64(keyPair.secretKey),
      };

      keyPair.publicKey.fill(0);
      generatedRecipient = { publicBundle, privateBundle, secretKey: keyPair.secretKey };
      recipientPublicBundle = publicBundle;
      recipientKeyStatus.textContent = `Keys are ready for ${recipient}. Share the public .qpk; keep the private .qsk only with ${recipient}.`;
      recipientPublicKeyStatus.textContent = `Using the locally created public key for ${recipient}. A sender could instead upload the downloaded .qpk file.`;
      recipientKeyDownloads.hidden = false;
      updateEncryptState();
      updateTamperAvailability(latestPackage, true);
    } catch (error) {
      recipientKeyStatus.textContent = `Key generation could not complete: ${error.message}`;
    } finally {
      generateRecipientKeysButton.disabled = false;
    }
  }

  async function loadRecipientPublicKey() {
    const keyFile = recipientPublicKeyInput.files?.[0];
    if (!keyFile) {
      recipientPublicKeyStatus.textContent = generatedRecipient
        ? `Using the locally created public key for ${generatedRecipient.publicBundle.recipient}.`
        : 'Upload the recipient’s public key, or create one in step 01 for this local demo.';
      if (!generatedRecipient) recipientPublicBundle = undefined;
      updateEncryptState();
      return;
    }

    try {
      if (keyFile.size > MAX_KEY_FILE_BYTES) throw new Error('This public-key file is unexpectedly large.');
      const publicBundle = JSON.parse(await keyFile.text());
      validatePublicKey(publicBundle);
      const publicKey = base64ToBytes(publicBundle.publicKeyBase64);
      if (publicKey.length === 0) throw new Error('The public key contains no key material.');
      publicKey.fill(0);
      recipientPublicBundle = publicBundle;
      recipientPublicKeyStatus.textContent = `Loaded ${publicBundle.recipient || 'recipient'}’s public key (.qpk). It can encrypt but cannot decrypt a package.`;
    } catch (error) {
      recipientPublicBundle = generatedRecipient?.publicBundle;
      recipientPublicKeyStatus.textContent = `Could not use this public key: ${error.message}`;
    } finally {
      updateEncryptState();
    }
  }

  async function encryptFile() {
    const file = fileInput.files?.[0];
    let recipientPublicKey;
    let sharedSecret;
    try {
      ensureCryptoSupport();
      validateSelectedFile(file);
      validatePublicKey(recipientPublicBundle);
      encryptButton.disabled = true;
      downloads.hidden = true;
      clearTamperedPackage();
      showResult(`Establishing a one-time ML-KEM-768 secret for ${recipientPublicBundle.recipient || 'the recipient'} and encrypting “${file.name}” locally…`);

      recipientPublicKey = base64ToBytes(recipientPublicBundle.publicKeyBase64);
      const recipientResult = mlKem.encapsulate(recipientPublicKey);
      sharedSecret = recipientResult.sharedSecret;
      const aesKey = await window.crypto.subtle.importKey('raw', sharedSecret, { name: 'AES-GCM' }, false, ['encrypt']);
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const plaintext = await file.arrayBuffer();
      const encryptedBuffer = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext);
      const encryptedBytes = new Uint8Array(encryptedBuffer);
      const createdAt = new Date().toISOString();

      latestPackage = {
        format: PACKAGE_FORMAT,
        version: 2,
        kem: 'ML-KEM-768',
        cipher: 'AES-256-GCM',
        recipient: recipientPublicBundle.recipient || 'Recipient',
        keyId: recipientPublicBundle.keyId,
        originalName: safeDownloadName(file.name, 'original-file'),
        originalType: file.type || 'application/octet-stream',
        originalSize: file.size,
        createdAt,
        kemCiphertextBase64: bytesToBase64(recipientResult.cipherText),
        ivBase64: bytesToBase64(iv),
        ciphertextBase64: bytesToBase64(encryptedBytes),
      };

      recipientResult.cipherText.fill(0);
      populatePacketInspection(latestPackage);
      updateTamperAvailability(latestPackage);
      showResult(`“${file.name}” is encrypted for ${latestPackage.recipient}. Download the .qshield package and share it; only the matching private .qsk can open it.`, true);
    } catch (error) {
      showResult(`File encryption could not complete: ${error.message}`);
    } finally {
      recipientPublicKey?.fill(0);
      sharedSecret?.fill(0);
      updateEncryptState();
    }
  }

  async function decryptFile() {
    const packageFile = encryptedPackageInput.files?.[0];
    const recoveryFile = recoveryKeyInput.files?.[0];
    let secretKey;
    let sharedSecret;
    try {
      ensureCryptoSupport();
      if (!packageFile || !recoveryFile) throw new Error('Upload both the encrypted package and its matching private recovery key.');
      if (packageFile.size > MAX_FILE_BYTES * 2 || recoveryFile.size > MAX_KEY_FILE_BYTES) throw new Error('One of the uploaded files is larger than this prototype supports.');
      decryptButton.disabled = true;
      showResult('Reading the encrypted package and recovering its one-time AES key locally…');

      const packet = JSON.parse(await packageFile.text());
      const recoveryKey = JSON.parse(await recoveryFile.text());
      validatePackage(packet);
      validateRecoveryKey(recoveryKey);
      if (packet.keyId !== recoveryKey.keyId) throw new Error('This private .qsk key does not belong to the recipient of this .qshield package.');

      const kemCiphertext = base64ToBytes(packet.kemCiphertextBase64);
      const iv = base64ToBytes(packet.ivBase64);
      const ciphertext = base64ToBytes(packet.ciphertextBase64);
      secretKey = base64ToBytes(recoveryKey.secretKeyBase64);
      if (iv.length !== 12 || ciphertext.length < 17) throw new Error('The encrypted package has an invalid AES-GCM payload.');

      sharedSecret = mlKem.decapsulate(kemCiphertext, secretKey);
      const aesKey = await window.crypto.subtle.importKey('raw', sharedSecret, { name: 'AES-GCM' }, false, ['decrypt']);
      const plaintext = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);

      const originalName = safeDownloadName(packet.originalName, 'recovered-file');
      downloadFile(new Blob([plaintext], { type: packet.originalType || 'application/octet-stream' }), originalName, packet.originalType);
      populatePacketInspection(packet);
      showResult(`Success — ${recoveryKey.recipient || 'the recipient'} decrypted “${originalName}” locally and it was downloaded.`, false);
    } catch (error) {
      showResult(`File decryption could not complete: ${error.message}`);
    } finally {
      secretKey?.fill(0);
      sharedSecret?.fill(0);
      updateDecryptState();
    }
  }

  async function runTamperTest() {
    let secretKey;
    let sharedSecret;
    try {
      ensureCryptoSupport();
      if (!latestPackage || !generatedRecipient || generatedRecipient.privateBundle.keyId !== latestPackage.keyId) {
        throw new Error('Create a recipient key pair in this tab, then encrypt a file for that recipient first.');
      }
      tamperButton.disabled = true;
      clearTamperedPackage();
      tamperStatus.textContent = 'An attacker flips one byte in the encrypted file payload. Attempting local decryption…';

      const alteredCiphertext = base64ToBytes(latestPackage.ciphertextBase64);
      alteredCiphertext[Math.floor(alteredCiphertext.length / 2)] ^= 1;
      const alteredPacket = { ...latestPackage, ciphertextBase64: bytesToBase64(alteredCiphertext) };
      alteredCiphertext.fill(0);
      secretKey = generatedRecipient.secretKey.slice();
      sharedSecret = mlKem.decapsulate(base64ToBytes(alteredPacket.kemCiphertextBase64), secretKey);
      const aesKey = await window.crypto.subtle.importKey('raw', sharedSecret, { name: 'AES-GCM' }, false, ['decrypt']);

      try {
        await window.crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: base64ToBytes(alteredPacket.ivBase64) },
          aesKey,
          base64ToBytes(alteredPacket.ciphertextBase64),
        );
        tamperStatus.textContent = 'Unexpected result: the altered package was accepted. Do not use this result; refresh the page and try again.';
      } catch {
        latestTamperedPackage = alteredPacket;
        downloadTamperedButton.hidden = false;
        downloadTamperedButton.disabled = false;
        tamperStatus.textContent = 'Tamper detected — AES-GCM authentication rejected the altered package. Download it below, upload it with the correct .qsk key, and the recipient decryption panel will reject it too.';
      }
    } catch (error) {
      tamperStatus.textContent = `Tamper test could not run: ${error.message}`;
    } finally {
      secretKey?.fill(0);
      sharedSecret?.fill(0);
      updateTamperAvailability(latestPackage, true);
    }
  }

  fileInput.addEventListener('change', () => {
    const file = fileInput.files?.[0];
    if (!file) {
      selectionOutput.textContent = 'No file selected yet.';
      updateEncryptState();
      return;
    }
    selectionOutput.textContent = `${file.name} · ${formatBytes(file.size)}`;
    updateEncryptState();
  });

  recipientPublicKeyInput.addEventListener('change', loadRecipientPublicKey);
  encryptedPackageInput.addEventListener('change', updateDecryptState);
  recoveryKeyInput.addEventListener('change', updateDecryptState);
  generateRecipientKeysButton.addEventListener('click', generateRecipientKeys);
  encryptButton.addEventListener('click', encryptFile);
  decryptButton.addEventListener('click', decryptFile);
  tamperButton.addEventListener('click', runTamperTest);
  downloadPackageButton.addEventListener('click', () => {
    if (!latestPackage) return;
    downloadFile(JSON.stringify(latestPackage, null, 2), `${fileStem(latestPackage.originalName)}.qshield`, 'application/json');
  });
  downloadTamperedButton.addEventListener('click', () => {
    if (!latestTamperedPackage) return;
    downloadFile(JSON.stringify(latestTamperedPackage, null, 2), `${fileStem(latestTamperedPackage.originalName)}-tampered.qshield`, 'application/json');
  });
  downloadPublicKeyButton.addEventListener('click', () => {
    if (!generatedRecipient) return;
    downloadFile(JSON.stringify(generatedRecipient.publicBundle, null, 2), `${keyStem(generatedRecipient.publicBundle.recipient)}-public.qpk`, 'application/json');
  });
  downloadPrivateKeyButton.addEventListener('click', () => {
    if (!generatedRecipient) return;
    downloadFile(JSON.stringify(generatedRecipient.privateBundle, null, 2), `${keyStem(generatedRecipient.privateBundle.recipient)}-private.qsk`, 'application/json');
  });
})();
