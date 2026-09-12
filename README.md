# QuantumShield DefenceGuard

QuantumShield DefenceGuard is a browser-based post-quantum security demonstrator for protecting fictional defence command messages and operational attachments.

## Run it

Open `index.html` in a modern browser. Start the defence workflow from `solution.html` or open `defence.html` directly.

## What works

- ML-KEM-768 establishes a post-quantum shared secret for the intended recipient.
- AES-256-GCM encrypts the message and optional file locally in the browser.
- The protected package contains ciphertext and non-secret metadata, not the recipient private key or plaintext.
- The receiver workflow verifies the protected package and demonstrates rejection of altered, replayed, expired, or untrusted packets.

## Accuracy boundary

This is an educational browser prototype using fictional data. A deployable defence system would additionally require identity assurance, protected key storage, access control, audited infrastructure, incident response, and independent security review.
