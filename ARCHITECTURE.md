# QuantumShield DefenceGuard architecture

DefenceGuard demonstrates a hybrid post-quantum protection path for a fictional command message or attachment.

1. A field unit creates an ML-KEM-768 key pair. Its public key can be shared with command; its private recovery key remains with the field unit.
2. Command encapsulates a one-time secret to the field unit's public key.
3. AES-256-GCM encrypts the command payload locally with the derived secret.
4. The transferable package contains ML-KEM ciphertext, AES-GCM IV, encrypted payload, non-secret metadata, and an origin-check value.
5. The receiving field unit recovers the secret locally and verifies the packet before releasing content.

The demonstrator is intentionally browser-only and uses fictional data. A production deployment requires authenticated identities, secure hardware or platform-backed private-key storage, certificate and key lifecycle management, access controls, logging, incident response, and external security review.
