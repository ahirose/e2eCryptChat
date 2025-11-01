// E2E Encryption Library using Double Ratchet Algorithm (Signal Protocol)

class DoubleRatchetCrypto {
  constructor() {
    this.identityKeyPair = null;
    this.sessions = new Map(); // peerId -> RatchetSession
  }

  /**
   * Generate identity key pair (long-term ECDH key)
   */
  async generateIdentityKeyPair() {
    this.identityKeyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      ['deriveKey', 'deriveBits']
    );
    return this.identityKeyPair;
  }

  /**
   * Export public identity key
   */
  async exportPublicKey() {
    if (!this.identityKeyPair) {
      throw new Error('Identity key pair not generated yet');
    }
    const exported = await window.crypto.subtle.exportKey(
      'raw',
      this.identityKeyPair.publicKey
    );
    return this.arrayBufferToBase64(exported);
  }

  /**
   * Import peer's public key
   */
  async importPublicKey(base64PublicKey) {
    const buffer = this.base64ToArrayBuffer(base64PublicKey);
    return await window.crypto.subtle.importKey(
      'raw',
      buffer,
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      []
    );
  }

  /**
   * Initialize session as Alice (initiator)
   */
  async initializeSessionAsAlice(peerId, peerIdentityPublicKey) {
    // Generate ephemeral key pair
    const ephemeralKeyPair = await this.generateEphemeralKeyPair();

    // Perform initial DH
    const dhOutput = await this.performDH(
      this.identityKeyPair.privateKey,
      peerIdentityPublicKey
    );

    // Derive root key from DH output
    const rootKey = await this.hkdf(dhOutput, new Uint8Array(32), 'RootKey', 32);

    // Create session
    const session = new RatchetSession(peerId);
    session.rootKey = rootKey;
    session.sendingChainKey = null;
    session.receivingChainKey = null;
    session.dhSelf = ephemeralKeyPair;
    session.dhPeer = peerIdentityPublicKey;
    session.sendMessageNumber = 0;
    session.receiveMessageNumber = 0;
    session.previousSendingChainLength = 0;

    this.sessions.set(peerId, session);

    return {
      ephemeralPublicKey: await this.exportEphemeralPublicKey(ephemeralKeyPair)
    };
  }

  /**
   * Initialize session as Bob (responder)
   */
  async initializeSessionAsBob(peerId, peerIdentityPublicKey, peerEphemeralPublicKey) {
    // Perform initial DH
    const dhOutput = await this.performDH(
      this.identityKeyPair.privateKey,
      peerIdentityPublicKey
    );

    // Derive root key from DH output
    const rootKey = await this.hkdf(dhOutput, new Uint8Array(32), 'RootKey', 32);

    // Create session
    const session = new RatchetSession(peerId);
    session.rootKey = rootKey;
    session.sendingChainKey = null;
    session.receivingChainKey = null;
    session.dhSelf = null; // Will be generated on first send
    session.dhPeer = await this.importPublicKey(peerEphemeralPublicKey);
    session.sendMessageNumber = 0;
    session.receiveMessageNumber = 0;
    session.previousSendingChainLength = 0;

    this.sessions.set(peerId, session);
  }

  /**
   * Generate ephemeral key pair for DH ratchet
   */
  async generateEphemeralKeyPair() {
    return await window.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      ['deriveKey', 'deriveBits']
    );
  }

  /**
   * Export ephemeral public key
   */
  async exportEphemeralPublicKey(keyPair) {
    const exported = await window.crypto.subtle.exportKey(
      'raw',
      keyPair.publicKey
    );
    return this.arrayBufferToBase64(exported);
  }

  /**
   * Perform Diffie-Hellman key agreement
   */
  async performDH(privateKey, publicKey) {
    const sharedSecret = await window.crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: publicKey
      },
      privateKey,
      256
    );
    return new Uint8Array(sharedSecret);
  }

  /**
   * HMAC-based Key Derivation Function (HKDF)
   */
  async hkdf(inputKeyMaterial, salt, info, length) {
    // Import input key material
    const ikm = await window.crypto.subtle.importKey(
      'raw',
      inputKeyMaterial,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    // Extract: PRK = HMAC(salt, IKM)
    const saltKey = await window.crypto.subtle.importKey(
      'raw',
      salt.length > 0 ? salt : new Uint8Array(32),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const prk = await window.crypto.subtle.sign('HMAC', saltKey, inputKeyMaterial);

    // Expand: OKM = HMAC(PRK, info || 0x01)
    const prkKey = await window.crypto.subtle.importKey(
      'raw',
      prk,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const encoder = new TextEncoder();
    const infoBytes = encoder.encode(info);
    const expandInput = new Uint8Array(infoBytes.length + 1);
    expandInput.set(infoBytes, 0);
    expandInput[infoBytes.length] = 0x01;

    const okm = await window.crypto.subtle.sign('HMAC', prkKey, expandInput);
    return new Uint8Array(okm).slice(0, length);
  }

  /**
   * KDF for chain keys
   */
  async kdfChain(chainKey) {
    const ck = await window.crypto.subtle.importKey(
      'raw',
      chainKey,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    // Next chain key = HMAC(chainKey, 0x01)
    const nextChainKey = await window.crypto.subtle.sign(
      'HMAC',
      ck,
      new Uint8Array([0x01])
    );

    // Message key = HMAC(chainKey, 0x02)
    const messageKey = await window.crypto.subtle.sign(
      'HMAC',
      ck,
      new Uint8Array([0x02])
    );

    return {
      chainKey: new Uint8Array(nextChainKey).slice(0, 32),
      messageKey: new Uint8Array(messageKey).slice(0, 32)
    };
  }

  /**
   * KDF for root key
   */
  async kdfRoot(rootKey, dhOutput) {
    const newRootKey = await this.hkdf(dhOutput, rootKey, 'RootKey', 32);
    const newChainKey = await this.hkdf(dhOutput, rootKey, 'ChainKey', 32);
    return { rootKey: newRootKey, chainKey: newChainKey };
  }

  /**
   * Perform DH Ratchet step
   */
  async dhRatchet(session, peerPublicKey) {
    // Save previous sending chain length
    session.previousSendingChainLength = session.sendMessageNumber;

    // Reset message numbers
    session.sendMessageNumber = 0;
    session.receiveMessageNumber = 0;

    // Update DH peer public key
    session.dhPeer = peerPublicKey;

    // Perform DH and derive new receiving chain
    const dhOutput = await this.performDH(session.dhSelf.privateKey, session.dhPeer);
    const { rootKey, chainKey } = await this.kdfRoot(session.rootKey, dhOutput);
    session.rootKey = rootKey;
    session.receivingChainKey = chainKey;

    // Generate new ephemeral key pair
    session.dhSelf = await this.generateEphemeralKeyPair();

    // Perform DH and derive new sending chain
    const dhOutput2 = await this.performDH(session.dhSelf.privateKey, session.dhPeer);
    const { rootKey: rootKey2, chainKey: chainKey2 } = await this.kdfRoot(session.rootKey, dhOutput2);
    session.rootKey = rootKey2;
    session.sendingChainKey = chainKey2;
  }

  /**
   * Encrypt message using Double Ratchet
   */
  async encrypt(message, peerId) {
    const session = this.sessions.get(peerId);
    if (!session) {
      throw new Error('Session not established with this peer');
    }

    // If this is the first message or we need to initialize sending chain
    if (!session.dhSelf) {
      session.dhSelf = await this.generateEphemeralKeyPair();
      const dhOutput = await this.performDH(session.dhSelf.privateKey, session.dhPeer);
      const { rootKey, chainKey } = await this.kdfRoot(session.rootKey, dhOutput);
      session.rootKey = rootKey;
      session.sendingChainKey = chainKey;
    }

    // Derive message key from sending chain
    const { chainKey, messageKey } = await this.kdfChain(session.sendingChainKey);
    session.sendingChainKey = chainKey;

    // Encrypt message with AES-GCM using message key
    const encoder = new TextEncoder();
    const plaintext = encoder.encode(message);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      messageKey,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const ciphertext = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      aesKey,
      plaintext
    );

    // Create message header
    const header = {
      dhPublicKey: await this.exportEphemeralPublicKey(session.dhSelf),
      messageNumber: session.sendMessageNumber,
      previousChainLength: session.previousSendingChainLength
    };

    session.sendMessageNumber++;

    // Combine header, IV, and ciphertext
    return {
      header: header,
      iv: this.arrayBufferToBase64(iv),
      ciphertext: this.arrayBufferToBase64(ciphertext)
    };
  }

  /**
   * Decrypt message using Double Ratchet
   */
  async decrypt(encryptedMessage, peerId) {
    const session = this.sessions.get(peerId);
    if (!session) {
      throw new Error('Session not established with this peer');
    }

    const { header, iv, ciphertext } = encryptedMessage;
    const peerPublicKey = await this.importPublicKey(header.dhPublicKey);

    // Check if we need to perform DH ratchet (new ephemeral key from peer)
    const currentPeerKey = session.dhPeer ?
      await this.exportEphemeralPublicKey({ publicKey: session.dhPeer }) : null;

    if (currentPeerKey !== header.dhPublicKey) {
      await this.dhRatchet(session, peerPublicKey);
    }

    // Derive message key from receiving chain
    let messageKey = session.receivingChainKey;
    for (let i = session.receiveMessageNumber; i < header.messageNumber; i++) {
      const result = await this.kdfChain(messageKey);
      messageKey = result.chainKey;
    }

    const { chainKey, messageKey: finalMessageKey } = await this.kdfChain(messageKey);
    session.receivingChainKey = chainKey;
    session.receiveMessageNumber = header.messageNumber + 1;

    // Decrypt message with AES-GCM
    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      finalMessageKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const ivBytes = this.base64ToArrayBuffer(iv);
    const ciphertextBytes = this.base64ToArrayBuffer(ciphertext);

    const plaintext = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes },
      aesKey,
      ciphertextBytes
    );

    const decoder = new TextDecoder();
    return decoder.decode(plaintext);
  }

  /**
   * Generate fingerprint from public key
   * Returns a human-readable fingerprint for key verification
   */
  async generateFingerprint(publicKeyBase64) {
    // Convert Base64 to ArrayBuffer
    const publicKeyBytes = this.base64ToArrayBuffer(publicKeyBase64);

    // Hash the public key with SHA-256
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', publicKeyBytes);
    const hashArray = new Uint8Array(hashBuffer);

    // Convert to numeric string
    let numericString = '';
    for (let i = 0; i < hashArray.length; i++) {
      numericString += hashArray[i].toString().padStart(3, '0');
    }

    // Take first 60 digits and format into groups of 5
    const digits = numericString.substring(0, 60);
    const groups = [];
    for (let i = 0; i < 60; i += 5) {
      groups.push(digits.substring(i, i + 5));
    }

    return groups.join(' ');
  }

  /**
   * Get fingerprint of own public key
   */
  async getOwnFingerprint() {
    const publicKey = await this.exportPublicKey();
    return await this.generateFingerprint(publicKey);
  }

  /**
   * Helper: Convert ArrayBuffer to Base64
   */
  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Helper: Convert Base64 to ArrayBuffer
   */
  base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
}

/**
 * Ratchet Session State
 */
class RatchetSession {
  constructor(peerId) {
    this.peerId = peerId;
    this.rootKey = null;                    // Root key (RK)
    this.sendingChainKey = null;            // Sending chain key (CKs)
    this.receivingChainKey = null;          // Receiving chain key (CKr)
    this.dhSelf = null;                     // Self DH key pair
    this.dhPeer = null;                     // Peer DH public key
    this.sendMessageNumber = 0;             // Message number for sending
    this.receiveMessageNumber = 0;          // Message number for receiving
    this.previousSendingChainLength = 0;    // Previous sending chain length
  }
}

// Alias for backward compatibility
class E2ECrypto extends DoubleRatchetCrypto {
  constructor() {
    super();
    this.selfId = null;
    this._pendingEphemeralKeys = new Map(); // peerId -> ephemeralPublicKey
  }

  // Set client ID for session initialization
  setClientId(clientId) {
    this.selfId = clientId;
  }

  // Maintain old API
  async generateKeyPair() {
    return await this.generateIdentityKeyPair();
  }

  // Simplified session initialization
  async deriveSharedSecret(peerPublicKey, peerId) {
    const importedKey = typeof peerPublicKey === 'string'
      ? await this.importPublicKey(peerPublicKey)
      : peerPublicKey;

    // Check if we already have a session
    if (this.sessions.has(peerId)) {
      return;
    }

    // Determine who is Alice and who is Bob based on peer IDs
    // (lexicographic comparison for deterministic ordering)
    const isAlice = this.selfId < peerId;

    if (isAlice) {
      const result = await this.initializeSessionAsAlice(peerId, importedKey);
      // Store ephemeral public key to send to peer
      this._pendingEphemeralKeys.set(peerId, result.ephemeralPublicKey);
    } else {
      // Initialize as Bob without ephemeral key (will wait for peer's)
      const dhOutput = await this.performDH(
        this.identityKeyPair.privateKey,
        importedKey
      );
      const rootKey = await this.hkdf(dhOutput, new Uint8Array(32), 'RootKey', 32);

      const session = new RatchetSession(peerId);
      session.rootKey = rootKey;
      session.sendingChainKey = null;
      session.receivingChainKey = null;
      session.dhSelf = null;
      session.dhPeer = importedKey; // Use identity key initially
      session.sendMessageNumber = 0;
      session.receiveMessageNumber = 0;
      session.previousSendingChainLength = 0;

      this.sessions.set(peerId, session);
    }
  }

  // Handle ephemeral key exchange (for Bob to receive Alice's ephemeral key)
  async handleEphemeralKey(peerId, ephemeralPublicKey) {
    const session = this.sessions.get(peerId);
    if (session) {
      // Update peer's ephemeral key
      session.dhPeer = await this.importPublicKey(ephemeralPublicKey);
    }
  }

  // Get pending ephemeral key for a specific peer
  getPendingEphemeralKey(peerId) {
    const key = this._pendingEphemeralKeys.get(peerId);
    if (key) {
      this._pendingEphemeralKeys.delete(peerId);
    }
    return key;
  }
}
