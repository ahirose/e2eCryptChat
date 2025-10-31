// E2E Encryption Library using Web Crypto API

class E2ECrypto {
  constructor() {
    this.keyPair = null;
    this.sharedSecrets = new Map(); // Store shared secrets per peer
  }

  /**
   * Generate ECDH key pair for key exchange
   */
  async generateKeyPair() {
    this.keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      ['deriveKey', 'deriveBits']
    );
    return this.keyPair;
  }

  /**
   * Export public key to share with peers
   */
  async exportPublicKey() {
    if (!this.keyPair) {
      throw new Error('Key pair not generated yet');
    }
    const exported = await window.crypto.subtle.exportKey(
      'raw',
      this.keyPair.publicKey
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
   * Derive shared secret with peer's public key
   */
  async deriveSharedSecret(peerPublicKey, peerId) {
    if (!this.keyPair) {
      throw new Error('Key pair not generated yet');
    }

    const importedPeerKey = typeof peerPublicKey === 'string'
      ? await this.importPublicKey(peerPublicKey)
      : peerPublicKey;

    const sharedSecret = await window.crypto.subtle.deriveKey(
      {
        name: 'ECDH',
        public: importedPeerKey
      },
      this.keyPair.privateKey,
      {
        name: 'AES-GCM',
        length: 256
      },
      true,
      ['encrypt', 'decrypt']
    );

    this.sharedSecrets.set(peerId, sharedSecret);
    return sharedSecret;
  }

  /**
   * Encrypt message using AES-GCM
   */
  async encrypt(message, peerId) {
    const sharedSecret = this.sharedSecrets.get(peerId);
    if (!sharedSecret) {
      throw new Error('Shared secret not established with this peer');
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      sharedSecret,
      data
    );

    // Combine IV and encrypted data
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);

    return this.arrayBufferToBase64(combined);
  }

  /**
   * Decrypt message using AES-GCM
   */
  async decrypt(encryptedBase64, peerId) {
    const sharedSecret = this.sharedSecrets.get(peerId);
    if (!sharedSecret) {
      throw new Error('Shared secret not established with this peer');
    }

    const combined = this.base64ToArrayBuffer(encryptedBase64);
    const iv = combined.slice(0, 12);
    const data = combined.slice(12);

    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      sharedSecret,
      data
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
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
