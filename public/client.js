// Chat Client with E2E Encryption

class ChatClient {
  constructor() {
    this.ws = null;
    this.crypto = new E2ECrypto();
    this.clientId = this.generateClientId();
    this.crypto.setClientId(this.clientId); // Set client ID for Double Ratchet
    this.currentPeerId = null;
    this.peers = new Map(); // Map of peerId -> { keyExchanged: boolean, publicKey: string }
    this.messageHistory = new Map(); // Map of peerId -> array of messages

    this.initializeUI();
    this.connect();
  }

  generateClientId() {
    return 'user_' + Math.random().toString(36).substr(2, 9);
  }

  initializeUI() {
    this.statusEl = document.getElementById('status');
    this.userIdEl = document.getElementById('user-id');
    this.peersListEl = document.getElementById('peers-list');
    this.messagesEl = document.getElementById('messages');
    this.messageForm = document.getElementById('message-form');
    // Firefox treats a disabled form as non-submittable even if children are re-enabled.
    this.messageForm.removeAttribute('disabled');
    this.messageInput = document.getElementById('message-input');
    this.sendButton = document.getElementById('send-button');
    this.currentPeerEl = document.getElementById('current-peer-name');

    // Mobile menu elements
    this.menuToggle = document.getElementById('menu-toggle');
    this.sidebar = document.querySelector('.sidebar');
    this.sidebarOverlay = document.getElementById('sidebar-overlay');

    // Notification container
    this.notificationContainer = document.getElementById('notification-container');

    this.userIdEl.textContent = this.clientId;

    this.messageForm.addEventListener('submit', (e) => {
      e.preventDefault();
      this.sendMessage();
    });

    // Mobile menu toggle
    this.menuToggle.addEventListener('click', () => {
      this.toggleSidebar();
    });

    // Close sidebar when clicking overlay
    this.sidebarOverlay.addEventListener('click', () => {
      this.closeSidebar();
    });
  }

  toggleSidebar() {
    this.sidebar.classList.toggle('active');
    this.sidebarOverlay.classList.toggle('active');
  }

  closeSidebar() {
    this.sidebar.classList.remove('active');
    this.sidebarOverlay.classList.remove('active');
  }

  showNotification(fromId, message) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = 'notification';
    notification.dataset.peerId = fromId;

    // Truncate message for preview
    const messagePreview = message.length > 50 ? message.substring(0, 50) + '...' : message;

    notification.innerHTML = `
      <div class="notification-header">
        <span class="notification-icon">💬</span>
        <span class="notification-from">${fromId}</span>
        <button class="notification-close" aria-label="閉じる">×</button>
      </div>
      <div class="notification-message">${messagePreview}</div>
    `;

    // Click to switch to that peer
    notification.addEventListener('click', (e) => {
      if (!e.target.classList.contains('notification-close')) {
        this.selectPeer(fromId);
        this.closeNotification(notification);
      }
    });

    // Close button handler
    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      this.closeNotification(notification);
    });

    // Add to container
    this.notificationContainer.appendChild(notification);

    // Auto-close after 5 seconds
    setTimeout(() => {
      if (notification.parentElement) {
        this.closeNotification(notification);
      }
    }, 5000);
  }

  closeNotification(notification) {
    notification.classList.add('closing');
    setTimeout(() => {
      if (notification.parentElement) {
        notification.remove();
      }
    }, 300); // Match animation duration
  }

  async connect() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}`;

    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = async () => {
      console.log('WebSocket connected');
      this.updateStatus(true);

      // Generate key pair for this client
      await this.crypto.generateKeyPair();
      console.log('Key pair generated');

      // Register with server
      this.ws.send(JSON.stringify({
        type: 'register',
        clientId: this.clientId
      }));
    };

    this.ws.onmessage = (event) => {
      this.handleMessage(JSON.parse(event.data));
    };

    this.ws.onclose = () => {
      console.log('WebSocket disconnected');
      this.updateStatus(false);
      setTimeout(() => this.connect(), 3000);
    };

    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
  }

  updateStatus(connected) {
    if (connected) {
      this.statusEl.textContent = '接続中';
      this.statusEl.className = 'status-connected';
    } else {
      this.statusEl.textContent = '接続していません';
      this.statusEl.className = 'status-disconnected';
    }
  }

  async handleMessage(message) {
    console.log('Received message:', message);

    switch (message.type) {
      case 'peer_list':
        // Initial list of peers
        for (const peerId of message.peers) {
          this.addPeer(peerId);
          // Initiate key exchange
          await this.initiateKeyExchange(peerId);
        }
        break;

      case 'peer_joined':
        // New peer joined
        this.addPeer(message.peerId);
        this.addSystemMessage(`${message.peerId} が参加しました`);
        // Initiate key exchange with new peer
        await this.initiateKeyExchange(message.peerId);
        break;

      case 'peer_left':
        // Peer left
        this.removePeer(message.peerId);
        this.addSystemMessage(`${message.peerId} が退出しました`);
        break;

      case 'key_exchange':
        // Received public key from peer
        await this.handleKeyExchange(message.fromId, message.publicKey, message.ephemeralKey);
        break;

      case 'ephemeral_key_exchange':
        // Received ephemeral key from peer (for Double Ratchet)
        await this.handleEphemeralKeyExchange(message.fromId, message.ephemeralKey);
        break;

      case 'encrypted_message':
        // Received encrypted message
        await this.handleEncryptedMessage(message.fromId, message.encryptedData);
        break;
    }
  }

  addPeer(peerId) {
    if (!this.peers.has(peerId)) {
      this.peers.set(peerId, { keyExchanged: false });
      this.messageHistory.set(peerId, []);
      this.renderPeersList();
    }
  }

  removePeer(peerId) {
    this.peers.delete(peerId);
    if (this.currentPeerId === peerId) {
      this.currentPeerId = null;
      this.updateCurrentPeer();
    }
    this.renderPeersList();
  }

  async initiateKeyExchange(peerId) {
    const publicKey = await this.crypto.exportPublicKey();
    this.ws.send(JSON.stringify({
      type: 'key_exchange',
      targetId: peerId,
      publicKey: publicKey
    }));
  }

  async handleKeyExchange(peerId, publicKey, ephemeralKey) {
    // Derive shared secret with peer's public key
    await this.crypto.deriveSharedSecret(publicKey, peerId);

    // Handle ephemeral key if provided
    if (ephemeralKey) {
      await this.crypto.handleEphemeralKey(peerId, ephemeralKey);
    }

    const peerInfo = this.peers.get(peerId);
    if (peerInfo) {
      // Store peer's public key for fingerprint verification
      peerInfo.publicKey = publicKey;

      // If this is not the first time, send our public key back
      if (!peerInfo.responseSent) {
        await this.initiateKeyExchange(peerId);
        peerInfo.responseSent = true;
      }

      // Check if we have a pending ephemeral key to send
      const pendingEphemeralKey = this.crypto.getPendingEphemeralKey(peerId);
      if (pendingEphemeralKey) {
        // Send ephemeral key to peer
        this.ws.send(JSON.stringify({
          type: 'ephemeral_key_exchange',
          targetId: peerId,
          ephemeralKey: pendingEphemeralKey
        }));
      }

      peerInfo.keyExchanged = true;
      this.renderPeersList();
      console.log(`Key exchange completed with ${peerId}`);

      // Update fingerprint display if this is the current peer
      if (this.currentPeerId === peerId) {
        await this.updateFingerprintDisplay();
      }
    }
  }

  async handleEphemeralKeyExchange(peerId, ephemeralKey) {
    // Handle ephemeral key from peer
    await this.crypto.handleEphemeralKey(peerId, ephemeralKey);
    console.log(`Ephemeral key exchange completed with ${peerId}`);
  }

  renderPeersList() {
    if (this.peers.size === 0) {
      this.peersListEl.innerHTML = '<p class="no-peers">他のユーザーがいません</p>';
      return;
    }

    this.peersListEl.innerHTML = '';
    this.peers.forEach((info, peerId) => {
      const peerEl = document.createElement('div');
      peerEl.className = 'peer-item';
      if (info.keyExchanged) {
        peerEl.classList.add('key-exchanged');
      }
      if (peerId === this.currentPeerId) {
        peerEl.classList.add('active');
      }
      peerEl.textContent = peerId;
      peerEl.addEventListener('click', () => this.selectPeer(peerId));
      this.peersListEl.appendChild(peerEl);
    });
  }

  selectPeer(peerId) {
    this.currentPeerId = peerId;
    this.updateCurrentPeer();
    this.renderPeersList();
    this.renderMessages();

    // Enable message form if key exchange is complete
    const peerInfo = this.peers.get(peerId);
    const canSend = peerInfo && peerInfo.keyExchanged;
    this.messageInput.disabled = !canSend;
    this.sendButton.disabled = !canSend;
    this.messageInput.placeholder = canSend
      ? 'メッセージを入力...'
      : '鍵交換を待機中...';

    // Update fingerprint display
    this.updateFingerprintDisplay();

    // Close sidebar on mobile after selecting peer
    if (window.innerWidth <= 768) {
      this.closeSidebar();
    }
  }

  updateCurrentPeer() {
    if (this.currentPeerId) {
      this.currentPeerEl.textContent = `${this.currentPeerId} とのチャット`;
    } else {
      this.currentPeerEl.textContent = 'チャット相手を選択してください';
    }
  }

  async sendMessage() {
    const message = this.messageInput.value.trim();
    if (!message || !this.currentPeerId) return;

    const peerInfo = this.peers.get(this.currentPeerId);
    if (!peerInfo || !peerInfo.keyExchanged) {
      alert('鍵交換が完了していません');
      return;
    }

    try {
      // Encrypt message
      const encryptedData = await this.crypto.encrypt(message, this.currentPeerId);

      // Send encrypted message
      this.ws.send(JSON.stringify({
        type: 'encrypted_message',
        recipientId: this.currentPeerId,
        encryptedData: encryptedData
      }));

      // Add to local message history
      const history = this.messageHistory.get(this.currentPeerId);
      history.push({
        type: 'sent',
        content: message,
        timestamp: new Date()
      });

      this.renderMessages();
      this.messageInput.value = '';
    } catch (error) {
      console.error('Error sending message:', error);
      alert('メッセージの送信に失敗しました');
    }
  }

  async handleEncryptedMessage(fromId, encryptedData) {
    try {
      // Decrypt message
      const decryptedMessage = await this.crypto.decrypt(encryptedData, fromId);

      // Add to message history
      let history = this.messageHistory.get(fromId);
      if (!history) {
        history = [];
        this.messageHistory.set(fromId, history);
      }

      history.push({
        type: 'received',
        content: decryptedMessage,
        timestamp: new Date()
      });

      // Render messages if this is the current peer
      if (this.currentPeerId === fromId) {
        this.renderMessages();
      } else {
        // Show notification for messages from other peers
        this.showNotification(fromId, decryptedMessage);
      }
    } catch (error) {
      console.error('Error decrypting message:', error);
    }
  }

  renderMessages() {
    if (!this.currentPeerId) {
      this.messagesEl.innerHTML = '';
      return;
    }

    const history = this.messageHistory.get(this.currentPeerId) || [];
    this.messagesEl.innerHTML = '';

    history.forEach((msg) => {
      const msgEl = document.createElement('div');
      msgEl.className = `message ${msg.type}`;

      const contentEl = document.createElement('div');
      contentEl.textContent = msg.content;

      const metaEl = document.createElement('div');
      metaEl.className = 'message-meta';
      metaEl.textContent = msg.timestamp.toLocaleTimeString('ja-JP');

      msgEl.appendChild(contentEl);
      msgEl.appendChild(metaEl);
      this.messagesEl.appendChild(msgEl);
    });

    // Scroll to bottom
    this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
  }

  addSystemMessage(text) {
    const msgEl = document.createElement('div');
    msgEl.className = 'system-message';
    msgEl.textContent = text;
    this.messagesEl.appendChild(msgEl);
  }

  async updateFingerprintDisplay() {
    const fingerprintEl = document.getElementById('fingerprint-display');
    if (!fingerprintEl) return;

    if (!this.currentPeerId) {
      fingerprintEl.style.display = 'none';
      return;
    }

    const peerInfo = this.peers.get(this.currentPeerId);
    if (!peerInfo || !peerInfo.publicKey) {
      fingerprintEl.style.display = 'none';
      return;
    }

    // Generate fingerprints
    const ownFingerprint = await this.crypto.getOwnFingerprint();
    const peerFingerprint = await this.crypto.generateFingerprint(peerInfo.publicKey);

    // Update display
    fingerprintEl.style.display = 'block';
    fingerprintEl.innerHTML = `
      <div class="fingerprint-header">
        <span class="fingerprint-icon">🔑</span>
        <span class="fingerprint-title">Identity Key Fingerprints</span>
        <button class="fingerprint-toggle" aria-label="閉じる">−</button>
      </div>
      <div class="fingerprint-content">
        <div class="fingerprint-item">
          <div class="fingerprint-label">あなた (${this.clientId}):</div>
          <div class="fingerprint-value">${ownFingerprint}</div>
        </div>
        <div class="fingerprint-item">
          <div class="fingerprint-label">相手 (${this.currentPeerId}):</div>
          <div class="fingerprint-value">${peerFingerprint}</div>
        </div>
        <div class="fingerprint-note">
          ⚠️ これらの数字を帯域外（電話、対面など）で確認してください。
          一致すれば中間者攻撃を受けていません。
        </div>
      </div>
    `;

    // Add toggle functionality
    const toggleBtn = fingerprintEl.querySelector('.fingerprint-toggle');
    const content = fingerprintEl.querySelector('.fingerprint-content');
    toggleBtn.addEventListener('click', () => {
      content.classList.toggle('collapsed');
      toggleBtn.textContent = content.classList.contains('collapsed') ? '+' : '−';
    });
  }
}

// Initialize chat client when page loads
document.addEventListener('DOMContentLoaded', () => {
  new ChatClient();
});
