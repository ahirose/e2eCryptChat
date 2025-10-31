// Chat Client with E2E Encryption

class ChatClient {
  constructor() {
    this.ws = null;
    this.crypto = new E2ECrypto();
    this.clientId = this.generateClientId();
    this.currentPeerId = null;
    this.peers = new Map(); // Map of peerId -> { keyExchanged: boolean }
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
    this.messageInput = document.getElementById('message-input');
    this.sendButton = document.getElementById('send-button');
    this.currentPeerEl = document.getElementById('current-peer-name');

    this.userIdEl.textContent = this.clientId;

    this.messageForm.addEventListener('submit', (e) => {
      e.preventDefault();
      this.sendMessage();
    });
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
        await this.handleKeyExchange(message.fromId, message.publicKey);
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

  async handleKeyExchange(peerId, publicKey) {
    // Derive shared secret with peer's public key
    await this.crypto.deriveSharedSecret(publicKey, peerId);

    const peerInfo = this.peers.get(peerId);
    if (peerInfo) {
      peerInfo.keyExchanged = true;
      this.renderPeersList();
      console.log(`Key exchange completed with ${peerId}`);

      // If this is not the first time, send our public key back
      if (!peerInfo.responseSent) {
        await this.initiateKeyExchange(peerId);
        peerInfo.responseSent = true;
      }
    }
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
        // Show notification (could be enhanced with browser notifications)
        console.log(`New message from ${fromId}`);
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
}

// Initialize chat client when page loads
document.addEventListener('DOMContentLoaded', () => {
  new ChatClient();
});
