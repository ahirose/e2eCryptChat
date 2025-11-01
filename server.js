const http = require('http');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');

const PORT = process.env.PORT || 3000;

// Create HTTP server
const server = http.createServer((req, res) => {
  let filePath = req.url === '/' ? '/index.html' : req.url;
  filePath = path.join(__dirname, 'public', filePath);

  const extname = path.extname(filePath);
  const contentTypeMap = {
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.svg': 'image/svg+xml',
    '.png': 'image/png'
  };

  const contentType = contentTypeMap[extname] || 'text/plain';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/html' });
        res.end('<h1>404 Not Found</h1>', 'utf-8');
      } else {
        res.writeHead(500);
        res.end('Server Error: ' + err.code, 'utf-8');
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content, 'utf-8');
    }
  });
});

// Create WebSocket server
const wss = new WebSocket.Server({ server });

const clients = new Map(); // Map of clientId -> WebSocket

wss.on('connection', (ws) => {
  let clientId = null;

  console.log('New client connected');

  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data.toString());

      switch (message.type) {
        case 'register':
          // Register client with ID
          clientId = message.clientId;
          clients.set(clientId, ws);
          console.log(`Client registered: ${clientId}`);

          // Notify all other clients about new peer
          broadcast({
            type: 'peer_joined',
            peerId: clientId
          }, clientId);

          // Send list of existing peers to new client
          const existingPeers = Array.from(clients.keys()).filter(id => id !== clientId);
          ws.send(JSON.stringify({
            type: 'peer_list',
            peers: existingPeers
          }));
          break;

        case 'key_exchange':
          // Forward public key to target peer
          const targetClient = clients.get(message.targetId);
          if (targetClient && targetClient.readyState === WebSocket.OPEN) {
            targetClient.send(JSON.stringify({
              type: 'key_exchange',
              fromId: clientId,
              publicKey: message.publicKey,
              ephemeralKey: message.ephemeralKey
            }));
          }
          break;

        case 'ephemeral_key_exchange':
          // Forward ephemeral key to target peer (for Double Ratchet)
          const ephemeralTargetClient = clients.get(message.targetId);
          if (ephemeralTargetClient && ephemeralTargetClient.readyState === WebSocket.OPEN) {
            ephemeralTargetClient.send(JSON.stringify({
              type: 'ephemeral_key_exchange',
              fromId: clientId,
              ephemeralKey: message.ephemeralKey
            }));
          }
          break;

        case 'encrypted_message':
          // Forward encrypted message to target peer
          const recipientClient = clients.get(message.recipientId);
          if (recipientClient && recipientClient.readyState === WebSocket.OPEN) {
            recipientClient.send(JSON.stringify({
              type: 'encrypted_message',
              fromId: clientId,
              encryptedData: message.encryptedData
            }));
          }
          break;

        default:
          console.log('Unknown message type:', message.type);
      }
    } catch (error) {
      console.error('Error processing message:', error);
    }
  });

  ws.on('close', () => {
    if (clientId) {
      clients.delete(clientId);
      console.log(`Client disconnected: ${clientId}`);

      // Notify all clients about peer leaving
      broadcast({
        type: 'peer_left',
        peerId: clientId
      });
    }
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

// Broadcast message to all clients except sender
function broadcast(message, excludeClientId) {
  const messageStr = JSON.stringify(message);
  clients.forEach((client, id) => {
    if (id !== excludeClientId && client.readyState === WebSocket.OPEN) {
      client.send(messageStr);
    }
  });
}

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
