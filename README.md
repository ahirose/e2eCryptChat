# E2E暗号化チャットアプリ（Double Ratchet対応）

WebブラウザでEnd-to-End（E2E）暗号化を実装したリアルタイムチャットアプリケーションです。Signal Protocolの**Double Ratchetアルゴリズム**を採用し、前方秘匿性と後方秘匿性を実現しています。

## 特徴

- **🔐 Double Ratchet暗号化**: Signal MessengerやWhatsAppと同じプロトコル
- **🛡️ 前方秘匿性（Forward Secrecy）**: 鍵が漏洩しても過去のメッセージは安全
- **🔄 後方秘匿性（Future Secrecy）**: 鍵が漏洩しても将来のメッセージは安全
- **🔑 自動鍵回転**: メッセージごとに異なる暗号化鍵を使用
- **🌐 完全なE2E暗号化**: すべてのメッセージはクライアント側で暗号化され、サーバーでは復号化できません
- **📱 PWA対応**: インストール可能なプログレッシブWebアプリ
- **🔔 通知機能**: チャット中でない相手からのメッセージを通知
- **🎨 Cyberpunk 2077風UI**: ネオンカラー、グリッチエフェクト、未来的デザイン
- **📱 レスポンシブUI**: スマートフォン・タブレット対応のモバイルフレンドリーなデザイン
- **🔒 サブリソース整合性（SRI）**: JavaScriptファイルの改ざんを検知
- **⚡ リアルタイム通信**: WebSocketによる低遅延のメッセージ配信
- **👥 マルチユーザー対応**: 複数のユーザーが同時に接続可能
- **🌍 Web Crypto API**: ブラウザ標準のWeb Crypto APIを使用した暗号処理

## セキュリティアーキテクチャ

### Double Ratchetアルゴリズム

このアプリケーションは、Signal Protocolの中核を成す**Double Ratchet**アルゴリズムを実装しています。

```
        メッセージ1      メッセージ2      メッセージ3
             ↓              ↓              ↓
   RK → [DH] → RK' → [DH] → RK'' → [DH] → RK'''  (DHラチェット)
         ↓              ↓              ↓
        CK1 → MK1      CK2 → MK2      CK3 → MK3   (対称鍵ラチェット)
         ↓              ↓              ↓
     暗号文1         暗号文2         暗号文3
```

#### 2つのラチェット

1. **DHラチェット（Diffie-Hellmanラチェット）**
   - メッセージターンごとにエフェメラル鍵ペアを生成
   - 新しい共有秘密鍵を導出してルート鍵を更新
   - 前方秘匿性と後方秘匿性を実現

2. **対称鍵ラチェット（Symmetric-key ratchet）**
   - チェーン鍵（CK）からメッセージ鍵（MK）を導出
   - 各メッセージに一意の暗号化鍵を使用
   - HMAC-SHA256による鍵導出

### 暗号化プロセス

#### 初期セットアップ

1. **ID鍵ペア生成**: 各クライアントがECDH鍵ペア（公開鍵/秘密鍵）を生成
2. **ID鍵交換**: 公開鍵をサーバー経由で交換（サーバーは内容を読めません）
3. **ルート鍵導出**: ECDH + HKDFによりルート鍵を生成
4. **エフェメラル鍵交換**: Alice/Bob判定後、初回エフェメラル鍵を交換

#### メッセージ送信

5. **チェーン鍵の更新**: `HMAC(CK, 0x01)` → 次のチェーン鍵
6. **メッセージ鍵の導出**: `HMAC(CK, 0x02)` → メッセージ鍵
7. **暗号化**: AES-GCM-256でメッセージを暗号化
8. **ヘッダー付加**: DH公開鍵、メッセージ番号などのヘッダーを付加
9. **送信**: 暗号化されたデータのみをサーバー経由で送信

#### メッセージ受信

10. **DHラチェット判定**: 新しいDH公開鍵なら、DHラチェットを実行
11. **鍵導出**: 受信チェーン鍵からメッセージ鍵を導出
12. **復号化**: AES-GCMで暗号文を復号化
13. **表示**: 平文メッセージをUIに表示

### 使用技術

#### 暗号化プリミティブ

- **ECDH (Elliptic Curve Diffie-Hellman)**
  - 曲線: P-256 (secp256r1 / NIST P-256)
  - 用途: ID鍵とエフェメラル鍵による鍵交換

- **HKDF (HMAC-based Key Derivation Function)**
  - ハッシュ: SHA-256
  - 用途: ルート鍵とチェーン鍵の導出

- **HMAC (Hash-based Message Authentication Code)**
  - ハッシュ: SHA-256
  - 用途: チェーン鍵とメッセージ鍵の導出

- **AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)**
  - 鍵長: 256ビット
  - IV長: 12バイト (ランダム生成)
  - 認証付き暗号化により改ざん検知も実現

#### セキュリティ特性

| 特性 | 説明 |
|------|------|
| **前方秘匿性** | セッション鍵が漏洩しても過去のメッセージは安全 |
| **後方秘匿性** | 鍵が漏洩しても、DHラチェット後は再び安全 |
| **メッセージ単位の鍵** | 全メッセージが異なる鍵で暗号化 |
| **認証付き暗号化** | AES-GCMにより改ざん検知 |
| **リプレイ攻撃耐性** | メッセージ番号による順序保証 |

## プロジェクト構造

```
e2eCryptJS/
├── server.js              # WebSocketサーバー
├── package.json           # プロジェクト設定
├── generate-sri.sh        # SRIハッシュ生成スクリプト
├── public/
│   ├── index.html         # チャットUI (SRI対応)
│   ├── style.css          # Cyberpunk 2077風スタイルシート
│   ├── crypto.js          # Double Ratchet暗号化ライブラリ
│   ├── client.js          # チャットクライアントロジック
│   ├── manifest.json      # PWAマニフェスト
│   └── favicon.svg        # Cyberpunk風アイコン
└── README.md             # このファイル
```

## セットアップ

### 必要要件

- Node.js 14以上
- モダンなWebブラウザ (Chrome, Firefox, Safari, Edge)
  - Web Crypto API対応必須

### インストール

1. リポジトリをクローン:
```bash
git clone <repository-url>
cd e2eCryptJS
```

2. 依存パッケージをインストール:
```bash
npm install
```

### 起動

サーバーを起動:
```bash
npm start
```

ブラウザで以下にアクセス:
```
http://localhost:3000
```

複数のタブまたはブラウザを開いて、異なるユーザーとしてチャットできます。

## PWA対応

このアプリケーションはプログレッシブWebアプリ（PWA）として動作します。

### インストール方法

#### デスクトップ（Chrome/Edge）
1. ブラウザのアドレスバー右端の「インストール」アイコンをクリック
2. 確認ダイアログで「インストール」をクリック
3. デスクトップアプリとして起動可能に

#### モバイル（Android/iOS）
1. ブラウザのメニューから「ホーム画面に追加」を選択
2. アイコンが追加され、アプリとして起動可能に

### PWA機能

- **オフライン対応**: Service Worker（将来実装予定）
- **インストール可能**: デスクトップ/モバイルにインストール
- **スタンドアロンモード**: ブラウザUIなしで起動
- **テーマカラー**: Cyberpunkテーマ（#00ffff）

## Cyberpunk 2077風UI

このアプリケーションは、Cyberpunk 2077のゲームUIにインスパイアされた未来的なデザインを採用しています。

### デザイン要素

#### カラーパレット
- **シアン（Cyan）**: `#00ffff` - メインアクセントカラー
- **マゼンタ（Magenta）**: `#ff00ff` - セカンダリアクセント
- **ネオングリーン**: `#00ff41` - 接続状態表示
- **ネオンレッド**: `#ff0040` - エラーや切断状態
- **ダークブルー**: `#0a0e27` / `#050814` - 背景色

#### ビジュアルエフェクト

1. **スキャンラインエフェクト**: ブラウン管モニター風の走査線を画面全体に表示
2. **グリッチアニメーション**: タイトルが時々グリッチして、Cyberpunkの世界観を演出
3. **ネオングロー**: ボーダーやテキストが発光するエフェクト
4. **ホログラム風の光**: ヘッダー部分に流れる光のアニメーション
5. **角切りデザイン**: 未来的な角度のついたclip-path
6. **発光ボーダー**: サイドバーやメッセージフォームの動的なボーダーアニメーション

#### タイポグラフィ
- **Orbitron**: 見出しやボタンに使用する未来的なフォント
- **Rajdhani**: 本文に使用する読みやすいモノスペース風フォント
- 文字間隔（letter-spacing）を広げて、デジタル感を強調

#### インタラクション
- ホバー時にネオングローが強まる
- ボタンクリック時の波紋エフェクト
- スムーズなトランジションとアニメーション
- メッセージ表示時のスライドインアニメーション

### パフォーマンス最適化

すべてのアニメーションとエフェクトは、CSSのGPUアクセラレーションを使用して実装されており、
スムーズな60fpsでの動作を保証します。

## 使い方

### 基本的な使い方

1. ブラウザでアプリを開くと、自動的にユニークなユーザーIDが割り当てられます
2. 他のユーザーが参加すると、左側のサイドバーに表示されます
3. 鍵交換が完了すると、ユーザーアイテムに🔒が表示されます
4. チャットしたいユーザーをクリックして選択
5. メッセージを入力して送信

### 通知機能

現在チャット中でない相手からメッセージが届くと、画面右上に**通知**が表示されます。

- **自動消去**: 5秒後に自動的に消えます
- **クリックで移動**: 通知をクリックすると、その相手とのチャットに切り替わります
- **手動で閉じる**: ×ボタンで即座に閉じられます

### スマートフォンでの使い方

モバイルデバイスでは、以下の操作でユーザーリストにアクセスできます：

1. **ハンバーガーメニュー（☰）をタップ**: 画面左上のメニューボタンでユーザーリストを開く
2. **チャット相手を選択**: リストからユーザーをタップ
3. **自動的にチャット画面へ**: ユーザーを選択すると自動的にメニューが閉じて、チャット画面に戻ります
4. **オーバーレイをタップ**: メニュー外の暗い部分をタップしても閉じられます

モバイル対応機能：
- タッチフレンドリーなボタンサイズ
- 縦持ち・横持ち両方に対応
- スワイプ可能なサイドバー
- 動的ビューポート高さ対応（アドレスバーを考慮）
- 入力フォーカス時の自動ズーム防止

## サブリソース整合性（SRI）

このアプリケーションは、JavaScriptファイルの改ざんを検知するためにサブリソース整合性（SRI）を実装しています。

### SRIとは

SRI（Subresource Integrity）は、ブラウザがダウンロードしたリソース（JavaScriptやCSS）が改ざんされていないことを検証するセキュリティ機能です。HTMLに埋め込まれたハッシュ値と実際のファイルのハッシュ値を比較し、一致しない場合はリソースの読み込みをブロックします。

### SRIの利点

- **改ざん検知**: CDNやサーバーが侵害された場合でも、改ざんされたJavaScriptの実行を防止
- **中間者攻撃対策**: ネットワーク経路でスクリプトが書き換えられても検知可能
- **信頼性**: コードの整合性を保証

### JavaScriptファイルを更新した場合

`crypto.js` または `client.js` を変更した場合は、SRIハッシュを再生成する必要があります：

```bash
./generate-sri.sh
```

このスクリプトは新しいSHA-384ハッシュを生成し、`index.html`に追加すべきコードを表示します。

### 手動でSRIハッシュを生成

```bash
# crypto.js のハッシュ生成
openssl dgst -sha384 -binary public/crypto.js | openssl base64 -A

# client.js のハッシュ生成
openssl dgst -sha384 -binary public/client.js | openssl base64 -A
```

生成されたハッシュを`index.html`の`integrity`属性に設定してください。

## セキュリティに関する注意事項

### このアプリケーションの保護対象

- ✅ **サーバーからの盗聴**: サーバーはメッセージの内容を読めません
- ✅ **中間者攻撃（部分的）**: メッセージ内容は暗号化されています
- ✅ **改ざん検知**: AES-GCMにより改ざんを検知できます
- ✅ **前方秘匿性**: 過去のメッセージは鍵漏洩後も安全
- ✅ **後方秘匿性**: 将来のメッセージは鍵漏洩から回復
- ✅ **リプレイ攻撃**: メッセージ番号による順序保証

### このアプリケーションでは保護できないこと

- ❌ **鍵交換時の中間者攻撃**: 公開鍵の真正性を検証する仕組みがありません
  - 改善策: 公開鍵フィンガープリントを帯域外で確認する機能の追加
- ❌ **メタデータの保護**: 誰が誰とチャットしているかはサーバーに見えます
  - 改善策: Torやミキシングネットワークの使用
- ❌ **HTMLファイルの改ざん**: index.htmlが改ざんされるとSRIも無効化される
  - 改善策: HTTPS必須、Content Security Policy (CSP) の実装
- ❌ **エンドポイントセキュリティ**: クライアント端末がマルウェアに感染している場合
  - 改善策: セキュアブート、アンチウイルス、OS更新

### 本番環境での使用について

このアプリケーションは教育目的のデモンストレーションです。本番環境で使用する場合は、以下の追加対策が必要です:

1. **HTTPS/WSS**: 必ずHTTPS/WSSを使用（TLS 1.3推奨）
2. **身元確認**: 公開鍵フィンガープリントの検証機能（Safety Numbers）
3. **完全性チェック**: ✅ SRIによるスクリプトの整合性確認（実装済み）
4. **永続化**: メッセージの暗号化された保存
5. **認証**: ユーザー認証システムの実装
6. **CSP**: Content Security Policyの実装
7. **監査**: セキュリティ専門家によるコードレビュー
8. **Service Worker**: オフライン対応とキャッシュ管理
9. **鍵のバックアップ**: 安全な鍵のバックアップ・リストア機能
10. **グループチャット**: マルチデバイス・グループ対応

## 技術的な詳細

### crypto.js

#### DoubleRatchetCryptoクラス

Double Ratchetアルゴリズムを実装するコアクラス:

**鍵管理**:
- `generateIdentityKeyPair()`: ID鍵ペア（ECDH P-256）の生成
- `generateEphemeralKeyPair()`: エフェメラル鍵ペアの生成
- `exportPublicKey()` / `exportEphemeralPublicKey()`: 公開鍵のエクスポート（Base64）
- `importPublicKey()`: 公開鍵のインポート

**鍵導出**:
- `hkdf()`: HMAC-based鍵導出関数（HKDF-SHA256）
- `kdfChain()`: チェーン鍵からメッセージ鍵を導出
- `kdfRoot()`: ルート鍵とチェーン鍵を導出
- `performDH()`: Diffie-Hellman鍵交換

**ラチェット**:
- `dhRatchet()`: DHラチェットステップの実行
- `initializeSessionAsAlice()`: Aliceとしてセッション初期化
- `initializeSessionAsBob()`: Bobとしてセッション初期化

**暗号化/復号化**:
- `encrypt(message, peerId)`: メッセージの暗号化
  - 返り値: `{ header, iv, ciphertext }`
  - ヘッダーにDH公開鍵、メッセージ番号を含む
- `decrypt(encryptedMessage, peerId)`: メッセージの復号化
  - ヘッダーからDHラチェットの必要性を判定
  - 受信チェーン鍵から適切なメッセージ鍵を導出

#### RatchetSessionクラス

セッション状態を管理:

```javascript
{
  peerId: string,                 // ピアID
  rootKey: Uint8Array,            // ルート鍵 (RK)
  sendingChainKey: Uint8Array,    // 送信チェーン鍵 (CKs)
  receivingChainKey: Uint8Array,  // 受信チェーン鍵 (CKr)
  dhSelf: CryptoKeyPair,          // 自分のエフェメラルDH鍵ペア
  dhPeer: CryptoKey,              // 相手のエフェメラルDH公開鍵
  sendMessageNumber: number,      // 送信メッセージ番号
  receiveMessageNumber: number,   // 受信メッセージ番号
  previousSendingChainLength: number
}
```

#### E2ECryptoクラス

後方互換性のためのラッパークラス:
- `setClientId()`: クライアントIDの設定（Alice/Bob判定用）
- `deriveSharedSecret()`: 簡易セッション初期化
- `handleEphemeralKey()`: エフェメラル鍵交換の処理

### client.js

チャットクライアントの実装:

**初期化**:
- `constructor()`: WebSocketとUIの初期化
- `crypto.setClientId()`: Double Ratchet用のID設定

**鍵交換**:
- `initiateKeyExchange()`: ID公開鍵の送信
- `handleKeyExchange()`: ID公開鍵の受信とセッション初期化
- `handleEphemeralKeyExchange()`: エフェメラル鍵の受信

**メッセージング**:
- `sendMessage()`: メッセージの暗号化と送信
- `handleEncryptedMessage()`: 暗号文の受信と復号化

**通知**:
- `showNotification()`: 非アクティブピアからのメッセージ通知
- `closeNotification()`: 通知の消去

**モバイルUI**:
- `toggleSidebar()`: サイドバーの開閉
- レスポンシブメニュー管理

### サーバー (server.js)

WebSocketサーバーの役割:

- クライアント接続の管理
- 暗号化されたメッセージの中継（内容は読めない）
- ピア検出の支援
- 公開鍵交換の中継（`key_exchange`）
- エフェメラル鍵交換の中継（`ephemeral_key_exchange`）

**重要**: サーバーは暗号化されたデータのみを扱い、秘密鍵や平文メッセージにはアクセスできません。完全なE2E暗号化を実現しています。

## Double Ratchetの動作詳細

### メッセージ送信時のフロー

```javascript
// 1. セッション取得
const session = this.sessions.get(peerId);

// 2. 送信チェーンがなければDHラチェット
if (!session.dhSelf) {
  session.dhSelf = await generateEphemeralKeyPair();
  const dhOutput = await performDH(session.dhSelf.privateKey, session.dhPeer);
  const { rootKey, chainKey } = await kdfRoot(session.rootKey, dhOutput);
  session.rootKey = rootKey;
  session.sendingChainKey = chainKey;
}

// 3. チェーン鍵からメッセージ鍵を導出
const { chainKey, messageKey } = await kdfChain(session.sendingChainKey);
session.sendingChainKey = chainKey;

// 4. AES-GCMで暗号化
const ciphertext = await AES_GCM_encrypt(messageKey, plaintext, iv);

// 5. ヘッダーと暗号文を返す
return {
  header: { dhPublicKey, messageNumber, previousChainLength },
  iv,
  ciphertext
};
```

### メッセージ受信時のフロー

```javascript
// 1. ヘッダーからDH公開鍵を確認
const peerPublicKey = await importPublicKey(header.dhPublicKey);

// 2. 新しいDH公開鍵ならDHラチェット実行
if (currentPeerKey !== header.dhPublicKey) {
  await dhRatchet(session, peerPublicKey);
}

// 3. 受信チェーン鍵から適切なメッセージ鍵を導出
let messageKey = session.receivingChainKey;
for (let i = session.receiveMessageNumber; i < header.messageNumber; i++) {
  const result = await kdfChain(messageKey);
  messageKey = result.chainKey;
}
const { chainKey, messageKey: finalMessageKey } = await kdfChain(messageKey);
session.receivingChainKey = chainKey;

// 4. AES-GCMで復号化
const plaintext = await AES_GCM_decrypt(finalMessageKey, ciphertext, iv);
```

## 参考資料

### Double Ratchet / Signal Protocol
- [The Double Ratchet Algorithm - Signal](https://signal.org/docs/specifications/doubleratchet/)
- [Signal Protocol - Wikipedia](https://en.wikipedia.org/wiki/Signal_Protocol)
- [libsignal-protocol](https://github.com/signalapp/libsignal)

### Web Crypto API
- [Web Crypto API - MDN](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [ECDH - Wikipedia](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)
- [AES-GCM - Wikipedia](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
- [HKDF - RFC 5869](https://tools.ietf.org/html/rfc5869)

### PWA
- [Progressive Web Apps - MDN](https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps)
- [Web App Manifest - W3C](https://www.w3.org/TR/appmanifest/)

### セキュリティ
- [Subresource Integrity - W3C](https://www.w3.org/TR/SRI/)
- [Content Security Policy - MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

## ライセンス

MIT

## 貢献

プルリクエストを歓迎します。大きな変更の場合は、まずissueを開いて変更内容を議論してください。

## 著者

このプロジェクトは、E2E暗号化とDouble Ratchetアルゴリズムの学習目的で作成されました。
