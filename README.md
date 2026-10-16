# Whisper

Whisper is a web chat for two people. Message text is encrypted in the browser before it is sent, and the server stores ciphertext.

You can sign in with a username and password. Gmail sign-in works after you add a Google OAuth client.

## Run it

Node.js 24 or newer is required.

```bash
npm install
npm test
npm run dev
```

Open [http://localhost:5173](http://localhost:5173). Create two accounts, then start a chat with the other person's username.

On a phone or another computer on the same Wi-Fi, start the page with `npm run dev -w @whisper/client -- --host` and open the `https://` Network address Vite prints, such as `https://192.168.0.193:5173`. Continue past the certificate warning. A plain `http://` address hides the browser encryption API, so sign-in cannot run there.

Each browser tab keeps its own session, so you can log in as two people in two tabs on the same machine.

## Gmail

1. In Google Cloud, create an OAuth web client.
2. Set the redirect URI to `http://localhost:3001/api/auth/google/callback`.
3. Copy `.env.example` to `.env` and fill in `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`.
4. Restart `npm run dev`.

Gmail only proves who you are. The first time you sign in, Whisper asks for an encryption passphrase. That passphrase wraps your private keys and is not sent to the server. On a new browser, enter it again to unlock older messages.

Username accounts use the account password for that same wrapping step. The login request sends a verifier derived from the password, not the password itself.

## What the encryption does

Each account has an encryption key pair and a signing key pair, generated in the browser.

- Private keys are encrypted with AES-GCM before they are saved. The wrapping key comes from PBKDF2 over the password or passphrase.
- Each message is encrypted to the recipient with a fresh ephemeral P-256 key and AES-GCM. A second copy is encrypted to the sender so they can read their own history on another browser.
- Pictures and documents are encrypted with their own key before upload. The filename and that key travel inside the encrypted message, so the stored file is ciphertext. Each file can be up to 8 MB. A picture can be rotated and cropped in the browser before it is sent, including a photo just taken with the phone camera.
- Voice messages are recorded in the browser and encrypted the same way before upload. A recording can be up to 3 minutes.
- Replies and forwards are part of that same encrypted message. A reply stores a short quote. A forward copies the text, and any file is encrypted again for the destination chat.
- A chat can pin up to five messages. Everyone in the chat sees the same pins, numbered, with a short preview of who pinned each one. The pin only records which message it is; the text stays encrypted.
- Deleting a message removes its ciphertext for both people. A picture, document, or voice message attached to it is removed too.
- Editing a message replaces its ciphertext for both people and marks it edited. The original time stays. Only the sender can edit.
- Collect replies turns a message into a folder. Replies, including pictures, show on the folder. Open the folder to read them. Both people see the same folder.
- A group chat encrypts each message separately for every current member, up to 16 people. The person who starts the group is its admin and can add or remove people later. The server stores those copies and cannot read them. Someone who joins later does not receive older messages. The group name is visible to the server, the same way usernames are.
- The sender signs the ciphertext. The recipient checks that signature before showing the text.
- The conversation header shows a safety number. Compare it with the other person on a call or in person.

The server checks signatures so it can reject forged ciphertext. It does not have the private keys, so it cannot read the message text.

The server can still see account names, who talks to whom, timestamps, and the size of each ciphertext. Read receipts and typing signals are connection metadata.

If someone later copies a recipient's private key, they can decrypt messages sent to that key. Replacing your keys from the profile menu starts a new key pair; older messages stay unreadable.

A web app can only be end-to-end encrypted if the page you load is the real Whisper code. Use it on a machine and origin you trust.
