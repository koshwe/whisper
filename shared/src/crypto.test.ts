import assert from "node:assert/strict";
import test from "node:test";
import {
  decryptFile,
  decryptGroupMessage,
  decryptMessage,
  deriveAuthVerifier,
  encryptFile,
  encryptGroupMessage,
  encryptMessage,
  generateIdentity,
  packPayload,
  safetyNumber,
  sha256Base64,
  unpackPayload,
  unwrapIdentity,
  wrapIdentity,
} from "./crypto.ts";

test("encrypts a message for the recipient and keeps a copy the sender can read", async () => {
  const alice = await generateIdentity();
  const bob = await generateIdentity();
  const envelope = await encryptMessage({
    identity: alice,
    recipientEcdhPublic: bob.ecdhPublic,
    conversationId: "conversation-1",
    senderId: "alice-id",
    plaintext: "meet at the north gate",
  });

  const asBob = await decryptMessage({
    envelope,
    conversationId: "conversation-1",
    senderId: "alice-id",
    senderEcdsaPublic: alice.ecdsaPublic,
    myEcdhPrivate: bob.ecdhPrivate,
    copy: "recipient",
  });
  const asAlice = await decryptMessage({
    envelope,
    conversationId: "conversation-1",
    senderId: "alice-id",
    senderEcdsaPublic: alice.ecdsaPublic,
    myEcdhPrivate: alice.ecdhPrivate,
    copy: "sender",
  });

  assert.equal(asBob, "meet at the north gate");
  assert.equal(asAlice, "meet at the north gate");
  assert.equal(JSON.stringify(envelope).includes("meet at the north gate"), false);
});

test("rejects a tampered ciphertext", async () => {
  const alice = await generateIdentity();
  const bob = await generateIdentity();
  const envelope = await encryptMessage({
    identity: alice,
    recipientEcdhPublic: bob.ecdhPublic,
    conversationId: "conversation-1",
    senderId: "alice-id",
    plaintext: "unchanged",
  });
  const chars = envelope.forRecipient.ciphertext.split("");
  chars[8] = chars[8] === "A" ? "B" : "A";
  envelope.forRecipient.ciphertext = chars.join("");

  await assert.rejects(() =>
    decryptMessage({
      envelope,
      conversationId: "conversation-1",
      senderId: "alice-id",
      senderEcdsaPublic: alice.ecdsaPublic,
      myEcdhPrivate: bob.ecdhPrivate,
      copy: "recipient",
    }),
  );
});

test("rejects decryption by someone who is not the recipient", async () => {
  const alice = await generateIdentity();
  const bob = await generateIdentity();
  const carol = await generateIdentity();
  const envelope = await encryptMessage({
    identity: alice,
    recipientEcdhPublic: bob.ecdhPublic,
    conversationId: "conversation-1",
    senderId: "alice-id",
    plaintext: "only bob",
  });

  await assert.rejects(() =>
    decryptMessage({
      envelope,
      conversationId: "conversation-1",
      senderId: "alice-id",
      senderEcdsaPublic: alice.ecdsaPublic,
      myEcdhPrivate: carol.ecdhPrivate,
      copy: "recipient",
    }),
  );
});

test("encrypts a group message so each member can read only their copy", async () => {
  const alice = await generateIdentity();
  const bob = await generateIdentity();
  const carol = await generateIdentity();
  const secret = "the north gate is open";
  const envelope = await encryptGroupMessage({
    identity: alice,
    conversationId: "group-1",
    senderId: "alice-id",
    plaintext: secret,
    members: [
      { userId: "alice-id", ecdhPublic: alice.ecdhPublic },
      { userId: "bob-id", ecdhPublic: bob.ecdhPublic },
      { userId: "carol-id", ecdhPublic: carol.ecdhPublic },
    ],
  });
  assert.equal(JSON.stringify(envelope).includes(secret), false);
  for (const [memberId, keys] of [["bob-id", bob], ["carol-id", carol], ["alice-id", alice]] as const) {
    const copy = envelope.copies.find((item) => item.userId === memberId);
    assert.ok(copy);
    const opened = await decryptGroupMessage({
      conversationId: "group-1",
      senderId: "alice-id",
      nonce: envelope.nonce,
      memberId,
      bundle: copy,
      signature: copy.signature,
      senderEcdsaPublic: alice.ecdsaPublic,
      myEcdhPrivate: keys.ecdhPrivate,
    });
    assert.equal(opened, secret);
  }
  const bobCopy = envelope.copies.find((item) => item.userId === "bob-id");
  assert.ok(bobCopy);
  await assert.rejects(() => decryptGroupMessage({
    conversationId: "group-1",
    senderId: "alice-id",
    nonce: envelope.nonce,
    memberId: "bob-id",
    bundle: bobCopy,
    signature: bobCopy.signature,
    senderEcdsaPublic: alice.ecdsaPublic,
    myEcdhPrivate: carol.ecdhPrivate,
  }));
});

test("wraps private keys so only the password can unwrap them", async () => {
  const identity = await generateIdentity();
  const wrapped = await wrapIdentity(identity, "correct horse battery");
  const restored = await unwrapIdentity(wrapped, "correct horse battery");
  assert.equal(restored.ecdhPublic, identity.ecdhPublic);
  assert.equal(restored.ecdsaPublic, identity.ecdsaPublic);
  assert.equal(JSON.stringify(wrapped).includes("correct horse battery"), false);

  await assert.rejects(() => unwrapIdentity(wrapped, "wrong password"));
});

test("derives the same login verifier for the same username and password", async () => {
  const first = await deriveAuthVerifier("Alice", "a-long-password");
  const second = await deriveAuthVerifier("alice", "a-long-password");
  const otherUser = await deriveAuthVerifier("bob", "a-long-password");
  assert.equal(first, second);
  assert.notEqual(first, otherUser);
});

test("encrypts a file so only the file key can read it", async () => {
  const original = new TextEncoder().encode("quarterly-report-bytes");
  const encrypted = await encryptFile(original);
  const opened = await decryptFile(encrypted.ciphertext, encrypted.key, encrypted.iv);
  assert.equal(new TextDecoder().decode(opened), "quarterly-report-bytes");
  assert.equal(new TextDecoder().decode(encrypted.ciphertext).includes("quarterly-report-bytes"), false);
  const digest = await sha256Base64(encrypted.ciphertext);
  encrypted.ciphertext[3] ^= 0xff;
  assert.notEqual(await sha256Base64(encrypted.ciphertext), digest);
  await assert.rejects(() => decryptFile(encrypted.ciphertext, encrypted.key, encrypted.iv));
});

test("keeps older text messages readable and packs file metadata", () => {
  assert.deepEqual(unpackPayload("hello"), { text: "hello", file: null, reply: null, forwarded: false });
  const packed = packPayload({
    text: "see this",
    file: { id: "file-1", name: "notes.pdf", type: "application/pdf", size: 12, key: "aa", iv: "bb", sha256: "cc" },
  });
  const unpacked = unpackPayload(packed);
  assert.equal(unpacked.text, "see this");
  assert.equal(unpacked.file?.name, "notes.pdf");
  assert.equal(unpacked.reply, null);
  assert.equal(unpacked.forwarded, false);
  assert.equal(packed.startsWith('{"v":2'), true);
  assert.equal(packed.includes("aa"), true);
});

test("packs a reply and a forwarded copy inside the message", () => {
  const reply = unpackPayload(
    packPayload({
      text: "on it",
      reply: { id: "nonce-1", senderId: "user-1", sender: "Alice", preview: "see this" },
    }),
  );
  assert.equal(reply.text, "on it");
  assert.equal(reply.reply?.sender, "Alice");
  assert.equal(reply.reply?.preview, "see this");
  assert.equal(reply.forwarded, false);

  const forwarded = unpackPayload(
    packPayload({
      text: "see this",
      file: { id: "file-1", name: "notes.pdf", type: "application/pdf", size: 12, key: "aa", iv: "bb", sha256: "cc" },
      forwarded: true,
    }),
  );
  assert.equal(forwarded.forwarded, true);
  assert.equal(forwarded.file?.name, "notes.pdf");
  assert.equal(forwarded.reply, null);
  assert.equal(unpackPayload('{"v":3,"text":"x","reply":{"id":"","senderId":"u","sender":"A","preview":"p"}}').reply, null);
});

test("keeps voice-message length with the encrypted file metadata", () => {
  const unpacked = unpackPayload(
    packPayload({
      text: "",
      file: {
        id: "file-1",
        name: "voice.webm",
        type: "audio/webm",
        size: 12,
        key: "aa",
        iv: "bb",
        sha256: "cc",
        voice: true,
        durationMs: 3200.4,
      },
    }),
  );
  assert.equal(unpacked.file?.voice, true);
  assert.equal(unpacked.file?.durationMs, 3200);
  assert.equal(unpacked.text, "");
});

test("safety numbers do not depend on argument order", async () => {
  const alice = await generateIdentity();
  const bob = await generateIdentity();
  const forward = await safetyNumber(alice.ecdsaPublic, bob.ecdsaPublic);
  const backward = await safetyNumber(bob.ecdsaPublic, alice.ecdsaPublic);
  assert.deepEqual(forward, backward);
  assert.equal(forward.length, 12);
});
