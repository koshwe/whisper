import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
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
  sha256Base64,
  unwrapIdentity,
  wrapIdentity,
  type Identity,
} from "../../shared/src/crypto.ts";
import { createServer } from "../src/app.ts";

type Account = {
  id: string;
  username: string;
  ecdhPublic: string;
  ecdsaPublic: string;
};

async function registerUser(base: string, username: string, password: string, identity: Identity) {
  const wrapped = await wrapIdentity(identity, password);
  const authVerifier = await deriveAuthVerifier(username, password);
  const response = await fetch(`${base}/api/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, displayName: username, authVerifier, ...wrapped }),
  });
  const body = (await response.json()) as { token?: string; user?: Account; error?: string };
  assert.equal(response.status, 201, body.error);
  return { token: body.token as string, user: body.user as Account };
}

test("relays ciphertext and leaves the server unable to read it", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "whisper-"));
  const started = await createServer({ dbPath: path.join(directory, "whisper.sqlite"), port: 0 });
  const base = `http://127.0.0.1:${started.port}`;
  const secret = "swordfish-plaintext-9f3a only the two of us";

  try {
    const config = await fetch(`${base}/api/config`);
    assert.equal((await config.json()).googleEnabled, false);

    const aliceKeys = await generateIdentity();
    const bobKeys = await generateIdentity();
    const alice = await registerUser(base, "alice", "alice-password-1", aliceKeys);
    const bob = await registerUser(base, "bob", "bob-password-22", bobKeys);

    const opened = await fetch(`${base}/api/conversations`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify({ username: "bob" }),
    });
    const openedBody = (await opened.json()) as { conversation: { id: string }; error?: string };
    assert.equal(opened.status, 201, openedBody.error);
    const conversationId = openedBody.conversation.id;

    const people = await fetch(`${base}/api/users`, { headers: { Authorization: `Bearer ${alice.token}` } });
    const peopleBody = (await people.json()) as { users: Array<{ username: string }>; error?: string };
    assert.equal(people.status, 200, peopleBody.error);
    assert.equal(peopleBody.users.some((person) => person.username === "bob"), true);
    const bobChats = await fetch(`${base}/api/conversations`, { headers: { Authorization: `Bearer ${bob.token}` } });
    const bobChatsBody = (await bobChats.json()) as { conversations: Array<{ id: string }> };
    assert.equal(bobChats.status, 200);
    assert.equal(bobChatsBody.conversations.some((conversation) => conversation.id === conversationId), true);

    const envelope = await encryptMessage({
      identity: aliceKeys,
      recipientEcdhPublic: bob.user.ecdhPublic,
      conversationId,
      senderId: alice.user.id,
      plaintext: secret,
    });
    const sent = await fetch(`${base}/api/conversations/${conversationId}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify(envelope),
    });
    const sentBody = (await sent.json()) as { message: { id: string; signature: string }; error?: string };
    assert.equal(sent.status, 201, sentBody.error);
    assert.equal(JSON.stringify(sentBody).includes(secret), false);

    const listed = await fetch(`${base}/api/conversations/${conversationId}/messages`, {
      headers: { Authorization: `Bearer ${bob.token}` },
    });
    const listedBody = (await listed.json()) as {
      messages: Array<{
        id: string;
        senderId: string;
        nonce: string;
        forRecipient: { ephPublic: string; iv: string; ciphertext: string };
        forSender: { ephPublic: string; iv: string; ciphertext: string };
        signature: string;
      }>;
    };
    const stored = listedBody.messages[0];
    const plaintext = await decryptMessage({
      envelope: stored,
      conversationId,
      senderId: alice.user.id,
      senderEcdsaPublic: alice.user.ecdsaPublic,
      myEcdhPrivate: bobKeys.ecdhPrivate,
      copy: "recipient",
    });
    assert.equal(plaintext, secret);

    const collected = await fetch(`${base}/api/conversations/${conversationId}/messages/${stored.id}/collect`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify({ collects: true }),
    });
    assert.equal(collected.status, 200);
    const collectedList = await fetch(`${base}/api/conversations/${conversationId}/messages`, {
      headers: { Authorization: `Bearer ${bob.token}` },
    });
    const collectedBody = (await collectedList.json()) as { messages: Array<{ id: string; collectsReplies: boolean }> };
    assert.equal(collectedBody.messages.find((message) => message.id === stored.id)?.collectsReplies, true);
    const cleared = await fetch(`${base}/api/conversations/${conversationId}/messages/${stored.id}/collect`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${bob.token}` },
      body: JSON.stringify({ collects: false }),
    });
    assert.equal(cleared.status, 200);

    const reacted = await fetch(`${base}/api/conversations/${conversationId}/messages/${stored.id}/react`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${bob.token}` },
      body: JSON.stringify({ emoji: "👍" }),
    });
    assert.equal(reacted.status, 200);
    const reactedList = await fetch(`${base}/api/conversations/${conversationId}/messages`, {
      headers: { Authorization: `Bearer ${alice.token}` },
    });
    const reactedBody = (await reactedList.json()) as { messages: Array<{ id: string; reactions: Array<{ userId: string; emoji: string }> }> };
    assert.deepEqual(reactedBody.messages.find((message) => message.id === stored.id)?.reactions, [{ userId: bob.user.id, emoji: "👍" }]);
    const customReaction = await fetch(`${base}/api/conversations/${conversationId}/messages/${stored.id}/react`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${bob.token}` },
      body: JSON.stringify({ emoji: "⭐" }),
    });
    assert.equal(customReaction.status, 200);
    const rejectedReaction = await fetch(`${base}/api/conversations/${conversationId}/messages/${stored.id}/react`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify({ emoji: "hello" }),
    });
    assert.equal(rejectedReaction.status, 400);
    const clearedReaction = await fetch(`${base}/api/conversations/${conversationId}/messages/${stored.id}/react`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${bob.token}` },
      body: JSON.stringify({ emoji: null }),
    });
    assert.equal(clearedReaction.status, 200);

    const pinned = await fetch(`${base}/api/conversations/${conversationId}/messages/${stored.id}/pin`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify({ pinned: true }),
    });
    const pinnedBody = (await pinned.json()) as { pins?: Array<{ messageId: string; pinnedBy: string }>; error?: string };
    assert.equal(pinned.status, 200, pinnedBody.error);
    assert.equal(pinnedBody.pins?.length, 1);
    assert.equal(pinnedBody.pins?.[0]?.messageId, stored.id);
    assert.equal(pinnedBody.pins?.[0]?.pinnedBy, alice.user.id);
    const seenPins = await fetch(`${base}/api/conversations/${conversationId}/messages`, {
      headers: { Authorization: `Bearer ${bob.token}` },
    });
    const seenPinBody = (await seenPins.json()) as { pins: Array<{ messageId: string }> };
    assert.equal(seenPinBody.pins.length, 1);
    assert.equal(JSON.stringify(seenPinBody).includes(secret), false);
    const extraIds: string[] = [];
    for (let index = 0; index < 4; index += 1) {
      const extra = await encryptMessage({
        identity: aliceKeys,
        recipientEcdhPublic: bob.user.ecdhPublic,
        conversationId,
        senderId: alice.user.id,
        plaintext: `pin-note-${index}`,
      });
      const extraSent = await fetch(`${base}/api/conversations/${conversationId}/messages`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
        body: JSON.stringify(extra),
      });
      const extraBody = (await extraSent.json()) as { message: { id: string }; error?: string };
      assert.equal(extraSent.status, 201, extraBody.error);
      extraIds.push(extraBody.message.id);
      const extraPin = await fetch(`${base}/api/conversations/${conversationId}/messages/${extraBody.message.id}/pin`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${bob.token}` },
        body: JSON.stringify({ pinned: true }),
      });
      assert.equal(extraPin.status, 200);
    }
    const overflow = await encryptMessage({
      identity: aliceKeys,
      recipientEcdhPublic: bob.user.ecdhPublic,
      conversationId,
      senderId: alice.user.id,
      plaintext: "pin-note-overflow",
    });
    const overflowSent = await fetch(`${base}/api/conversations/${conversationId}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify(overflow),
    });
    const overflowBody = (await overflowSent.json()) as { message: { id: string }; error?: string };
    assert.equal(overflowSent.status, 201, overflowBody.error);
    const rejectedPin = await fetch(`${base}/api/conversations/${conversationId}/messages/${overflowBody.message.id}/pin`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify({ pinned: true }),
    });
    assert.equal(rejectedPin.status, 400);
    const unpinned = await fetch(`${base}/api/conversations/${conversationId}/messages/${stored.id}/pin`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify({ pinned: false }),
    });
    const unpinnedBody = (await unpinned.json()) as { pins: Array<{ messageId: string }>; error?: string };
    assert.equal(unpinned.status, 200, unpinnedBody.error);
    assert.equal(unpinnedBody.pins.length, 4);
    assert.equal(unpinnedBody.pins.some((pin) => pin.messageId === stored.id), false);
    assert.equal(extraIds.length, 4);

    const tampered = await fetch(`${base}/api/conversations/${conversationId}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify({ ...envelope, nonce: "AQIDBAUGBwgJCgsMDQ4PEA==", signature: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=" }),
    });
    assert.equal(tampered.status, 400);

    const outsider = await fetch(`${base}/api/conversations/${conversationId}/messages`);
    assert.equal(outsider.status, 401);

    const revised = "swordfish-revised-2c8b only the two of us";
    const editedEnvelope = await encryptMessage({
      identity: aliceKeys,
      recipientEcdhPublic: bob.user.ecdhPublic,
      conversationId,
      senderId: alice.user.id,
      plaintext: revised,
      nonce: stored.nonce,
    });
    const blockedEdit = await fetch(`${base}/api/conversations/${conversationId}/messages/${stored.id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${bob.token}` },
      body: JSON.stringify(editedEnvelope),
    });
    assert.equal(blockedEdit.status, 404);
    const mismatched = await encryptMessage({
      identity: aliceKeys,
      recipientEcdhPublic: bob.user.ecdhPublic,
      conversationId,
      senderId: alice.user.id,
      plaintext: revised,
    });
    const wrongNonce = await fetch(`${base}/api/conversations/${conversationId}/messages/${stored.id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify(mismatched),
    });
    assert.equal(wrongNonce.status, 400);
    const edited = await fetch(`${base}/api/conversations/${conversationId}/messages/${stored.id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify(editedEnvelope),
    });
    const editedBody = (await edited.json()) as { message?: { editedAt: string | null; nonce: string }; error?: string };
    assert.equal(edited.status, 200, editedBody.error);
    assert.equal(JSON.stringify(editedBody).includes(revised), false);
    assert.equal(typeof editedBody.message?.editedAt, "string");
    assert.equal(editedBody.message?.nonce, stored.nonce);
    const editedList = await fetch(`${base}/api/conversations/${conversationId}/messages`, {
      headers: { Authorization: `Bearer ${bob.token}` },
    });
    const editedMessages = (await editedList.json()) as {
      messages: Array<(typeof listedBody.messages)[number] & { editedAt: string | null }>;
    };
    const editedStored = editedMessages.messages.find((message) => message.id === stored.id);
    assert.ok(editedStored);
    assert.equal(JSON.stringify(editedStored).includes(revised), false);
    const editedPlain = await decryptMessage({
      envelope: editedStored,
      conversationId,
      senderId: alice.user.id,
      senderEcdsaPublic: alice.user.ecdsaPublic,
      myEcdhPrivate: bobKeys.ecdhPrivate,
      copy: "recipient",
    });
    assert.equal(editedPlain, revised);

    const blockedDelete = await fetch(`${base}/api/conversations/${conversationId}/messages/${stored.id}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${bob.token}` },
      body: JSON.stringify({}),
    });
    assert.equal(blockedDelete.status, 404);
    const deleted = await fetch(`${base}/api/conversations/${conversationId}/messages/${stored.id}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify({}),
    });
    assert.equal(deleted.status, 200);
    const afterDelete = await fetch(`${base}/api/conversations/${conversationId}/messages`, {
      headers: { Authorization: `Bearer ${bob.token}` },
    });
    const afterBody = (await afterDelete.json()) as { messages: Array<{ id: string }> };
    assert.equal(afterBody.messages.some((message) => message.id === stored.id), false);

    const selfChat = await fetch(`${base}/api/conversations`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify({ username: "alice" }),
    });
    assert.equal(selfChat.status, 400);

    const fileSecret = "secret-file-contents-xyz";
    const encryptedFile = await encryptFile(new TextEncoder().encode(fileSecret));
    const digest = await sha256Base64(encryptedFile.ciphertext);
    const uploaded = await fetch(`${base}/api/conversations/${conversationId}/attachments`, {
      method: "POST",
      headers: { Authorization: `Bearer ${alice.token}`, "Content-Type": "application/octet-stream" },
      body: Buffer.from(encryptedFile.ciphertext),
    });
    const uploadedBody = (await uploaded.json()) as { id?: string; error?: string };
    assert.equal(uploaded.status, 201, uploadedBody.error);
    const fileMessage = await encryptMessage({
      identity: aliceKeys,
      recipientEcdhPublic: bob.user.ecdhPublic,
      conversationId,
      senderId: alice.user.id,
      plaintext: packPayload({
        text: "the scan",
        file: {
          id: uploadedBody.id as string,
          name: "scan.png",
          type: "image/png",
          size: fileSecret.length,
          key: encryptedFile.key,
          iv: encryptedFile.iv,
          sha256: digest,
        },
      }),
    });
    const sentFile = await fetch(`${base}/api/conversations/${conversationId}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify(fileMessage),
    });
    assert.equal(sentFile.status, 201);
    const downloaded = await fetch(`${base}/api/conversations/${conversationId}/attachments/${uploadedBody.id}`, {
      headers: { Authorization: `Bearer ${bob.token}` },
    });
    assert.equal(downloaded.status, 200);
    const openedFile = await decryptFile(new Uint8Array(await downloaded.arrayBuffer()), encryptedFile.key, encryptedFile.iv);
    assert.equal(new TextDecoder().decode(openedFile), fileSecret);
    const blocked = await fetch(`${base}/api/conversations/${conversationId}/attachments/${uploadedBody.id}`);
    assert.equal(blocked.status, 401);
    const storedFile = await readFile(path.join(directory, "files", uploadedBody.id as string));
    assert.equal(storedFile.includes(Buffer.from(fileSecret)), false);

    started.db.checkpoint();
    const raw = JSON.stringify(started.db.listMessages(conversationId, alice.user.id, null, 10));
    assert.equal(raw.includes(secret), false);
  } finally {
    await started.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("seals a group message separately for each member", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "whisper-group-"));
  const started = await createServer({ dbPath: path.join(directory, "whisper.sqlite"), port: 0 });
  const base = `http://127.0.0.1:${started.port}`;
  const secret = "group-only-secret-north-gate";

  try {
    const aliceKeys = await generateIdentity();
    const bobKeys = await generateIdentity();
    const carolKeys = await generateIdentity();
    const daveKeys = await generateIdentity();
    const alice = await registerUser(base, "alice", "alice-password-1", aliceKeys);
    const bob = await registerUser(base, "bob", "bob-password-22", bobKeys);
    const carol = await registerUser(base, "carol", "carol-password-33", carolKeys);
    const dave = await registerUser(base, "dave", "dave-password-44", daveKeys);

    const created = await fetch(`${base}/api/groups`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify({ title: "North gate", usernames: ["bob", "carol"] }),
    });
    const createdBody = (await created.json()) as { conversation: { id: string; kind: string }; error?: string };
    assert.equal(created.status, 201, createdBody.error);
    assert.equal(createdBody.conversation.kind, "group");
    const conversationId = createdBody.conversation.id;

    const envelope = await encryptGroupMessage({
      identity: aliceKeys,
      conversationId,
      senderId: alice.user.id,
      plaintext: secret,
      members: [
        { userId: alice.user.id, ecdhPublic: alice.user.ecdhPublic },
        { userId: bob.user.id, ecdhPublic: bob.user.ecdhPublic },
        { userId: carol.user.id, ecdhPublic: carol.user.ecdhPublic },
      ],
    });

    const incomplete = await fetch(`${base}/api/conversations/${conversationId}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify({
        nonce: envelope.nonce,
        copies: envelope.copies.filter((copy) => copy.userId !== carol.user.id),
      }),
    });
    assert.equal(incomplete.status, 400);

    const sent = await fetch(`${base}/api/conversations/${conversationId}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify(envelope),
    });
    const sentBody = (await sent.json()) as { error?: string };
    assert.equal(sent.status, 201, sentBody.error);
    assert.equal(JSON.stringify(sentBody).includes(secret), false);

    async function readAs(token: string, keys: Identity, userId: string) {
      const listed = await fetch(`${base}/api/conversations/${conversationId}/messages`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      assert.equal(listed.status, 200);
      const body = (await listed.json()) as {
        messages: Array<{
          nonce: string;
          senderId: string;
          forMe: { ephPublic: string; iv: string; ciphertext: string } | null;
          signature: string;
        }>;
      };
      const message = body.messages[0];
      assert.ok(message?.forMe);
      return decryptGroupMessage({
        conversationId,
        senderId: message.senderId,
        nonce: message.nonce,
        memberId: userId,
        bundle: message.forMe,
        signature: message.signature,
        senderEcdsaPublic: alice.user.ecdsaPublic,
        myEcdhPrivate: keys.ecdhPrivate,
      });
    }

    assert.equal(await readAs(bob.token, bobKeys, bob.user.id), secret);
    assert.equal(await readAs(carol.token, carolKeys, carol.user.id), secret);

    const outsider = await fetch(`${base}/api/conversations/${conversationId}/messages`, {
      headers: { Authorization: `Bearer ${dave.token}` },
    });
    assert.equal(outsider.status, 404);

    started.db.checkpoint();
    const raw = JSON.stringify(started.db.listMessages(conversationId, alice.user.id, null, 10));
    assert.equal(raw.includes(secret), false);

    const listed = await fetch(`${base}/api/conversations`, { headers: { Authorization: `Bearer ${bob.token}` } });
    const listedBody = (await listed.json()) as {
      conversations: Array<{ id: string; viewerRole: string; members: Array<{ id: string; username: string; role: string }> }>;
    };
    const bobView = listedBody.conversations.find((item) => item.id === conversationId);
    assert.equal(bobView?.viewerRole, "member");
    assert.equal(bobView?.members.find((member) => member.username === "alice")?.role, "admin");

    const blockedAdd = await fetch(`${base}/api/groups/${conversationId}/members`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${bob.token}` },
      body: JSON.stringify({ username: "dave" }),
    });
    assert.equal(blockedAdd.status, 403);
    const blockedRemove = await fetch(`${base}/api/groups/${conversationId}/members/${carol.user.id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${bob.token}` },
    });
    assert.equal(blockedRemove.status, 403);

    const added = await fetch(`${base}/api/groups/${conversationId}/members`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify({ username: "dave" }),
    });
    const addedBody = (await added.json()) as { error?: string; conversation?: { members: Array<{ username: string }> } };
    assert.equal(added.status, 201, addedBody.error);
    assert.equal(addedBody.conversation?.members.some((member) => member.username === "dave"), true);

    const removed = await fetch(`${base}/api/groups/${conversationId}/members/${dave.user.id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${alice.token}` },
    });
    const removedBody = (await removed.json()) as { error?: string; conversation?: { members: Array<{ username: string }> } };
    assert.equal(removed.status, 200, removedBody.error);
    assert.equal(removedBody.conversation?.members.some((member) => member.username === "dave"), false);
    const daveMessages = await fetch(`${base}/api/conversations/${conversationId}/messages`, {
      headers: { Authorization: `Bearer ${dave.token}` },
    });
    assert.equal(daveMessages.status, 404);

    const left = await fetch(`${base}/api/groups/${conversationId}/members`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${alice.token}` },
    });
    assert.equal(left.status, 200);
    const after = await fetch(`${base}/api/conversations`, { headers: { Authorization: `Bearer ${bob.token}` } });
    const afterBody = (await after.json()) as { conversations: Array<{ id: string; viewerRole: string }> };
    assert.equal(afterBody.conversations.find((item) => item.id === conversationId)?.viewerRole, "admin");
  } finally {
    await started.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("changes a password without replacing encryption keys", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "whisper-password-"));
  const started = await createServer({ dbPath: path.join(directory, "whisper.sqlite"), port: 0 });
  const base = `http://127.0.0.1:${started.port}`;

  try {
    const aliceKeys = await generateIdentity();
    const alice = await registerUser(base, "alice", "alice-password-1", aliceKeys);
    const rejected = await fetch(`${base}/api/auth/password`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify({
        authVerifier: await deriveAuthVerifier("alice", "wrong-password"),
        nextAuthVerifier: await deriveAuthVerifier("alice", "alice-password-new"),
        ...(await wrapIdentity(aliceKeys, "alice-password-new")),
      }),
    });
    assert.equal(rejected.status, 401);

    const nextPassword = "alice-password-new";
    const changed = await fetch(`${base}/api/auth/password`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${alice.token}` },
      body: JSON.stringify({
        authVerifier: await deriveAuthVerifier("alice", "alice-password-1"),
        nextAuthVerifier: await deriveAuthVerifier("alice", nextPassword),
        ...(await wrapIdentity(aliceKeys, nextPassword)),
      }),
    });
    const changedBody = (await changed.json()) as {
      user?: { ecdhPublic: string; ecdsaPublic: string; wrappedEcdh: string; wrappedEcdsa: string; wrapSalt: string; wrapIterations: number };
      error?: string;
    };
    assert.equal(changed.status, 200, changedBody.error);
    assert.equal(changedBody.user?.ecdhPublic, alice.user.ecdhPublic);
    assert.equal(changedBody.user?.ecdsaPublic, alice.user.ecdsaPublic);
    const unlocked = await unwrapIdentity(
      {
        ecdhPublic: changedBody.user!.ecdhPublic,
        ecdsaPublic: changedBody.user!.ecdsaPublic,
        wrappedEcdh: changedBody.user!.wrappedEcdh,
        wrappedEcdsa: changedBody.user!.wrappedEcdsa,
        wrapSalt: changedBody.user!.wrapSalt,
        wrapIterations: changedBody.user!.wrapIterations,
      },
      nextPassword,
    );
    assert.equal(unlocked.ecdhPublic, aliceKeys.ecdhPublic);

    const oldLogin = await fetch(`${base}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "alice", authVerifier: await deriveAuthVerifier("alice", "alice-password-1") }),
    });
    assert.equal(oldLogin.status, 401);
    const newLogin = await fetch(`${base}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "alice", authVerifier: await deriveAuthVerifier("alice", nextPassword) }),
    });
    assert.equal(newLogin.status, 200);
  } finally {
    await started.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("hides a chat for one person and removes it without taking it from the other", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "whisper-hide-"));
  const started = await createServer({ dbPath: path.join(directory, "whisper.sqlite"), port: 0 });
  const base = `http://127.0.0.1:${started.port}`;

  try {
    const aliceKeys = await generateIdentity();
    const bobKeys = await generateIdentity();
    const carolKeys = await generateIdentity();
    const alice = await registerUser(base, "alice", "alice-password-1", aliceKeys);
    const bob = await registerUser(base, "bob", "bob-password-22", bobKeys);
    await registerUser(base, "carol", "carol-password-33", carolKeys);
    const auth = (token: string) => ({ Authorization: `Bearer ${token}`, "Content-Type": "application/json" });

    const opened = await fetch(`${base}/api/conversations`, {
      method: "POST",
      headers: auth(alice.token),
      body: JSON.stringify({ username: "bob" }),
    });
    const openedBody = (await opened.json()) as { conversation: { id: string; hidden: boolean }; error?: string };
    assert.equal(opened.status, 201, openedBody.error);
    assert.equal(openedBody.conversation.hidden, false);
    const conversationId = openedBody.conversation.id;

    const hidden = await fetch(`${base}/api/conversations/${conversationId}/hidden`, {
      method: "POST",
      headers: auth(alice.token),
      body: JSON.stringify({ hidden: true }),
    });
    const hiddenBody = (await hidden.json()) as { conversation: { hidden: boolean }; error?: string };
    assert.equal(hidden.status, 200, hiddenBody.error);
    assert.equal(hiddenBody.conversation.hidden, true);

    const aliceList = await fetch(`${base}/api/conversations`, { headers: auth(alice.token) });
    const aliceChats = (await aliceList.json()) as { conversations: Array<{ id: string; hidden: boolean }> };
    assert.equal(aliceChats.conversations.find((chat) => chat.id === conversationId)?.hidden, true);
    const bobList = await fetch(`${base}/api/conversations`, { headers: auth(bob.token) });
    const bobChats = (await bobList.json()) as { conversations: Array<{ id: string; hidden: boolean }> };
    assert.equal(bobChats.conversations.find((chat) => chat.id === conversationId)?.hidden, false);

    const unhidden = await fetch(`${base}/api/conversations/${conversationId}/hidden`, {
      method: "POST",
      headers: auth(alice.token),
      body: JSON.stringify({ hidden: false }),
    });
    assert.equal(unhidden.status, 200);
    assert.equal(((await unhidden.json()) as { conversation: { hidden: boolean } }).conversation.hidden, false);

    const removed = await fetch(`${base}/api/conversations/${conversationId}`, {
      method: "DELETE",
      headers: auth(alice.token),
    });
    assert.equal(removed.status, 200);
    const afterRemove = (await (await fetch(`${base}/api/conversations`, { headers: auth(alice.token) })).json()) as {
      conversations: Array<{ id: string }>;
    };
    assert.equal(afterRemove.conversations.some((chat) => chat.id === conversationId), false);
    const bobStill = (await (await fetch(`${base}/api/conversations`, { headers: auth(bob.token) })).json()) as {
      conversations: Array<{ id: string }>;
    };
    assert.equal(bobStill.conversations.some((chat) => chat.id === conversationId), true);

    const again = await fetch(`${base}/api/conversations`, {
      method: "POST",
      headers: auth(alice.token),
      body: JSON.stringify({ username: "bob" }),
    });
    const againBody = (await again.json()) as { conversation: { id: string; hidden: boolean }; error?: string };
    assert.equal(again.status, 201, againBody.error);
    assert.equal(againBody.conversation.id, conversationId);
    assert.equal(againBody.conversation.hidden, false);

    const created = await fetch(`${base}/api/groups`, {
      method: "POST",
      headers: auth(alice.token),
      body: JSON.stringify({ title: "North gate", usernames: ["bob", "carol"] }),
    });
    const group = (await created.json()) as { conversation: { id: string }; error?: string };
    assert.equal(created.status, 201, group.error);
    const groupHidden = await fetch(`${base}/api/conversations/${group.conversation.id}/hidden`, {
      method: "POST",
      headers: auth(alice.token),
      body: JSON.stringify({ hidden: true }),
    });
    assert.equal(groupHidden.status, 200);
    const left = await fetch(`${base}/api/conversations/${group.conversation.id}`, { method: "DELETE", headers: auth(alice.token) });
    assert.equal(left.status, 200);
    const aliceAfter = (await (await fetch(`${base}/api/conversations`, { headers: auth(alice.token) })).json()) as {
      conversations: Array<{ id: string }>;
    };
    assert.equal(aliceAfter.conversations.some((chat) => chat.id === group.conversation.id), false);
    const bobGroup = (await (await fetch(`${base}/api/conversations`, { headers: auth(bob.token) })).json()) as {
      conversations: Array<{ id: string; members: Array<{ username: string }> }>;
    };
    const kept = bobGroup.conversations.find((chat) => chat.id === group.conversation.id);
    assert.ok(kept);
    assert.equal(kept.members.some((member) => member.username === "alice"), false);
  } finally {
    await started.close();
    await rm(directory, { recursive: true, force: true });
  }
});
