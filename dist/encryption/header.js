"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const message_header_1 = require("../message-header");
const recipient_1 = require("./recipient");
const crypto = require("crypto");
const tweetnacl = require("tweetnacl");
const msgpack = require("@msgpack/msgpack");
class EncryptedMessageHeader extends message_header_1.default {
    constructor(public_key, sender_secretbox, recipients) {
        super();
        this._encoded_data = null;
        this.public_key = public_key;
        this.sender_secretbox = sender_secretbox;
        this.recipients = recipients;
    }
    get encoded_data() {
        return Object.defineProperty(this, '_encoded_data', {
            value: this.encode(),
        })._encoded_data;
    }
    /** The MessagePack encoded outer header data */
    get encoded() {
        return this.encoded_data[1];
    }
    /** The SHA512 hash of the MessagePack encoded inner header data */
    get hash() {
        return this.encoded_data[0];
    }
    static create(public_key, payload_key, sender_public_key, recipients) {
        // 3. Encrypt the sender's long-term public key using crypto_secretbox with the payload key and the nonce saltpack_sender_key_sbox, to create the sender secretbox.
        // const sender_secretbox = sodium_crypto_secretbox($sender_public_key, self::SENDER_KEY_SECRETBOX_NONCE, $payload_key);
        const sender_secretbox = tweetnacl.secretbox(sender_public_key, EncryptedMessageHeader.SENDER_KEY_SECRETBOX_NONCE, payload_key);
        return new this(Buffer.from(public_key), Buffer.from(sender_secretbox), recipients);
    }
    encode() {
        return EncryptedMessageHeader.encodeHeader(this.public_key, this.sender_secretbox, this.recipients);
    }
    static encodeHeader(public_key, sender, recipients) {
        const data = [
            'saltpack',
            [2, 0],
            message_header_1.MessageType.ENCRYPTION,
            public_key,
            sender,
            recipients.map(recipient => {
                // [
                //     recipient public key,
                //     payload key box,
                // ]
                return [
                    recipient.anonymous ? null : recipient.public_key,
                    recipient.encrypted_payload_key,
                ];
            }),
        ];
        const encoded = msgpack.encode(data);
        const header_hash = crypto.createHash('sha512').update(encoded).digest();
        return [header_hash, Buffer.from(msgpack.encode(encoded))];
    }
    static decode(encoded, unwrapped = false) {
        const [header_hash, data] = super.decode1(encoded, unwrapped);
        if (data[2] !== message_header_1.MessageType.ENCRYPTION)
            throw new Error('Invalid data');
        if (data.length < 6)
            throw new Error('Invalid data');
        const [, , , public_key, sender, recipients] = data;
        return new this(public_key, sender, recipients.map((recipient, index) => {
            return recipient_1.default.from(recipient[0], recipient[1], index);
        }));
    }
    /**
     * Decrypts and returns the payload key and recipient.
     */
    decryptPayloadKey(keypair) {
        // 5. Precompute the ephemeral shared secret using crypto_box_beforenm with the ephemeral public key and
        // the recipient's private key.
        const shared_secret = tweetnacl.box.before(this.public_key, keypair.secretKey);
        // 6. Try to open each of the payload key boxes in the recipients list using crypto_box_open_afternm,
        // the precomputed secret from #5, and the nonce saltpack_recipsbXXXXXXXX. XXXXXXXX is 8-byte big-endian
        // unsigned recipient index, where the first recipient is index 0. Successfully opening one gives the
        // payload key.
        for (const recipient of this.recipients) {
            if (recipient.public_key) {
                // If the recipient's public key is shown in the recipients list (that is, if the recipient is
                // not anonymous), clients may skip all the other payload key boxes in step #6.
                if (!Buffer.from(recipient.public_key).equals(keypair.publicKey))
                    continue;
            }
            const payload_key = recipient.decryptPayloadKey(this.public_key, keypair.secretKey, shared_secret);
            if (!payload_key)
                continue;
            recipient.setPublicKey(keypair.publicKey);
            return [payload_key, recipient];
        }
        throw new Error('keypair is not an intended recipient');
    }
    decryptSender(payload_key) {
        const sender_public_key = tweetnacl.secretbox.open(this.sender_secretbox, EncryptedMessageHeader.SENDER_KEY_SECRETBOX_NONCE, payload_key);
        if (!sender_public_key) {
            throw new Error('Failed to decrypt sender public key');
        }
        return sender_public_key;
    }
}
exports.default = EncryptedMessageHeader;
EncryptedMessageHeader.SENDER_KEY_SECRETBOX_NONCE = Buffer.from('saltpack_sender_key_sbox');
//# sourceMappingURL=header.js.map