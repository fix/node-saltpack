"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const message_header_1 = require("../message-header");
const recipient_1 = require("./recipient");
const crypto = require("crypto");
const tweetnacl = require("tweetnacl");
const msgpack = require("@msgpack/msgpack");
class SigncryptedMessageHeader extends message_header_1.default {
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
        // If Alice wants to be anonymous to recipients as well, she can supply an all-zero signing public key in
        // step #3.
        if (!sender_public_key)
            sender_public_key = Buffer.alloc(32);
        // 3. Encrypt the sender's long-term public key signing key using crypto_secretbox with the payload key and
        // the nonce saltpack_sender_key_sbox, to create the sender secretbox.
        const sender_secretbox = tweetnacl.secretbox(sender_public_key, SigncryptedMessageHeader.SENDER_KEY_SECRETBOX_NONCE, payload_key);
        return new this(public_key, sender_secretbox, recipients);
    }
    encode() {
        return SigncryptedMessageHeader.encodeHeader(this.public_key, this.sender_secretbox, this.recipients);
    }
    static encodeHeader(public_key, sender, recipients) {
        const data = [
            'saltpack',
            [2, 0],
            message_header_1.MessageType.SIGNCRYPTION,
            public_key,
            sender,
            recipients.map(recipient => {
                // [
                //     recipient identifier,
                //     payload key box,
                // ]
                return [
                    recipient.recipient_identifier,
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
        if (data[2] !== message_header_1.MessageType.SIGNCRYPTION)
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
    decryptPayloadKeyWithCurve25519Keypair(private_key) {
        // 5. Check to see if any of the recipient's Curve25519 private keys are in the recipients' list. For each
        // private key available, and for each recipient entry in the list, compute the identifier as in step #4
        // in the previous section. If any of the recipient entries match, decrypt the payload key and proceed to
        // step #7.
        for (const recipient of this.recipients) {
            const { recipient_identifier, shared_symmetric_key } = recipient_1.default.generateRecipientIdentifierForRecipient(this.public_key, private_key, recipient.recipient_index);
            if (!recipient_identifier.equals(recipient.recipient_identifier))
                continue;
            const payload_key = recipient.decryptPayloadKey(shared_symmetric_key);
            if (!payload_key) {
                throw new Error('Invalid shared symmetric key');
            }
            return [payload_key, recipient];
        }
        return null;
    }
    decryptPayloadKeyWithSymmetricKey(shared_symmetric_key, recipient_identifier) {
        // 6. If no Curve25519 keys matched in the previous step, check whether any of the recipient's symmetric
        // keys are in the message. The identifiers in this step are up to the application, and if the space of
        // possible keys is very large, the recipient might use server assistance to look up identifiers. If any
        // of the recipient entries match, decrypt the payload key. If not, decryption fails, and the client should
        // report that the current user isn't a recipient of this message.
        const identifier = recipient_identifier ?
            recipient_identifier instanceof Buffer ? recipient_identifier : Buffer.from(recipient_identifier) :
            null;
        for (const recipient of this.recipients) {
            if (identifier && !identifier.equals(recipient.recipient_identifier))
                continue;
            const payload_key = recipient.decryptPayloadKey(shared_symmetric_key);
            if (!payload_key)
                continue;
            return [payload_key, recipient];
        }
        return null;
    }
    decryptSender(payload_key) {
        const sender_public_key = tweetnacl.secretbox.open(this.sender_secretbox, SigncryptedMessageHeader.SENDER_KEY_SECRETBOX_NONCE, payload_key);
        if (!sender_public_key) {
            throw new Error('Failed to decrypt sender public key');
        }
        if (Buffer.alloc(32).equals(sender_public_key)) {
            return null;
        }
        return sender_public_key;
    }
}
exports.default = SigncryptedMessageHeader;
SigncryptedMessageHeader.SENDER_KEY_SECRETBOX_NONCE = Buffer.from('saltpack_sender_key_sbox');
//# sourceMappingURL=header.js.map