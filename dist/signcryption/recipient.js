"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
const tweetnacl = require("tweetnacl");
class SigncryptedMessageRecipient {
    constructor(recipient_identifier, /*shared_symmetric_key: Uint8Array | null,*/ encrypted_payload_key, index) {
        this.recipient_identifier = recipient_identifier;
        // this.shared_symmetric_key = shared_symmetric_key;
        this.encrypted_payload_key = encrypted_payload_key;
        this.index = index;
        this.recipient_index = SigncryptedMessageRecipient.generateRecipientIndex(index);
    }
    static create(public_key, ephemeral_private_key, payload_key, index) {
        if (typeof index === 'number')
            index = BigInt(index);
        const recipient_index = this.generateRecipientIndex(index);
        const { shared_symmetric_key, recipient_identifier } = this.generateRecipientIdentifierForSender(public_key, ephemeral_private_key, recipient_index);
        // Secretbox the payload key using this derived symmetric key, with the nonce saltpack_recipsbXXXXXXXX,
        // where XXXXXXXX is the 8-byte big-endian unsigned recipient index.
        const encrypted_payload_key = tweetnacl.secretbox(payload_key, recipient_index, shared_symmetric_key);
        return new this(recipient_identifier, /*shared_symmetric_key,*/ encrypted_payload_key, index);
    }
    static from(recipient_identifier, encrypted_payload_key, index) {
        if (typeof index === 'number')
            index = BigInt(index);
        return new this(recipient_identifier, /*null,*/ encrypted_payload_key, index);
    }
    static generateRecipientIndex(index) {
        const buffer = Buffer.alloc(8);
        buffer.writeBigUInt64BE(index);
        return Buffer.concat([this.PAYLOAD_KEY_BOX_NONCE_PREFIX_V2, buffer]);
    }
    /**
     * Decrypts the payload key.
     */
    decryptPayloadKey(shared_symmetric_key) {
        return tweetnacl.secretbox.open(this.encrypted_payload_key, this.recipient_index, shared_symmetric_key);
    }
    static generateRecipientIdentifierForSender(public_key, ephemeral_private_key, recipient_index) {
        // For Curve25519 recipient public keys, first derive a shared symmetric key by boxing 32 zero bytes with
        // the recipient public key, the ephemeral private key, and the nonce saltpack_derived_sboxkey, and taking
        // the last 32 bytes of the resulting box.
        const shared_symmetric_key = Buffer.from(tweetnacl.box(Buffer.alloc(32).fill('\0'), this.SHARED_KEY_NONCE, public_key, ephemeral_private_key)).slice(-32);
        // To compute the recipient identifier, concatenate the derived symmetric key and the
        // saltpack_recipsbXXXXXXXX nonce together, and HMAC-SHA512 them under the key saltpack signcryption box
        // key identifier. The identifier is the first 32 bytes of that HMAC.
        const recipient_identifier = crypto.createHmac('sha512', this.HMAC_KEY)
            .update(shared_symmetric_key)
            .update(recipient_index)
            .digest().slice(0, 32);
        return { shared_symmetric_key, recipient_identifier };
    }
    static generateRecipientIdentifierForRecipient(ephemeral_public_key, private_key, recipient_index) {
        // For Curve25519 recipient public keys, first derive a shared symmetric key by boxing 32 zero bytes with
        // the recipient public key, the ephemeral private key, and the nonce saltpack_derived_sboxkey, and taking
        // the last 32 bytes of the resulting box.
        const shared_symmetric_key = Buffer.from(tweetnacl.box(Buffer.alloc(32).fill('\0'), this.SHARED_KEY_NONCE, ephemeral_public_key, private_key)).slice(-32);
        // To compute the recipient identifier, concatenate the derived symmetric key and the
        // saltpack_recipsbXXXXXXXX nonce together, and HMAC-SHA512 them under the key saltpack signcryption box
        // key identifier. The identifier is the first 32 bytes of that HMAC.
        const recipient_identifier = crypto.createHmac('sha512', this.HMAC_KEY)
            .update(shared_symmetric_key)
            .update(recipient_index)
            .digest().slice(0, 32);
        return { shared_symmetric_key, recipient_identifier };
    }
}
exports.default = SigncryptedMessageRecipient;
SigncryptedMessageRecipient.SHARED_KEY_NONCE = Buffer.from('saltpack_derived_sboxkey');
SigncryptedMessageRecipient.HMAC_KEY = Buffer.from('saltpack signcryption box key identifier');
SigncryptedMessageRecipient.PAYLOAD_KEY_BOX_NONCE_PREFIX_V2 = Buffer.from('saltpack_recipsb');
//# sourceMappingURL=recipient.js.map