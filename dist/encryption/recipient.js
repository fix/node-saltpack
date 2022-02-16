"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
const tweetnacl = require("tweetnacl");
class EncryptedMessageRecipient {
    constructor(public_key, encrypted_payload_key, index, anonymous = false) {
        /** The MAC key for this recipient (this is used to generate the per-payload authenticators for this recipient) */
        this.mac_key = null;
        this.public_key = public_key;
        this.encrypted_payload_key = encrypted_payload_key;
        this.index = index;
        this.recipient_index = EncryptedMessageRecipient.generateRecipientIndex(index);
        this.anonymous = anonymous;
    }
    /** @private */
    setPublicKey(public_key) {
        // @ts-expect-error
        this.public_key = public_key;
    }
    static create(public_key, ephemeral_private_key, payload_key, index, anonymous = false) {
        if (typeof index === 'number')
            index = BigInt(index);
        const recipient_index = this.generateRecipientIndex(index);
        // 4. For each recipient, encrypt the payload key using crypto_box with the recipient's public key, the ephemeral private key, and the nonce saltpack_recipsbXXXXXXXX. XXXXXXXX is 8-byte big-endian unsigned recipient index, where the first recipient is index zero. Pair these with the recipients' public keys, or null for anonymous recipients, and collect the pairs into the recipients list.
        const encrypted_payload_key = tweetnacl.box(payload_key, recipient_index, public_key, ephemeral_private_key);
        return new this(public_key, encrypted_payload_key, index, anonymous);
    }
    static from(public_key, encrypted_payload_key, index) {
        if (typeof index === 'number')
            index = BigInt(index);
        return new this(public_key, encrypted_payload_key, index, public_key === null);
    }
    static generateRecipientIndex(index) {
        const buffer = Buffer.alloc(8);
        buffer.writeBigUInt64BE(index);
        return Buffer.concat([this.PAYLOAD_KEY_BOX_NONCE_PREFIX_V2, buffer]);
    }
    /**
     * Decrypts the payload key, returns null if wrong recipient.
     */
    decryptPayloadKey(ephemeral_public_key, recipient_private_key, secret = null) {
        const payload_key = secret ? tweetnacl.box.open.after(this.encrypted_payload_key, this.recipient_index, secret) : tweetnacl.box.open(this.encrypted_payload_key, this.recipient_index, ephemeral_public_key, recipient_private_key);
        if (!payload_key)
            return null;
        return payload_key;
    }
    generateMacKeyForSender(header_hash, ephemeral_private_key, sender_private_key, public_key = null) {
        if (!public_key && this.public_key)
            public_key = this.public_key;
        if (!public_key)
            throw new Error('Generating MAC key requires the recipient\'s public key');
        // 9. Concatenate the first 16 bytes of the header hash from step 7 above, with the recipient index from
        // step 4 above. This is the basis of each recipient's MAC nonce.
        const index_buffer = Buffer.alloc(8);
        index_buffer.writeBigUInt64BE(this.index);
        const nonce = Buffer.concat([header_hash.slice(0, 16), index_buffer]);
        // 10. Clear the least significant bit of byte 15. That is: nonce[15] &= 0xfe.
        nonce[15] &= 0xfe;
        // 11. Encrypt 32 zero bytes using crypto_box with the recipient's public key, the sender's long-term
        // private key, and the nonce from the previous step.
        const box_1 = tweetnacl.box(Buffer.alloc(32).fill('\0'), nonce, public_key, sender_private_key);
        // 12. Modify the nonce from step 10 by setting the least significant bit of byte
        // 12.1. That is: nonce[15] |= 0x01.
        nonce[15] |= 0x01;
        // 13. Encrypt 32 zero bytes again, as in step 11, but using the ephemeral private key rather than the
        // sender's long term private key.
        const box_2 = tweetnacl.box(Buffer.alloc(32).fill('\0'), nonce, public_key, ephemeral_private_key);
        // 14. Concatenate the last 32 bytes each box from steps 11 and 13. Take the SHA512 hash of that
        // concatenation. The recipient's MAC Key is the first 32 bytes of that hash.
        const mac_key = crypto.createHash('sha512')
            .update(box_1.slice(-32))
            .update(box_2.slice(-32))
            .digest().slice(0, 32);
        // @ts-expect-error
        this.mac_key = mac_key;
        return mac_key;
    }
    generateMacKeyForRecipient(header_hash, ephemeral_public_key, sender_public_key, private_key) {
        // 9. Concatenate the first 16 bytes of the header hash from step 7 above, with the recipient index from
        // step 4 above. This is the basis of each recipient's MAC nonce.
        const index_buffer = Buffer.alloc(8);
        index_buffer.writeBigUInt64BE(this.index);
        const nonce = Buffer.concat([header_hash.slice(0, 16), index_buffer]);
        // 10. Clear the least significant bit of byte 15. That is: nonce[15] &= 0xfe.
        nonce[15] &= 0xfe;
        // 11. Encrypt 32 zero bytes using crypto_box with the recipient's public key, the sender's long-term
        // private key, and the nonce from the previous step.
        const box_1 = tweetnacl.box(Buffer.alloc(32).fill('\0'), nonce, sender_public_key, private_key);
        // 12. Modify the nonce from step 10 by setting the least significant bit of byte
        // 12.1. That is: nonce[15] |= 0x01.
        nonce[15] |= 0x01;
        // 13. Encrypt 32 zero bytes again, as in step 11, but using the ephemeral private key rather than the
        // sender's long term private key.
        const box_2 = tweetnacl.box(Buffer.alloc(32).fill('\0'), nonce, ephemeral_public_key, private_key);
        // 14. Concatenate the last 32 bytes each box from steps 11 and 13. Take the SHA512 hash of that
        // concatenation. The recipient's MAC Key is the first 32 bytes of that hash.
        const mac_key = crypto.createHash('sha512')
            .update(box_1.slice(-32))
            .update(box_2.slice(-32))
            .digest().slice(0, 32);
        // @ts-expect-error
        this.mac_key = mac_key;
        return mac_key;
    }
}
exports.default = EncryptedMessageRecipient;
EncryptedMessageRecipient.PAYLOAD_KEY_BOX_NONCE_PREFIX_V2 = Buffer.from('saltpack_recipsb');
//# sourceMappingURL=recipient.js.map