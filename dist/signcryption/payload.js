"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
const tweetnacl = require("tweetnacl");
const msgpack = require("@msgpack/msgpack");
// [
//     signcrypted chunk,
//     final flag,
// ]
class SigncryptedMessagePayload {
    constructor(payload_secretbox, final) {
        this._encoded_data = null;
        this.payload_secretbox = payload_secretbox;
        this.final = final;
    }
    get encoded_data() {
        return Object.defineProperty(this, '_encoded_data', {
            value: this.encode(),
        })._encoded_data;
    }
    /** The MessagePack encoded payload data */
    get encoded() {
        return this.encoded_data;
    }
    static create(header, payload_key, private_key, data, index, final = false) {
        const nonce = this.generateNonce(header.hash, index, final);
        // 3. Sign the signature input with the sender's long-term private signing key, producing a 64-byte
        // Ed25519 signature. If the sender is anonymous, the signature is 64 zero bytes instead.
        const signature = private_key ?
            tweetnacl.sign.detached(this.generateSignatureData(header.hash, nonce, final, data), private_key) :
            Buffer.alloc(64);
        // 4. Prepend that signature onto the front of the plaintext chunk.
        // 5. Encrypt the attached signature from #4 using the payload key and the packet nonce.
        const payload_secretbox = Buffer.from(tweetnacl.secretbox(Buffer.concat([signature, data]), nonce, payload_key));
        return new this(payload_secretbox, final);
    }
    static generateNonce(header_hash, index, final) {
        // 1. Compute the packet nonce. Take the first 16 bytes of the header hash. If this is the final packet,
        // set the least significant bit of the last of those bytes to one (nonce[15] |= 0x01), otherwise set it
        // to zero (nonce[15] &= 0xfe). Finally, append the 8-byte unsigned big-endian packet number, where the
        // first payload packet is zero.
        const nonce = Buffer.alloc(24, Buffer.from(header_hash));
        nonce[15] = final ? nonce[15] | 0x01 : nonce[15] & 0xfe;
        nonce.writeBigUInt64BE(index, 16);
        return nonce;
    }
    static generateSignatureData(header_hash, nonce, final, data) {
        // 2. Concatenate several values to form the signature input:
        //     - the constant string saltpack encrypted signature
        //     - a null byte, 0x00
        //     - the header hash
        //     - the packet nonce computed above
        //     - the final flag byte, 0x00 for false and 0x01 for true
        //     - the SHA512 hash of the plaintext
        return Buffer.concat([
            Buffer.from('saltpack encrypted signature'),
            Buffer.from([0x00]),
            header_hash,
            nonce,
            Buffer.from([final ? 0x01 : 0x00]),
            crypto.createHash('sha512').update(data).digest(),
        ]);
    }
    encode() {
        return SigncryptedMessagePayload.encodePayload(this.payload_secretbox, this.final);
    }
    static encodePayload(payload_secretbox, final) {
        const data = [
            payload_secretbox,
            final,
        ];
        return Buffer.from(msgpack.encode(data));
    }
    static decode(encoded, unpacked = false) {
        const data = unpacked ? encoded : msgpack.decode(encoded);
        if (data.length < 2)
            throw new Error('Invalid data');
        const [payload_secretbox, final] = data;
        return new this(payload_secretbox, final);
    }
    decrypt(header, public_key, payload_key, index) {
        // 1. Compute the packet nonce as above.
        const nonce = SigncryptedMessagePayload.generateNonce(header.hash, index, this.final);
        // 2. Decrypt the chunk using the payload key and the packet nonce.
        const signature_data = tweetnacl.secretbox.open(this.payload_secretbox, nonce, payload_key);
        if (!signature_data) {
            throw new Error('Failed to decrypt data');
        }
        // 3. Take the first 64 bytes of the plaintext as the detached signature, and the rest as the payload chunk.
        const data = signature_data.slice(64);
        if (public_key) {
            const signature = signature_data.slice(0, 64);
            // 4. Compute the signature input as above.
            const sign_data = SigncryptedMessagePayload.generateSignatureData(header.hash, nonce, this.final, data);
            // 5. Verify the detached signature from step #3 against the signature input. If the sender's public key
            // is all zero bytes, however, then the sender is anonymous, and verification is skipped.
            if (!tweetnacl.sign.detached.verify(sign_data, signature, public_key)) {
                throw new Error('Invalid signature');
            }
        }
        // 6. If the signature was valid, output the payload chunk.
        return data;
    }
}
exports.default = SigncryptedMessagePayload;
SigncryptedMessagePayload.PAYLOAD_NONCE_PREFIX = Buffer.from('saltpack_ploadsb');
//# sourceMappingURL=payload.js.map