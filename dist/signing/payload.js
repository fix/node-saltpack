"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
const tweetnacl = require("tweetnacl");
const msgpack = require("@msgpack/msgpack");
// [
//     final flag,
//     signature,
//     payload chunk,
// ]
class SignedMessagePayload {
    constructor(final, signature, data) {
        this._encoded_data = null;
        this.final = final;
        this.signature = signature;
        this.data = data;
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
    static create(header, private_key, data, index, final = false) {
        if (!(private_key instanceof Buffer))
            private_key = Buffer.from(private_key);
        if (typeof index === 'number')
            index = BigInt(index);
        const sign_data = this.generateSignData(header.hash, index, final, data);
        const signature = tweetnacl.sign.detached(sign_data, private_key);
        return new this(final, Buffer.from(signature), data);
    }
    static generateSignData(header_hash, index, final, data) {
        // To make each signature, the sender first takes the SHA512 hash of the concatenation of four values:
        // the header hash from above
        // the packet sequence number, as a 64-bit big-endian unsigned integer, where the first payload packet is zero
        // the final flag, a 0x00 byte for false and a 0x01 byte for true
        // the payload chunk
        const index_buffer = Buffer.alloc(8);
        index_buffer.writeBigUInt64BE(index);
        return Buffer.concat([
            this.PAYLOAD_SIGNATURE_PREFIX,
            crypto.createHash('sha512')
                .update(header_hash)
                .update(index_buffer)
                .update(final ? '\x01' : '\x00')
                .update(data)
                .digest(),
        ]);
    }
    encode() {
        return SignedMessagePayload.encodePayload(this.final, this.signature, this.data);
    }
    static encodePayload(final, signature, payload_chunk) {
        return Buffer.from(msgpack.encode([
            final,
            signature,
            payload_chunk,
        ]));
    }
    static decode(encoded, unpacked = false) {
        const data = unpacked ? encoded : msgpack.decode(encoded);
        if (data.length < 3)
            throw new Error('Invalid data');
        const [final, signature, payload_chunk] = data;
        return new this(final, signature, payload_chunk);
    }
    verify(header, public_key, index) {
        const sign_data = SignedMessagePayload.generateSignData(header.hash, index, this.final, this.data);
        if (!tweetnacl.sign.detached.verify(sign_data, this.signature, public_key)) {
            throw new Error('Invalid signature');
        }
    }
}
exports.default = SignedMessagePayload;
SignedMessagePayload.PAYLOAD_SIGNATURE_PREFIX = Buffer.from('saltpack attached signature\0');
//# sourceMappingURL=payload.js.map