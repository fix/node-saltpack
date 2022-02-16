"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const message_header_1 = require("../message-header");
const crypto = require("crypto");
const tweetnacl = require("tweetnacl");
const msgpack = require("@msgpack/msgpack");
// [
//     format name,
//     version,
//     mode,
//     sender public key,
//     nonce,
// ]
class SignedMessageHeader extends message_header_1.default {
    constructor(public_key, nonce, attached = true) {
        super();
        this._encoded_data = null;
        this.public_key = public_key;
        this.nonce = nonce;
        this.attached = attached;
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
    static create(public_key, attached = true) {
        var _a;
        const nonce = (_a = this.debug_fix_nonce) !== null && _a !== void 0 ? _a : crypto.randomBytes(32);
        return new this(public_key, nonce, attached);
    }
    encode() {
        return SignedMessageHeader.encodeHeader(this.public_key, this.nonce, this.attached);
    }
    static encodeHeader(public_key, nonce, attached) {
        const data = [
            'saltpack',
            [2, 0],
            attached ? message_header_1.MessageType.ATTACHED_SIGNING : message_header_1.MessageType.DETACHED_SIGNING,
            public_key,
            nonce,
        ];
        const encoded = msgpack.encode(data);
        const header_hash = crypto.createHash('sha512').update(encoded).digest();
        return [header_hash, Buffer.from(msgpack.encode(encoded))];
    }
    static decode(encoded, unwrapped = false) {
        const [header_hash, data] = super.decode1(encoded, unwrapped);
        if (data[2] !== message_header_1.MessageType.ATTACHED_SIGNING &&
            data[2] !== message_header_1.MessageType.DETACHED_SIGNING)
            throw new Error('Invalid data');
        if (data.length < 5)
            throw new Error('Invalid data');
        const [, , , public_key, nonce] = data;
        return new this(public_key, nonce, data[2] === message_header_1.MessageType.ATTACHED_SIGNING);
    }
    signDetached(data, private_key) {
        if (this.attached) {
            throw new Error('Header attached is true');
        }
        const hash = crypto.createHash('sha512')
            .update(this.hash)
            .update(data)
            .digest();
        const sign_data = Buffer.concat([SignedMessageHeader.DETACHED_SIGNATURE_PREFIX, hash]);
        return Buffer.from(tweetnacl.sign.detached(sign_data, private_key));
    }
    verifyDetached(signature, data, public_key) {
        if (this.attached) {
            throw new Error('Header attached is true');
        }
        const hash = crypto.createHash('sha512')
            .update(this.hash)
            .update(data)
            .digest();
        const sign_data = Buffer.concat([SignedMessageHeader.DETACHED_SIGNATURE_PREFIX, hash]);
        if (!tweetnacl.sign.detached.verify(sign_data, signature, public_key)) {
            throw new Error('Invalid signature');
        }
    }
}
exports.default = SignedMessageHeader;
SignedMessageHeader.DETACHED_SIGNATURE_PREFIX = Buffer.from('saltpack detached signature\0');
SignedMessageHeader.debug_fix_nonce = null;
//# sourceMappingURL=header.js.map