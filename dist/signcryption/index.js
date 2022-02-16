"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __asyncValues = (this && this.__asyncValues) || function (o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DesigncryptStream = exports.designcrypt = exports.SigncryptStream = exports.signcrypt = exports.debug_fix_keypair = exports.debug_fix_key = exports.debug = void 0;
const header_1 = require("./header");
const recipient_1 = require("./recipient");
const payload_1 = require("./payload");
const util_1 = require("../util");
const stream_1 = require("stream");
const crypto = require("crypto");
const util = require("util");
const tweetnacl = require("tweetnacl");
const msgpack = require("@msgpack/msgpack");
const Decoder_1 = require("@msgpack/msgpack/dist/Decoder");
const randomBytes = util.promisify(crypto.randomBytes);
const CHUNK_LENGTH = 1024 * 1024;
exports.debug = false;
exports.debug_fix_key = null;
exports.debug_fix_keypair = null;
function signcrypt(data, keypair, recipients_keys) {
    var _a, _b;
    return __awaiter(this, void 0, void 0, function* () {
        const chunks = util_1.chunkBuffer(data, CHUNK_LENGTH);
        // 1. Generate a random 32-byte payload key.
        const payload_key = exports.debug_fix_key !== null && exports.debug_fix_key !== void 0 ? exports.debug_fix_key : yield randomBytes(32);
        // 2. Generate a random ephemeral keypair, using crypto_box_keypair.
        const ephemeral_keypair = exports.debug_fix_keypair !== null && exports.debug_fix_keypair !== void 0 ? exports.debug_fix_keypair : tweetnacl.box.keyPair();
        const recipients = recipients_keys.map((key, index) => {
            return recipient_1.default.create(key, ephemeral_keypair.secretKey, payload_key, index);
        });
        const header = header_1.default.create(ephemeral_keypair.publicKey, payload_key, (_a = keypair === null || keypair === void 0 ? void 0 : keypair.publicKey) !== null && _a !== void 0 ? _a : null, recipients);
        const payloads = [];
        for (const i in chunks) {
            const chunk = chunks[i];
            const final = chunks.length === (parseInt(i) + 1);
            const payload = payload_1.default.create(header, payload_key, (_b = keypair === null || keypair === void 0 ? void 0 : keypair.secretKey) !== null && _b !== void 0 ? _b : null, chunk, BigInt(i), final);
            payloads.push(payload);
        }
        return Buffer.concat([
            header.encoded,
            Buffer.concat(payloads.map(payload => payload.encoded)),
        ]);
    });
}
exports.signcrypt = signcrypt;
class SigncryptStream extends stream_1.Transform {
    constructor(keypair, recipients_keys) {
        var _a, _b;
        super();
        this.in_buffer = Buffer.alloc(0);
        this.payload_index = BigInt(0);
        this.i = 0;
        // 1. Generate a random 32-byte payload key.
        this.payload_key = exports.debug_fix_key !== null && exports.debug_fix_key !== void 0 ? exports.debug_fix_key : crypto.randomBytes(32);
        // 2. Generate a random ephemeral keypair, using crypto_box_keypair.
        this.ephemeral_keypair = exports.debug_fix_keypair !== null && exports.debug_fix_keypair !== void 0 ? exports.debug_fix_keypair : tweetnacl.box.keyPair();
        this.keypair = keypair;
        const recipients = recipients_keys.map((key, index) => {
            return recipient_1.default.create(key, this.ephemeral_keypair.secretKey, this.payload_key, index);
        });
        this.header = header_1.default.create(this.ephemeral_keypair.publicKey, this.payload_key, (_b = (_a = this.keypair) === null || _a === void 0 ? void 0 : _a.publicKey) !== null && _b !== void 0 ? _b : null, recipients);
        this.push(this.header.encoded);
    }
    _transform(data, encoding, callback) {
        var _a, _b;
        if (exports.debug)
            console.log('Processing chunk #%d: %s', this.i++, data);
        this.in_buffer = Buffer.concat([this.in_buffer, data]);
        while (this.in_buffer.length > CHUNK_LENGTH) {
            const chunk = this.in_buffer.slice(0, CHUNK_LENGTH);
            this.in_buffer = this.in_buffer.slice(CHUNK_LENGTH);
            // This is never the final payload as there must be additional data in `in_buffer`
            const payload = payload_1.default.create(this.header, this.payload_key, (_b = (_a = this.keypair) === null || _a === void 0 ? void 0 : _a.secretKey) !== null && _b !== void 0 ? _b : null, chunk, this.payload_index, /* final */ false);
            this.push(payload.encoded);
            this.payload_index++;
        }
        callback();
    }
    _flush(callback) {
        var _a, _b, _c, _d;
        while (this.in_buffer.length >= CHUNK_LENGTH) {
            const chunk = this.in_buffer.slice(0, CHUNK_LENGTH);
            this.in_buffer = this.in_buffer.slice(CHUNK_LENGTH);
            const final = !this.in_buffer.length;
            const payload = payload_1.default.create(this.header, this.payload_key, (_b = (_a = this.keypair) === null || _a === void 0 ? void 0 : _a.secretKey) !== null && _b !== void 0 ? _b : null, chunk, this.payload_index, final);
            this.push(payload.encoded);
            this.payload_index++;
        }
        if (this.in_buffer.length) {
            const chunk = this.in_buffer;
            this.in_buffer = Buffer.alloc(0);
            const final = !this.in_buffer.length;
            const payload = payload_1.default.create(this.header, this.payload_key, (_d = (_c = this.keypair) === null || _c === void 0 ? void 0 : _c.secretKey) !== null && _d !== void 0 ? _d : null, chunk, this.payload_index, final);
            this.push(payload.encoded);
            this.payload_index++;
        }
        callback();
    }
}
exports.SigncryptStream = SigncryptStream;
function designcrypt(signcrypted, keypair, sender) {
    var e_1, _a;
    return __awaiter(this, void 0, void 0, function* () {
        const stream = new stream_1.Readable();
        stream.push(signcrypted);
        stream.push(null);
        const items = [];
        try {
            for (var _b = __asyncValues(msgpack.decodeStream(stream)), _c; _c = yield _b.next(), !_c.done;) {
                const item = _c.value;
                items.push(item);
            }
        }
        catch (e_1_1) { e_1 = { error: e_1_1 }; }
        finally {
            try {
                if (_c && !_c.done && (_a = _b.return)) yield _a.call(_b);
            }
            finally { if (e_1) throw e_1.error; }
        }
        const header_data = items.shift();
        const header = header_1.default.decode(header_data, true);
        // TODO: handle other recipient types
        const payload_key_and_recipient = header.decryptPayloadKeyWithCurve25519Keypair(keypair.secretKey);
        if (!payload_key_and_recipient)
            throw new Error('keypair is not an intended recipient');
        const [payload_key, recipient] = payload_key_and_recipient;
        const sender_public_key = header.decryptSender(payload_key);
        if (sender && (!sender_public_key || !Buffer.from(sender_public_key).equals(sender))) {
            throw new Error('Sender public key doesn\'t match');
        }
        let output = Buffer.alloc(0);
        for (const i in items) {
            const message = items[i];
            const payload = payload_1.default.decode(message, true);
            const final = items.length === (parseInt(i) + 1);
            if (payload.final && !final) {
                throw new Error('Found payload with invalid final flag, message extended?');
            }
            if (!payload.final && final) {
                throw new Error('Found payload with invalid final flag, message truncated?');
            }
            output = Buffer.concat([output, payload.decrypt(header, sender_public_key, payload_key, BigInt(i))]);
        }
        if (!items.length) {
            throw new Error('No signcrypted payloads, message truncated?');
        }
        return Object.assign(output, {
            sender_public_key,
        });
    });
}
exports.designcrypt = designcrypt;
class DesigncryptStream extends stream_1.Transform {
    constructor(keypair, sender) {
        super();
        this.keypair = keypair;
        this.decoder = new msgpack.Decoder(undefined, undefined);
        this.header_data = null;
        this.last_payload = null;
        this.payload_index = BigInt(-1);
        this.i = 0;
        this.sender = sender !== null && sender !== void 0 ? sender : null;
    }
    get header() {
        if (!this.header_data)
            throw new Error('Header hasn\'t been decoded yet');
        return this.header_data[0];
    }
    get payload_key() {
        if (!this.header_data)
            throw new Error('Header hasn\'t been decoded yet');
        return this.header_data[1];
    }
    get recipient() {
        if (!this.header_data)
            throw new Error('Header hasn\'t been decoded yet');
        return this.header_data[2];
    }
    get sender_public_key() {
        if (!this.header_data)
            throw new Error('Header hasn\'t been decoded yet');
        return this.header_data[3];
    }
    _transform(data, encoding, callback) {
        this.decoder.appendBuffer(data);
        try {
            let message;
            while (message = this.decoder.decodeSync()) {
                const remaining = Buffer.from(this.decoder.bytes).slice(this.decoder.pos);
                this.decoder.setBuffer(remaining);
                this._handleMessage(message);
            }
        }
        catch (err) {
            if (!(err instanceof Decoder_1.DataViewIndexOutOfBoundsError)) {
                return callback(err);
            }
        }
        callback();
    }
    _handleMessage(data) {
        if (exports.debug)
            console.log('Processing chunk #%d: %s', this.i++, data);
        if (!this.header_data) {
            const header = header_1.default.decode(data, true);
            // TODO: handle other recipient types
            const payload_key_and_recipient = header.decryptPayloadKeyWithCurve25519Keypair(this.keypair.secretKey);
            if (!payload_key_and_recipient)
                throw new Error('keypair is not an intended recipient');
            const [payload_key, recipient] = payload_key_and_recipient;
            const sender_public_key = header.decryptSender(payload_key);
            if (this.sender && (!sender_public_key || !Buffer.from(sender_public_key).equals(this.sender))) {
                throw new Error('Sender public key doesn\'t match');
            }
            this.header_data = [header, payload_key, recipient, sender_public_key];
        }
        else {
            this.payload_index++;
            if (this.last_payload) {
                if (this.last_payload.final) {
                    throw new Error('Found payload with invalid final flag, message extended?');
                }
                this.push(this.last_payload.decrypt(this.header, this.sender_public_key, this.payload_key, this.payload_index - BigInt(1)));
            }
            const payload = payload_1.default.decode(data, true);
            this.last_payload = payload;
        }
    }
    _flush(callback) {
        try {
            if (this.last_payload) {
                if (!this.last_payload.final) {
                    throw new Error('Found payload with invalid final flag, message truncated?');
                }
                this.push(this.last_payload.decrypt(this.header, this.sender_public_key, this.payload_key, this.payload_index));
            }
            if (!this.last_payload) {
                throw new Error('No signcrypted payloads, message truncated?');
            }
        }
        catch (err) {
            return callback(err);
        }
        callback();
    }
}
exports.DesigncryptStream = DesigncryptStream;
//# sourceMappingURL=index.js.map