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
exports.verifyDetached = exports.signDetached = exports.VerifyStream = exports.verify = exports.SignStream = exports.sign = exports.CHUNK_LENGTH = exports.debug = void 0;
const header_1 = require("./header");
const payload_1 = require("./payload");
const util_1 = require("../util");
const stream_1 = require("stream");
const msgpack = require("@msgpack/msgpack");
const Decoder_1 = require("@msgpack/msgpack/dist/Decoder");
exports.debug = false;
exports.CHUNK_LENGTH = 1024 * 1024;
function sign(data, keypair) {
    const chunks = util_1.chunkBuffer(data, exports.CHUNK_LENGTH);
    const header = header_1.default.create(keypair.publicKey, true);
    const payloads = [];
    for (const i in chunks) {
        const chunk = chunks[i];
        const final = chunks.length === (parseInt(i) + 1);
        const payload = payload_1.default.create(header, keypair.secretKey, chunk, BigInt(i), final);
        payloads.push(payload);
    }
    return Buffer.concat([
        header.encoded,
        Buffer.concat(payloads.map(payload => payload.encoded)),
    ]);
}
exports.sign = sign;
class SignStream extends stream_1.Transform {
    constructor(keypair) {
        super();
        this.keypair = keypair;
        this.in_buffer = Buffer.alloc(0);
        this.payload_index = BigInt(0);
        this.header = header_1.default.create(keypair.publicKey, true);
        this.push(this.header.encoded);
    }
    _transform(data, encoding, callback) {
        if (exports.debug)
            console.log('Processing chunk #d: %s', -1, data);
        this.in_buffer = Buffer.concat([this.in_buffer, data]);
        while (this.in_buffer.length > exports.CHUNK_LENGTH) {
            const chunk = this.in_buffer.slice(0, exports.CHUNK_LENGTH);
            this.in_buffer = this.in_buffer.slice(exports.CHUNK_LENGTH);
            // This is never the final payload as there must be additional data in `in_buffer`
            const payload = payload_1.default.create(this.header, this.keypair.secretKey, chunk, this.payload_index, /* final */ false);
            this.push(payload.encoded);
            this.payload_index++;
        }
        callback();
    }
    _flush(callback) {
        while (this.in_buffer.length >= exports.CHUNK_LENGTH) {
            const chunk = this.in_buffer.slice(0, exports.CHUNK_LENGTH);
            this.in_buffer = this.in_buffer.slice(exports.CHUNK_LENGTH);
            const final = !this.in_buffer.length;
            const payload = payload_1.default.create(this.header, this.keypair.secretKey, chunk, this.payload_index, final);
            this.push(payload.encoded);
            this.payload_index++;
        }
        if (this.in_buffer.length) {
            const chunk = this.in_buffer;
            this.in_buffer = Buffer.alloc(0);
            const final = !this.in_buffer.length;
            const payload = payload_1.default.create(this.header, this.keypair.secretKey, chunk, this.payload_index, final);
            this.push(payload.encoded);
            this.payload_index++;
        }
        callback();
    }
}
exports.SignStream = SignStream;
function verify(signed, public_key) {
    var e_1, _a;
    return __awaiter(this, void 0, void 0, function* () {
        const stream = new stream_1.Readable();
        stream.push(signed);
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
        if (public_key && !Buffer.from(header.public_key).equals(public_key)) {
            throw new Error('Sender public key doesn\'t match');
        }
        let output = Buffer.alloc(0);
        for (const i in items) {
            const message = items[i];
            const final = items.length === (parseInt(i) + 1);
            const payload = payload_1.default.decode(message, true);
            payload.verify(header, header.public_key, BigInt(i));
            if (payload.final && !final) {
                throw new Error('Found payload with invalid final flag, message extended?');
            }
            if (!payload.final && final) {
                throw new Error('Found payload with invalid final flag, message truncated?');
            }
            output = Buffer.concat([output, payload.data]);
        }
        if (!items.length) {
            throw new Error('No signed payloads, message truncated?');
        }
        return Object.assign(output, {
            public_key: new Uint8Array(header.public_key),
        });
    });
}
exports.verify = verify;
class VerifyStream extends stream_1.Transform {
    constructor(public_key) {
        super();
        this.decoder = new msgpack.Decoder(undefined, undefined);
        this.header_data = null;
        this.last_payload = null;
        this.payload_index = BigInt(-1);
        this.i = 0;
        this._public_key = public_key !== null && public_key !== void 0 ? public_key : null;
    }
    get header() {
        if (!this.header_data)
            throw new Error('Header hasn\'t been decoded yet');
        return this.header_data;
    }
    get public_key() {
        return this.header.public_key;
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
            console.log('Processing chunk #%d: %O', this.i++, data);
        if (!this.header_data) {
            const header = header_1.default.decode(data, true);
            if (this._public_key && !Buffer.from(header.public_key).equals(this._public_key)) {
                throw new Error('Sender public key doesn\'t match');
            }
            this.header_data = header;
            // @ts-expect-error
            header.public_key = new Uint8Array(header.public_key);
        }
        else {
            this.payload_index++;
            if (this.last_payload) {
                if (this.last_payload.final) {
                    throw new Error('Found payload with invalid final flag, message extended?');
                }
                this.push(this.last_payload.data);
            }
            const payload = payload_1.default.decode(data, true);
            payload.verify(this.header, this.header.public_key, this.payload_index);
            this.last_payload = payload;
        }
    }
    _flush(callback) {
        try {
            if (this.last_payload) {
                if (!this.last_payload.final) {
                    throw new Error('Found payload with invalid final flag, message truncated?');
                }
                this.push(this.last_payload.data);
            }
            if (!this.last_payload) {
                throw new Error('No signed payloads, message truncated?');
            }
        }
        catch (err) {
            return callback(err);
        }
        callback();
    }
}
exports.VerifyStream = VerifyStream;
function signDetached(data, keypair) {
    const header = header_1.default.create(keypair.publicKey, false);
    return Buffer.concat([
        header.encoded,
        msgpack.encode(header.signDetached(Buffer.from(data), keypair.secretKey)),
    ]);
}
exports.signDetached = signDetached;
function verifyDetached(signature, data, public_key) {
    var e_2, _a;
    return __awaiter(this, void 0, void 0, function* () {
        const stream = new stream_1.Readable();
        stream.push(signature);
        stream.push(null);
        const items = [];
        try {
            for (var _b = __asyncValues(msgpack.decodeStream(stream)), _c; _c = yield _b.next(), !_c.done;) {
                const item = _c.value;
                items.push(item);
            }
        }
        catch (e_2_1) { e_2 = { error: e_2_1 }; }
        finally {
            try {
                if (_c && !_c.done && (_a = _b.return)) yield _a.call(_b);
            }
            finally { if (e_2) throw e_2.error; }
        }
        const [header_data, signature_data] = items;
        const header = header_1.default.decode(header_data, true);
        if (public_key && !Buffer.from(header.public_key).equals(public_key)) {
            throw new Error('Sender public key doesn\'t match');
        }
        header.verifyDetached(signature_data, Buffer.from(data), header.public_key);
        return {
            public_key: new Uint8Array(header.public_key),
        };
    });
}
exports.verifyDetached = verifyDetached;
//# sourceMappingURL=index.js.map