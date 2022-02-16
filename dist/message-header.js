"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MessageType = void 0;
const crypto = require("crypto");
const msgpack = require("@msgpack/msgpack");
var MessageType;
(function (MessageType) {
    MessageType[MessageType["ENCRYPTION"] = 0] = "ENCRYPTION";
    MessageType[MessageType["ATTACHED_SIGNING"] = 1] = "ATTACHED_SIGNING";
    MessageType[MessageType["DETACHED_SIGNING"] = 2] = "DETACHED_SIGNING";
    MessageType[MessageType["SIGNCRYPTION"] = 3] = "SIGNCRYPTION";
})(MessageType = exports.MessageType || (exports.MessageType = {}));
class Header {
    static decode1(encoded, unwrapped = false) {
        // 1-3
        const data = unwrapped ? encoded : msgpack.decode(encoded);
        const header_hash = crypto.createHash('sha512').update(data).digest();
        const inner = msgpack.decode(data);
        // 4
        if (inner.length < 2)
            throw new Error('Invalid data');
        const [format_name, version, mode] = inner;
        if (format_name !== 'saltpack')
            throw new Error('Invalid data');
        if (version.length !== 2)
            throw new Error('Invalid data');
        if (version[0] !== 2)
            throw new Error('Unsupported version');
        if (version[1] !== 0)
            throw new Error('Unsupported version');
        return [header_hash, inner];
    }
}
exports.default = Header;
//# sourceMappingURL=message-header.js.map