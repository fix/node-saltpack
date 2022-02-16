"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.chunkString = exports.chunkBuffer = void 0;
function chunkBuffer(_buffer, length) {
    let buffer = _buffer instanceof Buffer ? _buffer : Buffer.from(_buffer);
    const result = [];
    while (buffer.length > length) {
        const chunk = buffer.slice(0, length);
        buffer = buffer.slice(length);
        result.push(chunk);
    }
    if (buffer.length) {
        result.push(buffer);
    }
    return result;
}
exports.chunkBuffer = chunkBuffer;
function chunkString(string, length) {
    const result = [];
    while (string.length > length) {
        const chunk = string.substr(0, length);
        string = string.substr(length);
        result.push(chunk);
    }
    if (string.length) {
        result.push(string);
    }
    return result;
}
exports.chunkString = chunkString;
//# sourceMappingURL=util.js.map