"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.efficientCharsSizes = exports.decodeBlock = exports.encodeBlock = exports.DearmorStream = exports.dearmor = exports.ArmorStream = exports.armor = exports.MessageType = exports.debug = void 0;
const message_header_1 = require("./message-header");
const util_1 = require("./util");
const stream_1 = require("stream");
const chunk = require("lodash.chunk");
exports.debug = false;
/** The Base62 alphabet */
const BASE62_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
/** The Base64 alphabet */
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
/** The Base85 alphabet */
const BASE85_ALPHABET = '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu';
// Also accept message type "MESSAGE"
// (should really be "ENCRYPTED MESSAGE", "SIGNED MESSAGE" or "DETACHED SIGNATURE")
const HEADER_REGEX = /^[>\n\r\t ]*BEGIN[>\n\r\t ]+(([a-zA-Z0-9]+)[>\n\r\t ]+)?SALTPACK[>\n\r\t ]+(MESSAGE|ENCRYPTED[>\n\r\t ]+MESSAGE|SIGNED[>\n\r\t ]+MESSAGE|DETACHED[>\n\r\t ]+SIGNATURE)[>\n\r\t ]*$/;
const FOOTER_REGEX = /^[>\n\r\t ]*END[>\n\r\t ]+(([a-zA-Z0-9]+)[>\n\r\t ]+)?SALTPACK[>\n\r\t ]+(MESSAGE|ENCRYPTED[>\n\r\t ]+MESSAGE|SIGNED[>\n\r\t ]+MESSAGE|DETACHED[>\n\r\t ]+SIGNATURE)[>\n\r\t ]*$/;
var MessageType;
(function (MessageType) {
    MessageType["ENCRYPTED_MESSAGE"] = "ENCRYPTED MESSAGE";
    MessageType["SIGNED_MESSAGE"] = "SIGNED MESSAGE";
    MessageType["DETACHED_SIGNATURE"] = "DETACHED SIGNATURE";
    /** @private */
    // MESSAGE = 'MESSAGE',
})(MessageType = exports.MessageType || (exports.MessageType = {}));
function modeToStringType(type) {
    switch (type) {
        case message_header_1.MessageType.ENCRYPTION: return MessageType.ENCRYPTED_MESSAGE;
        case message_header_1.MessageType.ATTACHED_SIGNING: return MessageType.SIGNED_MESSAGE;
        case message_header_1.MessageType.DETACHED_SIGNING: return MessageType.DETACHED_SIGNATURE;
        case message_header_1.MessageType.SIGNCRYPTION: return MessageType.ENCRYPTED_MESSAGE;
        default: return 'MESSAGE';
    }
}
/** The default options used by the armor/dearmor methods. */
const DEFAULT_OPTIONS = {
    alphabet: BASE62_ALPHABET,
    block_size: 32,
    char_block_size: 43,
    raw: false,
    shift: false,
    message_type: 'MESSAGE',
    app_name: null,
};
/** Return the index of the specified +char+ in +alphabet+, raising an appropriate error if it is not found. */
function getCharIndex(alphabet, char) {
    const rval = alphabet.indexOf(char);
    if (rval === -1) {
        throw new Error('Could not find ' + char + ' in alphabet ' + alphabet);
    }
    return rval;
}
/** Return the minimum number of characters needed to encode +bytes_size+ bytes using the given +alphabet+. */
function characterBlockSize(alphabet_size, bytes_size) {
    return Math.ceil(8 * bytes_size / Math.log2(alphabet_size));
}
/** Return the maximum number of bytes needed to encode +chars_size+ characters using the given +alphabet+. */
function maxBytesSize(alphabet_size, chars_size) {
    return Math.floor(Math.log2(alphabet_size) / 8 * chars_size);
}
/**
 * Return the number of bits left over after using an alphabet of the specified +alphabet_size+ to encode a
 * payload of +bytes_size+ with +chars_size+ characters.
 */
function extraBits(alphabet_size, chars_size, bytes_size) {
    const total_bits = Math.floor(Math.log2(alphabet_size) * chars_size);
    return total_bits - 8 * bytes_size;
}
function armor(input, _options) {
    const options = Object.assign({}, DEFAULT_OPTIONS, _options);
    if (typeof options.message_type === 'number')
        options.message_type = modeToStringType(options.message_type);
    const chunks = util_1.chunkBuffer(input, options.block_size);
    let output = '';
    for (const chunk of chunks) {
        output += encodeBlock(chunk, options.alphabet, options.shift);
    }
    if (options.raw) {
        const out_chunks = util_1.chunkString(output, 43);
        return out_chunks.join(' ');
    }
    const word_chunks = util_1.chunkString(output, 15);
    const sentences = chunk(word_chunks, 200);
    const joined = sentences.map(words => words.join(' ')).join('\n');
    const app = options.app_name ? ' ' + options.app_name : '';
    const header = 'BEGIN' + app + ' SALTPACK ' + options.message_type + '. ';
    const footer = '. END' + app + ' SALTPACK ' + options.message_type + '.';
    return header + joined + footer;
}
exports.armor = armor;
class ArmorStream extends stream_1.Transform {
    constructor(options) {
        super();
        this.in_buffer = Buffer.alloc(0);
        this.out_buffer = '';
        this.words = 0;
        this.i = 0;
        this.armor_options = Object.assign({}, DEFAULT_OPTIONS, options);
        if (typeof this.armor_options.message_type === 'number') {
            // @ts-expect-error
            this.armor_options.message_type = modeToStringType(this.armor_options.message_type);
        }
        const app = this.armor_options.app_name ? ' ' + this.armor_options.app_name : '';
        this.armor_header = 'BEGIN' + app + ' SALTPACK ' + this.armor_options.message_type + '. ';
        this.armor_footer = '. END' + app + ' SALTPACK ' + this.armor_options.message_type + '.';
        if (!this.armor_options.raw) {
            this.push(this.armor_header);
        }
    }
    _transform(data, encoding, callback) {
        if (exports.debug)
            console.log('Processing chunk #%d: %O', this.i++, data);
        this.in_buffer = Buffer.concat([this.in_buffer, data]);
        while (this.in_buffer.length > this.armor_options.block_size) {
            const block = this.in_buffer.slice(0, this.armor_options.block_size);
            this.in_buffer = this.in_buffer.slice(this.armor_options.block_size);
            this.out_buffer += encodeBlock(block, this.armor_options.alphabet, this.armor_options.shift);
        }
        if (this.armor_options.raw) {
            while (this.out_buffer.length > 43) {
                this.push(this.out_buffer.substr(0, 43) + ' ');
                this.out_buffer = this.out_buffer.substr(43);
            }
        }
        else {
            while (this.out_buffer.length > 15) {
                const word = this.out_buffer.substr(0, 15);
                this.out_buffer = this.out_buffer.substr(15);
                this.words++;
                if (this.words >= 200) {
                    this.push(word + '\n');
                    this.words = 0;
                }
                else {
                    this.push(word + ' ');
                }
            }
        }
        callback();
    }
    _flush(callback) {
        if (this.in_buffer.length > 0) {
            this.out_buffer += encodeBlock(this.in_buffer, this.armor_options.alphabet, this.armor_options.shift);
            this.in_buffer = Buffer.alloc(0);
        }
        if (this.armor_options.raw) {
            while (this.out_buffer.length > 43) {
                this.push(this.out_buffer.substr(0, 43) + ' ');
                this.out_buffer = this.out_buffer.substr(43);
            }
        }
        else {
            while (this.out_buffer.length > 15) {
                const word = this.out_buffer.substr(0, 15);
                this.out_buffer = this.out_buffer.substr(15);
                this.words++;
                if (this.words >= 200) {
                    this.push(word + '\n');
                    this.words = 0;
                }
                else {
                    this.push(word + ' ');
                }
            }
        }
        this.push(this.out_buffer);
        if (!this.armor_options.raw) {
            this.push(this.armor_footer);
        }
        callback();
    }
}
exports.ArmorStream = ArmorStream;
function dearmor(input, _options) {
    var _a;
    const options = Object.assign({}, DEFAULT_OPTIONS, _options);
    let header, header_info = null, footer, remaining = null, match;
    if (!options.raw) {
        [header, input, footer, remaining] = input.split('.', 4);
        remaining = Buffer.from(remaining);
        if (!(match = header.match(HEADER_REGEX))) {
            throw new Error('Invalid header');
        }
        header_info = {
            message_type: match[3],
            app_name: (_a = match[2]) !== null && _a !== void 0 ? _a : null,
        };
        if (!(match = footer.match(FOOTER_REGEX))) {
            throw new Error('Invalid footer');
        }
        if (header_info.message_type !== match[3] ||
            header_info.app_name != match[2]) {
            throw new Error('Footer doesn\'t match header');
        }
    }
    input = input.replace(/[>\n\r\t ]/g, '');
    const chunks = util_1.chunkString(input, options.char_block_size);
    const output_chunks = chunks.map(chunk => decodeBlock(chunk, options.alphabet, options.shift));
    const output = Buffer.concat(output_chunks);
    return Object.assign(output, {
        remaining: remaining,
        header_info: header_info,
    });
}
exports.dearmor = dearmor;
class DearmorStream extends stream_1.Transform {
    constructor(options) {
        super();
        this.in_buffer = Buffer.alloc(0);
        this.out_buffer = '';
        this.armor_header_info = null;
        this.armor_header = null;
        this.armor_footer = null;
        this.words = 0;
        this.i = 0;
        this.armor_options = Object.assign({}, DEFAULT_OPTIONS, options);
    }
    get header() {
        if (this.armor_options.raw)
            throw new Error('Header isn\'t available when decoding raw armored data');
        if (!this.armor_header)
            throw new Error('Header hasn\'t been decoded yet');
        return this.armor_header;
    }
    get footer() {
        if (this.armor_options.raw)
            throw new Error('Footer isn\'t available when decoding raw armored data');
        if (!this.armor_footer)
            throw new Error('Footer hasn\'t been decoded yet');
        return this.armor_footer;
    }
    get info() {
        if (this.armor_options.raw)
            throw new Error('Header isn\'t available when decoding raw armored data');
        if (!this.armor_header_info)
            throw new Error('Header hasn\'t been decoded yet');
        return this.armor_header_info;
    }
    _transform(data, encoding, callback) {
        var _a;
        if (exports.debug)
            console.log('Processing chunk #%d: %O', this.i++, data);
        if (!this.armor_options.raw && this.armor_header === null) {
            this.in_buffer = Buffer.concat([this.in_buffer, data]);
            const index = this.in_buffer.indexOf('.');
            if (index === -1)
                return callback();
            this.armor_header = this.in_buffer.slice(0, index).toString();
            data = this.in_buffer.slice(index + 1);
            const header_match = this.armor_header.match(HEADER_REGEX);
            if (!header_match) {
                const err = new Error('Invalid header');
                callback(err);
                throw err;
            }
            this.armor_header_info = {
                message_type: header_match[3],
                app_name: (_a = header_match[2]) !== null && _a !== void 0 ? _a : null,
            };
            if (exports.debug)
                console.log('Read header: %s', this.armor_header);
        }
        if (!this.armor_options.raw && this.armor_footer !== null) {
            this.armor_footer += data.toString();
            const remaining_index = this.armor_footer.indexOf('.');
            if (remaining_index !== -1) {
                this.armor_footer = this.armor_footer.substr(0, remaining_index);
                return callback();
            }
        }
        if (!this.armor_options.raw && this.armor_footer === null) {
            const index = data.indexOf('.');
            if (index !== -1) {
                this.armor_footer = data.slice(index + 1).toString();
                data = data.slice(0, index);
                this.out_buffer = data.toString().replace(/[>\n\r\t ]/g, '');
                const remaining_index = this.armor_footer.indexOf('.');
                if (remaining_index !== -1) {
                    this.armor_footer = this.armor_footer.substr(0, remaining_index);
                    return callback();
                }
                return callback();
            }
        }
        if (this.armor_options.raw || this.armor_footer === null) {
            this.out_buffer += data.toString().replace(/[>\n\r\t ]/g, '');
            while (this.out_buffer.length > this.armor_options.char_block_size) {
                const block = this.out_buffer.substr(0, this.armor_options.char_block_size);
                this.out_buffer = this.out_buffer.substr(this.armor_options.char_block_size);
                this.push(decodeBlock(block, this.armor_options.alphabet, this.armor_options.shift));
            }
        }
        callback();
    }
    _flush(callback) {
        var _a;
        while (this.out_buffer.length > this.armor_options.char_block_size) {
            const block = this.out_buffer.substr(0, this.armor_options.char_block_size);
            this.out_buffer = this.out_buffer.substr(this.armor_options.char_block_size);
            this.push(decodeBlock(block, this.armor_options.alphabet, this.armor_options.shift));
        }
        if (this.out_buffer.length > 0) {
            this.push(decodeBlock(this.out_buffer, this.armor_options.alphabet, this.armor_options.shift));
            this.out_buffer = '';
        }
        if (!this.armor_options.raw && this.armor_footer === null) {
            const err = new Error('Input stream doesn\'t contain a valid header and footer');
            callback(err);
            throw err;
        }
        if (!this.armor_options.raw) {
            const footer_match = (_a = this.armor_footer) === null || _a === void 0 ? void 0 : _a.match(FOOTER_REGEX);
            if (!footer_match) {
                throw new Error('Invalid footer');
            }
            if (this.armor_header_info.message_type !== footer_match[3] ||
                this.armor_header_info.app_name != footer_match[2]) {
                throw new Error('Footer doesn\'t match header');
            }
            if (exports.debug)
                console.log('Read footer: %s', this.armor_footer);
        }
        callback();
    }
}
exports.DearmorStream = DearmorStream;
/**
 * Encode a single block of ascii-armored output from +bytes_block+ using the specified +alphabet+ and +shift+.
 */
function encodeBlock(bytes_block, alphabet = BASE62_ALPHABET, shift = false) {
    const block_size = characterBlockSize(alphabet.length, bytes_block.length);
    const extra = extraBits(alphabet.length, block_size, bytes_block.length);
    // Convert the bytes into an integer, big-endian
    let bytes_int = BigInt('0x' + bytes_block.toString('hex'));
    if (shift) {
        bytes_int <<= BigInt(extra);
    }
    const alphabet_size = BigInt(alphabet.length);
    const places = [];
    for (let i = 0; i < block_size; i++) {
        const rem = parseInt((bytes_int % alphabet_size).toString());
        places.unshift(rem);
        bytes_int = bytes_int / alphabet_size;
    }
    return places.map(i => alphabet[i]).join('');
}
exports.encodeBlock = encodeBlock;
/**
 * Decode the specified ascii-armored +chars_block+ using the specified +alphabet+ and +shift+.
 */
function decodeBlock(chars_block, alphabet = BASE62_ALPHABET, shift = false) {
    const bytes_size = maxBytesSize(alphabet.length, chars_block.length);
    const expected_block_size = characterBlockSize(alphabet.length, bytes_size);
    if (chars_block.length !== expected_block_size) {
        throw new TypeError('Illegal block size ' + chars_block.length + ', expected ' + expected_block_size);
    }
    const extra = extraBits(alphabet.length, chars_block.length, bytes_size);
    let bytes_int = BigInt(getCharIndex(alphabet, chars_block[0]));
    for (let i = 1; i < chars_block.length; i++) {
        bytes_int = bytes_int * BigInt(alphabet.length);
        bytes_int = bytes_int + BigInt(getCharIndex(alphabet, chars_block[i]));
    }
    if (shift) {
        bytes_int >>= BigInt(extra);
    }
    return Buffer.from(bytes_int.toString(16)
        .padStart(bytes_size * 2, '0').slice(0, bytes_size * 2), 'hex');
}
exports.decodeBlock = decodeBlock;
function efficientCharsSizes(alphabet_size, chars_size_upper_bound = 50) {
    const out = [];
    let max_efficiency = 0;
    for (let chars_size = 1; chars_size < chars_size_upper_bound; chars_size++) {
        const bytes_size = maxBytesSize(alphabet_size, chars_size);
        const efficiency = bytes_size / chars_size;
        if (efficiency > max_efficiency) {
            out.push([chars_size, bytes_size, efficiency]);
            max_efficiency = efficiency;
        }
    }
    return out;
}
exports.efficientCharsSizes = efficientCharsSizes;
//# sourceMappingURL=armor.js.map