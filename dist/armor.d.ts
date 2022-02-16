/// <reference types="node" />
import { MessageType as Mode } from './message-header';
import { Transform, TransformCallback } from 'stream';
export declare let debug: boolean;
/** The Base62 alphabet */
declare const BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/** The Base64 alphabet */
declare const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/** The Base85 alphabet */
declare const BASE85_ALPHABET = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu";
export declare type Alphabet = typeof BASE62_ALPHABET | typeof BASE64_ALPHABET | typeof BASE85_ALPHABET;
export declare enum MessageType {
    ENCRYPTED_MESSAGE = "ENCRYPTED MESSAGE",
    SIGNED_MESSAGE = "SIGNED MESSAGE",
    DETACHED_SIGNATURE = "DETACHED SIGNATURE"
}
export interface Options {
    /** The BaseX alphabet - usually Base62, or less frequently Base64 or Base85 */
    alphabet: Alphabet;
    block_size: number;
    char_block_size: number;
    /** Whether to output raw ASCII-armored data or include the header+footer */
    raw: boolean;
    shift: boolean;
    /** The message type to use in the header+footer */
    message_type: MessageType | Mode;
    /** The application name to use in the header+footer */
    app_name: string | null;
}
/**
 * Return the +input_bytes+ ascii-armored using the specified +options+
 */
export declare function armor(input: Uint8Array | string, options?: Partial<Options>): string;
export declare class ArmorStream extends Transform {
    readonly armor_options: Readonly<Options>;
    private in_buffer;
    private out_buffer;
    readonly armor_header: string;
    readonly armor_footer: string;
    private words;
    private i;
    constructor(options?: Partial<Options>);
    _transform(data: Buffer, encoding: string, callback: TransformCallback): void;
    _flush(callback: TransformCallback): void;
}
export interface DearmorResult extends Buffer {
    /** Any remaining data after the first armored data */
    remaining: Buffer;
    /** The message type and app name included in the header+footer */
    header_info: ArmorHeaderInfo;
}
export interface RawDearmorResult extends Buffer {
    /** Any remaining data after the first armored data */
    remaining: null;
    /** The message type and app name included in the header+footer */
    header_info: null;
}
export interface ArmorHeaderInfo {
    /** The message type from the header+footer */
    message_type: MessageType | string;
    /** The application name from the header+footer */
    app_name: string | null;
}
/**
 * Decode the ascii-armored data from the specified +input_chars+ using the given +options+.
 */
export declare function dearmor(input: string, options: Partial<Options> & {
    raw: true;
}): RawDearmorResult;
export declare function dearmor(input: string, options?: Partial<Options> & {
    raw: false | null | undefined;
}): DearmorResult;
export declare function dearmor(input: string, options?: Partial<Options>): DearmorResult | RawDearmorResult;
export declare class DearmorStream extends Transform {
    readonly armor_options: Readonly<Options>;
    private in_buffer;
    private out_buffer;
    private armor_header_info;
    private armor_header;
    private armor_footer;
    private words;
    private i;
    get header(): string;
    get footer(): string;
    get info(): ArmorHeaderInfo;
    constructor(options?: Partial<Options>);
    _transform(data: Buffer, encoding: string, callback: TransformCallback): void;
    _flush(callback: TransformCallback): void;
}
/**
 * Encode a single block of ascii-armored output from +bytes_block+ using the specified +alphabet+ and +shift+.
 */
export declare function encodeBlock(bytes_block: Buffer, alphabet?: Alphabet, shift?: boolean): string;
/**
 * Decode the specified ascii-armored +chars_block+ using the specified +alphabet+ and +shift+.
 */
export declare function decodeBlock(chars_block: string, alphabet?: Alphabet, shift?: boolean): Buffer;
export declare function efficientCharsSizes(alphabet_size: number, chars_size_upper_bound?: number): number[][];
export {};
