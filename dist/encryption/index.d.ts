/// <reference types="node" />
import EncryptedMessageHeader from './header';
import EncryptedMessageRecipient from './recipient';
import { Transform, TransformCallback } from 'stream';
import * as tweetnacl from 'tweetnacl';
export declare let debug: boolean;
export declare let debug_fix_key: Buffer | null;
export declare let debug_fix_keypair: tweetnacl.BoxKeyPair | null;
export declare function encrypt(data: Uint8Array | string, keypair: tweetnacl.BoxKeyPair | null, recipients_keys: Uint8Array[]): Promise<Buffer>;
export declare class EncryptStream extends Transform {
    readonly payload_key: Buffer;
    readonly ephemeral_keypair: tweetnacl.BoxKeyPair;
    readonly keypair: tweetnacl.BoxKeyPair;
    readonly header: EncryptedMessageHeader;
    private in_buffer;
    private payload_index;
    private i;
    constructor(keypair: tweetnacl.BoxKeyPair | null, recipients_keys: Uint8Array[]);
    _transform(data: Buffer, encoding: string, callback: TransformCallback): void;
    _flush(callback: TransformCallback): void;
}
export interface DecryptResult extends Buffer {
    sender_public_key: Uint8Array | null;
}
export declare function decrypt(encrypted: Uint8Array, keypair: tweetnacl.BoxKeyPair, sender?: Uint8Array | null): Promise<DecryptResult>;
export declare class DecryptStream extends Transform {
    readonly keypair: tweetnacl.BoxKeyPair;
    readonly sender: Uint8Array | null;
    private decoder;
    private header_data;
    private last_payload;
    private payload_index;
    private i;
    constructor(keypair: tweetnacl.BoxKeyPair, sender?: Uint8Array | null);
    get header(): EncryptedMessageHeader;
    get payload_key(): Uint8Array;
    get recipient(): EncryptedMessageRecipient;
    get sender_public_key(): Uint8Array;
    _transform(data: Buffer, encoding: string, callback: TransformCallback): void;
    private _handleMessage;
    _flush(callback: TransformCallback): void;
}
