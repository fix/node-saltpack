/// <reference types="node" />
import SigncryptedMessageHeader from './header';
import SigncryptedMessageRecipient from './recipient';
import { Transform, TransformCallback } from 'stream';
import * as tweetnacl from 'tweetnacl';
export declare let debug: boolean;
export declare let debug_fix_key: Buffer | null;
export declare let debug_fix_keypair: tweetnacl.BoxKeyPair | null;
export declare function signcrypt(data: Uint8Array | string, keypair: tweetnacl.SignKeyPair | null, recipients_keys: Uint8Array[]): Promise<Buffer>;
export declare class SigncryptStream extends Transform {
    readonly payload_key: Buffer;
    readonly ephemeral_keypair: tweetnacl.BoxKeyPair;
    readonly keypair: tweetnacl.SignKeyPair | null;
    readonly header: SigncryptedMessageHeader;
    private in_buffer;
    private payload_index;
    private i;
    constructor(keypair: tweetnacl.SignKeyPair | null, recipients_keys: Uint8Array[]);
    _transform(data: Buffer, encoding: string, callback: TransformCallback): void;
    _flush(callback: TransformCallback): void;
}
export interface DesigncryptResult extends Buffer {
    sender_public_key: Uint8Array | null;
}
export declare function designcrypt(signcrypted: Uint8Array, keypair: tweetnacl.BoxKeyPair, sender?: Uint8Array | null): Promise<DesigncryptResult>;
export declare class DesigncryptStream extends Transform {
    readonly keypair: tweetnacl.BoxKeyPair;
    readonly sender: Uint8Array | null;
    private decoder;
    private header_data;
    private last_payload;
    private payload_index;
    private i;
    constructor(keypair: tweetnacl.BoxKeyPair, sender?: Uint8Array | null);
    get header(): SigncryptedMessageHeader;
    get payload_key(): Uint8Array;
    get recipient(): SigncryptedMessageRecipient;
    get sender_public_key(): Uint8Array | null;
    _transform(data: Buffer, encoding: string, callback: TransformCallback): void;
    private _handleMessage;
    _flush(callback: TransformCallback): void;
}
