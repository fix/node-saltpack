/// <reference types="node" />
import SignedMessageHeader from './header';
import { Transform, TransformCallback } from 'stream';
import * as tweetnacl from 'tweetnacl';
export declare let debug: boolean;
export declare const CHUNK_LENGTH: number;
export declare function sign(data: Uint8Array | string, keypair: tweetnacl.SignKeyPair): Buffer;
export declare class SignStream extends Transform {
    readonly keypair: tweetnacl.SignKeyPair;
    readonly header: SignedMessageHeader;
    private in_buffer;
    private payload_index;
    constructor(keypair: tweetnacl.SignKeyPair);
    _transform(data: Buffer, encoding: string, callback: TransformCallback): void;
    _flush(callback: TransformCallback): void;
}
export interface VerifyResult extends Buffer {
    public_key: Uint8Array;
}
export declare function verify(signed: Uint8Array, public_key?: Uint8Array | null): Promise<VerifyResult>;
export declare class VerifyStream extends Transform {
    private readonly _public_key;
    private decoder;
    private header_data;
    private last_payload;
    private payload_index;
    private i;
    constructor(public_key?: Uint8Array | null);
    get header(): SignedMessageHeader;
    get public_key(): Uint8Array;
    _transform(data: Buffer, encoding: string, callback: TransformCallback): void;
    private _handleMessage;
    _flush(callback: TransformCallback): void;
}
export declare function signDetached(data: Uint8Array | string, keypair: tweetnacl.SignKeyPair): Buffer;
export interface VerifyDetachedResult {
    public_key: Uint8Array;
}
export declare function verifyDetached(signature: Uint8Array, data: Uint8Array | string, public_key?: Uint8Array | null): Promise<VerifyDetachedResult>;
