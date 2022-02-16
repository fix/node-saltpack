/// <reference types="node" />
import Header from '../message-header';
export default class SignedMessageHeader extends Header {
    static readonly DETACHED_SIGNATURE_PREFIX: Buffer;
    static debug_fix_nonce: Buffer | null;
    /** The sender's Ed25519 public key */
    readonly public_key: Uint8Array;
    /** Random data for this message */
    readonly nonce: Uint8Array;
    /** `true` if this is an attached signature header, `false` if this is a detached signature header */
    readonly attached: boolean;
    private _encoded_data;
    constructor(public_key: Uint8Array, nonce: Uint8Array, attached?: boolean);
    get encoded_data(): [Buffer, Buffer];
    /** The MessagePack encoded outer header data */
    get encoded(): Buffer;
    /** The SHA512 hash of the MessagePack encoded inner header data */
    get hash(): Buffer;
    static create(public_key: Uint8Array, attached?: boolean): SignedMessageHeader;
    encode(): [Buffer, Buffer];
    static encodeHeader(public_key: Uint8Array, nonce: Uint8Array, attached: boolean): [Buffer, Buffer];
    static decode(encoded: Uint8Array, unwrapped?: boolean): SignedMessageHeader;
    signDetached(data: Uint8Array, private_key: Uint8Array): Buffer;
    verifyDetached(signature: Uint8Array, data: Uint8Array, public_key: Uint8Array): void;
}
