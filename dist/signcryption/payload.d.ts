/// <reference types="node" />
import SigncryptedMessageHeader from './header';
export default class SigncryptedMessagePayload {
    static readonly PAYLOAD_NONCE_PREFIX: Buffer;
    /** The NaCl secretbox for this payload */
    readonly payload_secretbox: Uint8Array;
    /** `true` if this is the final payload */
    readonly final: boolean;
    private _encoded_data;
    constructor(payload_secretbox: Uint8Array, final: boolean);
    get encoded_data(): Buffer;
    /** The MessagePack encoded payload data */
    get encoded(): Buffer;
    static create(header: SigncryptedMessageHeader, payload_key: Uint8Array, private_key: Uint8Array | null, data: Buffer, index: bigint, final?: boolean): SigncryptedMessagePayload;
    static generateNonce(header_hash: Uint8Array, index: bigint, final: boolean): Buffer;
    static generateSignatureData(header_hash: Uint8Array, nonce: Uint8Array, final: boolean, data: Uint8Array): Buffer;
    encode(): Buffer;
    static encodePayload(payload_secretbox: Uint8Array, final: boolean): Buffer;
    static decode(encoded: any, unpacked?: boolean): SigncryptedMessagePayload;
    decrypt(header: SigncryptedMessageHeader, public_key: Uint8Array | null, payload_key: Uint8Array, index: bigint): Uint8Array;
}
