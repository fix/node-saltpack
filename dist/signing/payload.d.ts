/// <reference types="node" />
import SignedMessageHeader from './header';
export default class SignedMessagePayload {
    static readonly PAYLOAD_SIGNATURE_PREFIX: Buffer;
    /** `true` if this is the final payload */
    readonly final: boolean;
    /** The NaCl detached signature for this payload */
    readonly signature: Buffer;
    /** This payload's data */
    readonly data: Buffer;
    private _encoded_data;
    constructor(final: boolean, signature: Buffer, data: Buffer);
    get encoded_data(): Buffer;
    /** The MessagePack encoded payload data */
    get encoded(): Buffer;
    static create(header: SignedMessageHeader, private_key: Uint8Array, data: Buffer, index: number | bigint, final?: boolean): SignedMessagePayload;
    static generateSignData(header_hash: Buffer, index: bigint, final: boolean, data: Buffer): Buffer;
    encode(): Buffer;
    static encodePayload(final: boolean, signature: Buffer, payload_chunk: Buffer): Buffer;
    static decode(encoded: any, unpacked?: boolean): SignedMessagePayload;
    verify(header: SignedMessageHeader, public_key: Uint8Array, index: bigint): void;
}
