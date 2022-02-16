/// <reference types="node" />
import EncryptedMessageHeader from './header';
import EncryptedMessageRecipient from './recipient';
export default class EncryptedMessagePayload {
    static readonly PAYLOAD_NONCE_PREFIX: Buffer;
    /** `true` if this is the final payload */
    readonly final: boolean;
    /** An array of per-recipient authentication data */
    readonly authenticators: Uint8Array[];
    /** The NaCl secretbox for this payload */
    readonly payload_secretbox: Uint8Array;
    private _encoded_data;
    constructor(final: boolean, authenticators: Uint8Array[], payload_secretbox: Uint8Array);
    get encoded_data(): Buffer;
    /** The MessagePack encoded payload data */
    get encoded(): Buffer;
    static create(header: EncryptedMessageHeader, payload_key: Buffer, data: Buffer, index: bigint, final?: boolean): EncryptedMessagePayload;
    static generateAuthenticatorHash(header_hash: Buffer, payload_secretbox: Uint8Array, payload_secretbox_nonce: Uint8Array, final: boolean): Buffer;
    encode(): Buffer;
    static encodePayload(final: boolean, authenticators: Uint8Array[], payload_secretbox: Uint8Array): Buffer;
    static decode(encoded: any, unpacked?: boolean): EncryptedMessagePayload;
    decrypt(header: EncryptedMessageHeader, recipient: EncryptedMessageRecipient, payload_key: Uint8Array, index: bigint): Uint8Array;
}
