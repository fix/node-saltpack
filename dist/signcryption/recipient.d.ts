/// <reference types="node" />
export default class SigncryptedMessageRecipient {
    static readonly SHARED_KEY_NONCE: Buffer;
    static readonly HMAC_KEY: Buffer;
    static readonly PAYLOAD_KEY_BOX_NONCE_PREFIX_V2: Buffer;
    readonly recipient_identifier: Uint8Array;
    /** The NaCl secretbox containing the payload key for this recipient */
    readonly encrypted_payload_key: Uint8Array;
    /** The recipient index, starting from zero */
    readonly index: bigint;
    /** The nonce for `encrypted_payload_key` */
    readonly recipient_index: Buffer;
    constructor(recipient_identifier: Uint8Array, /*shared_symmetric_key: Uint8Array | null,*/ encrypted_payload_key: Uint8Array, index: bigint);
    static create(public_key: Uint8Array, ephemeral_private_key: Uint8Array, payload_key: Uint8Array, index: number | bigint): SigncryptedMessageRecipient;
    static from(recipient_identifier: Uint8Array, encrypted_payload_key: Uint8Array, index: number | bigint): SigncryptedMessageRecipient;
    static generateRecipientIndex(index: bigint): Buffer;
    /**
     * Decrypts the payload key.
     */
    decryptPayloadKey(shared_symmetric_key: Uint8Array): Uint8Array | null;
    static generateRecipientIdentifierForSender(public_key: Uint8Array, ephemeral_private_key: Uint8Array, recipient_index: Uint8Array): {
        shared_symmetric_key: Buffer;
        recipient_identifier: Buffer;
    };
    static generateRecipientIdentifierForRecipient(ephemeral_public_key: Uint8Array, private_key: Uint8Array, recipient_index: Uint8Array): {
        shared_symmetric_key: Buffer;
        recipient_identifier: Buffer;
    };
}
