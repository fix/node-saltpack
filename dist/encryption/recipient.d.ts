/// <reference types="node" />
export default class EncryptedMessageRecipient {
    static readonly PAYLOAD_KEY_BOX_NONCE_PREFIX_V2: Buffer;
    /** The recipient's X25519 public key, or null if the recipient is anonymous and we aren't the sender */
    readonly public_key: Uint8Array | null;
    /** The NaCl box containing the payload key for this recipient */
    readonly encrypted_payload_key: Uint8Array;
    /** The recipient index, starting from zero */
    readonly index: bigint;
    /** The nonce for `encrypted_payload_key` */
    readonly recipient_index: Buffer;
    /** `true` if this recipient is anonymous */
    readonly anonymous: boolean;
    /** The MAC key for this recipient (this is used to generate the per-payload authenticators for this recipient) */
    readonly mac_key: Buffer | null;
    constructor(public_key: Uint8Array | null, encrypted_payload_key: Uint8Array, index: bigint, anonymous?: boolean);
    /** @private */
    setPublicKey(public_key: Uint8Array): void;
    static create(public_key: Uint8Array, ephemeral_private_key: Uint8Array, payload_key: Uint8Array, index: number | bigint, anonymous?: boolean): EncryptedMessageRecipient;
    static from(public_key: Uint8Array | null, encrypted_payload_key: Uint8Array, index: number | bigint): EncryptedMessageRecipient;
    static generateRecipientIndex(index: bigint): Buffer;
    /**
     * Decrypts the payload key, returns null if wrong recipient.
     */
    decryptPayloadKey(ephemeral_public_key: Uint8Array, recipient_private_key: Uint8Array, secret?: Uint8Array | null): Uint8Array | null;
    generateMacKeyForSender(header_hash: Uint8Array, ephemeral_private_key: Uint8Array, sender_private_key: Uint8Array, public_key?: Uint8Array | null): Buffer;
    generateMacKeyForRecipient(header_hash: Uint8Array, ephemeral_public_key: Uint8Array, sender_public_key: Uint8Array, private_key: Uint8Array): Buffer;
}
