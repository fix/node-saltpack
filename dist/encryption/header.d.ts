/// <reference types="node" />
import Header from '../message-header';
import EncryptedMessageRecipient from './recipient';
import * as tweetnacl from 'tweetnacl';
export default class EncryptedMessageHeader extends Header {
    static readonly SENDER_KEY_SECRETBOX_NONCE: Buffer;
    /** The 32 byte X25519 ephemeral public key */
    readonly public_key: Buffer;
    /**
     * A NaCl secretbox containing the sender's actual X25519 public key (or the epemeral public key, if the
     * sender wishes to be anonymous)
     */
    readonly sender_secretbox: Buffer;
    /** An array of recipient objects */
    readonly recipients: EncryptedMessageRecipient[];
    readonly _encoded_data: [Buffer, Buffer] | null;
    constructor(public_key: Buffer, sender_secretbox: Buffer, recipients: EncryptedMessageRecipient[]);
    get encoded_data(): [Buffer, Buffer];
    /** The MessagePack encoded outer header data */
    get encoded(): Buffer;
    /** The SHA512 hash of the MessagePack encoded inner header data */
    get hash(): Buffer;
    static create(public_key: Uint8Array, payload_key: Uint8Array, sender_public_key: Uint8Array, recipients: EncryptedMessageRecipient[]): EncryptedMessageHeader;
    encode(): [Buffer, Buffer];
    static encodeHeader(public_key: Buffer, sender: Buffer, recipients: EncryptedMessageRecipient[]): [Buffer, Buffer];
    static decode(encoded: Uint8Array, unwrapped?: boolean): EncryptedMessageHeader;
    /**
     * Decrypts and returns the payload key and recipient.
     */
    decryptPayloadKey(keypair: tweetnacl.BoxKeyPair): [Uint8Array, EncryptedMessageRecipient];
    decryptSender(payload_key: Uint8Array): Uint8Array;
}
