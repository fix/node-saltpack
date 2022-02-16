/// <reference types="node" />
import Header from '../message-header';
import SigncryptedMessageRecipient from './recipient';
export default class SigncryptedMessageHeader extends Header {
    static readonly SENDER_KEY_SECRETBOX_NONCE: Buffer;
    /** The 32 byte X25519 ephemeral public key */
    readonly public_key: Uint8Array;
    /**
     * A NaCl secretbox containing the sender's actual X25519 public key (or the epemeral public key, if the
     * sender wishes to be anonymous)
     */
    readonly sender_secretbox: Uint8Array;
    /** An array of recipient objects */
    readonly recipients: SigncryptedMessageRecipient[];
    readonly _encoded_data: [Buffer, Buffer] | null;
    constructor(public_key: Uint8Array, sender_secretbox: Uint8Array, recipients: SigncryptedMessageRecipient[]);
    get encoded_data(): [Buffer, Buffer];
    /** The MessagePack encoded outer header data */
    get encoded(): Buffer;
    /** The SHA512 hash of the MessagePack encoded inner header data */
    get hash(): Buffer;
    static create(public_key: Uint8Array, payload_key: Uint8Array, sender_public_key: Uint8Array | null, recipients: SigncryptedMessageRecipient[]): SigncryptedMessageHeader;
    encode(): [Buffer, Buffer];
    static encodeHeader(public_key: Uint8Array, sender: Uint8Array, recipients: SigncryptedMessageRecipient[]): [Buffer, Buffer];
    static decode(encoded: Uint8Array, unwrapped?: boolean): SigncryptedMessageHeader;
    /**
     * Decrypts and returns the payload key and recipient.
     */
    decryptPayloadKeyWithCurve25519Keypair(private_key: Uint8Array): [Uint8Array, SigncryptedMessageRecipient] | null;
    decryptPayloadKeyWithSymmetricKey(shared_symmetric_key: Uint8Array, recipient_identifier?: Uint8Array | null): [Uint8Array, SigncryptedMessageRecipient] | null;
    decryptSender(payload_key: Uint8Array): Uint8Array | null;
}
