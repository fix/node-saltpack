/// <reference types="node" />
import { DecryptStream, DecryptResult } from './encryption';
import { VerifyStream, VerifyResult, VerifyDetachedResult } from './signing';
import { DesigncryptStream, DesigncryptResult } from './signcryption';
import { DearmorStream, Options as ArmorOptions, ArmorHeaderInfo, DearmorResult } from './armor';
import * as tweetnacl from 'tweetnacl';
import Pumpify = require('pumpify');
export declare function encryptAndArmor(data: Uint8Array | string, keypair: tweetnacl.BoxKeyPair | null, recipients_keys: Uint8Array[]): Promise<string>;
export declare function dearmorAndDecrypt(encrypted: string, keypair: tweetnacl.BoxKeyPair, sender?: Uint8Array | null): Promise<DearmorAndDecryptResult>;
export declare type DearmorAndDecryptResult = DearmorResult & DecryptResult;
export declare class EncryptAndArmorStream extends Pumpify {
    constructor(keypair: tweetnacl.BoxKeyPair | null, recipients_keys: Uint8Array[], armor_options?: Partial<ArmorOptions>);
}
export declare class DearmorAndDecryptStream extends Pumpify {
    readonly dearmor: DearmorStream;
    readonly decrypt: DecryptStream;
    constructor(keypair: tweetnacl.BoxKeyPair, sender?: Uint8Array | null, armor_options?: Partial<ArmorOptions>);
    get info(): ArmorHeaderInfo;
    get sender_public_key(): Uint8Array;
}
export declare function signAndArmor(data: Uint8Array | string, keypair: tweetnacl.SignKeyPair): Promise<string>;
export declare function verifyArmored(signed: string, public_key?: Uint8Array | null): Promise<DearmorAndVerifyResult>;
export declare type DearmorAndVerifyResult = DearmorResult & VerifyResult;
export declare class SignAndArmorStream extends Pumpify {
    constructor(keypair: tweetnacl.SignKeyPair, armor_options?: Partial<ArmorOptions>);
}
export declare class DearmorAndVerifyStream extends Pumpify {
    readonly dearmor: DearmorStream;
    readonly verify: VerifyStream;
    constructor(public_key?: Uint8Array | null, armor_options?: Partial<ArmorOptions>);
    get info(): ArmorHeaderInfo;
    get public_key(): Uint8Array;
}
export declare function signDetachedAndArmor(data: Uint8Array | string, keypair: tweetnacl.SignKeyPair): Promise<string>;
export declare function verifyDetachedArmored(signature: string, data: Uint8Array | string, public_key?: Uint8Array | null): Promise<DearmorAndVerifyDetachedResult>;
export interface DearmorAndVerifyDetachedResult extends VerifyDetachedResult {
    remaining: Buffer;
    header_info: ArmorHeaderInfo;
}
export declare function signcryptAndArmor(data: Uint8Array | string, keypair: tweetnacl.SignKeyPair | null, recipients_keys: Uint8Array[]): Promise<string>;
export declare function dearmorAndDesigncrypt(signcrypted: string, keypair: tweetnacl.BoxKeyPair, sender?: Uint8Array | null): Promise<DearmorAndDesigncryptResult>;
export declare type DearmorAndDesigncryptResult = DearmorResult & DesigncryptResult;
export declare class SigncryptAndArmorStream extends Pumpify {
    constructor(keypair: tweetnacl.SignKeyPair | null, recipients_keys: Uint8Array[], armor_options?: Partial<ArmorOptions>);
}
export declare class DearmorAndDesigncryptStream extends Pumpify {
    readonly dearmor: DearmorStream;
    readonly decrypt: DesigncryptStream;
    constructor(keypair: tweetnacl.BoxKeyPair, armor_options?: Partial<ArmorOptions>);
    get info(): ArmorHeaderInfo;
    get sender_public_key(): Uint8Array | null;
}
