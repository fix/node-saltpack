"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DearmorAndDesigncryptStream = exports.SigncryptAndArmorStream = exports.dearmorAndDesigncrypt = exports.signcryptAndArmor = exports.verifyDetachedArmored = exports.signDetachedAndArmor = exports.DearmorAndVerifyStream = exports.SignAndArmorStream = exports.verifyArmored = exports.signAndArmor = exports.DearmorAndDecryptStream = exports.EncryptAndArmorStream = exports.dearmorAndDecrypt = exports.encryptAndArmor = void 0;
const encryption_1 = require("./encryption");
const signing_1 = require("./signing");
const signcryption_1 = require("./signcryption");
const armor_1 = require("./armor");
const Pumpify = require("pumpify");
function encryptAndArmor(data, keypair, recipients_keys) {
    return __awaiter(this, void 0, void 0, function* () {
        const encrypted = yield encryption_1.encrypt(data, keypair, recipients_keys);
        return armor_1.armor(encrypted, { message_type: armor_1.MessageType.ENCRYPTED_MESSAGE });
    });
}
exports.encryptAndArmor = encryptAndArmor;
function dearmorAndDecrypt(encrypted, keypair, sender) {
    return __awaiter(this, void 0, void 0, function* () {
        const dearmored = armor_1.dearmor(encrypted);
        return Object.assign(yield encryption_1.decrypt(dearmored, keypair, sender), {
            remaining: dearmored.remaining,
            header_info: dearmored.header_info,
        });
    });
}
exports.dearmorAndDecrypt = dearmorAndDecrypt;
class EncryptAndArmorStream extends Pumpify {
    constructor(keypair, recipients_keys, armor_options) {
        const encrypt = new encryption_1.EncryptStream(keypair, recipients_keys);
        const armor = new armor_1.ArmorStream(Object.assign({
            message_type: armor_1.MessageType.ENCRYPTED_MESSAGE,
        }, armor_options));
        super(encrypt, armor);
    }
}
exports.EncryptAndArmorStream = EncryptAndArmorStream;
class DearmorAndDecryptStream extends Pumpify {
    constructor(keypair, sender, armor_options) {
        const dearmor = new armor_1.DearmorStream(armor_options);
        const decrypt = new encryption_1.DecryptStream(keypair, sender);
        super(dearmor, decrypt);
        this.dearmor = dearmor;
        this.decrypt = decrypt;
    }
    get info() {
        return this.dearmor.info;
    }
    get sender_public_key() {
        return this.decrypt.sender_public_key;
    }
}
exports.DearmorAndDecryptStream = DearmorAndDecryptStream;
function signAndArmor(data, keypair) {
    return __awaiter(this, void 0, void 0, function* () {
        const signed = signing_1.sign(data, keypair);
        return armor_1.armor(signed, { message_type: armor_1.MessageType.SIGNED_MESSAGE });
    });
}
exports.signAndArmor = signAndArmor;
function verifyArmored(signed, public_key) {
    return __awaiter(this, void 0, void 0, function* () {
        const dearmored = armor_1.dearmor(signed);
        return Object.assign(yield signing_1.verify(dearmored, public_key), {
            remaining: dearmored.remaining,
            header_info: dearmored.header_info,
        });
    });
}
exports.verifyArmored = verifyArmored;
class SignAndArmorStream extends Pumpify {
    constructor(keypair, armor_options) {
        const sign = new signing_1.SignStream(keypair);
        const armor = new armor_1.ArmorStream(Object.assign({
            message_type: armor_1.MessageType.SIGNED_MESSAGE,
        }, armor_options));
        super(sign, armor);
    }
}
exports.SignAndArmorStream = SignAndArmorStream;
class DearmorAndVerifyStream extends Pumpify {
    constructor(public_key, armor_options) {
        const dearmor = new armor_1.DearmorStream(armor_options);
        const verify = new signing_1.VerifyStream(public_key);
        super(dearmor, verify);
        this.dearmor = dearmor;
        this.verify = verify;
    }
    get info() {
        return this.dearmor.info;
    }
    get public_key() {
        return this.verify.public_key;
    }
}
exports.DearmorAndVerifyStream = DearmorAndVerifyStream;
function signDetachedAndArmor(data, keypair) {
    return __awaiter(this, void 0, void 0, function* () {
        const signed = signing_1.signDetached(data, keypair);
        return armor_1.armor(signed, { message_type: armor_1.MessageType.DETACHED_SIGNATURE });
    });
}
exports.signDetachedAndArmor = signDetachedAndArmor;
function verifyDetachedArmored(signature, data, public_key) {
    return __awaiter(this, void 0, void 0, function* () {
        const dearmored = armor_1.dearmor(signature);
        const result = yield signing_1.verifyDetached(dearmored, data, public_key);
        return {
            remaining: dearmored.remaining,
            header_info: dearmored.header_info,
            public_key: result.public_key,
        };
    });
}
exports.verifyDetachedArmored = verifyDetachedArmored;
function signcryptAndArmor(data, keypair, recipients_keys) {
    return __awaiter(this, void 0, void 0, function* () {
        const encrypted = yield signcryption_1.signcrypt(data, keypair, recipients_keys);
        return armor_1.armor(encrypted, { message_type: armor_1.MessageType.ENCRYPTED_MESSAGE });
    });
}
exports.signcryptAndArmor = signcryptAndArmor;
function dearmorAndDesigncrypt(signcrypted, keypair, sender) {
    return __awaiter(this, void 0, void 0, function* () {
        const dearmored = armor_1.dearmor(signcrypted);
        return Object.assign(yield signcryption_1.designcrypt(dearmored, keypair, sender), {
            remaining: dearmored.remaining,
            header_info: dearmored.header_info,
        });
    });
}
exports.dearmorAndDesigncrypt = dearmorAndDesigncrypt;
class SigncryptAndArmorStream extends Pumpify {
    constructor(keypair, recipients_keys, armor_options) {
        const encrypt = new signcryption_1.SigncryptStream(keypair, recipients_keys);
        const armor = new armor_1.ArmorStream(Object.assign({
            message_type: armor_1.MessageType.ENCRYPTED_MESSAGE,
        }, armor_options));
        super(encrypt, armor);
    }
}
exports.SigncryptAndArmorStream = SigncryptAndArmorStream;
class DearmorAndDesigncryptStream extends Pumpify {
    constructor(keypair, armor_options) {
        const dearmor = new armor_1.DearmorStream(armor_options);
        const decrypt = new signcryption_1.DesigncryptStream(keypair);
        super(dearmor, decrypt);
        this.dearmor = dearmor;
        this.decrypt = decrypt;
    }
    get info() {
        return this.dearmor.info;
    }
    get sender_public_key() {
        return this.decrypt.sender_public_key;
    }
}
exports.DearmorAndDesigncryptStream = DearmorAndDesigncryptStream;
//# sourceMappingURL=with-armor.js.map