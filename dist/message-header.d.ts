/// <reference types="node" />
export declare enum MessageType {
    ENCRYPTION = 0,
    ATTACHED_SIGNING = 1,
    DETACHED_SIGNING = 2,
    SIGNCRYPTION = 3
}
export default class Header {
    static decode1(encoded: Uint8Array, unwrapped?: boolean): [Buffer, any];
}
