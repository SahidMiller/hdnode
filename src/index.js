"use strict";

// See: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
// See: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki


import { Base58 } from "@ethersproject/basex";
import { arrayify, concat, hexDataSlice, hexZeroPad, hexlify } from "@ethersproject/bytes";
import { BigNumber } from "@ethersproject/bignumber";
import { toUtf8Bytes } from "@ethersproject/strings";
import { defineReadOnly } from "@ethersproject/properties";
import { SigningKey } from "@ethersproject/signing-key";
import { computeHmac, ripemd160, sha256, SupportedAlgorithm } from "@ethersproject/sha2";
import bip39 from 'bip39-light'

import { Logger } from "@ethersproject/logger";
const logger = new Logger();

const N = BigNumber.from("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");


// "Bitcoin seed"
const MasterSecret = toUtf8Bytes("Bitcoin seed");

const HardenedBit = 0x80000000;

function bytes32(value) {
    return hexZeroPad(hexlify(value), 32);
}

function base58check(data) {
    return Base58.encode(concat([ data, hexDataSlice(sha256(sha256(data)), 0, 4) ]));
}

const _constructorGuard = {};

export const defaultPath = "m/44'/60'/0'/0/0";
export { bip39 as bip39 }

export class HDNode {

    /**
     *  This constructor should not be called directly.
     *
     *  Please use:
     *   - fromSeed
     */
    constructor(constructorGuard, privateKey, publicKey, parentFingerprint, chainCode, index, depth, path) {
        logger.checkNew(new.target, HDNode);

        /* istanbul ignore if */
        if (constructorGuard !== _constructorGuard) {
            throw new Error("HDNode constructor cannot be called directly");
        }

        if (privateKey) {
            const signingKey = new SigningKey(privateKey);
            defineReadOnly(this, "privateKey", signingKey.privateKey);
            defineReadOnly(this, "publicKey", signingKey.compressedPublicKey);
        } else {
            defineReadOnly(this, "privateKey", null);
            defineReadOnly(this, "publicKey", hexlify(publicKey));
        }

        defineReadOnly(this, "parentFingerprint", parentFingerprint);
        defineReadOnly(this, "fingerprint", hexDataSlice(ripemd160(sha256(this.publicKey)), 0, 4));

        defineReadOnly(this, "chainCode", chainCode);

        defineReadOnly(this, "index", index);
        defineReadOnly(this, "depth", depth);

        if (path == null) {
            // From a source that does not preserve the path (e.g. extended keys)
            defineReadOnly(this, "path", null);

        } else {
            // From a fully qualified source
            defineReadOnly(this, "path", typeof(path) === "string" ? path : path.path);
        }
    }

    get extendedKey() {
        // We only support the mainnet values for now, but if anyone needs
        // testnet values, let me know. I believe current senitment is that
        // we should always use mainnet, and use BIP-44 to derive the network
        //   - Mainnet: public=0x0488B21E, private=0x0488ADE4
        //   - Testnet: public=0x043587CF, private=0x04358394

        if (this.depth >= 256) { throw new Error("Depth too large!"); }

        return base58check(concat([
            ((this.privateKey != null) ? "0x0488ADE4": "0x0488B21E"),
            hexlify(this.depth),
            this.parentFingerprint,
            hexZeroPad(hexlify(this.index), 4),
            this.chainCode,
            ((this.privateKey != null) ? concat([ "0x00", this.privateKey ]): this.publicKey),
        ]));
    }

    neuter() {
        return new HDNode(_constructorGuard, null, this.publicKey, this.parentFingerprint, this.chainCode, this.index, this.depth, this.path);
    }

    derive(index) {
        if (index > 0xffffffff) { throw new Error("invalid index - " + String(index)); }

        // Base path
        let path = this.path;
        if (path) { path += "/" + (index & ~HardenedBit); }

        const data = new Uint8Array(37);

        if (index & HardenedBit) {
            if (!this.privateKey) {
                throw new Error("cannot derive child of neutered node");
            }

            // Data = 0x00 || ser_256(k_par)
            data.set(arrayify(this.privateKey), 1);

            // Hardened path
            if (path) { path += "'"; }

        } else {
            // Data = ser_p(point(k_par))
            data.set(arrayify(this.publicKey));
        }

        // Data += ser_32(i)
        for (let i = 24; i >= 0; i -= 8) { data[33 + (i >> 3)] = ((index >> (24 - i)) & 0xff); }

        const I = arrayify(computeHmac(SupportedAlgorithm.sha512, this.chainCode, data));
        const IL = I.slice(0, 32);
        const IR = I.slice(32);

        // The private key
        let ki = null

        // The public key
        let Ki = null;

        if (this.privateKey) {
            ki = bytes32(BigNumber.from(IL).add(this.privateKey).mod(N));
        } else {
            const ek = new SigningKey(hexlify(IL));
            Ki = ek._addPoint(this.publicKey);
        }

        return new HDNode(_constructorGuard, ki, Ki, this.fingerprint, bytes32(IR), index, this.depth + 1, path);
    }

    derivePath(path) {
        const components = path.split("/");

        if (components.length === 0 || (components[0] === "m" && this.depth !== 0)) {
            throw new Error("invalid path - " + path);
        }

        if (components[0] === "m") { components.shift(); }

        let result = this;
        for (let i = 0; i < components.length; i++) {
            const component = components[i];
            if (component.match(/^[0-9]+'$/)) {
                const index = parseInt(component.substring(0, component.length - 1));
                if (index >= HardenedBit) { throw new Error("invalid path index - " + component); }
                result = result.derive(HardenedBit + index);
            } else if (component.match(/^[0-9]+$/)) {
                const index = parseInt(component);
                if (index >= HardenedBit) { throw new Error("invalid path index - " + component); }
                result = result.derive(index);
            } else {
                throw new Error("invalid path component - " + component);
            }
        }

        return result;
    }

    static fromSeed(seed) {
        const seedArray = arrayify(seed);
        if (seedArray.length < 16 || seedArray.length > 64) { throw new Error("invalid seed"); }

        const I = arrayify(computeHmac(SupportedAlgorithm.sha512, MasterSecret, seedArray));

        return new HDNode(_constructorGuard, bytes32(I.slice(0, 32)), null, "0x00000000", bytes32(I.slice(32)), 0, 0, null);
    }

    static fromExtendedKey(extendedKey) {
        const bytes = Base58.decode(extendedKey);

        if (bytes.length !== 82 || base58check(bytes.slice(0, 78)) !== extendedKey) {
            logger.throwArgumentError("invalid extended key", "extendedKey", "[REDACTED]");
        }

        const depth = bytes[4];
        const parentFingerprint = hexlify(bytes.slice(5, 9));
        const index = parseInt(hexlify(bytes.slice(9, 13)).substring(2), 16);
        const chainCode = hexlify(bytes.slice(13, 45));
        const key = bytes.slice(45, 78);

        switch (hexlify(bytes.slice(0, 4))) {
            // Public Key
            case "0x0488b21e": case "0x043587cf":
                return new HDNode(_constructorGuard, null, hexlify(key), parentFingerprint, chainCode, index, depth, null);

            // Private Key
            case "0x0488ade4": case "0x04358394 ":
                if (key[0] !== 0) { break; }
                return new HDNode(_constructorGuard, hexlify(key.slice(1)), null, parentFingerprint, chainCode, index, depth, null);
        }

        return logger.throwArgumentError("invalid extended key", "extendedKey", "[REDACTED]");
    }
}