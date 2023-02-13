// =============================================================================
// Created by Maarten Billemont on 2021-11-28.
// Copyright (c) 2011, Maarten Billemont.
//
// This file is part of Spectre.
// Spectre is free software. You can modify it under the terms of
// the GNU General Public License, either version 3 or any later version.
// See the LICENSE file for details or consult <http://www.gnu.org/licenses/>.
//
// Note: this grant does not include any rights for use of Spectre's trademarks.
// =============================================================================

/**
 * spectre-algorithm
 * =================
 * 
 * This file is responsible for implementing the Spectre algorithm implementation.
 * 
 * It provides a SpectreUser class which can be used to instantiate and interact with a single long-lived Spectre user identity.
 * 
 * It attaches the following functions to the global `spectre` object:
 * `newUserKey`, `newSiteKey`, `newSiteResult` & `newIdenticon`: They are used to perform stateless Spectre algorithm operations.
 */

// import { scrypt } from 'js/mpw-js/scrypt';
// importScripts("file:///Users/lhunath/workspace/lyndir/Spectre/web/js/spectre/.js");
importScripts(new URL("js/spectre/spectre-types.js", baseURI).href);
importScripts(new URL("js/spectre/scrypt.js", baseURI).href);

class SpectreError extends Error {
    constructor(cause, ...params) {
        super(...params)
        this.name = "SpectreError"
        this.cause = cause
    }
}

class SpectreUser {
    constructor(userName, userSecret, algorithmVersion = spectre.algorithm.current) {
        this.userName = userName;
        this.algorithmVersion = algorithmVersion;
        this.identiconPromise = spectre.newIdenticon(userName, userSecret);
        this.userKeyPromise = spectre.newUserKey(userName, userSecret, algorithmVersion);

    }

    async password(siteName, resultType = spectre.resultType.defaultPassword,
                       keyCounter = spectre.counter.default, keyContext = null) {
        let userKey = await this.userKeyPromise
        return this.result(userKey, siteName, resultType, keyCounter, spectre.purpose.authentication, keyContext);
    }

    async login(siteName, resultType = spectre.resultType.defaultLogin,
                keyCounter = spectre.counter.default, keyContext = null) {
        let userKey = await this.userKeyPromise
        return this.result(userKey, siteName, resultType, keyCounter, spectre.purpose.identification, keyContext);
    }

    async answer(siteName, resultType = spectre.resultType.defaultAnswer,
                 keyCounter = spectre.counter.default, keyContext = null) {
        let userKey = await this.userKeyPromise
        return this.result(userKey, siteName, resultType, keyCounter, spectre.purpose.recovery, keyContext);
    }

    async result(siteName, resultType, keyCounter, keyPurpose, keyContext) {
        let userKey = await this.userKeyPromise
        return spectre.newSiteResult(userKey, siteName, resultType, keyCounter, keyPurpose, keyContext);
    }

    invalidate() {
        this.userKeyPromise = Promise.reject(new SpectreError("invalidate", `User logged out.`));
    }

    static async test() {
        let user = await new SpectreUser("Robert Lee Mitchell", "banana colored duckling");
        let password = await user.authenticate("masterpasswordapp.com")
        if (password !== "Jejr5[RepuSosp")
            throw "Internal consistency test failed.";
    }
}

spectre.newUserKey = Object.freeze(async(userName, userSecret, algorithmVersion = spectre.algorithm.current) => {
    console.trace(`[spectre]: userKey: ${userName} (algorithmVersion=${algorithmVersion})`);

    if (!crypto.subtle) {
        throw new SpectreError("internal", `Cryptography unavailable.`);
    } else if (algorithmVersion < spectre.algorithm.first || algorithmVersion > spectre.algorithm.last) {
        throw new SpectreError("algorithmVersion", `Unsupported algorithm version: ${algorithmVersion}.`);
    } else if (!userName || !userName.length) {
        throw new SpectreError("userName", `Missing user name.`);
    } else if (!userSecret || !userSecret.length) {
        throw new SpectreError("userSecret", `Missing user secret.`);
    }

    try {
        let userSecretBytes = spectre.encoder.encode(userSecret);
        let userNameBytes = spectre.encoder.encode(userName);
        let keyPurpose = spectre.encoder.encode(spectre.purpose.authentication);

        // 1. Populate user salt: scope | #userName | userName
        let userSalt = new Uint8Array(keyPurpose.length + 4/*sizeof(uint32)*/ + userNameBytes.length);
        let userSaltView = new DataView(userSalt.buffer, userSalt.byteOffset, userSalt.byteLength);

        let uS = 0;
        userSalt.set(keyPurpose, uS);
        uS += keyPurpose.length;

        if (algorithmVersion < 3) {
            // V0, V1, V2 incorrectly used the character length instead of the byte length.
            userSaltView.setUint32(uS, userName.length, false/*big-endian*/);
            uS += 4/*sizeof(uint32)*/;
        } else {
            userSaltView.setUint32(uS, userNameBytes.length, false/*big-endian*/);
            uS += 4/*sizeof(uint32)*/;
        }

        userSalt.set(userNameBytes, uS);
        uS += userNameBytes.length;

        // 2. Derive user key from user secret and user salt.
        let userKeyData = await scrypt(userSecretBytes, userSalt, 32768, 8, 2, 64)
        let userKeyCrypto = await crypto.subtle.importKey("raw", userKeyData, {
            name: "HMAC", hash: {name: "SHA-256"}
        }, false, ["sign"])
        return ({keyCrypto: userKeyCrypto, keyAlgorithm: algorithmVersion})
    } catch (e) {
        throw e;
    }
});

spectre.newSiteKey = Object.freeze(async(userKey, siteName, keyCounter = spectre.counter.default,
    keyPurpose = spectre.purpose.authentication, keyContext = null) => {
    console.trace(`[spectre]: siteKey: ${siteName} (keyCounter=${keyCounter}, keyPurpose=${keyPurpose}, keyContext=${keyContext})`);

    if (!crypto.subtle) {
        throw new SpectreError("internal", `Cryptography unavailable.`);
    } else if (!userKey) {
        throw new SpectreError("userKey", `Missing user secret.`);
    } else if (!siteName || !siteName.length) {
        throw new SpectreError("siteName", `Missing site name.`);
    } else if (keyCounter < 1 || keyCounter > 4294967295/*Math.pow(2, 32) - 1*/) {
        throw new SpectreError("keyCounter", `Invalid counter value: ${keyCounter}.`);
    }

    try {
        let siteNameBytes = spectre.encoder.encode(siteName);
        let keyPurposeBytes = spectre.encoder.encode(keyPurpose);
        let keyContextBytes = keyContext && spectre.encoder.encode(keyContext);

        // 1. Populate site salt: keyPurpose | #siteName | siteName | keyCounter | #keyContext | keyContext
        let siteSalt = new Uint8Array(
            keyPurposeBytes.length
            + 4/*sizeof(uint32)*/ + siteNameBytes.length
            + 4/*sizeof(int32)*/
            + (keyContextBytes ? 4/*sizeof(uint32)*/ + keyContextBytes.length : 0)
        );
        let siteSaltView = new DataView(siteSalt.buffer, siteSalt.byteOffset, siteSalt.byteLength);

        let sS = 0;
        siteSalt.set(keyPurposeBytes, sS);
        sS += keyPurposeBytes.length;

        if (userKey.keyAlgorithm < 2) {
            // V0, V1 incorrectly used the character length instead of the byte length.
            siteSaltView.setUint32(sS, siteName.length, false/*big-endian*/);
            sS += 4/*sizeof(uint32)*/;
        } else {
            siteSaltView.setUint32(sS, siteNameBytes.length, false/*big-endian*/);
            sS += 4/*sizeof(uint32)*/;
        }

        siteSalt.set(siteNameBytes, sS);
        sS += siteNameBytes.length;

        siteSaltView.setInt32(sS, keyCounter, false/*big-endian*/);
        sS += 4/*sizeof(int32)*/;

        if (keyContextBytes) {
            siteSaltView.setUint32(sS, keyContextBytes.length, false/*big-endian*/);
            sS += 4/*sizeof(uint32)*/;

            siteSalt.set(keyContextBytes, sS);
            sS += keyContextBytes.length;
        }

        // 2. Derive site key from user key and site salt.
        let keyData = await crypto.subtle.sign({
            name: "HMAC", hash: {name: "SHA-256"}
        }, userKey.keyCrypto, siteSalt)
        return ({keyData: new Uint8Array(keyData), keyAlgorithm: userKey.keyAlgorithm})
    } catch (e) {
        throw e;
    }
});

spectre.newSiteResult = Object.freeze(async(userKey, siteName,
    resultType = spectre.resultType.defaultPassword, keyCounter = spectre.counter.default,
    keyPurpose = spectre.purpose.authentication, keyContext = null) => {
    console.trace(`[spectre]: result: ${siteName} (resultType=${resultType}, keyCounter=${keyCounter}, keyPurpose=${keyPurpose}, keyContext=${keyContext})`);

    let resultTemplates = spectre.templates[resultType]
    if (!resultTemplates) {
        throw new SpectreError("resultType", `Unsupported result template: ${resultType}.`);
    }

    let siteKey = await spectre.newSiteKey(userKey, siteName, keyCounter, keyPurpose, keyContext)
    let siteKeyBytes = siteKey.keyData
    if (siteKey.keyAlgorithm < 1) {
        // V0 incorrectly converts bytes into 16-bit big-endian numbers.
        let siteKeyV0Bytes = new Uint16Array(siteKeyBytes.length);
        for (let sK = 0; sK < siteKeyV0Bytes.length; sK++) {
            siteKeyV0Bytes[sK] = (siteKeyBytes[sK] > 127 ? 0x00ff : 0x0000) | (siteKeyBytes[sK] << 8);
        }
        siteKeyBytes = siteKeyV0Bytes
    }

    // key byte 0 selects the template from the available result templates.
    let resultTemplate = resultTemplates[siteKeyBytes[0] % resultTemplates.length];

    // key byte 1+ selects a character from the template's character class.
    return resultTemplate.split("").map((characterClass, rT) => {
        let characters = spectre.characters[characterClass];
        return characters[siteKeyBytes[rT + 1] % characters.length];
    }).join("");
});

spectre.newIdenticon = Object.freeze(async(userName, userSecret) => {
    console.trace(`[spectre]: identicon: ${userName}`);

    let key = await crypto.subtle.importKey("raw", spectre.encoder.encode(userSecret), {
        name: "HMAC", hash: {name: "SHA-256"}
    }, false, ["sign"])
    let seed = await crypto.subtle.sign("HMAC", key, spectre.encoder.encode(userName))

    return {
        "leftArm": spectre.identicons.leftArm[seed[0] % spectre.identicons.leftArm.length],
        "body": spectre.identicons.body[seed[0] % spectre.identicons.body.length],
        "rightArm": spectre.identicons.rightArm[seed[0] % spectre.identicons.rightArm.length],
        "accessory": spectre.identicons.accessory[seed[0] % spectre.identicons.accessory.length],
    }
});
