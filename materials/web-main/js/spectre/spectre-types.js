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
 * spectre-types
 * =============
 *
 * This file is responsible for providing Spectre's constants and algorithm configuration.
 *
 * It creates the global `spectre` object and attaches the following properties to it:
 * `encoder`, `algorithm`, `purpose`, `class`, `feature`, `resultType`, `counter`, `templates`, `characters`, `identicons`:
 * They are used to obtain information on Spectre's range of capabilities and to communicate with the Spectre APIs.
 */

let spectre = {}
spectre.encoder = Object.freeze(new TextEncoder());
spectre.algorithm = {
    /** (2012-03-05) V0 incorrectly performed host-endian math with bytes translated into 16-bit network-endian. */
    v0: 0,
    /** (2012-07-17) V1 incorrectly sized site name fields by character count rather than byte count. */
    v1: 1,
    /** (2014-09-24) V2 incorrectly sized user name fields by character count rather than byte count. */
    v2: 2,
    /** (2015-01-15) V3 is the current version. */
    v3: 3,
};
spectre.algorithm = Object.freeze({
    ...spectre.algorithm,
    current: spectre.algorithm.v3,
    first: spectre.algorithm.v0,
    last: spectre.algorithm.v3,
});
spectre.purpose = Object.freeze({
    /** Generate a key for authentication. */
    authentication: "com.lyndir.masterpassword",
    /** Generate a name for identification. */
    identification: "com.lyndir.masterpassword.login",
    /** Generate a recovery token. */
    recovery: "com.lyndir.masterpassword.answer",
});
spectre.class = Object.freeze({
    /** Use the site key to generate a result from a template. */
    template: 1 << 4,
    /** Use the site key to encrypt and decrypt a stateful entity. */
    stateful: 1 << 5,
    /** Use the site key to derive a site-specific object. */
    derive: 1 << 6,
});
spectre.feature = Object.freeze({
    none: 0,
    /** Export the key-protected content data. */
    exportContent: 1 << 10,
    /** Never export content. */
    devicePrivate: 1 << 11,
    /** Don't use this as the primary authentication result type. */
    alternate: 1 << 12,
});
spectre.resultType = {
    /** 0: Don't produce a result */
    none: 0,

    /** 16: pg^VMAUBk5x3p%HP%i4= */
    templateMaximum: 0x0 | spectre.class.template | spectre.feature.none,
    /** 17: BiroYena8:Kixa */
    templateLong: 0x1 | spectre.class.template | spectre.feature.none,
    /** 18: BirSuj0- */
    templateMedium: 0x2 | spectre.class.template | spectre.feature.none,
    /** 19: Bir8 */
    templateShort: 0x3 | spectre.class.template | spectre.feature.none,
    /** 20: pO98MoD0 */
    templateBasic: 0x4 | spectre.class.template | spectre.feature.none,
    /** 21: 2798 */
    templatePIN: 0x5 | spectre.class.template | spectre.feature.none,
    /** 30: birsujano */
    templateName: 0xE | spectre.class.template | spectre.feature.none,
    /** 31: bir yennoquce fefi */
    templatePhrase: 0xF | spectre.class.template | spectre.feature.none,

    /** 1056: Custom saved result. */
    statePersonal: 0x0 | spectre.class.stateful | spectre.feature.exportContent,
    /** 2081: Custom saved result that should not be exported from the device. */
    stateDevice: 0x1 | spectre.class.stateful | spectre.feature.devicePrivate,

    /** 4160: Derive a unique binary key. */
    deriveKey: 0x0 | spectre.class.derive | spectre.feature.alternate,
};
spectre.resultType = Object.freeze({
    ...spectre.resultType,
    defaultPassword: spectre.resultType.templateLong,
    defaultLogin: spectre.resultType.templateName,
    defaultAnswer: spectre.resultType.templatePhrase,
});
spectre.resultName = Object.freeze({
    [spectre.resultType.templateMaximum]: "Maximum",
    [spectre.resultType.templateLong]: "Long",
    [spectre.resultType.templateMedium]: "Medium",
    [spectre.resultType.templateShort]: "Short",
    [spectre.resultType.templateBasic]: "Basic",
    [spectre.resultType.templatePIN]: "PIN",
    [spectre.resultType.templateName]: "Name",
    [spectre.resultType.templatePhrase]: "Phrase",
    [spectre.resultType.statePersonal]: "Own",
    [spectre.resultType.stateDevice]: "Device",
    [spectre.resultType.deriveKey]: "Key",
});
spectre.counter = {
    /** Use a time-based counter value, resulting in a TOTP generator. */
    TOTP: 0,
    /** The initial value for a site's counter. */
    initial: 1,
};
spectre.counter = Object.freeze({
    ...spectre.counter,
    default: spectre.counter.initial,
    first: spectre.counter.TOTP,
    last: 4294967295,
});
spectre.templates = Object.freeze({
    [spectre.resultType.templateMaximum]: [
        "anoxxxxxxxxxxxxxxxxx",
        "axxxxxxxxxxxxxxxxxno"
    ],
    [spectre.resultType.templateLong]: [
        "CvcvnoCvcvCvcv",
        "CvcvCvcvnoCvcv",
        "CvcvCvcvCvcvno",
        "CvccnoCvcvCvcv",
        "CvccCvcvnoCvcv",
        "CvccCvcvCvcvno",
        "CvcvnoCvccCvcv",
        "CvcvCvccnoCvcv",
        "CvcvCvccCvcvno",
        "CvcvnoCvcvCvcc",
        "CvcvCvcvnoCvcc",
        "CvcvCvcvCvccno",
        "CvccnoCvccCvcv",
        "CvccCvccnoCvcv",
        "CvccCvccCvcvno",
        "CvcvnoCvccCvcc",
        "CvcvCvccnoCvcc",
        "CvcvCvccCvccno",
        "CvccnoCvcvCvcc",
        "CvccCvcvnoCvcc",
        "CvccCvcvCvccno"
    ],
    [spectre.resultType.templateMedium]: [
        "CvcnoCvc",
        "CvcCvcno"
    ],
    [spectre.resultType.templateShort]: [
        "Cvcn"
    ],
    [spectre.resultType.templateBasic]: [
        "aaanaaan",
        "aannaaan",
        "aaannaaa"
    ],
    [spectre.resultType.templatePIN]: [
        "nnnn"
    ],
    [spectre.resultType.templateName]: [
        "cvccvcvcv"
    ],
    [spectre.resultType.templatePhrase]: [
        "cvcc cvc cvccvcv cvc",
        "cvc cvccvcvcv cvcv",
        "cv cvccv cvc cvcvccv"
    ],
});
spectre.characters = Object.freeze({
    V: "AEIOU",
    C: "BCDFGHJKLMNPQRSTVWXYZ",
    v: "aeiou",
    c: "bcdfghjklmnpqrstvwxyz",
    A: "AEIOUBCDFGHJKLMNPQRSTVWXYZ",
    a: "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",
    n: "0123456789",
    o: "@&%?,=[]_:-+*$#!'^~;()/.",
    x: "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()",
    ' ': " "
});
spectre.identicons = Object.freeze({
    leftArm: ["╔", "╚", "╰", "═"],
    body: ["█", "░", "▒", "▓", "☺", "☻"],
    rightArm: ["╗", "╝", "╯", "═"],
    accessory: [
        "◈", "◎", "◐", "◑", "◒", "◓", "☀", "☁", "☂", "☃", "☄", "★", "☆", "☎", "☏", "⎈", "⌂", "☘", "☢", "☣",
        "☕", "⌚", "⌛", "⏰", "⚡", "⛄", "⛅", "☔", "♔", "♕", "♖", "♗", "♘", "♙", "♚", "♛", "♜", "♝", "♞", "♟",
        "♨", "♩", "♪", "♫", "⚐", "⚑", "⚔", "⚖", "⚙", "⚠", "⌘", "⏎", "✄", "✆", "✈", "✉", "✌",
    ],
})
