# =============================================================================
# Created by Tom Arn on 2023-02-12 ported from the Spectre code 
# of Maarten Billemont.
# Copyright (c) 2023, Tom Arn, www.t-arn.com
#
# This file is part of pySpectre.
# pySpectre is free software. You can modify it under the terms of
# the GNU General Public License, either version 3 or any later version.
# See the LICENSE file for details or consult <http://www.gnu.org/licenses/>.
#
# Note: this grant does not include any rights for use of Spectre's trademarks.
# =============================================================================

# spectre_types
# =============
#
# This file is responsible for providing Spectre's constants and algorithm configuration.
#
# It creates the global `spectreTypes` object and attaches the following properties to it:
# `encoder`, `algorithm`, `purpose`, `clazz`, `feature`, `resultType`, `counter`, `templates`, `characters`, `identicons`:
# They are used to obtain information on Spectre's range of capabilities and to communicate with the Spectre APIs.

class TextEncoder:
    def encode(self, string):
        return list(string.encode('utf8'))
    # encode
# TextEncoder

class SpectreTypes:
    
    def __init__(self):
         self.encoder = TextEncoder()
    # __init__
    
    algorithm = {
        # (2012-03-05) V0 incorrectly performed host-endian math with bytes translated into 16-bit network-endian.
        "v0": 0,
        # (2012-07-17) V1 incorrectly sized site name fields by character count rather than byte count.
        "v1": 1,
        # (2014-09-24) V2 incorrectly sized user name fields by character count rather than byte count.
        "v2": 2,
        # (2015-01-15) V3 is the current version. */
        "v3": 3
    }
    algorithm["current"] = algorithm["v3"]
    algorithm["first"]   = algorithm["v0"]
    algorithm["last"]    = algorithm["v3"]
    
    purpose = {
        # Generate a key for authentication.
        "authentication": "com.lyndir.masterpassword",
        # Generate a name for identification.
        "identification": "com.lyndir.masterpassword.login",
        # Generate a recovery token.
        "recovery": "com.lyndir.masterpassword.answer"
    }
    
    clazz = {
        # Use the site key to generate a result from a template.
        "template": 1 << 4,
        # Use the site key to encrypt and decrypt a stateful entity.
        "stateful": 1 << 5,
        # Use the site key to derive a site-specific object.
        "derive": 1 << 6
    }
    
    feature = {
        "none": 0,
        # Export the key-protected content data.
        "exportContent": 1 << 10,
        # Never export content.
        "devicePrivate": 1 << 11,
        # Don't use this as the primary authentication result type.
        "alternate": 1 << 12
    }

    resultType = {
        # 0: Don't produce a result
        "none": 0,
        
        # 16: pg^VMAUBk5x3p%HP%i4=
        "templateMaximum": 0x0 | clazz["template"] | feature["none"],
        # 17: BiroYena8:Kixa
        "templateLong": 0x1 | clazz["template"] | feature["none"],
        # 18: BirSuj0-
        "templateMedium": 0x2 | clazz["template"] | feature["none"],
        # 19: Bir8
        "templateShort": 0x3 | clazz["template"] | feature["none"],
        # 20: pO98MoD0
        "templateBasic": 0x4 | clazz["template"] | feature["none"],
        # 21: 2798
        "templatePIN": 0x5 | clazz["template"] | feature["none"],
        # 30: birsujano
        "templateName": 0xE | clazz["template"] | feature["none"],
        # 31: bir yennoquce fefi
        "templatePhrase": 0xF | clazz["template"] | feature["none"],
    
        # 1056: Custom saved result.
        "statePersonal": 0x0 | clazz["stateful"] | feature["exportContent"],
        # 2081: Custom saved result that should not be exported from the device.
        "stateDevice": 0x1 | clazz["stateful"] | feature["devicePrivate"],
    
        # 4160: Derive a unique binary key.
        "deriveKey": 0x0 | clazz["derive"] | feature["alternate"]
    }
    resultType["defaultPassword"] = resultType["templateLong"]
    resultType["defaultLogin"] = resultType["templateName"]
    resultType["defaultAnswer"] = resultType["templatePhrase"]

    resultName = {}
    resultName[str(resultType["templateMaximum"])] = "Maximum"
    resultName[str(resultType["templateLong"])] = "Long"
    resultName[str(resultType["templateMedium"])] = "Medium"
    resultName[str(resultType["templateShort"])] = "Short"
    resultName[str(resultType["templateBasic"])] = "Basic"
    resultName[str(resultType["templatePIN"])] = "PIN"
    resultName[str(resultType["templateName"])] = "Name"
    resultName[str(resultType["templatePhrase"])] = "Phrase"
    resultName[str(resultType["statePersonal"])] = "Own"
    resultName[str(resultType["stateDevice"])] = "Device"
    resultName[str(resultType["deriveKey"])] = "Key"

    counter = {
        # Use a time - based counter value, resulting in a TOTP generator.
        "TOTP": 0,
        # The initial value for a site's counter.
        "initial": 1,
    }
    counter["default"] = counter["initial"]
    counter["first"] = counter["TOTP"]
    counter["last"] = 4294967295

    templates = {}
    templates[str(resultType["templateMaximum"])] = [
        "anoxxxxxxxxxxxxxxxxx",
        "axxxxxxxxxxxxxxxxxno"
    ]
    templates[str(resultType["templateLong"])] = [
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
    ]
    templates[str(resultType["templateMedium"])] = [
        "CvcnoCvc",
        "CvcCvcno"
    ]
    templates[str(resultType["templateShort"])] = [
        "Cvcn"
    ]
    templates[str(resultType["templateBasic"])] = [
        "aaanaaan",
        "aannaaan",
        "aaannaaa"
    ]
    templates[str(resultType["templatePIN"])] = [
        "nnnn"
    ]
    templates[str(resultType["templateName"])] = [
        "cvccvcvcv"
    ]
    templates[str(resultType["templatePhrase"])] = [
        "cvcc cvc cvccvcv cvc",
        "cvc cvccvcvcv cvcv",
        "cv cvccv cvc cvcvccv"
    ]

    characters = {
        "V": "AEIOU",
        "C": "BCDFGHJKLMNPQRSTVWXYZ",
        "v": "aeiou",
        "c": "bcdfghjklmnpqrstvwxyz",
        "A": "AEIOUBCDFGHJKLMNPQRSTVWXYZ",
        "a": "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",
        "n": "0123456789",
        "o": "@&%?,=[]_:-+*$#!'^~;()/.",
        "x": "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()",
        " ": " "
    }

    identicons = {
        "leftArm": ["╔", "╚", "╰", "═"],
        "body": ["█", "░", "▒", "▓", "☺", "☻"],
        "rightArm": ["╗", "╝", "╯", "═"],
        "accessory": [
            "◈", "◎", "◐", "◑", "◒", "◓", "☀", "☁", "☂", "☃", "☄", "★", "☆", "☎", "☏", "⎈", "⌂", "☘", "☢", "☣",
            "☕", "⌚", "⌛", "⏰", "⚡", "⛄", "⛅", "☔", "♔", "♕", "♖", "♗", "♘", "♙", "♚", "♛", "♜", "♝", "♞", "♟",
            "♨", "♩", "♪", "♫", "⚐", "⚑", "⚔", "⚖", "⚙", "⚠", "⌘", "⏎", "✄", "✆", "✈", "✉", "✌",
        ],
        "color": ["red", "green", "yellow", "blue", "magenta", "cyan", "currentcolor"]
    }

# SpectreTypes
    
spectreTypes = SpectreTypes()
