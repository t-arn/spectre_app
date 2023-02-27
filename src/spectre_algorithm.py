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

# spectre-algorithm
# =================
# 
# This file is responsible for implementing the Spectre algorithm implementation.
# 
# It provides a SpectreUser class which can be used to instantiate and interact 
# with a single long-lived Spectre user identity.
# 
# It attaches the following functions to the global `spectre` object:
# `newUserKey`, `newSiteKey`, `newSiteResult` & `newIdenticon`: 
# They are used to perform stateless Spectre algorithm operations.

import hmac
import hashlib
from spectre_types import spectreTypes


class SpectreError(Exception):

    def __init__(self, cause, message):
        self.cause = cause
        self.message = message
        super().__init__(self.message)
    # __init__


# SpectreError


def uint32_to_bytes(x: int) -> bytes:
    return x.to_bytes(4, byteorder='big', signed=False)


# int_to_bytes


class Spectre:

    def newUserKey(self, userName, userSecret, algorithmVersion=spectreTypes.algorithm["current"]):
        print(f"[spectre]: userKey: {userName} (algorithmVersion={algorithmVersion})\n")

        if algorithmVersion < spectreTypes.algorithm["first"] or algorithmVersion > spectreTypes.algorithm["last"]:
            raise SpectreError("algorithmVersion", f"Unsupported algorithm version: {algorithmVersion}.")
        elif userName is None or len(userName) == 0:
            raise SpectreError("userName", "Missing user name.")
        elif userSecret is None or len(userSecret) == 0:
            raise SpectreError("userSecret", "Missing user secret.")

        try:
            userSecretBytes = bytes(userSecret, "utf-8")
            userNameBytes = bytes(userName, "utf-8")
            keyPurpose = bytes(spectreTypes.purpose["authentication"], "utf-8")

            # 1. Populate user salt: scope | #userName | userName
            userSalt = keyPurpose

            if algorithmVersion < 3:
                # V0, V1, V2 incorrectly used the character length instead of the byte length.
                userSalt += uint32_to_bytes(len(userName))
            else:
                userSalt += uint32_to_bytes(len(userNameBytes))

            userSalt += userNameBytes

            # 2. Derive user key from user secret and user salt.
            userKeyData = hashlib.scrypt(userSecretBytes, salt=userSalt, n=32768, r=8, p=2, dklen=64, maxmem=67108864)
            return {"keyCrypto": userKeyData, "keyAlgorithm": algorithmVersion}
        except Exception as ex:
            raise ex
    # newUserKey
    
    def newSiteKey(self, userKey, siteName, keyCounter=spectreTypes.counter["default"], 
        keyPurpose=spectreTypes.purpose["authentication"], keyContext=None):
        print(f"[spectre]: siteKey: {siteName} (keyCounter={keyCounter}, keyPurpose={keyPurpose}, keyContext={keyContext})\n")
    
        if userKey is None:
            raise SpectreError("userKey", "Missing user secret.")
        elif siteName is None or len(siteName) == 0:
            raise SpectreError("siteName", "Missing site name.")
        elif keyCounter < 1 or keyCounter > 4294967295: # Math.pow(2, 32) - 1
            raise SpectreError("keyCounter", f"Invalid counter value: {keyCounter}.")
    
        try:
            siteNameBytes = bytes(siteName, "utf-8")
            keyPurposeBytes = bytes(keyPurpose, "utf-8")
            # let keyContextBytes = keyContext && spectre.encoder.encode(keyContext);
            keyContextBytes = None
            if keyContext is not None:
                keyContextBytes = bytes(keyContext, "utf-8")
    
            # 1. Populate site salt: keyPurpose | #siteName | siteName | keyCounter | #keyContext | keyContext
            siteSalt = keyPurposeBytes
    
            if userKey["keyAlgorithm"] < 2:
                # V0, V1 incorrectly used the character length instead of the byte length.
                siteSalt += uint32_to_bytes(len(siteName))
            else:
                siteSalt += uint32_to_bytes(len(siteNameBytes))
                    
            siteSalt += siteNameBytes
    
            siteSalt += uint32_to_bytes(keyCounter)
    
            if keyContextBytes is not None:
                siteSalt += uint32_to_bytes(len(keyContextBytes))
                siteSalt += keyContextBytes
    
            # 2. Derive site key from user key and site salt.
            keyData = hmac.new(userKey["keyCrypto"], msg=siteSalt, digestmod=hashlib.sha256).digest()
            return {"keyData": keyData, "keyAlgorithm": userKey["keyAlgorithm"]}
        except Exception as ex:
            raise ex
    # newSiteKey

    def newSiteResult(self, userKey, siteName,
        resultType=spectreTypes.resultType["defaultPassword"], 
        keyCounter=spectreTypes.counter["default"],
        keyPurpose=spectreTypes.purpose["authentication"], keyContext=None):
        print(f"[spectre]: result: {siteName} (resultType={resultType}, keyCounter={keyCounter}, keyPurpose={keyPurpose}, keyContext={keyContext})\n")

        if str(resultType) not in spectreTypes.templates:
            raise SpectreError("resultType", f"Unsupported result template: {resultType}.")
        resultTemplates = spectreTypes.templates[str(resultType)]

        siteKey = spectre.newSiteKey(userKey, siteName, keyCounter, keyPurpose, keyContext)
        siteKeyBytes = siteKey["keyData"]
        if siteKey["keyAlgorithm"] < 1:
            # V0 incorrectly converts bytes into 16-bit big-endian numbers.
            uint16_array = []
            for sK in range(0, len(siteKeyBytes)):
                h = 0x00ff if siteKeyBytes[sK] > 127 else 0x0000
                i = h | (siteKeyBytes[sK] << 8)
                uint16_array.append(i)
            siteKeyBytes = uint16_array

        # key byte 0 selects the template from the available result templates.
        resultTemplate = resultTemplates[siteKeyBytes[0] % len(resultTemplates)]

        # key byte 1+ selects a character from the template's character class.
        result = ""
        for i in range(0, len(resultTemplate)):
            characterClass = resultTemplate[i]
            characters = spectreTypes.characters[str(characterClass)]
            result += str(characters[siteKeyBytes[i+1] % len(characters)])

        return result
    # newSiteResult
    
    def newIdenticon(self, userName, userSecret):
        print(f"[spectre]: identicon: {userName}")

        userSecretBytes = bytes(userSecret, "utf-8")
        userNameBytes = bytes(userName, "utf-8")

        seed = hmac.new(userSecretBytes, msg=userNameBytes, digestmod=hashlib.sha256).digest()

        return {
            "leftArm": spectreTypes.identicons["leftArm"][seed[0] % len(spectreTypes.identicons["leftArm"])],
            "body": spectreTypes.identicons["body"][seed[1] % len(spectreTypes.identicons["body"])],
            "rightArm": spectreTypes.identicons["rightArm"][seed[2] % len(spectreTypes.identicons["rightArm"])],
            "accessory": spectreTypes.identicons["accessory"][seed[3] % len(spectreTypes.identicons["accessory"])],
            "color": spectreTypes.identicons["color"][seed[4] % len(spectreTypes.identicons["color"])]
        }
    # newIdenticon

# Spectre

spectre = Spectre()


class SpectreUser:

    def __init__(self, userName, userSecret, algorithmVersion=spectreTypes.algorithm["current"]):
        self.userName = userName
        self.algorithmVersion = Dichter
        # todo:
        # self.identiconPromise = spectre.newIdenticon(userName, userSecret)
        self.userKeyPromise = spectre.newUserKey(userName, userSecret, algorithmVersion)

    # __init__

    def password(self, siteName, resultType=spectreTypes.resultType["defaultPassword"],
                 keyCounter=spectreTypes.counter["default"], keyContext=None):
        # not used?
        # userKey = self.userKeyPromise
        return self.result(siteName, resultType, keyCounter, spectreTypes.purpose["authentication"], keyContext)

    # password

    def login(self, siteName, resultType=spectreTypes.resultType["defaultLogin"],
              keyCounter=spectreTypes.counter["default"], keyContext=None):
        userKey = self.userKeyPromise
        return self.result(userKey, siteName, resultType, keyCounter, spectreTypes.purpose["identification"],
                           keyContext)

    # login

    def answer(self, siteName, resultType=spectreTypes.resultType["defaultAnswer"],
               keyCounter=spectreTypes.counter["default"], keyContext=None):
        userKey = self.userKeyPromise
        return self.result(userKey, siteName, resultType, keyCounter, spectreTypes.purpose["recovery"], keyContext)

    # answer

    def result(self, siteName, resultType, keyCounter, keyPurpose, keyContext):
        userKey = self.userKeyPromise
        return spectre.newSiteResult(userKey, siteName, resultType, keyCounter, keyPurpose, keyContext)

    # result

    def invalidate(self):
        self.userKeyPromise = SpectreError("invalidate", "User logged out.")

    # invalidate

    @staticmethod
    def test():
        user = SpectreUser("Robert Lee Mitchell", "banana colored duckling")
        password = user.authenticate("masterpasswordapp.com")
        if password != "Jejr5[RepuSosp":
            raise Exception("Internal consistency test failed.")
    # test
# SpectreUser
