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

from hashlib import scrypt
from spectre_types import spectreTypes

class SpectreError(Exception):
    
    def __init__(self, cause, message):
        self.cause = cause
        self.message = message
        super().__init__(self.message)
    # __init__

# SpectreError


class Spectre:
    
    async def newUserKey(self, userName, userSecret, algorithmVersion=spectreTypes.algorithm["current"]):
        print(f"[spectre]: userKey={userName}, algorithmVersion={algorithmVersion}\n")

        if (algorithmVersion < spectreTypes.algorithm["first"] || algorithmVersion > spectreTypes.algorithm["last"]) {
            raise SpectreError("algorithmVersion", f"Unsupported algorithm version: {algorithmVersion}.")
        } else if (userName is None || len(userName)==0) {
            raise SpectreError("userName", "Missing user name.")
        } else if (userSecret is None || len(userSecret)==0) {
            raise SpectreError("userSecret", "Missing user secret.")
        }
    
        try:
            userSecretBytes = spectre.encoder.encode(userSecret);
            userNameBytes = spectre.encoder.encode(userName);
            keyPurpose = spectre.encoder.encode(spectre.purpose["authentication"]);
    
            # 1. Populate user salt: scope | #userName | userName
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
        except Exception as ex:
            raise ex
    # newUserKey
    
    
# Spectre

spectre = Spectre()

    
class SpectreUser:
    
    def __init__(self, userName, userSecret, algorithmVersion = spectreTypes.algorithm["current"]:
        self.userName = userName
        self.algorithmVersion = algorithmVersion
        self.identiconPromise = spectre.newIdenticon(userName, userSecret)
        self.userKeyPromise = spectre.newUserKey(userName, userSecret, algorithmVersion)

    # __init__

    async def password(self, siteName, resultType = spectre.resultType["defaultPassword"],
                       keyCounter = spectre.counter["default"], keyContext = None):
        userKey = await self.userKeyPromise
        return self.result(userKey, siteName, resultType, keyCounter, spectre.purpose["authentication"], keyContext)
    # password

    async def login(self, siteName, resultType = spectre.resultType["defaultLogin"],
                keyCounter = spectre.counter["default"], keyContext = None):
        userKey = await self.userKeyPromise
        return self.result(userKey, siteName, resultType, keyCounter, spectre.purpose["identification"], keyContext)
    # login

    async def answer(self, siteName, resultType = spectre.resultType["defaultAnswer"],
                 keyCounter = spectre.counter["default"], keyContext = None):
        userKey = await self.userKeyPromise
        return self.result(userKey, siteName, resultType, keyCounter, spectre.purpose["recovery"], keyContext)
    # answer

    async def result(self, siteName, resultType, keyCounter, keyPurpose, keyContext):
        userKey = await this.userKeyPromise
        return spectre.newSiteResult(userKey, siteName, resultType, keyCounter, keyPurpose, keyContext)
    # result

    def invalidate(self):
        self.userKeyPromise = SpectreError("invalidate", "User logged out.")
    # invalidate

    async def test():
        user = SpectreUser("Robert Lee Mitchell", "banana colored duckling")
        password = await user.authenticate("masterpasswordapp.com")
        if (password != "Jejr5[RepuSosp")
            raise Exception("Internal consistency test failed.")
    # test
# SpectreUser
