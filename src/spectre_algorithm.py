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
        print(f"[spectre]: userKey={userName}, algorithmVersion={algorithmVersion}\n")

        if (algorithmVersion < spectreTypes.algorithm["first"] || algorithmVersion > spectreTypes.algorithm["last"]):
            raise SpectreError("algorithmVersion", f"Unsupported algorithm version: {algorithmVersion}.")
        else if (userName is None || len(userName)==0):
            raise SpectreError("userName", "Missing user name.")
        else if (userSecret is None || len(userSecret)==0):
            raise SpectreError("userSecret", "Missing user secret.")
    
        try:
            userSecretBytes = bytes(userSecret)
            userNameBytes = bytes(userName)
            keyPurpose = bytes(spectre.purpose["authentication"])
    
            # 1. Populate user salt: scope | #userName | userName
            userSalt = keyPurpose
    
            if (algorithmVersion < 3):
                # V0, V1, V2 incorrectly used the character length instead of the byte length.
                userSalt += uint32_to_bytes(len(userName))
            else:
                userSalt += uint32_to_bytes(len(userNameBytes))
    
            userSalt += userNameBytes
    
            # 2. Derive user key from user secret and user salt.
            userKeyData = hashlib.scrypt(userSecretBytes, userSalt, 32768, 8, 2, 64)
            userKeyCrypto = hmac.new(userKeyData, msg=None, digestmod=hashlib.sha256).digest()
            return {"keyCrypto": userKeyCrypto, "keyAlgorithm": algorithmVersion}
        except Exception as ex:
            raise ex
    # newUserKey
    
    
# Spectre

spectre = Spectre()

    
class SpectreUser:
    
    def __init__(self, userName, userSecret, algorithmVersion = spectreTypes.algorithm["current"]):
        self.userName = userName
        self.algorithmVersion = algorithmVersion
        self.identiconPromise = spectre.newIdenticon(userName, userSecret)
        self.userKeyPromise = spectre.newUserKey(userName, userSecret, algorithmVersion)
    # __init__

    def password(self, siteName, resultType = spectre.resultType["defaultPassword"],
                       keyCounter = spectre.counter["default"], keyContext = None):
        userKey = self.userKeyPromise
        return self.result(userKey, siteName, resultType, keyCounter, spectre.purpose["authentication"], keyContext)
    # password

    def login(self, siteName, resultType = spectre.resultType["defaultLogin"],
                keyCounter = spectre.counter["default"], keyContext = None):
        userKey = self.userKeyPromise
        return self.result(userKey, siteName, resultType, keyCounter, spectre.purpose["identification"], keyContext)
    # login

    def answer(self, siteName, resultType = spectre.resultType["defaultAnswer"],
                 keyCounter = spectre.counter["default"], keyContext = None):
        userKey = self.userKeyPromise
        return self.result(userKey, siteName, resultType, keyCounter, spectre.purpose["recovery"], keyContext)
    # answer

    def result(self, siteName, resultType, keyCounter, keyPurpose, keyContext):
        userKey = this.userKeyPromise
        return spectre.newSiteResult(userKey, siteName, resultType, keyCounter, keyPurpose, keyContext)
    # result

    def invalidate(self):
        self.userKeyPromise = SpectreError("invalidate", "User logged out.")
    # invalidate

    def test():
        user = SpectreUser("Robert Lee Mitchell", "banana colored duckling")
        password = user.authenticate("masterpasswordapp.com")
        if (password != "Jejr5[RepuSosp"):
            raise Exception("Internal consistency test failed.")
    # test
# SpectreUser
