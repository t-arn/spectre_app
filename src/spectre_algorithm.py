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

from spectre_types import spectre

class SpectreError (Exception):
    
    def __init__(self, cause, message):
        self.cause = cause
        self.message = message
        super().__init__(self.message)
    # __init__

# SpectreError


class SpectreUser:
    
    def __init__(userName, userSecret, algorithmVersion = spectre.algorithm.current) {
        self.userName = userName;
        self.algorithmVersion = algorithmVersion;
        self.identiconPromise = spectre.newIdenticon(userName, userSecret);
        self.userKeyPromise = spectre.newUserKey(userName, userSecret, algorithmVersion);

    # __init__

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
# SpectreUser
