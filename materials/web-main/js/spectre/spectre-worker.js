// =============================================================================
// Created by Maarten Billemont on 2021-11-29.
// Copyright (c) 2011, Maarten Billemont.
//
// This file is part of Spectre.
// Spectre is free software. You can modify it under the terms of
// the GNU General Public License, either version 3 or any later version.
// See the LICENSE file for details or consult <http://www.gnu.org/licenses/>.
//
// Note: this grant does not include any rights for use of Spectre's trademarks.
// =============================================================================

importScripts(new URL("js/spectre/spectre-algorithm.js", baseURI).href);

/**
 * spectre-worker
 * ==============
 *
 * This file is responsible for implementing the Spectre web worker.
 * The worker manages a single internal Spectre user identity through requested operations.
 *
 * It listens to `onmessage` events for Spectre operation requests and posts back messages in response with the operation results.
 *
 * It attaches the following properties to the global `spectre` object:
 * `user`: It is used internally to process and track the requested operations.
 * 
 * To perform an operation, send a message to the worker using any of the following inputs:
 * 
 * Input:
 *  - userName:
 *      The full name of the user whose Spectre identity to derive. [invalidate?, identicon, user, site?]
 *  - userSecret:
 *      The Spectre secret of the user whose Spectre identity to derive. [identicon, user, site?]
 *  - algorithmVersion:
 *      The version of the Spectre algorithm to use for deriving the Spectre identity. [identicon, user, site?]
 *  - siteName:
 *      The site for which the user wants to derive a result. [site]
 *  - resultType:
 *      The type of result to generate. [site]
 *  - keyCounter:
 *      A linear version of the result to generate. [site]
 *  - keyPurpose:
 *      The purpose class for which this result token should be used. [site]
 *  - keyContext:
 *      The context parameter to pass into the result type for scoping the result token. [site]
 *  - invalidate:
 *      If set, wipe the currently authenticated user identity from memory. [invalidate]
 *      
 *  | Input > Operation | invalidate | identicon | user     | site     |
 *  |-------------------|------------|-----------|----------|----------|
 *  | userName          | optional   | required  | required | optional |
 *  | userSecret        |            | required  | required | optional |
 *  | algorithmVersion  |            | required  | required | optional |
 *  | siteName          |            |           |          | required |
 *  | resultType        |            |           |          | required | 
 *  | keyCounter        |            |           |          | required |
 *  | keyPurpose        |            |           |          | required |
 *  | keyContext        |            |           |          | required |
 *  | invalidate        | required   |           |          |          |
 *
 * The worker will perform every operation for which the received message has input parameters present.
 * Once an operation is completed, the worker will post back the operation's results using the following outputs:
 * 
 * Output:
 *  - operation:
 *      An identifier for the requested operation whose result is being returned. [invalidate, identicon, user, site]
 *  - userName:
 *      The full name of the user whose Spectre identity was involved in the operation's result. [invalidate, identicon, user, site]
 *  - userIdenticon:
 *      A graphical fingerprint for the user whose Spectre identity was involved in the operation's result. [identicon]
 *  - siteName:
 *      The site for which the result was derived. [site]
 *  - resultType:
 *      The type that was used for the site result which was derived. [site]
 *  - keyCounter:
 *      A linear version that was used for the site result which was derived. [site]
 *  - keyPurpose:
 *      The purpose class that was used for the site result which was derived. [site]
 *  - keyContext:
 *      The context parameter that was used for the site result which was derived. [site]
 *  - siteResult:
 *      The result which was derived by the Spectre algorithm from the request. [site]
 *  - error:
 *      If the operation failed, a description of what went wrong. [identicon, user, site]
 *  - cause:
 *      An identifier for the token which is related to the error that has occurred. [identicon, user, site]
 */

onmessage = (msg) => {
    if (msg.data.invalidate) {
        let userName = spectre.user && spectre.user.userName
        if (spectre.user && (!msg.data.userName || spectre.user.userName === msg.data.userName)) {
            spectre.user.invalidate()
        }

        postMessage({
            "operation": "invalidate",
            "userName": userName,
        })
        return
    }

    if (!spectre.user || msg.data.userSecret) {
        spectre.user = new SpectreUser(msg.data.userName, msg.data.userSecret, msg.data.algorithmVersion || spectre.algorithm.current);
        spectre.user.identiconPromise.then(
            identicon =>
                postMessage({
                    "operation": "identicon",
                    "userName": spectre.user && spectre.user.userName,
                    "userIdenticon": identicon,
                }),
            error => {
                console.error(`[spectre]: ${error}`);
                postMessage({
                    "operation": "identicon",
                    "userName": spectre.user.userName,
                    "error": error.message,
                    "cause": error.cause,
                })
            }
        )
        spectre.user.userKeyPromise.then(
            key =>
                postMessage({
                    "operation": "user",
                    "userName": spectre.user && spectre.user.userName,
                }),
            error => {
                console.error(`[spectre]: ${error}`);
                postMessage({
                    "operation": "user",
                    "userName": spectre.user.userName,
                    "error": error.message,
                    "cause": error.cause,
                })
            }
        )
    }

    if (msg.data.siteName && (!msg.data.userName || spectre.user.userName === msg.data.userName)) {
        let request = {
            siteName: msg.data.siteName,
            resultType: msg.data.resultType,
            keyCounter: msg.data.keyCounter || spectre.counter.default,
            keyPurpose: msg.data.keyPurpose || spectre.purpose.authentication,
            keyContext: msg.data.keyContext,
        }
        if (!request.resultType) {
            switch (request.keyPurpose) {
                case spectre.purpose.authentication:
                    request.resultType = spectre.resultType.defaultPassword;
                    break;
                case spectre.purpose.identification:
                    request.resultType = spectre.resultType.defaultLogin;
                    break;
                case spectre.purpose.recovery:
                    request.resultType = spectre.resultType.defaultAnswer;
                    break;
            }
        }

        spectre.user.result(request.siteName, request.resultType, request.keyCounter, request.keyPurpose, request.keyContext).then(
            siteResult =>
                postMessage({
                    ...request,
                    "operation": "site",
                    "userName": spectre.user && spectre.user.userName,
                    "siteResult": siteResult,
                }),
            error => {
                console.error(`[spectre]: ${error}`);
                postMessage({
                    ...request,
                    "operation": "site",
                    "userName": spectre.user.userName,
                    "error": error.message,
                    "cause": error.cause,
                })
            }
        );
    }
};
