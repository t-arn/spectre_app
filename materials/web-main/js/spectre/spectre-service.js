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

/**
 * spectre-service
 * ===============
 *
 * This file is responsible for providing a Spectre service which operates through a background Spectre web worker.
 * The service manages a single internal Spectre user identity through requested operations.
 *
 * It attaches the following properties to the global `spectre` object:
 * `userName`, `identicon`, `authenticated` & `site`: They describe the current state of the Spectre identity managed through the service.
 * It attaches the following functions to the global `spectre` object:
 * `invalidate`, `authenticate`, `password`, `login` & `answer`: They operate on the Spectre identity managed through the service.
 */

spectre.observers = [];
spectre.operations = {
    user: {
        pending: false,
        error: null,
        cause: null,
        userName: null,
        identicon: null,
        authenticated: false,
    },
    site: {
        pending: false,
        error: null,
        cause: null,
        result: [],
    }
};

spectre.invalidate = Object.freeze(() => {
    spectre.operations.user.pending = true;
    spectre.operations.site.pending = true;
    for (const observer of spectre.observers) {
        observer()
    }

    spectre.worker.postMessage({
        "userName": spectre.operations.user.userName,
        "invalidate": true,
    });
});
spectre.authenticate = Object.freeze((userName, userSecret, algorithmVersion) => {
    spectre.operations.user.pending = true;
    spectre.operations.user.userName = userName;
    for (const observer of spectre.observers) {
        observer()
    }

    spectre.worker.postMessage({
        "userName": userName,
        "userSecret": userSecret,
        "algorithmVersion": algorithmVersion,
    });
});
spectre.password = Object.freeze((siteName, resultType, keyCounter, keyContext) => {
    spectre.request(siteName, resultType, keyCounter, spectre.purpose.authentication, keyContext);
});
spectre.login = Object.freeze((siteName, resultType, keyCounter, keyContext) => {
    spectre.request(siteName, resultType, keyCounter, spectre.purpose.identification, keyContext);
});
spectre.answer = Object.freeze((siteName, resultType, keyCounter, keyContext) => {
    spectre.request(siteName, resultType, keyCounter, spectre.purpose.recovery, keyContext);
});
spectre.request = Object.freeze((siteName, resultType, keyCounter, keyPurpose, keyContext) => {
    spectre.operations.site.pending = true;
    for (const observer of spectre.observers) {
        observer()
    }

    spectre.worker.postMessage({
        "userName": spectre.operations.user.userName,
        "siteName": siteName,
        "resultType": resultType,
        "keyCounter": keyCounter,
        "keyPurpose": keyPurpose,
        "keyContext": keyContext,
    });
});
spectre.result = Object.freeze((siteName, keyPurpose = spectre.purpose.authentication, keyContext = null) => {
    return ((spectre.operations.site.result[siteName || ""] || {})[keyPurpose || ""] || {})[keyContext || ""]
});

function newWorkerFromURL(workerURL) {
    let blobURL = URL.createObjectURL(new Blob([
        'let baseURI = ', JSON.stringify(document.baseURI), '; ' +
        'importScripts(new URL(', JSON.stringify(workerURL), ', baseURI).href)',
    ], {type: 'application/javascript'}));

    try {
        return new Worker(blobURL);
    } finally {
        URL.revokeObjectURL(blobURL);
    }
}

function mergeInto(host, ...objects) {
    if (!objects.length)
        return host;

    const object = objects.shift();
    for (const key in object) {
        let item = object[key]
        if (item && typeof item === 'object' && !Array.isArray(item) && host[key]) {
            mergeInto(host[key], item);
        } else {
            Object.assign(host, { [key]: item });
        }
    }

    return mergeInto(host, ...objects);
}

spectre.worker = newWorkerFromURL("js/spectre/spectre-worker.js");
spectre.worker.onmessage = (msg) => {
    console.trace(`[spectre]: onmessage: ${JSON.stringify(msg.data)})`);
    if (msg.data.userName !== spectre.operations.user.userName)
        return;

    switch (msg.data.operation) {
        case 'invalidate':
            spectre.operations.user.userName = null;
            spectre.operations.user.identicon = null;
            spectre.operations.user.pending = false;
            spectre.operations.user.authenticated = false;
            spectre.operations.user.error = null;
            spectre.operations.user.cause = null;
            spectre.operations.site.pending = false;
            spectre.operations.site.error = null;
            spectre.operations.site.cause = null;
            spectre.operations.site.result = [];
            break;
        case 'identicon':
            spectre.operations.user.identicon = msg.data.userIdenticon;
            break;
        case 'user':
            spectre.operations.user.pending = false;
            spectre.operations.user.authenticated = msg.data.error === undefined;
            spectre.operations.user.error = msg.data.error;
            spectre.operations.user.cause = msg.data.cause;
            break;
        case 'site':
            spectre.operations.site.pending = false;
            spectre.operations.site.error = msg.data.error;
            spectre.operations.site.cause = msg.data.cause;
            mergeInto(spectre.operations.site.result, {
                [msg.data.siteName || ""]: {
                    [msg.data.keyPurpose || ""]: {
                        [msg.data.keyContext || ""]: msg.data.siteResult
                    }
                }
            });
            break;
    }
    
    for (const observer of spectre.observers) {
        observer()
    }
};
