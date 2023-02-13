function spinnerBusy(element, busy) {
    element.data("spin", busy);

    if (busy) {
        element.finish().fadeIn();
    } else {
        element.finish().fadeOut();
    }
}

$(() => {
    let signOutButton = $('#signout');
    let user = $('#user');
    let userForm = user.find('form');
    let userName = user.find('#userName');
    let userNameInput = userName.find('input');
    let userSecret = user.find('#userSecret');
    let userSecretInput = userSecret.find('input');
    let userSecretSpinner = userSecret.find('.fa-spin');
    let userAlgorithm = user.find('#algorithmVersion');
    let userAlgorithmInput = userAlgorithm.find('select');
    let userMessage = user.find('p.info');
    let userError = user.find('p.error');
    let site = $('#site');
    let siteForm = site.find('form');
    let siteName = site.find('#siteName');
    let siteNameInput = siteName.find('input');
    let sitePurposeInputs = site.find('input[name="sitePurpose"]');
    let siteCounter = site.find('#siteCounter');
    let siteCounterInput = siteCounter.find('input');
    let siteType = site.find('#siteType');
    let siteTypeInput = siteType.find('select');
    let siteResult = site.find('#siteResult');
    let siteResultSpinner = siteResult.find('.fa-spin');
    let siteResultButton = siteResult.find('button');
    let siteResultInput = siteResultButton.find('input')
    let siteMessage = site.find('p.info');
    let siteError = site.find('p.error');

    for (template in spectre.templates) {
        let option = document.createElement('option');
        option.text = spectre.resultName[template];
        option.value = template;
        siteTypeInput[0].add(option);
    }
    for (option of sitePurposeInputs) {
        option.checked = option.value === spectre.purpose.authentication;
    }

    function updateDefaults() {
        userAlgorithmInput[0].value = spectre.algorithm.current;
        siteCounterInput[0].value = spectre.counter.initial;
        
        switch (sitePurposeInputs.filter(':checked')[0].value) {
            case spectre.purpose.authentication: {
                siteTypeInput[0].value = spectre.resultType.defaultPassword;
                break;
            }
            case spectre.purpose.identification: {
                siteTypeInput[0].value = spectre.resultType.defaultLogin;
                break;
            }
            case spectre.purpose.recovery: {
                siteTypeInput[0].value = spectre.resultType.defaultAnswer;
                break;
            }
        }
    }

    function updateSpectre() {
        spectre.request(
            siteNameInput[0].value,
            siteTypeInput[0].value,
            siteCounterInput[0].value,
            sitePurposeInputs.filter(':checked')[0].value,
            null //keyContext
        );
    }

    function updateView() {
        spinnerBusy(userSecretSpinner, spectre.operations.user.pending);
        spinnerBusy(siteResultSpinner, spectre.operations.site.pending);

        userNameInput.val(spectre.operations.user.userName);
        userSecretInput.val(null);
        siteResultInput.val(spectre.result(siteNameInput[0].value, sitePurposeInputs.filter(':checked')[0].value));

        if (spectre.operations.user.authenticated) {
            user.attr("data-active", false);
            site.attr("data-active", true);
            siteNameInput.focus()
        } else {
            user.attr("data-active", true);
            site.attr("data-active", false);
            userAlgorithmInput.val(spectre.algorithm.current);
            siteNameInput.val(null);
            userNameInput.focus()
        }
    }

    updateDefaults();
    spectre.observers.push(updateView);
    updateView();

    userForm.on('submit', (e) => {
        e.preventDefault();
        spectre.authenticate(userNameInput[0].value, userSecretInput[0].value, userAlgorithmInput[0].value);
    });
    siteForm.on('submit', (e) => {
        e.preventDefault()
        siteResultInput.select()
        if (navigator.clipboard.writeText(siteResultInput[0].value) || document.execCommand('copy')) {
            siteResultButton.attr("title", "Copied!").tooltip("_fixTitle").tooltip("show");
            setTimeout(() => {
                siteResultButton.tooltip("hide").attr("title", "Copy Password").tooltip("_fixTitle");
            }, 1000);
        }
    });

    signOutButton.on('click', () => {
        spectre.invalidate();
    });
    siteNameInput.on('input', () => {
        updateSpectre();
    });
    sitePurposeInputs.on('input', () => {
        updateDefaults();
        updateSpectre();
    });
    siteCounterInput.on('input', () => {
        updateSpectre();
    });
    siteTypeInput.on('input', () => {
        updateSpectre();
    });
});
