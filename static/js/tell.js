const loginForm = document.getElementById("NewSecretForm");
loginForm.addEventListener('submit', function (e) {
    e.preventDefault();
    sendFormData();
});
var keepAliveCount = 0;
var keep_alive_interval = initKeepAliveInterval("/authenticated/keep_session_alive");
queryWebService("/system/is_server_ready", validateSystemStatus, systemIsNotReady);
queryWebService("/authenticated/user/get/details/from", displayFromData, function () { });
queryWebService("/system/get/mail-hint", setMailHint, function () { });

function setMailHint(resulttext) {
    try {
        var data = JSON.parse(resulttext);
        if (data.MailHint) {
            const imprint = document.getElementById("ToEmail");
            imprint.setAttribute('placeholder', data.MailHint);
        }
    }
    catch (e) {
        console.log(e);
    }
}

function displaySubmission(resulttext) {
    if (typeof resulttext !== 'undefined') {
        disableInputs();
        if (resulttext == "OK") {
            showSuccessMessageWithTimer("Secret saved, the receiver will be notified via email.", 15);
            startBackHomeTimer(16);
        }
    }
}

function displayFromData(result) {
    if (typeof result !== 'undefined') {
        let data = JSON.parse(result);
        document.getElementById("FromDisplayName").value = data.DisplayName;
        document.getElementById("FromEmail").value = data.Email;
        document.getElementById("ToEmail").focus();
    }
}

function disableInputs() {
    ToEmail.disabled = true;
    Context.disabled = true;
    Secret.disabled = true;
}

function sendFormData() {
    let secret;
    try {
        // encode password to transfer special characters
        secret = btoa(unescape(encodeURIComponent(document.getElementById("Secret").value)));
    }
    catch (error) {
        console.log("ERROR: could not convert secret to base64: " + output);
        showErrorMessage("ERROR: could not convert secret to base64");
    }
    let jsonObject = {
        FromEmail: document.getElementById("FromEmail").value,
        FromDisplayName: document.getElementById("FromDisplayName").value,
        ToEmail: document.getElementById("ToEmail").value,
        ToDisplayName: document.getElementById("ToDisplayName").value,
        Context: document.getElementById("Context").value,
        Secret: secret,
    };
    let jsonString = JSON.stringify(jsonObject);
    console.log(jsonString);
    sendToWebService("/authenticated/secret/tell", displaySubmission, disableInputs, jsonString);
    document.getElementById("SubmitButton").style.visibility = "hidden";
}