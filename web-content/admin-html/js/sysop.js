const rsaForm = document.getElementById("RsaPasswordForm");
rsaForm.addEventListener('submit', function (e) {
    e.preventDefault();
    setRsaPassword();
});
var keepAliveCount = 0;
var keep_alive_interval = initKeepAliveInterval("/authenticated/keep_session_alive");

queryWebService("/system/is_server_ready", validateSystemStatusLocal, systemIsNotReadyLocal);
document.getElementById("RsaPassword").focus();

function validateSystemStatusLocal(resulttext) {
    try {
        var data = JSON.parse(resulttext);
        if (data.isReady) {
            systemIsReadyLocal();
        }
        else
            systemIsNotReadyLocal();
    }
    catch (e) {
        console.log(e);
        systemIsNotReadyLocal();
    }
}

function systemIsNotReadyLocal() {
    document.getElementById("ServiceIsNotReady").classList.remove("lmtyas-none");
    document.getElementById("ServiceIsNotReady").classList.add("lmtyas-block");

    document.getElementById("ServiceIsReady").classList.remove("lmtyas-block");
    document.getElementById("ServiceIsReady").classList.add("lmtyas-none");
}

function systemIsReadyLocal() {
    document.getElementById("ServiceIsNotReady").classList.remove("lmtyas-block");
    document.getElementById("ServiceIsNotReady").classList.add("lmtyas-none");

    document.getElementById("ServiceIsReady").classList.remove("lmtyas-none");
    document.getElementById("ServiceIsReady").classList.add("lmtyas-block");
}

function setRsaPassword() {
    let rsaPassword;
    try {
        // encode password to transfer special characters
        rsaPassword = btoa(unescape(encodeURIComponent(document.getElementById("RsaPassword").value)));
    }
    catch (error) {
        console.log("ERROR: could not convert password to base64: " + output);
        showErrorMessage("ERROR: could not convert password to base64");
    }
    let payload = rsaPassword + ';' + document.getElementById("CsrfToken").value;
    sendToWebService("/authenticated/sysop/set_password_for_rsa_rivate_key", displaySubmission, errorOnSubmission, payload, 5);
    document.getElementById("SubmitButton").classList.add("lmtyas-hidden");
}

function displaySubmission(resulttext) {
    stopForm(rsaForm, 10);
    if (typeof resulttext !== 'undefined') {
        if (resulttext == "OK") {
            showSuccessMessage("RSA private key has been loaded successfully.");
        }
    }
}

function errorOnSubmission() {
    console.log("errorOnSubmission()");
    stopForm(rsaForm, 6);
}