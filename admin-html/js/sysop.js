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
    document.getElementById("ServiceIsNotReady").style.display = "block";
    document.getElementById("ServiceIsReady").style.display = "none";
}

function systemIsReadyLocal() {
    document.getElementById("ServiceIsNotReady").style.display = "none";
    document.getElementById("ServiceIsReady").style.display = "block";  
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
    let url = "/authenticated/sysop/set_password_for_rsa_rivate_key/" + rsaPassword;
    sendToWebService(url, displaySubmission, errorOnSubmission, 5);
}

function displaySubmission(resulttext) {
    stopForm(rsaForm, 10);
    if (typeof resulttext !== 'undefined') {
        if (resulttext == "OK") {
            showSuccessMessage("Password for RSA private key is set.");
        }
    }
}

function errorOnSubmission() {
    console.log("errorOnSubmission()");
    stopForm(rsaForm, 6);
}