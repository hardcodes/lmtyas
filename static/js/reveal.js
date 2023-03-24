const secretId = findGetParameterNoDecodeURIComponent("secret_id");
const revealForm = document.getElementById("RevealSecretForm");

var keepAliveCount = 0;
if (secretId != null && typeof (secretId !== 'undefined')) {
    var keep_alive_interval = initKeepAliveInterval("/authenticated/keep_session_alive");
    keepSessionAlive("/authenticated/keep_session_alive");
    queryWebService("/system/is_server_ready", validateSystemStatus, systemIsNotReady);
    queryWebService("/authenticated/secret/reveal/" + secretId, displaySecret, errorOnReveal, 5);
}
else {
    showErrorMessage("No SecretId found!");
    stopForm(revealForm, 5);
}

function errorOnReveal() {
    console.log("errorOnReveal()");
    stopForm(revealForm, 6);
}

function displaySecret(resulttext) {
    if (typeof resulttext !== 'undefined') {
        let data = JSON.parse(resulttext);
        document.getElementById("FromDisplayName").value = data.FromDisplayName;
        document.getElementById("FromEmail").value = data.FromEmail;
        document.getElementById("Context").value = data.Context;
        let secret;
        try {
            // decode password to transfer special characters
            secret = decodeURIComponent(escape(window.atob(data.Secret)));
        }
        catch (error) {
            console.log("ERROR: could not convert secret from base64: " + output);
            showErrorMessage("ERROR: could not convert secret from base64");
        }
        document.getElementById("Secret").value = secret;
        document.getElementById("RevealSecretForm").classList.remove("lmtyas-none");
        document.getElementById("RevealSecretForm").classList.add("lmtyas-block");
    }
}
