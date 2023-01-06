let secretId = findGetParameterNoDecodeURIComponent("secret_id");
var keepAliveCount = 0;
if (secretId != null && typeof (secretId !== 'undefined')) {
    var keep_alive_interval = initKeepAliveInterval("/authenticated/keep_session_alive");
    keepSessionAlive("/authenticated/keep_session_alive");
    queryWebService("/system/is_server_ready", validateSystemStatus, systemIsNotReady);
    queryWebService("/authenticated/secret/reveal/" + secretId, displaySecret, function () { });
}
else {
    showErrorMessage("No SecretId found!");
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
            console.log("ERROR: could not convert secret to base64: " + output);
            showErrorMessage("ERROR: could not convert secret to base64");
        }
        document.getElementById("Secret").value = secret;
        document.getElementById("RevealSecretForm").style.display = "block";
    }
}

function disableInputs() {
    ToEmail.disabled = true;
    Context.disabled = true;
    Secret.disabled = true;
}