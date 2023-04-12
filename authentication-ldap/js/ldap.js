const loginForm = document.getElementById("LoginForm");
loginForm.addEventListener('submit', function (e) {
    e.preventDefault();
    sendLoginData(loginForm);
    return false;
});
queryWebService("/system/is_server_ready", validateSystemStatusLocal, systemIsNotReadyLocal);
queryWebService("/system/get/login-hint", showLoginHint, function () { });
document.getElementById("LoginName").focus();

function validateSystemStatusLocal(resulttext) {
    try {
        var data = JSON.parse(resulttext);
        if (!data.isReady) {
            systemIsNotReadyLocal();
        }
    }
    catch (e) {
        console.log(e);
        systemIsNotReadyLocal();
    }
}

function systemIsNotReadyLocal() {
    document.getElementById("ServiceIsNotReady").classList.remove("lmtyas-none");
    document.getElementById("ServiceIsNotReady").classList.add("lmtyas-block");
}

function showLoginHint(resulttext) {
    if (typeof resulttext !== 'undefined') {
        document.getElementById("LoginName").placeholder = resulttext;
    }
}

function sendLoginData(loginForm) {
    console.log("sendLoginData()");
    let requestId = findGetParameterNoDecodeURIComponent("request");
    if (requestId != null && typeof (requestId !== 'undefined')) {
        let loginPassword;
        try {
            // encode password to transfer special characters
            loginPassword = btoa(unescape(encodeURIComponent(loginForm.password.value)));
        }
        catch (error) {
            console.log("ERROR: could not convert password to base64: " + output);
            showErrorMessage("ERROR: could not convert password to base64");
        }
        let jsonObject = {
            LoginName: loginForm.username.value,
            LoginPassword: loginPassword,
            RequestId: requestId
        };
        let jsonString = JSON.stringify(jsonObject);
        document.getElementById("SubmitButton").classList.add("lmtyas-hidden");
        sendToWebService("/authentication/login", openUrl, stopForm(loginForm, 6), jsonString, 5);
    }
    else {
        document.getElementById("SubmitButton").classList.add("lmtyas-hidden");
        showErrorMessageWithTimer("ERROR: could not find request id", 10);
    }
}

function openUrl(url) {
    window.open(url, "_self");
}

