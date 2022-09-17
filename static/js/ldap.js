const loginForm = document.getElementById("LoginForm");
loginForm.addEventListener('submit', function (e) {
    e.preventDefault();
    sendLoginData();
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
    document.getElementById("ServiceIsNotReady").style.display = "block";
}

function showLoginHint(resulttext) {
    if (typeof resulttext !== 'undefined') {
        document.getElementById("LoginName").placeholder = resulttext;
    }
}

function sendLoginData() {
    let request = findGetParameterNoDecodeURIComponent("request");
    if (request != null && typeof (request !== 'undefined')) {
        sendFormData(request);
    }
    else {
        document.getElementById("SubmitButton").style.visibility = "hidden";
        showErrorMessageWithTimer("ERROR: could not find request id", 10);
    }
}

function sendFormData(requestId) {
    if (requestId != null && typeof (requestId !== 'undefined')) {
        let loginPassword;
        try {
            // encode password to transfer special characters
            loginPassword = btoa(unescape(encodeURIComponent(document.getElementById("LoginPassword").value)));
        }
        catch (error) {
            console.log("ERROR: could not convert password to base64: " + output);
            showErrorMessage("ERROR: could not convert password to base64");
        }
        let loginName = document.getElementById("LoginName").value;
        let jsonObject = {
            LoginName: loginName,
            LoginPassword: loginPassword,
            RequestId: requestId
        };
        let jsonString = JSON.stringify(jsonObject);
        document.getElementById("SubmitButton").style.visibility = "hidden";
        sendToWebService("/authentication/login", openUrl, startBackHomeTimer(3), jsonString, 2);
    }
    else {
        showErrorMessageWithTimer("ERROR: cannot get request data!", 10);
    }
}

function openUrl(url) {
    window.open(url, "_self");
}