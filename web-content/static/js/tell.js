const toEmailAddress = document.getElementById("ToEmail");
const email_regex = toEmailAddress.attributes['pattern'].value;
const to_email_regex_pattern = new RegExp('^' + email_regex + '$');
const forgiving_email_regex = '^.*?<(?<cap_email>' + email_regex + ')>.*?$';
const forgiving_email_regex_pattern = new RegExp(forgiving_email_regex);
const emailValidiationStates = {
    Unkown: 'The email address status is unkown',
    Invalid: 'Please enter a valid receiver email address',
    QueryStarted: 'The receiver email address is still beeing validated',
    QueryInterrupted: 'The email address could not be validated, please try again later!',
    Valid: ''
}
var toEmailStatus = emailValidiationStates.Unkown;
let validateEmailTimer;

toEmailAddress.addEventListener(
    'input',
    validateToEmailRegex,
    false
);

function validateToEmailRegex() {
    let mail = toEmailAddress.value.toLowerCase();
    if (forgiving_email_regex_pattern.test(mail)) {
        console.log("extracting email address from input");
	    mail = mail.replace(forgiving_email_regex_pattern, "$<cap_email>");
        toEmailAddress.value = mail;
    }
    if (to_email_regex_pattern.test(mail)) {
        toEmailStatus = emailValidiationStates.QueryStarted;
        if (typeof validateEmailTimer !== 'undefined') {
            clearTimeout(validateEmailTimer);
        }
        validateEmailTimer = setTimeout(queryToEmail, 1000);
    }
    else {
        toEmailStatus = emailValidiationStates.Invalid;
    }
    console.log("toEmailStatus = " + toEmailStatus);
}

function queryToEmail() {
    if (typeof validateEmailTimer !== 'undefined') {
        clearTimeout(validateEmailTimer);
    }
    let mail = toEmailAddress.value.toLowerCase();
    let queryUrl = "/authenticated/receiver/get/validated_email/" + mail;
    toEmailAddress.disabled = true;
    queryWebService(queryUrl, validateToEmail, validateToEmail, 0);
}

function validateToEmail(resulttext) {
    console.log(resulttext);
    console.log(typeof resulttext);
    if (typeof resulttext !== 'undefined') {
        let mail = toEmailAddress.value.toLowerCase();
        if (mail === resulttext) {
            console.log("is valid receiver mail");
            toEmailStatus = emailValidiationStates.Valid;
        }
        else {
            toEmailStatus = emailValidiationStates.Invalid;
        }
    }
    else{
        toEmailStatus = emailValidiationStates.QueryInterrupted;
    }
    console.log("toEmailStatus = " + toEmailStatus);
    toEmailAddress.disabled = false;
    setAriaAttribute(toEmailAddress, toEmailStatus);
    secretForm.reportValidity();
}

const secretForm = document.getElementById("NewSecretForm");
initAriaAttributes(secretForm);
const secretFormInputs = secretForm.elements;
secretForm.addEventListener('submit', function (e) {
    e.preventDefault();
    for (var input of secretFormInputs) {
        if (!input.validity) {
            console.log(`input ${input.id} is invalid`);
        }
        if (input == toEmailAddress) {
            setAriaAttribute(toEmailAddress, toEmailStatus);
        }
    }
    secretForm.reportValidity();
    if (secretForm.checkValidity()) {
        console.log("form is valid, sending data");
        sendFormData();
    }
    else {
        console.log("form is invalid, not sending data");
    }
});

const secretTextarea = document.getElementById("Secret");
const secretMaxLength = secretTextarea.maxLength;
let validateTextareaTimer;
secretTextarea.addEventListener('paste', function (e) {
    let paste = (e.clipboardData || window.clipboardData).getData("text");
    let pasteLength = paste.length;
    let remainingChars = secretMaxLength - secretTextarea.value.length;
    if (remainingChars > pasteLength) {
        console.log("pasting text");
        setAriaAttribute(secretTextarea, "");
    }
    else {
        let errorMsg = `Pasted text with ${pasteLength} chars does not fit in ${remainingChars} remaining chars!`;
        setAriaAttribute(secretTextarea, errorMsg);
        console.log("pasting too much text, aborting!");
        validateTextareaTimer = setTimeout(resetTextAreaAria, 3000);
        e.preventDefault();
    }
    secretTextarea.reportValidity();
});

function resetTextAreaAria(){
    if (typeof validateTextareaTimer !== 'undefined') {
        clearTimeout(validateTextareaTimer);
    }
    setAriaAttribute(secretTextarea, "");
    secretTextarea.reportValidity();
}

secretTextarea.addEventListener('change', function (e) {
    resetTextAreaAria()
});

var keepAliveCount = 0;
var keep_alive_interval = initKeepAliveInterval("/authenticated/keep_session_alive");
keepSessionAlive("/authenticated/keep_session_alive");

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
        disableFormInputs(secretForm);
        if (resulttext == "OK") {
            showSuccessMessageWithTimer("Secret saved, the receiver will be notified via email.", 5);
            startBackHomeTimer(6);
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

function sendFormData() {
    let secret;
    try {
        // encode password to transfer special characters
        secret = btoa(unescape(encodeURIComponent(secretTextarea.value)));
    }
    catch (error) {
        console.log("ERROR: could not convert secret to base64: " + output);
        showErrorMessage("ERROR: could not convert secret to base64");
    }
    let jsonObject = {
        FromEmail: document.getElementById("FromEmail").value,
        FromDisplayName: document.getElementById("FromDisplayName").value,
        ToEmail: document.getElementById("ToEmail").value.toLowerCase(),
        ToDisplayName: document.getElementById("ToDisplayName").value,
        Context: document.getElementById("Context").value,
        Secret: secret,
        CsrfToken: document.getElementById("CsrfToken").value,
    };
    let jsonString = JSON.stringify(jsonObject);
    sendToWebService("/authenticated/secret/tell", displaySubmission, errorOnSubmission, jsonString, 5);
    document.getElementById("SubmitButton").classList.add("lmtyas-hidden");
}

function errorOnSubmission() {
    console.log("errorOnSubmission()");
    stopForm(secretForm, 6);
}

if (document.readyState !== "interactive" && document.readyState !== "complete") {
    function initializer() {
        document.querySelectorAll(".lmtyas-input-hint").forEach((hintNode) => {
            const targetId = hintNode.dataset.for;
            const target = document.getElementById(targetId);
            let maxLength = null;
            if ("maxlength" in target.dataset) {
                maxLength = parseInt(target.dataset.maxlength);
            } else {
                maxLength = parseInt(target.getAttribute("maxlength"));
            }
            function updater() {
                hintNode.innerText = `${target.value.length} chars (max. ${maxLength})`;
                if (target.value.length > maxLength) {
                    target.classList.add("invalid");
                } else {
                    target.classList.remove("invalid");
                }
            };
            target.addEventListener("input", updater);
            target.addEventListener("keyup", updater);
            updater();
        });
    };
    document.addEventListener("readystatechange", initializer);
}
