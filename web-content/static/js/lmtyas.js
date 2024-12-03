function showErrorMessage(messagetext) {
  if (!document.getElementById("ErrorMessage")) {
    var div = document.createElement('div');
    div.setAttribute('class', 'error-msg');
    div.setAttribute('role', 'alert');
    div.setAttribute('id', 'ErrorMessage');
    document.body.appendChild(div);
  }
  document.getElementById("ErrorMessage").innerHTML = messagetext;
  document.getElementById("ErrorMessage").classList.add("lmtyas-visible");
}

function hideErrorMessage() {
  document.getElementById("ErrorMessage").classList.remove("lmtyas-visible");
  document.getElementById("ErrorMessage").classList.add("lmtyas-hidden");
}

function showErrorMessageWithTimer(messagetext, seconds = 0) {
  showErrorMessage(messagetext);
  if (seconds != 0) {
    var timer = window.setTimeout(hideErrorMessage, (seconds * 1000));
  }
}

function showSuccessMessage(messagetext) {
  if (!document.getElementById("SuccessMessage")) {
    var div = document.createElement('div');
    div.setAttribute('class', 'success-msg');
    div.setAttribute('role', 'alert');
    div.setAttribute('id', 'SuccessMessage');
    document.body.appendChild(div);
  }
  document.getElementById("SuccessMessage").innerHTML = messagetext;
  document.getElementById("SuccessMessage").classList.add("lmtyas-visible");
}

function hideSuccessMessage() {
  document.getElementById("SuccessMessage").classList.remove("lmtyas-visible");
  document.getElementById("SuccessMessage").classList.add("lmtyas-hidden");
}

function showSuccessMessageWithTimer(messagetext, seconds = 0) {
  showSuccessMessage(messagetext);
  if (seconds != 0) {
    var timer = window.setTimeout(hideSuccessMessage, (seconds * 1000));
  }
}

function showNotifyMessage(messagetext) {
  if (!document.getElementById("NotifyMessage")) {
    var div = document.createElement('div');
    div.setAttribute('class', 'notify-msg');
    div.setAttribute('id', 'NotifyMessage');
    document.body.appendChild(div);
  }
  document.getElementById("NotifyMessage").innerHTML = messagetext;
  document.getElementById("NotifyMessage").classList.add("lmtyas-inline-block");
  document.getElementById("NotifyMessage").classList.add("lmtyas-visible");
}

function startProgressSpinner() {
  if (!document.getElementById("ProgressSpinner")) {
    var div = document.createElement('div');
    div.setAttribute('class', 'progress-spinner');
    div.setAttribute('id', 'ProgressSpinner');
    document.body.appendChild(div);
  }
  document.getElementById("ProgressSpinner").classList.remove("lmtyas-hidden");
  document.getElementById("ProgressSpinner").classList.add("lmtyas-visible");
}

function stopProgressSpinner() {
  document.getElementById("ProgressSpinner").classList.remove("lmtyas-visible");
  document.getElementById("ProgressSpinner").classList.add("lmtyas-hidden");
}


function accessWebService(url, okcallback, errorcallback, method = "GET", formdata = null, seconds = 0, timeout = 0) {
  var xhttp = new XMLHttpRequest();

  xhttp.onreadystatechange = function () {
    if (this.readyState == 4 && (this.status == 200 || (this.status >= 400 && this.status < 500))) {
      stopProgressSpinner();
      if (this.status >= 400 && this.status < 500 || this.responseText.includes("ERROR:")) {
        showErrorMessageWithTimer(this.responseText, seconds);
        if (typeof errorcallback == "function") {
          errorcallback();
        }
      }
      else {
        if (typeof okcallback == "function") {
          okcallback(this.responseText);
        }
      }
    }
  };
  xhttp.ontimeout = function () {
    showErrorMessageWithTimer("Timeout: can not load data!", seconds);
    stopProgressSpinner();
  };
  xhttp.onabort = function () {
    showErrorMessageWithTimer("Timeout: loading the data was interrupted!", seconds);
    stopProgressSpinner();
  };
  xhttp.onerror = function () {
    showErrorMessageWithTimer("Timeout: error while loading the data!", seconds);
    stopProgressSpinner();
  };
  startProgressSpinner();
  xhttp.open(method, url, true);
  xhttp.timeout = timeout;
  if (method === "POST") {
    xhttp.setRequestHeader("Content-Type", "application/x-www-form-urlencoded", seconds);
  }
  xhttp.send(formdata);
}

function queryWebService(url, okcallback, errorcallback, seconds = 0, timeout = 0) {
  accessWebService(url, okcallback, errorcallback, "GET", null, seconds, timeout)
}

function sendToWebService(url, okcallback, errorcallback, formdata, seconds = 0, timeout = 0) {
  accessWebService(url, okcallback, errorcallback, "POST", formdata, seconds, timeout)
}

function validateSystemStatus(resulttext) {
  try {
    var data = JSON.parse(resulttext);
    if (data.isReady) {
      document.getElementById("ServiceIsReady").classList.remove("lmtyas-none");
      document.getElementById("ServiceIsReady").classList.add("lmtyas-block");
    }
    else {
      systemIsNotReady();
    }
  }
  catch (e) {
    console.log(e);
    systemIsNotReady();
  }
}

function systemIsNotReady() {
  console.log("hiding content")
  document.getElementById("ServiceIsReady").classList.remove("lmtyas-block");
  document.getElementById("ServiceIsReady").classList.add("lmtyas-none");

  document.getElementById("ServiceIsNotReady").classList.remove("lmtyas-none");
  document.getElementById("ServiceIsNotReady").classList.add("lmtyas-block");

}

function startBackHomeTimer(seconds = 15, url = '/index.html') {
  if (seconds > 0) {
    let redirectBackHomeTimeout = setTimeout(function () { redirectHome(url) }, (seconds * 1000));
  }
}

function redirectHome(url) {
  if (typeof url !== 'undefined') {
    window.location.replace(url);
  }
}

function logQueryResult(resulttext) {
  if (typeof resulttext !== 'undefined') {
    console.log(resulttext);
  }
  else {
    console.log("ERROR: undefined result!")
  }
}

function keepSessionAlive(url) {
  console.log("keepAliveCount = " + keepAliveCount);
  if (keepAliveCount > 30) {
    console.log("stale session, redirecting to index.html");
    clearInterval(keep_alive_interval);
    showErrorMessageWithTimer("Session was active for more than 30 minutes, redirecting...", 10);
    let redirectTimeout = setTimeout(function () { redirectHome("/index.html"); }, 11000);
  }
  else {
    keepAliveCount++;
    if (keepAliveCount > 1) {
      queryWebService(url, logQueryResult, logQueryResult);
    }
    else{
      console.log("skipping immediate keepalive query")
    }
  }
}

function initKeepAliveInterval(url, seconds = 60) {
  if (seconds != 0) {
    let timer = window.setInterval(function () { keepSessionAlive(url) }, (seconds * 1000));
    return timer;
  }
}

// inspired by https://stackoverflow.com/questions/5448545/how-to-retrieve-get-parameters-from-javascript
function findGetParameterNoDecodeURIComponent(parameterName) {
  var result = null,
    tmp = [];
  window.location.search
    .substring(1)
    .split("&")
    .forEach(function (item) {
      tmp = item.split("=");
      if (tmp[0] === parameterName) result = tmp[1];
    });
  return result;
}

function setImprintLink(resulttext) {
  try {
    var data = JSON.parse(resulttext);
    const imprint = document.getElementById("Imprint");
    imprint.setAttribute('href', data.href);
    imprint.setAttribute('target', data.target);
  }
  catch (e) {
    console.log(e);
  }
}

function setPrivacyLink(resulttext) {
  try {
    var data = JSON.parse(resulttext);
    const privacy = document.getElementById("Privacy");
    privacy.setAttribute('href', data.href);
    privacy.setAttribute('target', data.target);
  }
  catch (e) {
    console.log(e);
  }
}

function startLocationReloadTimer(seconds = 5) {
  if (seconds > 0) {
    let locationReloadTimeout = setTimeout(function () { window.location.replace(window.location.pathname); }, (seconds * 1000));
  }
}

function disableFormInputs(formId) {
  if (typeof formId !== 'undefined') {
    var formInputs = formId.elements;
    if (typeof formInputs !== 'undefined' && formInputs !== null) {
      for (var input of formInputs) {
        input.disabled = true;
      }
    }
  }
}

function stopForm(formId, backHomeTimerSeconds = 10) {
  if (typeof keep_alive_interval !== 'undefined') {
    clearInterval(keep_alive_interval);
  }
  disableFormInputs(formId);
  startBackHomeTimer(backHomeTimerSeconds);
}

function setAriaAttribute(inputElement, validityMessage) {
  if (validityMessage) {
      inputElement.setCustomValidity(validityMessage);
      inputElement.setAttribute("aria-invalid", "true");
  }
  else {
      inputElement.setCustomValidity('');
      inputElement.removeAttribute("aria-invalid");
  }
}

function initAriaAttributes(form) {
  if (typeof form !== 'undefined') {
    for (const field of form.elements) {
      field.addEventListener("invalid", function handleInvalidField(event) {
        field.setAttribute("aria-invalid", "true");
      });

      field.addEventListener("blur", function handleFieldBlur() {
        field.removeAttribute("aria-invalid");
        field.checkValidity();
      });
    }
  }
}

queryWebService("/system/get/imprint-link", setImprintLink, function () { });
queryWebService("/system/get/privacy-link", setPrivacyLink, function () { });


