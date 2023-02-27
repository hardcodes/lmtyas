const tellButton = document.getElementById("tell");
queryWebService("/system/is_server_ready", validateSystemStatus, notReady);

function notReady(){
    tellButton.disabled = true;
    systemIsNotReady;
}