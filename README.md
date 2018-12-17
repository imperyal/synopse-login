# synopse-login

- Based on RangerX's code ( https://synopse.info/forum/viewtopic.php?pid=2995#p2995 )
- Requires JQuery
- Requires sha256 (https://github.com/emn178/js-sha256)
- crc32 code included (from https://stackoverflow.com/questions/18638900/javascript-crc32)
- Uses Localstorage to store session data like in the original code


Example usage:

-> Config variables (set before using the class)

var G_SERVER_URL  = "http://127.0.0.1:8080";
var G_SERVER_ROOT = "root";
var G_MAIN_URL    = G_SERVER_URL + '/' + G_SERVER_ROOT;   // Main URL


-> Login

const APP_Login = new SYN_login;
APP_Login.login(userName, userPass, F_loginResult);

function F_loginResult(result) {
    if (result) { alert("Login OK"); }
    else        { alert("Login ERROR"); }
}

-> Use $.ajax to call your interfaces, etc..
