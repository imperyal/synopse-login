/**********************************************************************************************/
/*                                                                                            */
/*    ======= Synopse login class =======                                                     */
/*                                                                                            */
/*                                                                                            */
/* - Based on RangerX's code ( https://synopse.info/forum/viewtopic.php?pid=2995#p2995 )      */
/* - Requires JQuery                                                                          */
/* - Requires sha256 (https://github.com/emn178/js-sha256)                                    */
/* - crc32 code included (from https://stackoverflow.com/questions/18638900/javascript-crc32) */
/* - Uses Localstorage to store session data like in the original code                        */
/*                                                                                            */
/*                                                                                            */
/*  Example usage:                                                                            */
/*                                                                                            */
/* -> Config variables (set before using the class)                                           */
/*                                                                                            */
/* var G_SERVER_URL  = "http://127.0.0.1:8080";              // Server URL                    */
/* var G_SERVER_ROOT = "root";                               // Server root                   */
/* var G_MAIN_URL    = G_SERVER_URL + '/' + G_SERVER_ROOT;   // Main URL                      */
/*                                                                                            */
/*                                                                                            */
/* -> Login                                                                                   */
/*                                                                                            */
/*  const APP_Login = new SYN_login;                                                          */
/*  APP_Login.login(userName, userPass, F_loginResult);                                       */
/*                                                                                            */
/*  function F_loginResult(result) {                                                          */
/*      if (result) { alert("Login OK"); }                                                    */
/*      else        { alert("Login ERROR"); }                                                 */
/*  }                                                                                         */
/*                                                                                            */
/*  -> Use $.ajax to call your interfaces, etc..                                              */
/*                                                                                            */
/**********************************************************************************************/

class SYN_login {

    login(userName, usarPass, callBack) {
        let servnonce;
        let currDate;
        let clientnonce;
        let dataString;
        let password;
        let charPlusPos;

        let self = this;
    
        this.setAjaxPrefilter();

        this.CloseSession(); // try to close previously opened session
    
        currDate    = new Date();
        clientnonce = currDate.getTime() / (1000 * 60 * 5); // valid for 5*60*1000 ms = 5 minutes;
        clientnonce = sha256("" + clientnonce);
        dataString  = {'UserName': userName};
    
        // First request, to get the servnonce for the user 
        $.ajax({
            type:     "GET",
            dataType: "json",
            url:      G_MAIN_URL + '/auth',
            data:     dataString,
            timeout:  2000,
            success: function(data, textStatus, jqXHR) {
                servnonce  = data.result;            
                password   = sha256(G_SERVER_ROOT + servnonce + clientnonce + userName + sha256('salt' + usarPass));  // Sha256(ModelRoot+Nonce+ClientNonce+UserName+Sha256('salt'+PassWord))
                dataString = {'UserName': userName, 'Password': password, 'ClientNonce': clientnonce};
    
                // Secound request, sending required data including the spicedup password, to get a session
                $.ajax({
                    type:        "GET",
                    dataType:    "json",
                    url:         G_MAIN_URL + '/auth',
                    data:        dataString,
                    crossDomain: true,
                    timeout:     2000, 
                    success: function(data, textStatus, jqXHR) {
                        charPlusPos = data.result.indexOf('+');
                        if (charPlusPos > -1) {

                            // ******************************************
                            // Save relevant session data on localstorage
                            self.setNameValue('SESSION_ID',          data.result.substr(0, charPlusPos));
                            self.setNameValue('SESSION_PRIVATE_KEY', data.result + sha256('salt' + usarPass));
                            self.setNameValue('SESSION_USERNAME',    userName);
                            
                            callBack(true);
                            return true;
                        }
                    },
                    error: function (jqXHR, textStatus, errorThrown) {
                        callBack(false);
                        return false;
                        if (jqXHR.status == 404) {return false;}  // Not used so far
                    }
    
                });
            },
            error: function() {
                callBack(false);
                return false;
            }
        });
    }



    InitSession() {
        localStorage.removeItem(self.getPrefixed('SESSION_ID'));
        localStorage.removeItem(self.getPrefixed('SESSION_PRIVATE_KEY'));
        localStorage.removeItem(self.getPrefixed('SESSION_LAST_TICK_COUNT'));
        localStorage.removeItem(self.getPrefixed('SESSION_TICK_COUNT_OFFSET'));
        localStorage.removeItem(self.getPrefixed('SESSION_USERNAME'));
        return true;
    }
    
    CloseSession() {
        self = this;

        if (!this.getValue_FromNameAsInt('SESSION_ID')) return;
    
        $.ajax({
            type:     "GET",
            dataType: "json",
            url:      G_MAIN_URL + '/auth',
            data:     {'session': this.getValue_FromNameAsInt('SESSION_ID'), 'UserName': this.getValue_FromName('SESSION_USERNAME')},
            timeout:  2000,
            success:  self.InitSession,
            error:    self.InitSession
        });
    }
    


    // converted from TSQLRestClientURI.SessionSign function
    // expected format is 'session_signature='Hexa8(SessionID)+Hexa8(TimeStamp)+
    // Hexa8(crc32('SessionID+HexaSessionPrivateKey'+Sha256('salt'+PassWord)+
    // Hexa8(TimeStamp)+url))
    GetSessionSignature(url) {
        let currDate;
        let currMsecs;
        let prefix;
        let nonce;
        let ss_id_hex;
        let ss_keyNonceUrl_crc32;
        let ss_keyNonceUrl_hex;
        let final_SIGN;

        currDate  = new Date();
        currMsecs = currDate.getTime();
        prefix    = '?';

        if (currMsecs < this.getValue_FromNameAsInt('SESSION_LAST_TICK_COUNT')) // wrap around 0 after 49.7 days
            this.setNameValue('SESSION_TICK_COUNT_OFFSET', this.getValue_FromNameAsInt('SESSION_TICK_COUNT_OFFSET') + 1 << (32 - 8)); // allows 35 years timing
        
        this.setNameValue('SESSION_LAST_TICK_COUNT', currMsecs);
    
        nonce = currMsecs >>> 8 + this.getValue_FromNameAsInt('SESSION_TICK_COUNT_OFFSET');
        nonce = this.numToHex(nonce);

        ss_id_hex            = this.numToHex(this.getValue_FromNameAsInt('SESSION_ID'));
        ss_keyNonceUrl_crc32 = this.getValue_FromName('SESSION_PRIVATE_KEY') + nonce + url;
        ss_keyNonceUrl_crc32 = this.crc32(   ss_keyNonceUrl_crc32);
        ss_keyNonceUrl_hex   = this.numToHex(ss_keyNonceUrl_crc32);

        // Final signature
        final_SIGN  = ss_id_hex + nonce + ss_keyNonceUrl_hex;  

        // Change prefix if necessary (if the URL already has variables add "&" to set another, keep "?" is this is the only one)
        if (url.indexOf('?') >= 0) 
           prefix = '&';
        
        return  prefix + 'session_signature=' + final_SIGN;
    }
    

    // Set ajaxPrefilter function - will run on every jQuery ajax call to add the SessionSignature   */
    setAjaxPrefilter() {
        self = this;

        $.ajaxPrefilter(function(options, _, jqXHR) {    
            let new_url;
            let session_sign;
        
            if (self.getValue_FromNameAsInt('SESSION_ID') > 0 && options.url.indexOf(G_MAIN_URL) > -1) { // User is authenticated
                new_url = options.url;
                if (options.data && options.type == "GET")
                {
                    new_url      = new_url + '?' + options.data;
                    options.data = null;  // prevents jQuery from adding these to the URL
                }
                session_sign  = self.GetSessionSignature(new_url.substr(G_SERVER_URL.length + 1));
                options.url   = new_url + session_sign;
                options.cache = true; // we don't want anti-cache "_" JQuery-parameter
            }
        });
    }

    

    // Convert number to Hex with 8 caracters
    numToHex(d) {
        let hex = Number(d).toString(16);    // Converts to Hex (base 16)
        
        while (hex.length < 8) {
            hex = "0" + hex;
        }
        return hex;
    }



    /****************************/
    /*     Local Storage        */
    /****************************/
    getPrefixed(name)            { return 'syn_' + name; }
    getValue_FromName(name)      { return localStorage.getItem(this.getPrefixed(name)); }
    setNameValue(name, value)    { return localStorage.setItem(this.getPrefixed(name), value); }
    getValue_FromNameAsInt(name) { return Number(this.getValue_FromName(name)) ? this.getValue_FromName(name) : 0; } // Operator "?" = if then    ":"" = else 



    /*****************************************************************/
    /*                        crc32 functions                        */
    /* https://stackoverflow.com/questions/18638900/javascript-crc32 */
    /*****************************************************************/
    makeCRCTable() {
        let c;
        let crcTable = [];
        for(let n =0; n < 256; n++){
            c = n;
            for(let k =0; k < 8; k++){
                c = ((c&1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
            }
            crcTable[n] = c;
        }
        return crcTable;
    }
    
    crc32(str) {
        let crcTable = window.crcTable || (window.crcTable = this.makeCRCTable());
        let crc = 0 ^ (-1);
    
        for (let i = 0; i < str.length; i++ ) {
            crc = (crc >>> 8) ^ crcTable[(crc ^ str.charCodeAt(i)) & 0xFF];
        }
    
        return (crc ^ (-1)) >>> 0;
    };    
  }


/*********************************************/
/*    Check for localstorage functionality   */
/*********************************************/
$(function() {
    if (typeof(localStorage) == 'undefined')
        alert('You do not have HTML5 localStorage support in your browser. Please update or application cannot work as expected');
});