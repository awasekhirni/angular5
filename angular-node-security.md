
#AES- CRYPTO JS LIBRARY FOR ENCRYPTION AND DECRYPTION FOR SENDING DATA FROM SERVER TO THE CLIENT AND BACK
https://www.npmjs.com/package/crypto-js 
https://www.npmjs.com/package/node-aes-gcm
https://www.npmjs.com/package/cryptico-js
protection against dictionary attacks
https://www.npmjs.com/package/easy-encryption

mongoose cipher to encrypt the fileds that you select before saving them on the database
https://www.npmjs.com/package/mongoose-cipher

#AngularJS Cryptography Library 
https://github.com/gdi2290/angular-crypto

#A Native implementation of TLS in Javascript and tools to write crypto-based and network-heavy webapplications 
https://github.com/digitalbazaar/forge 
npm install node-forge
npm install --save 
npm run minify 

exampleApp.service("CipherService", function() {

    /*
     * Encrypt a message with a passphrase or password
     *
     * @param    string message
     * @param    string password
     * @return   object
     */
    this.encrypt = function(message, password) {
        var salt = forge.random.getBytesSync(128);
        var key = forge.pkcs5.pbkdf2(password, salt, 4, 16);
        var iv = forge.random.getBytesSync(16);
        var cipher = forge.cipher.createCipher('AES-CBC', key);
        cipher.start({iv: iv});
        cipher.update(forge.util.createBuffer(message));
        cipher.finish();
        var cipherText = forge.util.encode64(cipher.output.getBytes());
        return {cipher_text: cipherText, salt: forge.util.encode64(salt), iv: forge.util.encode64(iv)};
    }

    /*
     * Decrypt cipher text using a password or passphrase and a corresponding salt and iv
     *
     * @param    string (Base64) cipherText
     * @param    string password
     * @param    string (Base64) salt
     * @param    string (Base64) iv
     * @return   string
     */
    this.decrypt = function(cipherText, password, salt, iv) {
        var key = forge.pkcs5.pbkdf2(password, forge.util.decode64(salt), 4, 16);
        var decipher = forge.cipher.createDecipher('AES-CBC', key);
        decipher.start({iv: forge.util.decode64(iv)});
        decipher.update(forge.util.createBuffer(forge.util.decode64(cipherText)));
        decipher.finish();
        return decipher.output.toString();
    }

});


#Use wireshark for debugging your network https streams, getting it from server to client and back. 

#Webcryptography 
https://github.com/diafygi/webcrypto-examples 
https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
https://github.com/shershen08/ng2-web-cryptography

#Nodejs => Security => Authentication and Authorization 
Passport/OAuth => 480 strategies currently 
https://www.npmjs.com/package/passport
https://www.npmjs.com/package/passport-jwt
https://www.npmjs.com/package/passport-strategy
https://www.npmjs.com/package/passport-linkedin

#Nodejs => Session Management 
node-session, history 
https://www.npmjs.com/package/node-session
https://www.npmjs.com/package/history
https://www.npmjs.com/package/connect-history-api-fallback
https://www.npmjs.com/package/history-ts

#Cross Site Request Forgery 
csrf and csrf-token package in nodejs 
https://www.npmjs.com/package/csrf
https://www.npmjs.com/package/csrf-tokens
https://www.npmjs.com/package/csrf-token

#cors cross origin resource sharing webbrowser security cross domain requests
https://www.npmjs.com/package/cors
https://www.npmjs.com/package/http-proxy-middleware
https://www.npmjs.com/package/has-cors
https://www.npmjs.com/package/corser


#OWASP security
https://www.npmjs.com/package/juice-shop-ctf-cli
https://www.npmjs.com/package/owasp-password-strength-test
https://www.npmjs.com/package/owasp-threat-dragon-core
https://www.npmjs.com/package/csp-headers
https://www.npmjs.com/package/security
https://www.npmjs.com/package/dependjs
https://www.npmjs.com/package/secure-redirects


#File upload & download. [nodejs=>express-fileupload]
https://www.npmjs.com/package/fileupload
https://www.npmjs.com/package/express-fileupload
https://www.npmjs.com/package/fileuploader

Digital Signature. [Nodejs =>passport-docusign,sessionkeys]
https://www.npmjs.com/package/docusign-esign
https://www.npmjs.com/package/passport-digital-signature
https://www.npmjs.com/package/xml-crypto-forked
https://www.npmjs.com/package/xml-crypto
https://www.npmjs.com/package/passport-docusign
https://www.npmjs.com/package/session-keys
https://www.npmjs.com/package/docusign-esign
https://www.npmjs.com/package/passport-challenge

SSL.[Nodejs=>ssl,xmlhttprequest-ssl,express-sslify,loopback-ssl]
https://www.npmjs.com/package/ssl
https://www.npmjs.com/package/xmlhttprequest-ssl
https://www.npmjs.com/package/loopback-ssl
https://www.npmjs.com/package/socks5-https-client
https://www.npmjs.com/package/ssl-express-www
https://www.npmjs.com/package/@dadi/ssl
https://www.npmjs.com/package/ssl-config
https://www.npmjs.com/package/express-sslify
https://www.npmjs.com/package/ssl-date-checker
https://www.npmjs.com/package/ssl-config
https://www.npmjs.com/package/passport-client-cert
https://www.npmjs.com/package/certificate-monitor
https://www.npmjs.com/package/certifi
https://www.npmjs.com/package/cmr1-ssl-validator
https://www.npmjs.com/package/@kgryte/https-server
https://www.npmjs.com/package/ssl-certs
https://www.npmjs.com/package/selfsigned.js
https://www.npmjs.com/package/node-quickfix-ssl



Scalability/Fault tolerance.
View -  HTML/XML/XHTML.=> Rendering Templates (jade, ejs, swig) 


SFTP connection - upload & download files..[nodejs=>sftp,ssh2-sftp-client,node-ssh,sftp-promises,ssh2,sftp-resolver-fs,ssh2-streams]

Build & Release,Patching. [Grunt,Gulp,Webpack with git]

Auditing & logging. [Nodejs=> auditing and logging]
https://www.npmjs.com/package/auditing
https://www.npmjs.com/package/easy-audit
https://www.npmjs.com/package/express-requests-logger
https://www.npmjs.com/package/mongoose-diff-history
https://www.npmjs.com/package/sequelize-version
https://www.npmjs.com/package/sequelize-paper-trail
https://www.npmjs.com/package/gulp-audit
https://www.npmjs.com/package/loopback-audit-logger


Monitoring node application.[Nodejs=>nodemon, express-status-monitor,monitoring,pm2]
https://www.npmjs.com/package/monitoring
https://www.npmjs.com/package/nodemon
https://www.npmjs.com/package/newrelic
https://www.npmjs.com/package/express-status-monitor
https://www.npmjs.com/package/good
https://www.npmjs.com/package/pm2
https://www.npmjs.com/package/bugsnag-js
https://www.npmjs.com/package/web-monitoring
https://www.npmjs.com/package/event-loop-stats
https://www.npmjs.com/package/phantomas
https://www.npmjs.com/package/pg-monitor
https://www.npmjs.com/package/pmx
https://www.npmjs.com/package/easy-monitor
https://www.npmjs.com/package/monitr
https://www.npmjs.com/package/durations

Charts & Graphs. [Angular+Highcharts, Angular +D3JS]

Push Notifications.[Nodejs=> web-push]
Email/SMS & any third party service integration.

Cron jobs configuration/Scheduler [Nodejs=>cron,cron-parser,node-schedule,node-cron,pm2]
ORM. [Nodejs =>Sequelize,mysql, mongoose]
Documentation -  like Javadoc. [Nodejs=> documentation]
Automation testing.[nodejs=> pally, testcafe,axe=core]



