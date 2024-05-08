# lmtyas - Let me tell you a secret

A web service written in Rust that allows an authenticated user to send secrets like passwords to other authenticated users in a secure way.

In a perfect world we wouldn't need passwords anymore but more often than not we also still do need to tell them to other people. There is a world almost without passwords out there, e.g. have a look at [SQRL](https://www.grc.com/sqrl/sqrl.htm) or [fido2](https://en.wikipedia.org/wiki/FIDO2_Project). Passkeys may be [not](https://fy.blackhats.net.au/blog/2024-04-26-passkeys-a-shattered-dream/) the solution.

Sending passwords by email is insecure because most people are not able to receive encrypted emails. Sending passwords by snail mail is slow. Using a second channel, e.g. like a chat program, may work but often leaves traces of the secret or involves third parties you do not trust. Telling a password via phone is next to impossible.

*"Let me tell you a secret" enters the stage*

Simply enter a

- secret (like a password)
- context (a hint what the secret is for) and
- an email address of the receiver

on the website driven by this web service and the receiver will get an email with a link that entitles to read the secret. The secret Id and thus the receiver is encoded in the link and since authentication is needed to open the secret, we make sure that only the right person reads the secret.

![tell a secret](resources/gfx/lmtyas-screenshot-001.png)

Yes, identities can be stolen and/or hacked - but then you have got bigger problems at hand. Again, have a good look at [SQRL](https://www.grc.com/sqrl/sqrl.htm) or [fido2](https://en.wikipedia.org/wiki/FIDO2_Project).

- **NOTE 1**: Secrets like passwords should be forced or at least encouraged to be changed after first use!
- **NOTE 2**: The email with the link also leaves traces, so other parties may become aware that a secret has been sent and what it is meant for. But in a company context this should be fine. The sole purpose of this tool is to protect the secret itself!


# Configuration file

See [lmtyas-config.json](resources/config/lmtyas-config.json) for an example configuration binding to `127.0.0.1:8844`.

| config item                      | config data                                                                                               |
|----------------------------------|-----------------------------------------------------------------------------------------------------------|
| {                                | ==> begin of root object                                                                                  |
| "web_bind_address"               | ip address and port to bind to, e.g. `"127.0.0.1:8844"`                                                   |
| "ssl_private_key_file"           | path/filename of the SSL private key, e.g. `"resources/tests/ssl/lmtyas/lmtyas-selfsigned.key"`           |
| "ssl_certificate_chain_file"     | path/filename of the SSL certificate chain, e.g. `"resources/tests/ssl/lmtyas-selfsigned-cert.pem"`       |
| "rsa_private_key_file"           | path/filename of the RSA private key file, e.g. `"resources/tests/rsa/lmtyas_rsa_private.key"`            |
| "rsa_public_key_file"            | path/filename of the RSA public key file, e.g. `"resources/tests/rsa/lmtyas_rsa_public.key"`              |
| "secret_directory"               | path to store the secret files, e.g. `"output/secrets"`                                                   |
| "email_configuration" : {        | ==> object with email configuration details                                                               |
|     "mail_server_address"        | name or ip address of mail server, e.g.`"127.0.0.1"`                                                      |
|     "mail_server_port"           | port number of mail server, e.g. `2525`                                                                   |
|     "mail_from"                  | mail address that sends secrets, e.g. `"IT-department <do-not-reply@lmtyas.acme.home.arpa>"`              |
|     "mail_subject"               | subject used in mails, e.g. `"Your new password for {Context}"`                                           |
|     "mail_template_file"         | path/filename of mail template, e.g. `"resources/tests/config/mailtemplate.txt"`                          |
| },                               | <== end of object with email configuration details                                                        |
| "admin_accounts"                 | array with valid admin accounts to set password, e.g. `["walter"]`                                        |
| "max_authrequest_age_seconds"    | time in seconds an authentiction attempt is valid, e.g. `300`                                             |
| "max_cookie_age_seconds"         | time in seconds an account is still logged in, e.g. `90` (forms keep accounts alive every 60 seconds)     |
| "fqdn"                           | fqdn to use in redirects, e,g, `"my-server.local:8844"`                                                   |
| "ldap_common_configuration": {   | ==> object with common ldap configuration                                                                 |
|     "url"                        | url to connect to ldap server, e.g. `"ldap://127.0.0.1:3893"`                                             |
|     "base_ou"                    | ou where user accounts are stored, e.g. `"ou=superheros,dc=acme,dc=local"`                                |
|     "bind_passwd"                | password to bind to the ldap server, e.g. `"ldapsecr3t"`                                                  |
|     "bind_dn"                    | dn of user that is allowed to query the ldap, e.g. `"cn=ldap-tec-user,ou=svcaccts,dc=acme,dc=local"`      |
|     "user_filter"                | filter to used to query accounts, `{0}` is replaced with login name, e.g. `"(uid={0})"`                   |
|     "mail_filter"                | filter to used to query accounts, `{0}` is replaced with mail address, e.g. `"(mail={0})"`                |
|     "authentication:": {         | object with optional ldap authentication configuration                                                    |
|     "ldap_bind_user_dn"          | dn of users logging in, `{0}` is replaced with login name, e.g. `"cn={0},ou=superheros,dc=acme,dc=local"` |
|     "valid_user_regex"           | regex of valid user names, e.g. `"^[\\w\\d\\-]{3,8}"`                                                     |
|     },                           | <== end of object with ldap authentication configuration                                                  |
| },                               | <== end of object with common ldap configuration                                                          |
| "oidc_configuration": {          | ==> object with optional oidc configuration                                                               |
|     "provider_metadata_url":     | base url which serves `.well-known/openid-configuration`, e.g. `"https://acme.eu.auth0.com/"`             | 
|     "client_id":                 | oidc client Id of this application, e.g. `"Y2xpZW50X2lk"`                                                 |
|     "client_secret":             | oidc client secret of this application, e.g. `"Y2xpZW50X3NlY3JldA=="`                                     |
|     "valid_user_regex":          | regex of valid user names (email), e.g. `"^[\\w\\d\\-]{3,8}@acme\\.local$"`                               |
| },                               | <== end object with optional oidc configuration                                                           |
| "access_token_configuration": {  | ==> object with access token configuration                                                                |
|     "api_access_files":          | directory with access token files, e.g. `"resources/tests/access_token_files"`                            |
| },                               | <== end object with access token configuration                                                            |
| "login_hint"                     | hint for users which account to use for login, e.g. `"A.C.M.E. LDAP account"`                             |
| "mail_hint"                      | optional hint what mail address format should be used, e.g. `givenname.surname@acme.local`                |
| "imprint": {                     | ==> object with imprint link data                                                                         |
| "href"                           | link to an imprint page, e.g. `"https://www.acme.local/imprint"`                                          |
| "target"                         | target window for imprint, one out of `"_self"`, `"_blank"`, `"_parent"`, `"_top"`                        |
| },                               | <== end of with imprint link data                                                                         |
| "privacy": {                     | ==> object with privacy statement link data                                                               |
| "href"                           | link to a privacy page, e.g. `"https://www.acme.local/privacy"`                                           |
| "target"                         | target window for privacy statement, one out of `"_self"`, `"_blank"`, `"_parent"`, `"_top"`              |
| }                                | <== end of with privacy link data                                                                         |
| }                                | <== end of root object                                                                                    |

- **NOTE  1**
    - "mail_subject": `{Context}` is replaced with the context entered in the web form.
    - "mail_template_file":
        - `{ToDisplayName}` is replaced with the display name of the receiver,
        - `{FromDisplayName}` is replaced with the display name of the sender,
        - `{Context}` is replaced with the context entered in the web form.
        - `{UrlPayload}` is replaced with the encrypted secret Id to access the secret.
     
        URL must be in the template, see [mailtemplate.txt](./resources/config/mailtemplate.txt).

        Depending on your authentication backends you may not know the data for each of the placeholders!
- **NOTE 2** The objects `email_configuration`, `ldap_configuration`, `access_token_configuration` and `oidc_configuration` may be absent or differ, depending on the selected features. See section *[Compile and install -features](#compile-and-install---features)*.
- **NOTE 3** The directive `mail_hint` may be absent. If so the default `firstname.lastname@acme.local` will be used.

You need a SSL certificate and its unencrypted key in pem format. Create your own *[set of rsa keys](#security---data-encryption---rsa-keys)*.


# External dependencies

## External dependencies - libaries

An installed `openssl` library is needed on the server side, the header files are needed on your development machine.


## External dependencies - services

The following services need to be available for `lmtyas` to work properly:

- ldap server
- mail server
- oidc server (default, but optional)


# Compile and install

Compiling probably works on any system that has a Rust compiler and recent OpenSSL packages including header files available.

Here is an example that works for Ubutu 20.04 LTS , Ubuntu 22.04 LTS and CentOS7. Probably any recent Linux distro with Systemd will work. Every distro without Systemd or Unix system will probably also work with some modifications for the startup process (you might want to look into [deamonize](https://software.clapper.org/daemonize/)).

Head over to [www.rust-lang.org](https://www.rust-lang.org/tools/install) and follow the instructions if you don't have a Rust compiler installed yet.

```bash
# done as regular user
sudo apt update
sudo apt upgrade
# install the only dependency:
sudo apt install openssl
sudo apt install libssl-dev # only needed on dev machine
# clone and compile the code
git clone git@github.com:hardcodes/lmtyas.git
cd lmtyas
cargo build --release
# create user for running the service
sudo groupadd lmtyas
sudo adduser --disabled-login --home /opt/lmtyas --no-create-home --system  --shell /usr/sbin/nologin --ingroup lmtyas lmtyas
# create directory structure
sudo mkdir /etc/lmtays/
sudo mkdir -p /opt/lmtyas/access_token_files
sudo mkdir -p /opt/lmtyas/output/secrets
sudo mkdir -p /opt/lmtyas/web-content
sudo mkdir -p /opt/lmtyas/local/css
sudo mkdir -p /opt/lmtyas/local/gfx
sudo mkdir -p /opt/lmtyas/local/js
# copy binary
sudo cp target/release/lmtyas /opt/lmtyas/
# copy files
sudo cp --recursive web-content/* /opt/lmtyas/web-content/

# create systemd unit file
sudo cat << __EOF__ > /etc/systemd/system/lmtyas.service
[Unit]
Description=[lmtyas.service] let me tell you a secret service
After=network.target
Wants=basic.target

[Install]
WantedBy=multi-user.target

[Service]
EnvironmentFile=-/etc/lmtyas/lmtyas-systemd.conf
Type=simple
Restart=always
User=lmtyas
Group=lmtyas
WorkingDirectory=/opt/lmtyas
ExecStart=/opt/lmtyas/lmtyas --config-file \${lmtyasCFGFILE}
# the settings from here on may not work with older versions of systemd!
NoNewPrivileges=true
PrivateTmp=yes
RestrictNamespaces=uts ipc pid user cgroup
RestrictAddressFamilies=AF_INET
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectKernelLogs=yes
ProtectHome=yes
ProtectHostname=yes
ProtectSystem=strict
ProtectClock=yes
ProtectKernelLogs=yes
ProtectProc=invisible
PrivateUsers=yes
InaccessibleDirectories=/home /root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ReadWritePaths=/opt/lmtyas/output
MemoryDenyWriteExecute=yes
DevicePolicy=closed
LockPersonality=yes
__EOF__

# create systemd environment file
sudo cat << __EOF__ > /etc/lmtyas/lmtyas-systemd.conf
lmtyasCFGFILE="/etc/lmtyas/lmtyas-config.json"
__EOF__

# fix owner and acl
sudo chown -R lmtyas:lmtyas /opt/lmtyas/
sudo find /opt/lmtyas/ -type f -exec chmod 640 {} \;
sudo find /opt/lmtyas/web-content -type f -exec chmod 440 {} \;
sudo find /opt/lmtyas/ -type d -exec chmod 550 {} \;
chmod 750 output/secrets
sudo chmod 550 /opt/lmtyas/lmtyas
sudo chown -R root:lmtyas /etc/lmtyas/
sudo chmod -R 640 /etc/lmtyas/

# enable service
sudo systemctl daemon-reload
sudo systemctl enable lmtyas.service
sudo systemctl unmask lmtyas.service
```

Create a [`/etc/lmtyas/lmtyas-config.json`](#configuration-file), the *[rsa keys](#security---data-encryption---rsa-keys)* and get a ssl certficate in PEM format --- this may be self signed, depending on your own personal needs; in a company context you probably want a signed certifcate from some sort of CA/PKI. Then

```bash
sudo find /etc/lmtyas/ -type f -exec chmod 640 {} \;
chown root:lmtyas /etc/lmtyas/lmtyas-config.json
sudo systemctl start lmtyas.service
```


## Compile and install - features

Also see [Cargo.toml](./Cargo.toml), section `[features]`.

- Default: **oidc-auth-ldap**, **mail-noauth-notls**, **api-access-token** (users are authenticated with an external oidc server: Authorization Code Flow with Proof Key for Code Exchange (PKCE). The only scope used is `email`, user details are queried from an external ldap server and emails are sent through a smtp server with no authentication and no encryption. Sending secrets via access token is enabled.)

  You may ask why we need oidc when we have a ldap server, we use to query user details: when an oidc server is available, your users know the look and feel of the login page. This way they may be more confidend to enter their credentials. Maybe you even use 2FA for your oidc solution, so why not benefit?

  If you implement the `OidcUserDetails` for your oidc server, you don't need a ldap server. Pull requests are welcome.

  **HINT** When you use [auth0](https://auth0.com/) as oidc provider, the dependency section of the `openidconnect` crate must be changed from

  ```
  openidconnect = { version = "3.0.0", optional = true}
  ```

  to

  ```
  openidconnect = { version = "3.0.0", features = ["accept-rfc3339-timestamps"], optional = true}
  ```

  See https://github.com/ramosbugs/openidconnect-rs/issues/23.
- **ldap-auth**: authenticate users with an external ldap server. Makes use of of the **ldap-common** and **get-userdata-ldap** feature.
- **ldap-common**: holds the ldap configuration file and brings basic ldap functions to query users by name or email address.
- **oidc-auth-ldap**: authenticate users with an external oidc server. Makes use of of the **authentication-oidc**, **oidc-ldap**, **ldap-common** and **get-userdata-ldap** feature. **NOTE**: right now the provider metadata server is only queried when the service is started. If the provider changes the configuration, the web service must be restarted!
- **authentication-oidc**: holds the oidc implementation.
- **oidc-ldap**: query user details from an external ldap server.
- **mail-noauth-notls**: send mails to user via mail server that does not need authentication and uses no encrypted transport.
- **get-userdata-ldap**: query userdata (frist and last name by email address of secret receiver) from a ldap server.
- **no-userdata-backend**: use this, when there is no backend (like e.g., a ldap server) to query userdata.
- **api-access-token**: useful for scripted sending of secrets authenicated with an access token, see section [Security - API Token](#security---api-token).

So far these combinations make sense:

- `default = ["oidc-auth-ldap", "mail-noauth-notls", "api-access-token"]`
  
  ```bash
  # compile with
  cargo build --release
  ```
- `"oidc-auth-ldap", "mail-noauth-notls"`
  
  ```bash
  # compile with
  cargo build --release --no-default-features --features oidc-auth-ldap,mail-noauth-notls
  ```
- `"ldap-auth", "mail-noauth-notls", "api-access-token"`
  
  ```bash
  # compile with
  cargo build --release --no-default-features --features ldap-auth,mail-noauth-notls,api-access-token
- `"ldap-auth", "mail-noauth-notls"`
  
  ```bash
  # compile with
  cargo build --release --no-default-features --features ldap-auth,mail-noauth-notls
  ```


# Customization


## Customization - company logo

To customize the company logo displayed for the site create a folder `local/gfx` and put a png file `company-logo.png` into it.


## Customization - favicon

To customize the favicon displayed for the site create a folder `local/gfx` and put a png file `favicon.png` into it.


## Customization - colors

To customize the colors applied to the css create a folder `local/css` and put a tweaked copy of the file [web-content/static/css/colors.css](./web-content/static/css/colors.css) into it.


## Customization - css

To customize the custom style sheet (css) create a folder `local/css` and put a tweaked copy of the file [web-content/static/css/lmtyas.css](./web-content/static/css/lmtyas.css) into it.


# Set RSA password

If the service is (re-)started, a valid administrator (see `admin_accounts` in section *[Configuration file](#configuration-file)*) must set the password of the RSA private key first. The rsa private key is loaded afterwards. Therefore open the URL

`https://<dns name or ip address>:<port number>/authenticated/sysop/sysop.html`

**Example**

`https://127.0.0.1:8844/authenticated/sysop/sysop.html` when running on localhost or

`https://let-me-tell-you-a-secret.home.arpa:8844/authenticated/sysop/sysop.html` if your local DNS server resolves that to the appropiate ip address.

- **NOTE1**: the password for the RSA private key must be at least 14 characters long, it will be checked in the web form! 14 is the absolute minimum, better use 32 or 64 characters for the password.
- **NOTE2**: the RSA key must have a minimum 2048 bit size to make sure that the data fits into it and can be encrypted.


# Security

## Security - Data Encryption

The web service uses a combination of RSA public key encryption and AES symmetric encryption to secure
the data. Only encryted data is stored on the disk.

For security reasons the password for the RSA private key is not stored in the configuration file. It must be entered by the administrator every time the web service gets started. The password only lives in the service for the short time it is needed to load the private RSA key.


## Security - Data Encryption - Workflow 

After a new secret has been entered,

- the receiver, context and the secret is encrypted with the public key of the web service.
- A new AES key/IV pair is randomly chosen.
    - The secret will additionaly be encrypted with the randomly chosen key/IV.
    - The random key/IV will be encrypted with the RSA public key of the web service.
- A link for the email will be constructed of
    - the Id (= file name) of the secret
    - the key/IV that were used to encrypt the secret before storing it to disk
- The link will be enrypted with the RSA public key of the web service.
- data is stored on disk (encrypted by a randomly chosen generated AES key and IV using AES in CBC mode which itself are encrypted using the web service RSA public key):
    - AES key and IV
    - receiver
    - context
    - secret (AES encrypted by random key/IV)
- The receiver will get an email with the encrypted link.


When opening the link,

- the link is decrypted using the RSA private key of the web service.
- The stored data is read from the file whose Id was in the decrypted link data.
- The AES key and IV inside the file is decrypted using the RSA private key of the web service.
  - The data fields except the secret are decrypted using the AES key and IV.
- The authenticated user is compared with the user stored in the file as receiver
    - if the user does not match,
        - an error will be shown and
        - runtime data discarded.
        - The file will stay untouched, the process ends.
    - if the user matches the process continues:
      - The key/IV inside the decrypted link data is used to rebuild the secret.
      - The file is deleted
      - The secret is shown to the authenticated user, the process ends.

Since the data stored on disk is encrypted using the RSA public key of the web service, a hacker could not read the secrets even if he had access to the files.

The administrator of the web service could decrypt the file but not the secret itself because it's encrypted by a randomly chosen key/IV. The only way an administrator could read the secret would be if they had access to the email with the link. We must assume that the administrator is a trustworthy person and the system running this service is designed in a way that supports the administrator in claiming that he has no access to the secrets (e.g. the administrator does not get blind copies of the emails). If the receiver of the secret waives the mail with the link in front of the administrator you have bigger problems at hand. If in doubt you can split the administrator role in two:

1. The first administrator has knowledge about the password for the RSA private key of the webservice and access to the form that allows setting the password.
2. The second administrator has access to the system itself. Even with some bogus mindset he had no access to the encrypted data.

Most of the time the people creating and sending the secrets are the same people operating the web service, hence they know the secrets anyway.


## Security - Data Encryption - RSA Keys

- **NOTE1**: the password for the RSA private key must be at least 14 characters long, it will be checked in the web form! 14 is the absolute minimum, better use 32 or 64 characters for the password.
- **Note2**: you must use at least 2048 bits for the rsa key (modulus >= 256) to make sure we can encrypt/decrypt all the data with the rsa key pair.

The keys can be created with the `openssl` command:

- **RSA private key**

    ```bash
    [ -d "resources/tests/rsa" ] || mkdir -p "resources/tests/rsa"; cd "resources/tests/rsa"
    openssl genrsa -out lmtyas_rsa_private.key -aes256 4096
    # (...)
    Enter pass phrase for lmtyas_encrypt_key:
    Verifying - Enter pass phrase for lmtyas_encrypt_key:
    ```
- **RSA public key**

    ```bash
    openssl rsa -in lmtyas_rsa_private.key -pubout > lmtyas_rsa_public.key
    Enter pass phrase for lmtyas_rsa_private.key:
    writing RSA key
    ```

**NOTE3** You need to store the password for the RSA private key in a save place, e.g. some sort of password manager. Every time the service is (re-)started, the password must be entered, before the system works.

**NOTE4** The password for the private RSA test key is the very **unsecure** value of `12345678901234`.


## Security - Web Service - SSL/TLS

For development a self signed certificate was used, in production you can use a certificate from any CA that you trust (or your browser, to be more specific).

```bash
[ -d "resources/tests/ssl" ] || mkdir -p "resources/tests/ssl"; cd "resources/tests/ssl"
openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:4096 -keyout lmtyas-selfsigned.key -out lmtyas-selfsigned-cert.pem
Generating a RSA private key
(...)
Country Name (2 letter code) [AU]:DE   
State or Province Name (full name) [Some-State]:NRW 
Locality Name (eg, city) []:DORTMUND
Organization Name (eg, company) [Internet Widgits Pty Ltd]:ACME
Organizational Unit Name (eg, section) []:HQ
Common Name (e.g. server FQDN or YOUR name) []:lmtyas.home.arpa
Email Address []:rainer.zufall@lmtyas.home.arpa
```


## Security - API Token

**Server side**

Execute the following in a Unix shell:

```bash
# List of IP addresses from which passwords are to be sent via script.
# This should be done as sparingly as possible.
IPADDRESSES='"192.168.42.78","192.168.42.79"'
# Expiration date of the access token
ENDDATE=$(date -d "Dec 31 2099" +%s)
# This e-mail address is entered by the server as the sender of the password
EMAIL="IT scripting team <do-not-reply@lmtyas.acme.home.arpa>"
# This is the name of the sender in the email, the {FromDisplayName} field from
# from the template is replaced here. It should make sense in context of the
# salutation used in the template.
DISPLAYNAME="our scriptig team"

# Do not change anything here!
NOW=$(date +%s)
UUID=$(uuidgen)
```

In a subsequent step, create the file for the server:

```bash
cat << __EOF__ > "${UUID}"
{
    "ip_adresses": [${IPADDRESSES}],
    "nbf": ${NOW},
    "exp": ${ENDDATE},
    "from_email": "${EMAIL}",
    "from_display_name": "${DISPLAYNAME}",
    "iss": "https://127.0.0.1:8844",
    "aud": "https://127.0.0.1:8844/api/v1/secret"
}
__EOF__
```

The file generated in this way must be copied to the server to the configured `api_access_files`. Change the owner of the file to to service user, e.g. `lmtyas` and the permissions to `440` (read only).

**NOTE**: `iss` and `aud` are optional and will only be validated if present in the access token file on the server side.


**Access token**

The same values must be used for `NOW` and `ENDDATE` as well as `UUID` that are used in the server file!

```bash
# The UUID is encrypted here with the server's RSA public key and encoded in Base64.
JTI=$(echo -n "${UUID}"|openssl pkeyutl -encrypt -inkey <public rsa key file> -pubin|base64 --wrap 0)
```

Now "generate" the access token:

```bash
cat << __EOF__
{
    "iss": "https://127.0.0.1:8844",
    "sub": "${UUID}",
    "aud": "https://127.0.0.1:8844/api/v1/secret",
    "nbf": ${NOW},
    "exp": ${ENDDATE},
    "jti": "${JTI}"
}
__EOF__
```

The values for `iss` and `aud` do technically not really matter, they are just meant for the user of the access token. so that they know, what the token is used for.

**NOTE**: `iss` and `aud` will be validated if present in the access token file on the server side!

You can use this web service to send them the token in a secure way ;-)

**Token usage**

Use a base64 encoded value for the `"Secret":"<value>"` part, like e.g.

```bash
echo -n "super secret!"|base64 --wrap 0
# result:
c3VwZXIgc2VjcmV0IQ==
```

Here is an example utilizing `curl` to send a secret to user *Alice* via the URL `https://<server name or ip address>:<port>/api/v1/secret`:

```bash
FILECONTENT=$(cat resources/tests/access_token_payload/test-token-payload.json)
TOKEN=$(echo -n "${FILECONTENT}"|base64 --wrap 0)
# Add --insecure if your web service uses a self signed certificate.
curl --include \
--header "Authorization: Bearer ${TOKEN}" \
--request POST \
--data "{\"FromEmail\":\"\",\
\"FromDisplayName\":\"\",\
\"ToEmail\":\"alice@acme.local\",\
\"ToDisplayName\":\"\",\
\"Context\":\"script test\",\
\"Secret\":\"c3VwZXIgc2VjcmV0IQ==\"}" \
https://127.0.0.1:8844/api/v1/secret
```


## Security - Email - Signature

If you want to sign the emails sent by this tool, think about using a mailserver on the same host that does the signing for you, e.g. like [Postfix](https://www.postfix.org/) with the [signing-milter](https://signing-milter.org/) (or this link [for the systemd-daemon](https://github.com/smeinecke/signing-milter)).

A good german documentation can be found at the [University of Münster](https://www.uni-muenster.de/imperia/md/content/iv-sicherheit/signing-milter.pdf).


# Monitoring

Set up your monitoring software to probe the path `monitoring/still_alive`. If the service is still running, "Yes sir, I can boogie!" will be returned. This path is accessible without authentication.

***Example***

```bash
curl --insecure https://127.0.0.1:8844/monitoring/still_alive
```


# Icon source

See [license.md](resources/gfx/license.md).


# Development

For developing and testing the following components need to run besides the lmtyas web service:

- ldap server

  We make use of [glauth](https://glauth.github.io/) and its [docker container](https://hub.docker.com/r/glauth/glauth/tags).
- mail server

  We use [mailhog](https://github.com/mailhog/MailHog) and its [docker container](https://hub.docker.com/r/mailhog/mailhog/). When it's running, you can open [http://127.0.0.1:8025](http://127.0.0.1:8025) and see the mails sent by lmtyas. Plus clicking on the links is also possible.
- oidc provider

  We use [magnolia mock server](https://docs.magnolia-cms.com/magnolia-sso/3.1.x/guides/using-a-mock-oidc-server/) and its [docker container](https://hub.docker.com/r/magnolia/mock-oidc-user-server).

  It accepts any user or password combination. Therefore it does not fill the email claim, we fake it in code! It should be clear: **do not ever use this in production!**


## Development - container helper

The containers are used with [podman](https://podman.io/), just add an alias for `docker` if you prefer that. The command arguments are mostly the same.

```bash
alias docker=podman
```

See also `CONTAINER_COMMAND` in [lib.rs](src/lib.rs) for testing.


**Starting the containers**


```bash
# ldap server
podman run \
  -d \
  --rm \
  --name lmtyas-glauth \
  -p 3893:3893 \
  -v ./resources/tests/ldap/ldap.conf:/app/config/config.cfg \
  docker.io/glauth/glauth:latest
# mail server
podman run \
  -d \
  --rm \
  --name lmtyas-mailhog \
  -p 2525:1025 \
  -p 8025:8025 \
  docker.io/mailhog/mailhog:latest
# oidc provider server
podman run \
  -d \
  --rm \
  --name lmtyas-oidc \
  --env PORT=9090 \
  --env CLIENT_ID=id \
  --env CLIENT_SECRET=secret \
  --env CLIENT_REDIRECT_URI=https://127.0.0.1:8844/authentication/callback \
  --env CLIENT_LOGOUT_REDIRECT_URI=http://localhost:8080/.magnolia/admincentral \
  -p 9090:9090 \
  docker.io/magnolia/mock-oidc-user-server:latest
```

**Stopping the containers**


```bash
podman stop lmtyas-glauth
podman stop lmtyas-mailhog
podman stop lmtyas-oidc
```

## Development - by hand


### Development - by hand - dummy mail server

Simply start one with this one line of python code:

```bash
python3 -m smtpd -n -c DebuggingServer 127.0.0.1:2525
```

It will accept any incoming requests and dump the data to stdout.


### Development - by hand - LDAP server

For developing of the default `ldap-auth` feature, I wanted a leightweight LDAP server without the hazzle of setting up an openldap server. I chose [glauth](https://github.com/glauth/glauth) written in Go.

Really easy to set up:

1. install a recent version (>= 1.16)of [Go](https://go.dev/doc/install)

    or for Ubuntu 20.04 LTS

    ```bash
    sudo apt install ldap-utils
    # meh, snap
    sudo snap install go --classic
    go version
    go version go1.18.5 linux/amd64
    ```
2. download the source and compile

    ```bash
    git clone https://github.com/glauth/glauth
    cd glauth/v2
    # can it build?
    go build
    # install
    [-d ${HOME}/bin ] || mkdir -p ${HOME}/bin
    go env -w GOBIN=${HOME}/bin
    go install
    glauth
        Usage:
            glauth [options] -c <file|s3 url>
            glauth -h --help
            glauth --version
    ```
3. configure

    See [ldap.conf](./resources/tests/ldap/ldap.conf)

    Password hashes were created this way:

    ```bash
    echo -n "passw0rd" | openssl dgst -sha256
    (stdin)= 8f0e2f76e22b43e2855189877e7dc1e1e7d98c226c95db247cd1d547928334a9
    echo -n "ldapsecr3t" | openssl dgst -sha256
    (stdin)= 8241458a26f1d73036ce59d448ed11d49d01cdc11fcef87c1050a165ca298c96
    ```
4. run

    ```bash
    glauth -c resources/tests/ldap/ldap.conf
    ```
5. test

    ```bash
    ldapsearch -LLL -H ldap://localhost:3893 \
    -D "cn=ldap-tec-user,ou=svcaccts,dc=acme,dc=local" \
    -w "ldapsecr3t" \
    -b "ou=superheros,dc=acme,dc=local" \
    "(uid=*)"
    dn: cn=alice,ou=superheros,dc=acme,dc=local
    cn: alice
    uid: alice
    givenName: Alice
    sn: Henderson
    ou: superheros
    uidNumber: 5001
    accountStatus: active
    mail: alice@acme.local
    userPrincipalName: alice@acme.local
    objectClass: posixAccount
    objectClass: shadowAccount
    loginShell: /bin/bash
    homeDirectory: /home/alice
    description: alice
    gecos: alice
    gidNumber: 5501
    memberOf: ou=superheros,ou=groups,dc=acme,dc=local
    shadowExpire: -1
    shadowFlag: 134538308
    shadowInactive: -1
    shadowLastChange: 11000
    shadowMax: 99999
    shadowMin: -1
    shadowWarning: 7

    dn: cn=bob,ou=superheros,dc=acme,dc=local
    cn: bob
    uid: bob
    givenName: Bob
    sn: Sanders
    ou: superheros
    uidNumber: 5002
    accountStatus: active
    mail: bob@acme.local
    userPrincipalName: bob@acme.local
    objectClass: posixAccount
    objectClass: shadowAccount
    loginShell: /bin/bash
    homeDirectory: /home/bob
    description: bob
    gecos: bob
    gidNumber: 5501
    memberOf: ou=superheros,ou=groups,dc=acme,dc=local
    shadowExpire: -1
    shadowFlag: 134538308
    shadowInactive: -1
    shadowLastChange: 11000
    shadowMax: 99999
    shadowMin: -1
    shadowWarning: 7

    dn: cn=walter,ou=superheros,dc=acme,dc=local
    cn: walter
    uid: walter
    givenName: Walter
    sn: Linz
    ou: superheros
    uidNumber: 5003
    accountStatus: active
    mail: walter@acme.local
    userPrincipalName: walter@acme.local
    objectClass: posixAccount
    objectClass: shadowAccount
    loginShell: /bin/bash
    homeDirectory: /home/walter
    description: walter
    gecos: walter
    gidNumber: 5501
    memberOf: ou=superheros,ou=groups,dc=acme,dc=local
    shadowExpire: -1
    shadowFlag: 134538308
    shadowInactive: -1
    shadowLastChange: 11000
    shadowMax: 99999
    shadowMin: -1
    shadowWarning: 7

    dn: cn=ldap-tec-user,ou=svcaccts,dc=acme,dc=local
    cn: ldap-tec-user
    uid: ldap-tec-user
    givenName: John
    sn: Doe
    ou: svcaccts
    uidNumber: 5501
    accountStatus: active
    objectClass: posixAccount
    objectClass: shadowAccount
    loginShell: /bin/bash
    homeDirectory: /home/ldap-tec-user
    description: ldap-tec-user
    gecos: ldap-tec-user
    gidNumber: 5502
    memberOf: ou=svcaccts,ou=groups,dc=acme,dc=local
    shadowExpire: -1
    shadowFlag: 134538308
    shadowInactive: -1
    shadowLastChange: 11000
    shadowMax: 99999
    shadowMin: -1
    shadowWarning: 7
    ```

    ```bash
    ldapsearch -LLL -H ldap://localhost:3893 \
    -D "cn=ldap-tec-user,ou=svcaccts,dc=acme,dc=local" \
    -w "ldapsecr3t" \
    -b "ou=superheros,dc=acme,dc=local" \
    "(uid=bob)"
    dn: cn=bob,ou=superheros,dc=acme,dc=local
    cn: bob
    uid: bob
    givenName: Bob
    sn: Sanders
    ou: superheros
    uidNumber: 5002
    accountStatus: active
    mail: bob@acme.local
    userPrincipalName: bob@acme.local
    objectClass: posixAccount
    objectClass: shadowAccount
    loginShell: /bin/bash
    homeDirectory: /home/bob
    description: bob
    gecos: bob
    gidNumber: 5501
    memberOf: ou=superheros,ou=groups,dc=acme,dc=local
    shadowExpire: -1
    shadowFlag: 134538308
    shadowInactive: -1
    shadowLastChange: 11000
    shadowMax: 99999
    shadowMin: -1
    shadowWarning: 7
    ```


# Testing the code

Tests are almost complete at the moment.

- Functions that need no running service are covered.
- Starting the service itself and testing it from outside is covered.
- Testing the login process from outside is still missing.


## Testing the code - prerequisites

- Before some of the tests are executed, a mail dummy mail server and a `glauth` ldap server are started, see section *[Development](#development)*.
- A Rsa public and private key with passphrase "12345678901234" are expected to exist in the folder `resources/tests/rsa`:
  - `resources/tests/rsa/lmtyas_rsa_private.key`
  - `resources/tests/rsa/lmtyas_rsa_public.key`

  See section *[Security - Data Encryption - RSA Keys](#security---data-encryption---rsa-keys)* how to create them.
- A folder `ignore/secrets` should exist.


## Testing the code - run tests

 To run the tests, enter

- **default features (oauth2 authentication)**

  ```bash
  cargo test
  ```
- **ldap authentication**

  ```bash
  cargo test --no-default-features --features ldap-auth,mail-noauth-notls,api-access-token
  ```

If test fails the external helper services may still be running.

**Using containers**

```bash
podman stop lmtyas-glauth
podman stop lmtyas-mailhog
podman stop lmtyas-oidc
podman rm lmtyas-glauth
podman rm lmtyas-mailhog
podman rm lmtyas-oidc
```

**testing by hand**

To find and kill them and assuming you have no other processes with these speficics, you can enter

```bash
# kill glauth ldap server
kill $(pidof glauth)
# kill dummy mail server
kill $(ps -aux|grep python3|grep smtpd|awk '{print $2;}')
```


------

# License

The code is dual licensed under the [MIT License](./LICENSE-MIT) **or** the [APACHE 2.0 License](http://www.apache.org/licenses/LICENSE-2.0), which ever suits you better.

# Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
