# ACME

Here is an example configuration to use the ACME protocol with the Let's Encrypt CA and certbot on Ubuntu. You probably don't want expose the server to the outside world, hence we use DNS proof in this example.

In the example

- the certficate files are daily checked for updates and renewed if they are due to expire. This step is run as user `certbot`.
- A script checks every sunday night, if there are were new certficate files downlaoded and if so, they are copied to `/etc/lmtyas/` and the owner is changed. This step is run as `root`.
- A query to the Unix domain socket of `lmtyas` created with `curl` every sunday night triggers a reload of `lmtyas`. The server will start with the certficate files present in `/etc/lmtyas/` but keep the running configuration, e.g. there is no need to reenter the password for the RSA private key. This step is initiated as `root`.


## ACME - certbot - install

The `.deb`-package is probably outdated, let's use [python/pip](https://certbot.eff.org/instructions?ws=other&os=pip&commit=%3E).

```bash
# root@your-server-name
apt install python3 python3-venv libaugeas0
# Create a Python virtual environment
#
# We temporarily change the umask to 022 or else the later
# created user `certbot` may not be able to call the needed
# scripts.
OLDUMASK=$(umask)
umask 022
python3 -m venv /opt/certbot/
/opt/certbot/bin/pip install --upgrade pip
# Install `certbot` via pip
/opt/certbot/bin/pip install certbot
ln -s /opt/certbot/bin/certbot /usr/bin/certbot
certbot --version
certbot 3.0.1
# Install the DNS plugin
/opt/certbot/bin/pip install certbot-dns-rfc2136
restore umask
umask ${OLDUMASK}
```

We create a group and user `certbot`, so that the `certbot` scripts do not need to run as `root`.

```bash
# root@your-server-name
groupadd certbot
sudo adduser --disabled-login \
      --home /opt/certbot/home \
      --no-create-home \
      --system \
      --shell /usr/sbin/nologin \
      --ingroup certbot \
      certbot
mkdir /opt/certbot/home
mkdir /opt/certbot/home/config
mkdir /opt/certbot/home/certs
mkdir /opt/certbot/home/log
mkdir /opt/certbot/home/work
chmod 700 /opt/certbot/home
chmod 770 /opt/certbot/home/config
chmod 770 /opt/certbot/home/certs
chmod 770 /opt/certbot/home/log
chmod 770 /opt/certbot/home/work
cat << __EOF__ > /opt/certbot/home/config/rfc2136.ini
# Target DNS server (IPv4 or IPv6 address, not a hostname)
dns_rfc2136_server = X.X.X.X # <========================== REPLACE HERE
# TSIG key name
dns_rfc2136_name = XXXXXXXXX # <========================== REPLACE HERE
# TSIG key secret
dns_rfc2136_secret = XXXXXXX # <========================== REPLACE HERE
# TSIG key algorithm
dns_rfc2136_algorithm = HMAC-SHA512
__EOF__
chmod 400 /opt/certbot/home/config/rfc2136.ini
chown -R certbot:certbot /opt/certbot/home
```


## ACME - certbot - update check

Create a script that does the daily update check:

```bash
cat << "__EOF__" > /opt/certbot/home/update-cert
#!/bin/bash
#
# Get/update let's encrypt certificate for
# our domain(s)

RFC2136_CONFIG_FILE="/opt/certbot/home/config/rfc2136.ini"
CONFIG_DIR="/opt/certbot/home/config"
WORK_DIR="/opt/certbot/home/work"
LOG_DIR="/opt/certbot/home/log"
CERT_DIR="/opt/certbot/home/certs"
EMAIL="XXXXX@XXXXX"           # <========================== REPLACE HERE

# Update all certficates that are due for renewal.
# Those certficates must have been registered with
# `certbot certonly` beforehand
/usr/bin/certbot renew \
  --quiet \
  --config-dir "${CONFIG_DIR}" \
  --cert-path "${CERT_DIR}" \
  --work-dir "${WORK_DIR}" \
  --logs-dir "${LOG_DIR}" \
    --agree-tos \
    -m "${EMAIL}" \
  --dns-rfc2136 \
  --dns-rfc2136-credentials "${RFC2136_CONFIG_FILE}" \
  --dns-rfc2136-propagation-seconds 10
__EOF__
chown root:certbot /opt/certbot/home/update-cert
chmod 750 /opt/certbot/home/update-cert
```


## ACME - certbot - fetch certificate 1st time

Now fetch the certficate manually for the first time (temporarily enable login for user `certbot`, so that you can do a `su certbot -` as user `root`).

Use multiple `-d` statements at the bottom of the certbot call like

```
-d YOUR.DOMA.IN \
-d 2ND.DOMA.IN \
-d 3RD.DOMA.IN
```

if you need a certficate that is valid for multiple domains.


```bash
# certbot@your-server-name
CONFIG_DIR="/opt/certbot/home/config"
WORK_DIR="/opt/certbot/home/work"
LOG_DIR="/opt/certbot/home/log"
CERT_DIR="/opt/certbot/home/certs"
EMAIL="XXXXX@XXXXX"           # <========================== REPLACE HERE
RFC2136_CONFIG_FILE="/opt/certbot/home/config/rfc2136.ini"

/usr/bin/certbot certonly \
  --config-dir "${CONFIG_DIR}" \
  --cert-path "${CERT_DIR}" \
  --work-dir "${WORK_DIR}" \
  --logs-dir "${LOG_DIR}" \
    --agree-tos \
    -m "${EMAIL}" \
  --dns-rfc2136 \
  --dns-rfc2136-credentials "${RFC2136_CONFIG_FILE}" \
  --dns-rfc2136-propagation-seconds 10 \
  --key-type ecdsa \
  -d YOUR.DOMA.IN              # <========================== REPLACE HERE
  
Saving debug log to /opt/certbot/home/log/letsencrypt.log

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Would you be willing, once your first certificate is successfully issued, to
share your email address with the Electronic Frontier Foundation, a founding
partner of the Let's Encrypt project and the non-profit organization that
develops Certbot? We'd like to send you email about our work encrypting the web,
EFF news, campaigns, and ways to support digital freedom.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(Y)es/(N)o: N 
Account registered.
Requesting a certificate for YOUR.DOMA.IN
Waiting 10 seconds for DNS changes to propagate

Successfully received certificate.
Certificate is saved at: /opt/certbot/home/config/live/YOUR.DOMA.IN/fullchain.pem
Key is saved at:         /opt/certbot/home/config/live/YOUR.DOMA.IN/privkey.pem
This certificate expires on xxxx-xx-xx.
These files will be updated when the certificate renews.

NEXT STEPS:
- The certificate will need to be renewed before it expires. Certbot can automatically renew the certificate in the background, but you may need to take steps to enable that functionality. See https://certbot.org/renewal-setup for instructions.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
If you like Certbot, please consider supporting our work by:
 * Donating to ISRG / Let's Encrypt:   https://letsencrypt.org/donate
 * Donating to EFF:                    https://eff.org/donate-le
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
```

Disable login for user `certbot` again.


## ACME - certbot - copy certificate files

Copy those new certificate files to our configuration folder.

```bash
# root@your-server-name

# REPLACE HERE -------------------------+
#                                       |
#                                       |
cp /opt/certbot/home/config/live/YOUR.DOMA.IN/fullchain.pem /etc/lmtyas/
cp /opt/certbot/home/config/live/YOUR.DOMA.IN/privkey.pem /etc/lmtyas
chown root:lmtyas /etc/lmtyas/fullchain.pem
chown root:lmtyas /etc/lmtyas/privkey.pem
chmod 640 /etc/lmtyas/fullchain.pem
chmod 640 /etc/lmtyas/privkey.pem
```

Now change the name of the certificate and private key file in your `/etc/lmtyas/lmtyas-config.json` configuration file.

```
{
(...)
    "ssl_private_key_file": "/etc/lmtyas/fullchain.pem",
    "ssl_certificate_chain_file": "/etc/lmtyas/privkey.pem",
(...)
}
```

Create a script that copies the renewed certificate files to `/etc/lmtyas/` if needed (will run as `root`).

```bash
# root@your-server-name
cat << "__EOF__" > /opt/certbot/home/copy-cert
# REPLACE HERE ------------------------------------+
#                                                  |
#                                                  |
SRC_FULLCHAIN="/opt/certbot/home/config/live/YOUR.DOMA.IN/fullchain.pem"
SRC_PRIVKEY="/opt/certbot/home/config/live/YOUR.DOMA.IN/privkey.pem"
DST_FULLCHAIN="/etc/lmtyas/fullchain.pem"
DST_PRIVKEY="/etc/lmtyas/privkey.pem"

date +'%Y%m%d - %H:%M START'
if ! [ -f "${SRC_FULLCHAIN}" ];then
    echo "${SRC_FULLCHAIN} does not exist!"
    exit 1
fi
if ! [ -f "${SRC_PRIVKEY}" ];then
    echo "${SRC_PRIVKEY} does not exist!"
    exit 1
fi
if ! [ -f "${DST_FULLCHAIN}" ];then
    echo "${DST_FULLCHAIN} does not exist!"
    exit 1
fi
if ! [ -f "${DST_PRIVKEY}" ];then
    echo "${DST_PRIVKEY} does not exist!"
    exit 1
fi

SRC_FULLCHAIN_SHA256SUM=$(/usr/bin/sha256sum "${SRC_FULLCHAIN}" |cut -d " " -f 1)
SRC_PRIVKEY_SHA256SUM=$(/usr/bin/sha256sum "${SRC_PRIVKEY}" |cut -d " " -f 1)
DST_FULLCHAIN_SHA256SUM=$(/usr/bin/sha256sum "${DST_FULLCHAIN}" |cut -d " " -f 1)
DST_PRIVKEY_SHA256SUM=$(/usr/bin/sha256sum "${DST_PRIVKEY}" |cut -d " " -f 1)

if [ "${SRC_FULLCHAIN_SHA256SUM}" = "${DST_FULLCHAIN_SHA256SUM}" ];then
    echo "${SRC_FULLCHAIN} has not been changed"
else
    echo "${SRC_FULLCHAIN} has changed"
    cp "${SRC_FULLCHAIN}" "${DST_FULLCHAIN}"
    chown root:lmtyas "${DST_FULLCHAIN}"
    chmod 640 "${DST_FULLCHAIN}"
    ls -lah "${DST_FULLCHAIN}"
fi
    
if [ "${SRC_PRIVKEY_SHA256SUM}" = "${DST_PRIVKEY_SHA256SUM}" ];then
    echo "${SRC_PRIVKEY} has not been changed"
else
    echo "${SRC_PRIVKEY} has changed"
    cp "${SRC_PRIVKEY}" "${DST_PRIVKEY}"
    chown root:lmtyas "${DST_PRIVKEY}"
    chmod 640 "${DST_PRIVKEY}"
    ls -lah "${DST_PRIVKEY}"
fi
date +'%Y%m%d - %H:%M END'
__EOF__
chmod 700 /opt/certbot/home/copy-cert
```


## ACME - certbot - cron jobs

**daily update check**

```bash
# root@your-server-name
cat << __EOF__ > /etc/cron.d/certbot
0 0 * * * certbot /opt/certbot/bin/python -c 'import random; import time; time.sleep(random.random() * 3600)' && /opt/certbot/home/update-cert
__EOF__
```


**weekly copy job**

```bash
cat << __EOF__ > /etc/cron.d/copy-cert
15 3 * * * root /opt/certbot/home/copy-cert >> /var/log/copy-cert.log 2>&1
__EOF__
cat << __EOF__ > /etc/logrotate.d/copy-cert
/var/log/copy-cert.log {
     monthly
     compress
     missingok
     nocopytruncate
     nodelaycompress
     nomail
     notifempty
     noolddir
     rotate 12
}
__EOF__
```


**weekly service reload**

```bash
# root@your-server-name
cat << __EOF__ > /etc/cron.d/lmtyas-cert-reload
15 4 * * 0 root /usr/bin/curl --no-progress-meter --fail-with-body --unix-socket /opt/lmtyas/socket/lmtyas-uds.socket http://localhost/reload-cert >> /var/log/lmtyas-cert-reload.log 2>&1
__EOF__
cat << __EOF__ > /etc/logrotate.d/lmtyas-cert-reload
/var/log/lmtyas-cert-reload.log {
     monthly
     compress
     missingok
     nocopytruncate
     nodelaycompress
     nomail
     notifempty
     noolddir
     rotate 12
}
__EOF__
```
