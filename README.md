# SAML 2.0 login test

# How to generate pem key and crt key

```sh
openssl genrsa -out private.pem 2048
openssl req -new -key private.pem -out rsacert.csr
openssl x509 -req -days 3650 -in rsacert.csr -signkey private.pem -out rsacert.crt
```

# What  supposed to prepare in SP

1. issue url likes main url.
2. consumer API for getting user info.
3. logout API for IDP sending logout request.
4. metadata url
  include rsacert.csr, but no '-----BEGIN CERTIFICATE-----' and '-----END CERTIFICATE-----'
  issue url
  consumer API
  logout API