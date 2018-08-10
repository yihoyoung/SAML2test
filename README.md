# SAML 2.0 login test

# How to generator pem key and crt key

```sh
openssl genrsa -out private.pem 2048
openssl req -new -key private.pem -out rsacert.csr
openssl x509 -req -days 3650 -in rsacert.csr -signkey private.pem -out rsacert.crt
```