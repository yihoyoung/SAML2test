/**
 * SAML 2.0 controller
 */


const SAML = require('../passport-saml/lib/passport-saml/saml').SAML
const fs = require('fs')
const path = require('path')
const co = require('co')



let options = {
  logoutUrl: 'http://119.254.155.28:6789/sso/saml2.0/logout',
  issuer: 'http://lcoalhost:3000',
  additionalParams: {

  },
  additionalAuthorizeParams: {

  },
  decryptionPvk: _getPvk(),
  logoutCallbackUrl: 'http://lcoalhost:3000/logout',
  cacheProvider: '',
  protocol: 'http',
  host: '',
  path: '',
  signatureAlgorithm: 'sha256',
  identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  entryPoint: 'http://119.254.155.28:6789/sso/saml2.0/authn',
}

const saml = new SAML(options)

// passport.use(new samlStrategy(
//   {
//     path: '/login/callback',
//     entryPoint: 'http://119.254.155.28:6789/sso/saml2.0/authn',
//     issuer: 'localhost:3000'
//   },
//   function(profile, done) {
//     findByEmail(profile.email, function(err, user) {
//       if (err) {
//         return done(err);
//       }
//       return done(null, user);
//     });
//   })
// )


exports.getMetadata = function (ctx) {
  const _method = 'getMetadata'
  console.log(_method)

  ctx.response.type = 'xml'

  console.log(JSON.stringify(typeof SAML))

  ctx.response.body = saml.generateServiceProviderMetadata(_getDecreptionCer())
}



exports.login = async function (ctx) {

  let result = await new Promise((resove, reject) => {
    saml.getAuthorizeUrl({}, (err, data) => {
      if (err) {
        reject({
          status: 500,
          message: err.message
        })
      }

      resove({
        status: 200,
        redirectUrl: data
      })
    })
  })

  console.log(JSON.stringify(result))
  if (result.status === 200) {
    ctx.response.redirect(result.redirectUrl)
  } else {
    ctx.response.body = result
  }
}


function _getDecreptionCer() {
  let cer = fs.readFileSync(path.join(__dirname, 'credentials/rsacert.crt'))
  cer = cer.toString()
  return cer
}

function _getPvk() {
  let pvk = fs.readFileSync(path.join(__dirname, 'credentials/private.pem'))
  pvk = pvk.toString()
  return pvk
}
