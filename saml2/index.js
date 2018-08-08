/**
 * SAML 2.0 controller
 */


const SAML = require('../passport-saml/lib/passport-saml/saml').SAML
const fs = require('fs')
const path = require('path')



let options = {
  logoutUrl: 'http://119.254.155.28:6789/sso/saml2.0/logout',
  issuer: 'http://140.143.17.92:3000',
  additionalParams: {

  },
  additionalAuthorizeParams: {

  },
  decryptionPvk: _getPvk(),
  logoutCallbackUrl: 'http://140.143.17.92:3000/saml2/logout',
  cacheProvider: '',
  protocol: '',
  host: '140.143.17.92:3000',
  path: '',
  signatureAlgorithm: 'sha256',
  identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  entryPoint: 'http://119.254.155.28:6789/sso/saml2.0/authn',
}

options.privateCert = options.decryptionPvk
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

  ctx.response.type = 'xml'
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

  if (result.status === 200) {
    ctx.response.redirect(result.redirectUrl)
  } else {
    ctx.response.body = result
  }
}


exports.consume = async function (ctx) {
  let body = ctx.request.body

  let check = await new Promise((resolve, reject) => {
    saml.validatePostResponse(body, (error, result) => {
      if (error) {
        reject({
          status: 500,
          message: error.message
        })
      }

      console.log(result)
      resolve(result)
    })
  })
  ctx.response.body = {
    status: 200,
    message: `This is consume page
    ${check}

    `
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
