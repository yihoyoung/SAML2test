/**
 * SAML 2.0 controller
 */


const SAML = require('./passport-saml').SAML
const fs = require('fs')
const path = require('path')
const request = require('request')



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
  path: '/saml2/consume',
  signatureAlgorithm: 'sha256',
  identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
  entryPoint: 'http://119.254.155.28:6789/sso/saml2.0/authn',
}

options.privateCert = options.decryptionPvk
const saml = new SAML(options)

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

  let userData = await new Promise((resolve, reject) => {
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

  if (!userData.status) {
    global.session = userData
    ctx.response.redirect('/')
  } else {
    ctx.response.status = userData.status
    ctx.response.body = userData
  }
}

exports.logout = async function (ctx) {

  let requestData = ctx.request.body
  let data = await new Promise((resolve, reject) => {
    saml.validatePostResponse(requestData, (error, result) => {
      if (error) {
        reject({
          status: 500,
          message: error.message
        })
      }

      resolve(result)
    })
  })

  console.log(JSON.stringify(data))
  global.session = null
  // session.removeKeyByIDPClientId(data.IDPClientId)

  let responseUrl = saml.getLogoutResponseUrl(data)
  request(responseUrl, (err, result) => {
    console.log(result)
  })
}

exports.logoutRedirect = async function (ctx) {

  let user = global.session
  let logoutUrl = await new Promise((resolve, reject) => {
    saml.getLogoutUrl({user}, (err, result) => {
      if (err) {
        reject(err)
      }

      resolve(result)
    })
  })

  try {
    let idpResult = await new Promise((resolve, reject) => {
      request.get(logoutUrl, null, function(err, response, body) {
        if (err) {
          reject(err)
        }
        console.log(`response: ${JSON.stringify(response)}`)
        console.log(`body: ${JSON.stringify(body)}`)
        resolve(response)
      })
    })

    console.log(JSON.stringify(idpResult))
  } catch (err) {
    console.error(err)
  }

  user = null
  //session.removeKeyByIDPClientId(user.IDPClientId)

  ctx.response.redirect('/')
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
