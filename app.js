/**
 * SAML 2.0 Test
 *
 */

'use strict'

const Koa = require('koa')
const app = new Koa()
const route = require('koa-route')
const koaBody = require('koa-body')
const fs = require('fs')

const saml = require('./saml2')

app.use(koaBody())

app.use(route.get('/metadata', saml.getMetadata))

app.use(route.get('/saml2/login', saml.login))

let callbackLogin = function (ctx) {
  ctx.response.body = {
    status: 200,
    message: 'hello, world!'
  }
}
app.use(route.get('/login/callback', callbackLogin))

app.use(route.get('/logout', saml.logout))
app.use(route.get('/saml2/logout', saml.logoutResponse))

app.use(route.post('/saml2/consume', saml.consume))

const main = ctx => {
  ctx.response.type = 'html'
  ctx.response.body = fs.createReadStream('./views/index.html')
}

app.use(main)

app.listen(3000)

console.log(`service started! localhost:3000`)