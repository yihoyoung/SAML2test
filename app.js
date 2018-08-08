/**
 * SAML 2.0 Test
 *
 */

'use strict'

const Koa = require('koa')
const app = new Koa()
const route = require('koa-route')
const koaBody = require('koa-body')

const saml = require('./saml2')

app.use(koaBody())

app.use(route.get('/metadata', saml.getMetadata))

app.use(route.get('/login/check', saml.login))

let callbackLogin = function (ctx) {
  ctx.response.body = {
    status: 200,
    message: 'hello, world!'
  }
}
app.use(route.get('/login/callback', callbackLogin))

let saml2logout = function (ctx) {
  ctx.response.body = {
    status: 200,
    message: 'hello, world!'
  }
}
app.use(route.get('/saml2/logout', saml2logout))

app.use(route.post('/saml2/consume', saml.consume))

const main = ctx => {
  ctx.response.body = 'Hello World'
}

app.use(main)

app.listen(3000)

console.log(`service started! localhost:3000`)