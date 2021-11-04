const async = require('async')
const express = require('express')
const path = require('path')
const util = require('util')
const session = require('express-session')
const bodyParser = require('body-parser')
const morgan = require('morgan')
const jwt = require('jsonwebtoken')
const fs = require('fs')
const Keypairs = require('keypairs')

// initialize sequelize with session store
const SequelizeStore = require('connect-session-sequelize')(session.Store)

const app = express()
const server = require('http').Server(app)

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'pug')

// LOG
if (app.get('env') === 'development') app.use(morgan('dev'))

let ens = null
if (process.env.EAUTH_COMPONENTS_ENS === 'true') {
  const ENS = require('./components/ens')
  ens = new ENS()
}

// issue, dev // maybe add salt with secret
app.set('secret', process.env.EAUTH_SECRET)

// initialize database
const db = require('./models')

const { User, Session } = db

// create database if not exist // if force == true : drop table
async function initialize() {
  // Initialize JWK
  let jwk_private, jwk_public_pem
  if (fs.existsSync('jwk_private.json') && fs.existsSync('jwk_public_pem')) {
    jwk_private = require('./jwk_private.json')
    jwk_public_pem = fs.readFileSync('./jwk_public_pem')
  } else {
    // generate a new keypair as jwk
    // (defaults to EC P-256 when no options are specified)
    const pair = await Keypairs.generate()
    jwk_private = pair.private
    jwk_public_pem = await Keypairs.export({ jwk: pair.public })
    fs.writeFileSync('jwk_private.json', JSON.stringify(jwk_private))
    fs.writeFileSync('jwk_public_pem', jwk_public_pem)
  }
  app.set('jwk_private', JSON.stringify(jwk_private))
  app.set('jwk_public_pem', jwk_public_pem)

  try {
    await User.sync()
    await Session.sync({ force: true })
  } catch (e) {
    console.error(e)

    setTimeout(() => {
      initialize()
    }, 5000)
  }
}
initialize()

const sequelizeStore = new SequelizeStore({
  db: db.sequelize,
  table: 'Session',
})

app.use(session({
  secret: app.get('secret'),
  store: sequelizeStore,
  resave: false,
  saveUninitialized: true,
}))

// Add body parser.
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

app.use(express.static(path.join(__dirname, 'public')))

function oauthMiddleware(req, res, next) {
  if (req.method == 'GET') {
    if (req.path === '/oauth/authorize' && req.session.previousPath === '/oauth/authorize') {
      return req.session.destroy((err) => {
        let location = '/'
        if (req.url) location = util.format('/?url=%s', encodeURIComponent(req.url))
        return res.redirect(location)
      })
    }
    
    req.session.previousPath = req.path
  }
  
  next()
}

app.use(oauthMiddleware)

function apiMiddleware(req, res, next) {
  const { token } = req.session
  
  if (token) {
    // issue case: after server restart will pass verify cond,but token is expire, maybe should check database
    jwt.verify(token, app.get('jwk_public_pem'), {algorithms: ["ES256"]}, (err, decoded) => {
      if (err) {
        return res.json({ success: false, message: 'Failed to authenticate token.' })
      }

      req.decoded = decoded
      return next()
    })
  } else {
    const url = req.url ? util.format('/?url=%s', encodeURIComponent(req.url)) : '/'
    res.redirect(url)
  }
}

const api = express.Router()
// api middleware
api.use(apiMiddleware)

require('./components/eauth')(app, api, User, ens)

if (process.env.EAUTH_COMPONENTS_CONTRACT === 'true')
  require('./components/contract')(app, User, ens)

if (process.env.EAUTH_COMPONENTS_OAUTH === 'true')
  require('./components/oauth')(app, api, User, ens)

if (process.env.EAUTH_COMPONENTS_QRCODE === 'true')
  require('./components/qrcode')(app, api, sequelizeStore, server)

// error handler
app.use((err, req, res, next) => {
  res.status(err.status || 500)
  res.render('error', {
    message: err.message,
    error: app.get('env') === 'development' ? err : {},
  })
})

const listener = server.listen(process.env.EAUTH_PORT || 8080, () => {
  console.log('Listening on port ' + listener.address().port)
})
