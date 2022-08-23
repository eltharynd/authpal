import * as express from 'express'
import * as bodyParser from 'body-parser'
import * as cookieParser from 'cookie-parser'

import { Authpal, AuthpalJWTPayload, AuthpalConfigs } from '../src/index'
//import { createServer } from 'http'

beforeAll((done) => {
  try {
    global.user = {
      id: 12345,
      username: 'eltharynd',
      password: 'asupersecurepassword',
      token: null,
    }

    let authpalConfigs: AuthpalConfigs<AuthpalJWTPayload> = {
      jwtSecret: 'asupersecretjwtsecret',
      findUserByUsernameCallback: (username) => {
        if (username === global.user.username) {
          return {
            userid: 12345,
          }
        } else return null
      },
      findUserByIDCallback: (userid) => {
        //@ts-ignore
        if (userid == user.id)
          return {
            userid: 12345,
          }
        return null
      },

      findUserByRefreshToken: (token) => {
        if (global.resume === token) {
          return {
            userid: 12345,
          }
        } else return null
      },

      verifyPasswordCallback: (username, password) => {
        return password === global.user.password
      },
      refreshTokenCallback: async (jwtPayload, token) => {
        global.user.token = token
      },
    }
    global.authpalConfigs = authpalConfigs
    global.authpal = new Authpal(authpalConfigs)

    let app: express.Application = express()
    app.use(bodyParser.json())
    app.use(cookieParser())

    global.app = app
    done()
  } catch (e) {
    console.error(e)
    done.fail()
  }
})
