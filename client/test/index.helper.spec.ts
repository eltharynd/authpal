import * as express from 'express'
import { filter, from, Subject, take } from 'rxjs'
import { AuthpalClient } from '../src/client/client'
import { Authpal } from '../../src/server/server'
import { UserChangesEmitter } from '../src/client/interfaces'
import * as bodyParser from 'body-parser'
import * as cookieParser from 'cookie-parser'

beforeAll((done) => {
  global.users = [
    {
      id: 123,
      username: 'eltharynd',
      password: 'asupersecurepassword',
    },
  ]
  global.sessions = []
  global.authpal = new Authpal({
    jwtSecret: 'asupersecretjwtsecret',
    usernameField: 'username',
    findUserByUsernameCallback: async (username) => {
      let found: any = await from(global.users)
        .pipe(
          filter((u: any) => u.username === username),
          take(1)
        )
        .toPromise()
      if (found) {
        return {
          userid: found.id,
        }
      } else return null
    },
    findUserByIDCallback: async (userid) => {
      let found: any = await from(global.users)
        .pipe(
          filter((u: any) => u.id === userid),
          take(1)
        )
        .toPromise()
      if (found)
        return {
          userid: found.id,
        }
      return null
    },

    findUserByRefreshToken: async (token) => {
      let found: any = await from(global.users)
        .pipe(
          filter((u: any) => u.token.token === token),
          take(1)
        )
        .toPromise()
      if (found) {
        return {
          userid: found.id,
        }
      } else return null
    },

    verifyPasswordCallback: async (username, password) => {
      let found: any = await from(global.users)
        .pipe(
          filter((u: any) => u.username === username),
          take(1)
        )
        .toPromise()
      return found && password === found.password
    },
    tokenRefreshedCallback: async (jwtPayload, token) => {
      let found: any = await from(global.users)
        .pipe(
          filter((u: any) => u.id === jwtPayload.userid),
          take(1)
        )
        .toPromise()
      if (found) found.token = token
    },
    tokenDeletedCallback: async (jwtPayload, token) => {
      let found: any = await from(global.users)
        .pipe(
          filter((u: any) => u.id === jwtPayload.userid),
          take(1)
        )
        .toPromise()
      if (found) found.token = null
    },
  })

  global.app = express()
  global.app.use(bodyParser.json())
  global.app.use(cookieParser())

  global.app.post('/login', global.authpal.loginMiddleWare)

  global.app.get('/resume', global.authpal.resumeMiddleware)

  global.app.get('/logout', global.authpal.logoutMiddleware)

  global.app.get(
    '/me',
    global.authpal.authorizationMiddleware,
    async (req, res) => {
      let found: any = await from(global.users).pipe(
        filter((u: any) => u.id === req.user.userid),
        take(1)
      )
      res.json(found)
    }
  )

  global.userChangesEmitter = new UserChangesEmitter()
  global.resumeDoneEmitter = new Subject()

  global.authPalClient = new AuthpalClient({
    loginPostURL: `http://localhost:9999/auth/login`,
    logoutGetURL: `http://localhost:9999/auth/logout`,
    resumeGetURL: `http://localhost:9999/auth/resume`,

    userChangesEmitter: global.userChangesEmitter,
    resumeDoneEmitter: global.resumeDoneEmitter,
    resumeDoneMiddleware: async (changes) => {},
  })

  done()
})
