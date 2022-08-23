import { Request, Response, NextFunction } from 'express'
import * as passport from 'passport'
import { Strategy as LocalStrategy } from 'passport-local'
import { Strategy as JWTStrategy, ExtractJwt } from 'passport-jwt'
import * as JWT from 'jsonwebtoken'
import { v4 } from 'uuid'

import {
  AuthpalJWTPayload,
  AuthpalConfigs,
  DEFAULT_EXPIRATION_TIME,
} from './interfaces'

export class Authpal<T extends AuthpalJWTPayload = AuthpalJWTPayload> {
  private serverConfigs: AuthpalConfigs

  constructor(serverConfigs: AuthpalConfigs) {
    this.serverConfigs = serverConfigs

    passport.use(
      'login',
      new LocalStrategy(
        {
          usernameField: this.serverConfigs.usernameField || 'username',
          passwordField: this.serverConfigs.passwordField || 'password',
        },
        async function (username, password, done) {
          try {
            let user = await serverConfigs.findUserByUsernameCallback(username)
            if (!user)
              return done(null, false, { message: 'Invalid credentials' })

            if (
              !(await serverConfigs.verifyPasswordCallback(username, password))
            )
              return done(null, false, { message: 'Invalid credentials' })

            return done(null, user, { message: 'User logged in' })
          } catch (e) {
            done(e)
          }
        }
      )
    )

    passport.use(
      new JWTStrategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          secretOrKey: serverConfigs.jwtSecret,
        },
        async function (jwtPayload, done) {
          try {
            let user = await serverConfigs.findUserByIDCallback(
              jwtPayload.userid
            )
            if (user) done(null, user)
            else done('Payload sent is invalid', null)
          } catch (e) {
            done(e)
          }
        }
      )
    )

    this.prepareMiddlewares()
  }

  private prepareMiddlewares() {
    let serverConfigs = this.serverConfigs
    this.loginMiddleWare = (
      req: Request,
      res: Response,
      next: NextFunction
    ) => {
      passport.authenticate('login', async function (err, jwtPayload: T) {
        if (err) return next(err)
        if (!jwtPayload) return res.sendStatus(401)
        req.login(jwtPayload, { session: false }, async function (error) {
          if (error) return next(error)
          let accessToken = JWT.sign(jwtPayload, serverConfigs.jwtSecret)
          let refreshToken = {
            token: v4(),
            expiration: new Date(
              Date.now() +
                (serverConfigs.refreshTokenExpiration ||
                  DEFAULT_EXPIRATION_TIME)
            ),
          }
          await serverConfigs.refreshTokenCallback(jwtPayload, refreshToken)
          res.header(
            'Set-Cookie',
            `refresh_token=${JWT.sign(
              { token: refreshToken.token, userid: jwtPayload.userid },
              serverConfigs.jwtSecret
            )}; expiration: ${refreshToken.expiration.toUTCString()}; HttpOnly`
          )
          return res.json({
            accessToken: accessToken,
          })
        })
      })(req, res, next)
    }

    this.refreshMiddleware = async (
      req: Request,
      res: Response,
      next: NextFunction
    ) => {
      if (req.cookies.refresh_token) {
        let decoded
        try {
          decoded = JWT.verify(
            req.cookies.refresh_token,
            serverConfigs.jwtSecret
          )
          if (!decoded) throw new Error(`Couldn't decode payload`)
        } catch (e) {
          res.sendStatus(401)
          return
        }

        let jwtPayload = await serverConfigs.findUserByRefreshToken(
          decoded.token
        )
        if (
          jwtPayload &&
          jwtPayload.userid === (<AuthpalJWTPayload>decoded).userid
        ) {
          let refreshToken = {
            token: req.cookies.refresh_token,
            expiration: new Date(
              Date.now() +
                (serverConfigs.refreshTokenExpiration ||
                  DEFAULT_EXPIRATION_TIME)
            ),
          }
          await serverConfigs.refreshTokenCallback(jwtPayload, refreshToken)
          res.header(
            'Set-Cookie',
            `refresh_token=${JWT.sign(
              { token: refreshToken.token, userid: jwtPayload.userid },
              serverConfigs.jwtSecret
            )}; expiration: ${refreshToken.expiration.toUTCString()}; HttpOnly`
          )
          return next()
        }
      }
      res.sendStatus(401)
    }

    //TODO verify if it shouldn't be passport.authorizate() instead
    this.authorizationMiddleware = (
      req: Request,
      res: Response,
      next: NextFunction
    ) => {
      passport.authenticate('jwt', { session: false }, (err, jwtPayload) => {
        if (err || !jwtPayload) {
          res.sendStatus(403)
        } else {
          req.user = jwtPayload
          next()
        }
      })(req, res, next)
    }

    //TODO last middleware that doesn't automatically return 403
  }

  loginMiddleWare = (req: Request, res: Response, next: NextFunction) => {}

  refreshMiddleware = async (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {}

  authorizationMiddleware = (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {}
}
