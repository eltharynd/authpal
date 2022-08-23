import { Request, Response, NextFunction } from 'express'
import * as passport from 'passport'
import { Strategy as LocalStrategy } from 'passport-local'
import { Strategy as JWTStrategy, ExtractJwt } from 'passport-jwt'
import * as JWT from 'jsonwebtoken'
import { v4 } from 'uuid'

import {
  IRefreshToken,
  IJWTPayload,
  IServerOptions,
  DEFAULT_EXPIRATION_TIME,
} from './interfaces'

export class Server {
  private serverOptions: IServerOptions

  constructor(serverOptions: IServerOptions) {
    this.serverOptions = serverOptions

    passport.use(
      'login',
      new LocalStrategy(
        {
          usernameField: this.serverOptions.usernameField,
          passwordField: this.serverOptions.passwordField,
        },
        async function (username, password, done) {
          try {
            let user = await serverOptions.findUserByUsernameCallback(username)
            if (!user)
              return done(null, false, { message: 'Invalid credentials' })

            if (
              !(await serverOptions.verifyPasswordCallback(username, password))
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
          secretOrKey: serverOptions.jwtSecret,
        },
        async function (jwtPayload, done) {
          try {
            let user = await serverOptions.findUserByIDCallback(
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
    let serverOptions = this.serverOptions
    this.loginMiddleWare = (
      req: Request,
      res: Response,
      next: NextFunction
    ) => {
      passport.authenticate(
        'login',
        async function (err, jwtPayload: IJWTPayload) {
          if (err) return next(err)
          if (!jwtPayload) return res.sendStatus(401)
          req.login(jwtPayload, { session: false }, async function (error) {
            if (error) return next(error)
            let accessToken = JWT.sign(jwtPayload, serverOptions.jwtSecret)
            let refreshToken = {
              token: v4(),
              expiration: new Date(
                Date.now() +
                  (serverOptions.refreshTokenExpiration ||
                    DEFAULT_EXPIRATION_TIME)
              ),
            }
            await serverOptions.refreshTokenCallback(jwtPayload, refreshToken)
            res.header(
              'Set-Cookie',
              `refresh_token=${
                refreshToken.token
              }; expiration: ${refreshToken.expiration.toUTCString()}; HttpOnly`
            )
            return res.json({
              accessToken: accessToken,
            })
          })
        }
      )(req, res, next)
    }

    this.refreshMiddleware = async (
      req: Request,
      res: Response,
      next: NextFunction
    ) => {
      if (req.cookies.refresh_token) {
        let jwtPayload = await serverOptions.findUserByRefreshToken(
          req.cookies.refresh_token
        )
        if (jwtPayload) {
          let refreshToken = {
            token: req.cookies.refresh_token,
            expiration: new Date(
              Date.now() +
                (serverOptions.refreshTokenExpiration ||
                  DEFAULT_EXPIRATION_TIME)
            ),
          }
          await serverOptions.refreshTokenCallback(jwtPayload, refreshToken)
          res.header(
            'Set-Cookie',
            `refresh_token=${
              refreshToken.token
            }; expiration: ${refreshToken.expiration.toUTCString()}; HttpOnly`
          )
          next()
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
