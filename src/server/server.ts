import { Request, Response, NextFunction } from 'express'
import * as passport from 'passport'
import { Strategy as LocalStrategy } from 'passport-local'
import { Strategy as JWTStrategy, ExtractJwt } from 'passport-jwt'
import * as JWT from 'jsonwebtoken'
import { v4 } from 'uuid'
import * as cookie from 'cookie'

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
          await serverConfigs.tokenRefreshedCallback(jwtPayload, refreshToken)

          //res.setHeader('Access-Control-Expose-Headers', 'Set-Cookie')
          res.setHeader(
            'Set-Cookie',
            cookie.serialize(
              'refresh_token',
              JWT.sign(
                { token: refreshToken.token, userid: jwtPayload.userid },
                serverConfigs.jwtSecret
              ),
              {
                httpOnly: true,
                expires: refreshToken.expiration,
                sameSite: 'none',
                secure: true,
                maxAge:
                  serverConfigs.refreshTokenExpiration ||
                  DEFAULT_EXPIRATION_TIME,
              }
            )
          )
          return res.json({
            accessToken: accessToken,
          })
        })
      })(req, res, next)
    }

    this.resumeMiddleware = async (
      req: Request,
      res: Response,
      next: NextFunction
    ) => {
      if (req.cookies?.refresh_token) {
        let decoded
        try {
          decoded = JWT.verify(
            req.cookies.refresh_token,
            serverConfigs.jwtSecret
          )
          if (!decoded) throw new Error(`Couldn't decode payload`)
        } catch (e) {
          res.setHeader(
            'Set-Cookie',
            cookie.serialize('refresh_token', 'deleted', {
              httpOnly: true,
              sameSite: 'none',
              secure: true,
              expires: new Date(),
              maxAge: 0,
            })
          )
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
          let accessToken = JWT.sign(jwtPayload, serverConfigs.jwtSecret)

          let refreshToken = {
            token: decoded.token,
            expiration: new Date(
              Date.now() +
                (serverConfigs.refreshTokenExpiration ||
                  DEFAULT_EXPIRATION_TIME)
            ),
          }
          await serverConfigs.tokenRefreshedCallback(jwtPayload, refreshToken)
          res.setHeader(
            'Set-Cookie',
            cookie.serialize(
              'refresh_token',
              JWT.sign(
                { token: refreshToken.token, userid: jwtPayload.userid },
                serverConfigs.jwtSecret
              ),
              {
                httpOnly: true,
                sameSite: 'none',
                secure: true,
                expires: refreshToken.expiration,
                maxAge:
                  serverConfigs.refreshTokenExpiration ||
                  DEFAULT_EXPIRATION_TIME,
              }
            )
          )
          res.json({
            accessToken: accessToken,
          })
          return
        } else {
          res.setHeader(
            'Set-Cookie',
            cookie.serialize('refresh_token', 'deleted', {
              httpOnly: true,
              sameSite: 'none',
              secure: true,
              expires: new Date(),
              maxAge: 0,
            })
          )
        }
      }
      res.sendStatus(401)
    }

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

    this.logoutMiddleware = async (
      req: Request,
      res: Response,
      next: NextFunction
    ) => {
      passport.authenticate(
        'jwt',
        { session: false },
        async (err, jwtPayload) => {
          if (err || !jwtPayload) {
            res.sendStatus(403)
          } else {
            jwtPayload.userid

            //DELETE ACCESS TOKEN HAPPENS ON SERVER

            if (req.cookies?.refresh_token) {
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

              await this.serverConfigs.tokenDeletedCallback(
                jwtPayload,
                decoded.token
              )

              res.setHeader(
                'Set-Cookie',
                cookie.serialize('refresh_token', 'deleted', {
                  httpOnly: true,
                  sameSite: 'none',
                  secure: true,
                  expires: new Date(),
                  maxAge: 0,
                })
              )
              res.sendStatus(200)
            } else res.sendStatus(403)

            req.user = jwtPayload
          }
        }
      )(req, res, next)
    }
  }

  loginMiddleWare = (req: Request, res: Response, next: NextFunction) => {}

  resumeMiddleware = async (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {}

  authorizationMiddleware = (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {}

  logoutMiddleware = (req: Request, res: Response, next: NextFunction) => {}
}
