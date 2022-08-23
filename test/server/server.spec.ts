import * as express from 'express'
import * as request from 'supertest'
import * as finishTestcase from 'jasmine-supertest'

import { Authpal, AuthpalJWTPayload } from '../../src'

describe('Server', () => {
  let app: express.Application
  let authpal: Authpal

  beforeAll(() => {
    app = global.app
    authpal = global.authpal

    app.post('/login', authpal.loginMiddleWare, (req, res) => {
      res.sendStatus(200)
    })

    app.get('/secure', authpal.authorizationMiddleware, (req, res) => {
      //@ts-ignore
      let user: AuthpalJWTPayload = req.user
      res.sendStatus(200)
    })

    app.get('/resume', authpal.refreshMiddleware, (req, res) => {
      res.sendStatus(200)
    })
  })

  it('should be initialized', () => {
    expect(app).toBeDefined()
  })

  it('should refuse login with invalid credentials', (done) => {
    request(app).post('/login').expect(401).end(finishTestcase(done))
  })

  it('should login user with valid credentials', (done) => {
    expect(2)
    request(app)
      .post('/login')
      .send({ username: 'eltharynd', password: 'asupersecurepassword' })
      .expect(200)
      .end((err, res) => {
        if (err) return done.fail(err)

        let cookie = res.headers['set-cookie'][0]
        expect(
          /^refresh_token=.*; expiration: .{3}, \d\d .{3} \d\d\d\d \d\d:\d\d:\d\d GMT; HttpOnly$/.test(
            cookie
          )
        ).toBeTrue()
        expect(res.body.accessToken).toBeDefined()
        done()
      })
  })

  it('should allow access to secure route with credentials', (done) => {
    request(app)
      .post('/login')
      .send({ username: 'eltharynd', password: 'asupersecurepassword' })
      .expect(200)
      .end((err, res) => {
        if (err) return done.fail(err)

        let accessToken = res.body.accessToken

        request(app)
          .get('/secure')
          .set('Authorization', `Bearer ${accessToken}`)
          .expect(200)
          .end((e, r) => {
            if (e) return done.fail(e)
            done()
          })
      })
  })

  it('should deny access to secure route w/o credentials', (done) => {
    request(app)
      .get('/secure')
      .expect(403)
      .end((e, r) => {
        if (e) return done.fail(e)
        done()
      })
  })

  it('should resume user login session', (done) => {
    request(app)
      .post('/login')
      .send({ username: 'eltharynd', password: 'asupersecurepassword' })
      .expect(200)
      .end((err, res) => {
        if (err) return done.fail(err)

        let refreshToken = res.headers['set-cookie'][0]
        global.resume = refreshToken
          .replace(/^refresh_token=/, '')
          .replace(/; .*$/, '')

        request(app)
          .get('/resume')
          .set('Cookie', `${refreshToken}`)
          .expect(200)
          .end((e, r) => {
            if (e) return done.fail(e)
            done()
          })
      })
  })

  it('should deny user login session', (done) => {
    request(app)
      .post('/login')
      .send({ username: 'eltharynd', password: 'asupersecurepassword' })
      .expect(200)
      .end((err, res) => {
        if (err) return done.fail(err)

        let refreshToken = res.headers['set-cookie'][0]
        global.resume = refreshToken
          .replace(/^refresh_token=/, '')
          .replace(/; .*$/, '')

        request(app)
          .get('/resume')
          .set('Cookie', `${refreshToken.replace(/token=.{3}/, 'token=124')}`)
          .expect(401)
          .end((e, r) => {
            if (e) return done.fail(e)
            done()
          })
      })
  })
})
