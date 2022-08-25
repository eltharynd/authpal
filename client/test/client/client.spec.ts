import * as express from 'express'
import * as request from 'supertest'
import { AuthpalClient } from '../../src/client/client'
import * as JWT from 'jsonwebtoken'

describe('Client', () => {
  let app: express.Application
  let authpalClient: AuthpalClient

  beforeAll(() => {
    app = global.app
    authpalClient = global.authpalClient

    global.userChangesEmitter.subscribe((changes) => {})
    global.resumeDoneEmitter.subscribe((changes) => {})
  })

  it('should deny login', (done) => {
    request(app)
      .post('/login')
      .send({ username: 'elthasarynd', password: 'asupersegacurepassword' })
      .expect(401)
      .end((err, res) => {
        if (err) return done.fail(err)
        done()
      })
  })

  it('should login', (done) => {
    request(app)
      .post('/login')
      .send({ username: 'eltharynd', password: 'asupersecurepassword' })
      .expect(200)
      .end((err, res) => {
        if (err) return done.fail(err)

        let accessToken = res.body.accessToken
        expect(accessToken).toBeDefined()
        let cookie = res.headers['set-cookie'][0]
        expect(/^refresh_token=.*;.*HttpOnly.*$/.test(cookie)).toBeTrue()

        done()
      })
  })

  it('should not authorize request', (done) => {
    request(app)
      .get('/me')
      .expect(403)
      .end((err, res) => {
        if (err) return done.fail(err)
        done()
      })
  })

  it('should authorize request', (done) => {
    request(app)
      .post('/login')
      .send({ username: 'eltharynd', password: 'asupersecurepassword' })
      .expect(200)
      .end((err, res) => {
        if (err) return done.fail(err)

        let accessToken = res.body.accessToken
        expect(accessToken).toBeDefined()

        request(app)
          .get('/me')
          .set('Authorization', `Bearer ${accessToken}`)
          .expect(200)
          .end((err, res) => {
            if (err) return done.fail(err)
            done()
          })
      })
  })

  it('should not resume session', (done) => {
    request(app)
      .get('/resume')
      .expect(401)
      .end((err, res) => {
        if (err) return done.fail(err)
        done()
      })
  })

  it('should resume session', (done) => {
    request(app)
      .post('/login')
      .send({ username: 'eltharynd', password: 'asupersecurepassword' })
      .expect(200)
      .end((err, res) => {
        if (err) return done.fail(err)

        let refreshToken = res.headers['set-cookie'][0]
        expect(/^refresh_token=.*;.*HttpOnly.*$/.test(refreshToken)).toBeTrue()

        request(app)
          .get('/resume')
          .set('Cookie', `${refreshToken}`)
          .expect(200)
          .end((err, res) => {
            if (err) return done.fail(err)
            let accessToken = res.body.accessToken
            expect(accessToken).toBeDefined()
            done()
          })
      })
  })

  it('should logout', (done) => {
    request(app)
      .post('/login')
      .send({ username: 'eltharynd', password: 'asupersecurepassword' })
      .expect(200)
      .end((err, res) => {
        if (err) return done.fail(err)

        let accessToken = res.body.accessToken
        expect(accessToken).toBeDefined()
        let refreshToken = res.headers['set-cookie'][0]
        expect(/^refresh_token=.*;.*HttpOnly.*$/.test(refreshToken)).toBeTrue()

        request(app)
          .get('/logout')
          .set('Authorization', `Bearer ${accessToken}`)
          .set('Cookie', `${refreshToken}`)
          .expect(200)
          .end((err, res) => {
            if (err) return done.fail(err)
            done()
          })
      })
  })
})
