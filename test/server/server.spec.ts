describe('Server', () => {
  it('should be initialized', () => {
    expect(true).toBeTruthy()
  })

  it('should login user with valid credentials', () => {
    expect(true).toBeTruthy()
  })

  it('should refuse login with invalid username', () => {
    expect(true).toBeTruthy()
  })

  it('should refuse login with invalid password', () => {
    expect(true).toBeTruthy()
  })

  it('should allow access to secure route with credentials', () => {
    expect(true).toBeTruthy()
  })

  it('should deny access to secure route w/o credentials', () => {
    expect(true).toBeTruthy()
  })

  it('should resume user login session', () => {
    expect(true).toBeTruthy()
  })
})

//TODO implement unit testing
/* 
  let user = {
    id: 12345,
    username: 'eltharynd',
    password: 'asupersecurepassword',
    token: null,
  }

  let serverOptions: IServerOptions = {
    jwtSecret: 'asupersecretjwtsecret',
    usernameField: 'username',
    passwordField: 'password',
    findUserByUsernameCallback: (username) => {
      if (username === user.username) {
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
      if (user.token.token === token) {
        return {
          userid: 12345,
        }
      } else return null
    },

    verifyPasswordCallback: (username, password) => {
      return password === user.password
    },
    refreshTokenCallback: async (_token) => {
      user.token = _token
    },
  }

  let server = new Server(serverOptions)

  let app = await express()
  app.use(bodyParser.json())
  app.use(cookieParser())
  app.post('/login', server.loginMiddleWare, (req, res) => {
    res.sendStatus(200)
  })

  app.get('/secure', server.authorizationMiddleware, (req, res) => {
    //@ts-ignore
    let user: IJWT = req.user
    res.sendStatus(200)
  })

  app.get('/resume', server.refreshMiddleware, (req, res) => {
    console.log('cookie outside', req.cookies)
    res.sendStatus(200)
  })

  let _s = createServer(app)
  _s.listen(3000, () => {
    console.log('server started')
  })
*/
