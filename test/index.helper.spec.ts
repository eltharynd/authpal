import { Server, IServerOptions } from '../src/server/server'
beforeAll((done) => {
  try {
    let serverOptions: IServerOptions = {
      jwtSecret: 'asupersecretjwtsecret',
      usernameField: 'username',
      passwordField: 'password',
      findUserByUsernameCallback: (username) => {
        return null
      },
      findUserByIDCallback: (token) => {
        return null
      },
      verifyPasswordCallback: (username, password) => {
        return true
      },
      refreshTokenCallback: async () => {
        return
      },
    }
    global.serverOptions = serverOptions
    global.server = new Server(serverOptions)
    done()
  } catch (e) {
    console.error(e)
    done.fail()
  }
})
