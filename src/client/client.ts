import { AuthpalClientConfigs } from './interfaces'
import axios from 'axios'

export class AuthpalClient {
  private accessToken: string
  clientConfigs: AuthpalClientConfigs

  constructor(clientConfigs: AuthpalClientConfigs) {
    this.clientConfigs = clientConfigs
    this.clientConfigs.userChangesEmitter.subscribe((changes) => {
      if (!changes.authenticated) {
        this.accessToken = null
        localStorage.APC_ATTEMPT_RESUME = false
      } else {
        localStorage.APC_ATTEMPT_RESUME = true
      }
    })
  }

  async login(credentials: { [key: string]: string }): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      axios({
        method: 'post',
        url: `${this.clientConfigs.loginPostURL}`,
        withCredentials: true,
        data: credentials,
      })
        .then(async ({ data }) => {
          this.accessToken = data.accessToken
          this.clientConfigs.userChangesEmitter.next({
            type: 'login',
            authenticated: true,
          })
          resolve()
        })
        .catch((error) => {
          if (error?.response?.status === 401) {
            this.clientConfigs.userChangesEmitter.next({
              type: 'login',
              authenticated: false,
            })
            reject(error)
          } else reject(error)
        })
    })
  }

  getAuthorizationHeader() {
    return this.accessToken
      ? { Authorization: `Bearer ${this.accessToken}` }
      : null
  }

  private resumeAttemted = false
  async attemptResume(): Promise<void> {
    if (this.resumeAttemted) {
      throw new Error(
        `You attempted to call resume but it's been already called.\n'attemptResume()' should only be called once at the start of your application or on page refresh.`
      )
    } else if (localStorage.APC_ATTEMPT_RESUME) {
      this.resume()
    } else {
      if (this.clientConfigs.resumeDoneMiddleware) {
        await this.clientConfigs.resumeDoneMiddleware()
      }
      this.clientConfigs.resumeDoneEmitter.complete()
    }
  }

  private async resume() {
    axios({
      method: 'get',
      url: `${this.clientConfigs.resumeGetURL}`,
      headers: {
        'Access-Control-Expose-Headers': 'Set-Cookie',
      },
      withCredentials: true,
    })
      .then(async ({ data }) => {
        this.accessToken = data.accessToken
        this.clientConfigs.userChangesEmitter.next({
          type: 'resume',
          authenticated: true,
        })
        if (this.clientConfigs.resumeDoneMiddleware) {
          await this.clientConfigs.resumeDoneMiddleware()
        }
        this.clientConfigs.resumeDoneEmitter.complete()
      })
      .catch(async (error) => {
        if (error?.response?.status === 401) {
          await this.clientConfigs.userChangesEmitter.next({
            type: 'resume',
            authenticated: false,
          })
          if (this.clientConfigs.resumeDoneMiddleware) {
            await this.clientConfigs.resumeDoneMiddleware()
          }
          this.clientConfigs.resumeDoneEmitter.complete()
        } else console.error(error)
      })
  }

  async logout() {
    //TODO remove token from server?
    this.clientConfigs.userChangesEmitter.next({
      type: 'logout',
      authenticated: false,
    })
  }
}
