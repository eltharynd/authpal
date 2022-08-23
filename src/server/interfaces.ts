export interface RefreshToken {
  token: string
  expiration: Date
}

//TODO make public and extendable so users can save more data in jwt paylod if they want to
export interface AuthpalJWTPayload {
  userid?: string | number
}

export interface AuthpalConfigs<
  TT extends AuthpalJWTPayload = AuthpalJWTPayload
> {
  jwtSecret: string

  usernameField?: string
  passwordField?: string

  refreshTokenExpiration?: number

  findUserByUsernameCallback(username: string): Promise<TT | null> | TT | null
  findUserByIDCallback(userid: string | number): Promise<TT | null> | TT | null

  findUserByRefreshToken(refreshToken: string): Promise<TT | null> | TT | null

  verifyPasswordCallback(
    username: string,
    password: string
  ): Promise<boolean> | boolean
  refreshTokenCallback(
    jwtPayload: TT,
    token: RefreshToken
  ): Promise<void> | void
}

export const DEFAULT_EXPIRATION_TIME: number = 14 * 24 * 60 * 60 * 1000
