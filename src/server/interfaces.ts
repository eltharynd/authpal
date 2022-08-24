export interface RefreshToken {
  token: string
  expiration: Date
}

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
  tokenRefreshedCallback(
    jwtPayload: TT,
    token: RefreshToken
  ): Promise<void> | void
  tokenDeletedCallback(
    jwtPayload: TT,
    token: RefreshToken
  ): Promise<void> | void
}

export const DEFAULT_EXPIRATION_TIME: number = 14 * 24 * 60 * 60 * 1000
