export interface IRefreshToken {
  token: string
  expiration: Date
}

//TODO make public and extendable so users can save more data in jwt paylod if they want to
export interface IJWTPayload {
  userid?: string | number
}

export interface IServerOptions {
  jwtSecret: string
  //TODO do i need these???
  usernameField: string
  passwordField: string

  refreshTokenExpiration?: number

  findUserByUsernameCallback(
    username: string
  ): Promise<IJWTPayload | null> | IJWTPayload | null
  findUserByIDCallback(
    userid: string | number
  ): Promise<IJWTPayload | null> | IJWTPayload | null

  findUserByRefreshToken(
    refreshToken: string
  ): Promise<IJWTPayload | null> | IJWTPayload | null

  verifyPasswordCallback(
    username: string,
    password: string
  ): Promise<boolean> | boolean
  refreshTokenCallback(
    jwtPayload: IJWTPayload,
    token: IRefreshToken
  ): Promise<void> | void
}

export const DEFAULT_EXPIRATION_TIME: number = 14 * 24 * 60 * 60 * 1000
