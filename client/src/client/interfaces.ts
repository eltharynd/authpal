import { Subject } from 'rxjs'

export class UserChangesEmitter extends Subject<UserChangesEvent> {}
type UserChangesEvent = { type: string; authenticated: boolean }

export interface AuthpalClientConfigs {
  userChangesEmitter: UserChangesEmitter
  resumeDoneEmitter: Subject<void>
  resumeDoneMiddleware?(changes?: UserChangesEvent): Promise<void>

  googlePostUrl?: string
  loginPostURL: string
  resumeGetURL: string
  logoutGetURL: string
}

export class LibraryMisusageError extends Error {}
