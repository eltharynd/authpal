import { Subject } from 'rxjs'

export class UserChangesEmitter extends Subject<UserChangesEvent> {}
type UserChangesEvent = { type: string; authenticated: boolean }

export interface AuthpalClientConfigs {
  userChangesEmitter: UserChangesEmitter
  resumeDoneEmitter: Subject<void>
  resumeDoneMiddleware?(): Promise<void>

  loginPostURL: string
  resumeGetURL: string
}

export class LibraryMisusageError extends Error {}
