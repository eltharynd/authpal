//import { Subject } from 'rxjs'

//export class UserChangesEmitter extends Subject<UserChangesEvent> {}
//type UserChangesEvent = { type: string; authenticated: boolean }

export interface AuthpalClientConfigs {
  userChangesEmitter: any //UserChangesEmitter
  resumeDoneEmitter: any //Subject<void>
  resumeDoneMiddleware?(): any //Promise<void>

  loginPostURL: string
  resumeGetURL: string
}

//export class LibraryMisusageError extends Error {}
