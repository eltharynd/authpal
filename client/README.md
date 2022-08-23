# Authpal

authpal

[![NPM Version][s-npm-version-image]][s-npm-url]
[![NPM Install Size][s-npm-install-size-image]][s-npm-install-size-url]
[![NPM Downloads][s-npm-downloads-image]][s-npm-downloads-url]

authpal-client

[![NPM Version][c-npm-version-image]][c-npm-url]
[![NPM Install Size][c-npm-install-size-image]][c-npm-install-size-url]
[![NPM Downloads][c-npm-downloads-image]][c-npm-downloads-url]

<br/>

A node package to handle user authentication and authorization securely on both client and server.

**Built on top of express, passport and jwt.**

Its goal is to be simple to use yet up to security standards. And be reusable across different apps so you don't have to rewrite the same thing every time you build a web app.

It uses the **accessToken & refreshToken** combo.
The latter is stored in cookies and the former should be stored in memory _(let accessToken, not localStorage.accessToken)_.

## Server

For quick setup follow [1️⃣](#1️⃣-setup) and [2️⃣](#2️⃣-configs-concretely).  
Your greens 🥦 are pretty good to have but you don't necessarily have to read.

## Client

Setup your project following [3️⃣](#3️⃣-setup) then [4️⃣](#4️⃣-configs) explains the configuration for the client side better.

</br>
</br>

# Server Side Usage

## 1️⃣ Setup

</br>

Install the package:

```bash
npm install authpal
```

Import the package and istantiate it:

```typescript
import { Authpal } from 'authpal'

//...

let authpal = new Authpal({
  //AuthpalConfigs are mandatory, read the 'Configs (concretely)' paragraph below
})

//...
```

Create your routes using the prebuilt middlewares:

```typescript
//retrieve accessToken and set-cookie refreshToken
app.post('/login', authpal.loginMiddleWare) //no need to setup response

//generate a new accessToken via refreshToken cookie
app.get('/resume', authpal.resumeMiddleware) //no need to setup response

//verify headers have 'Bearer <accessToken>'
app.get('/secure', authpal.authorizationMiddleware, (req, res) => {
  let user = req.user

  //DO YOUR THINGS HERE

  res.sendStatus(200)
})
```

</br>

## 🥦 Configs

<details>

<summary>The following section describes the config object. Click to expand.</summary>

---

<br/>

The way the interface is setup requires you to define callbacks to:

- find your user by username/id/refreshToken
- verify password
- store refreshToken

This allows you to handle your user data however you prefer.

The configs type looks like this:

```typescript
{
  jwtSecret: string //A secret used to encrypt the JWTs (usually in process.env.JWT_SECRET)

  /*
  By default authpal will look in the /login request body for 'username' and 'password'.
  These can be changed if you'd rather call them something else
  */
  usernameField?: string //Overrides 'username'
  passwordField?: string //Overrides 'password'

  refreshTokenExpiration?: number //How many seconds before refresh token expires (default 14 days)


  //A callback that must return the User Payload based on the username
  findUserByUsernameCallback(
    username: string
  ): Promise<AuthpalJWTPayload | null> | AuthpalJWTPayload | null

  //A callback that must return the User Payload based on the user ID
  findUserByIDCallback(
    userid: string | number
  ): Promise<AuthpalJWTPayload | null> | AuthpalJWTPayload | null

  //A callback that must return the User Payload based on the token
  findUserByRefreshToken(
    refreshToken: string
  ): Promise<AuthpalJWTPayload | null> | AuthpalJWTPayload | null

  //A callback that must return a boolean after verifying that password matches the user
  verifyPasswordCallback(
    username: string,
    password: string
  ): Promise<boolean> | boolean

  /*
  A callback that returns the refresh token object as well as the associated User Payload.
  Use this to store the token in your database.
  */
  tokenRefreshedCallback(
    jwtPayload: AuthpalJWTPayload,
    token: RefreshToken
  ): Promise<void> | void
}
```

</details>

</br>

</br>

## 🥦 Understand the User Payload (AuthpalJWTPayload)

<details>

<summary>The following section describes the Payload object. Click to expand. </summary>

---

<br/>

`AuthpalJWTPayload` is defined as

```typescript
{
  userid?: string | number
}
```

This is the object that will be passed around the middlewares and put into a JWT on the client's cookies.

If you don't understand what this is, your best bet is to just leave it as is, but this is passed as a generic and can therefore be extended.

For example if you require to send some more data you can do it this way:

```typescript
interface MyCustomPayload extends AuthpalJWTPayload {
  mayTheForce: 'Be with you. No Kathleen, not you...'
}

let authpal = new Authpal<MyCustomPayload>({
  //configs
})

//at this point if you need to extract it out of a secured route you can access
app.get('/secure', authpal.authorizationMiddleware, (req, res) => {
  let user = req.user.MayTheForce //'Be with you. No Kathleen, not you...'
  res.sendStatus(200)
})
```

</details>

</br>

## 2️⃣ Configs (concretely)

</br>

If you skipped the previous two paragraphs, it doesn't really matter, all you need to know is that you need to setup at least the basic configs in a similar fashion

```typescript
let authpal = new Authpal({
  jwtSecret: 'myJWTsecret', //please don't hardcode it but process.env.JWT_SECRET or something,

  //These examples are with mongo & mongoose but obviously you need to implement your own fetch callbacks
  findUserByUsernameCallback: async (username) => {
    return await UsersModel.findOne({ username })
  },
  findUserByIDCallback: async (userid) => {
    return await UsersModel.findOne({ _id: userid })
  },
  findUserByRefreshToken: async (token) => {
    let session = await SessionsModel.findOne({ token }) //You can save the tokens wherever you want, even straight up in the users documents.
    return {
      userid: session.user,
    }
  },
  tokenRefreshedCallback: async (jwtPayload, token) => {
    UsersModel.findOne({ _id: jwtPayload.userid }).then((user) => {
      //Delete or update existings ones to your discretion
      await SessionsModel.create({
        user: jwtPayload.userid,
        token: token.token,
        expiration: token.expiration,
      })
    })
  },

  //Example with bcrypt but you can implement your own
  verifyPasswordCallback: (username, password) => {
    let user = await UsersModel.findOne({ username })
    return bcrypt.compareSync(password, user.hash)
  },
})
```

</br>
</br>
</br>

# Client Side Usage

## 3️⃣ Setup

</br>

Install the package:

```bash
npm install authpal-client
```

Import the package and istantiate it:

```typescript
import { AuthpalClient } from 'authpal'

//...

let authpalClient = new AuthpalClient({
  //AuthpalClientConfigs are mandatory, read the 'Configs' paragraph below
})

//...
```

Here's how to use the library

```typescript
/*
  RESUME SESSION

  As soon as your application start attempt to resume to revalidate the refresh cookie.
  If it exists and the server validates it will receive a new access token and be logged in again.
*/
authpalClient.attemptResume()

/*
  LOGIN

  This method takes a credentials object as a parameter.
  These have to match what you selected on the server side as overrides.
  You you didn't change anything they'll be 'username' and 'password'.
*/
authpalClient.login({
  username: 'myusername',
  password: 'asupersecretpassword',
})

/*
  LOGOUT
*/
authpalClient.logout()
```

All of these methods are async Promises and can be awaited for.

The best method to catch the events is through the emitter that you can pass via the ClientConfigs:

```typescript
userChangesEmitter.subscribe((changes) => {
  //This fires with every event and change in login status.
})

/*
    resomeDoneEmitter is a Subject<void> (from 'rxjs').
    This is marked as .complete() whenever the attemptResume() is done.

    This is particulary useful when you need to wait until the resume 
    process is over before doing other things like rendering or requesting data
  */
await resumeDoneEmitter.toPromise() //Will only continue when is alredy or gets completed

/*
    Sometimes you wanna do more stuff before the resume process is over.
    You can provide a middleware function that gets fired right before completing succcessfully.
  */
{
  //... your client configs
  resumeDoneMiddleware: async () => {
    //User requests are now authenticated
    //Do whatever you need to do (ask for user data or ...)
  }
}
```

Once you're authenticated, you can pass the authorization token to your request library of choice like so:

```typescript
//This example is with axios but it should work with any library

axios
  .get({
    method: 'get',
    url: 'https://example.com/api/v1/secure/private/get-out/please-no',
    headers: {
      //Your other custom headers go here

      //Add Auth headers to the others
      ...this.authPalClient.getAuthorizationHeader(),
    },
  })
  .then(({ data }) => {
    console.log(data)
  })
```

Whenever you receive a userChangesEvent it's defined like so:

```typescript
/*
  The changes fired in your
  userChangesEmitter.subscribe((changes) => {})
*/
{
  type: string //this can be 'login', 'resume' or 'logout'
  authenticated: boolean //is user authenticated after this event?
}
```

## 4️⃣ Configs

The AuthpalClientConfigs object is defined this way:

```typescript
/*
  You wanna keep an outside reference to these so you can subscribe 
  and listen to events, or await for the resume process to be done
*/
let userChangesEmitter = new UserChangesEmitter()
let resumeDoneEmitter = new Subject()

let authpalClient = new AuthpalClient({
  //The POST endpoint for logging in on your server
  loginPostUrl: 'https://example.com/api/v1/login',
  //The GET endpoint for resuming the session in on your server
  loginPostUrl: 'https://example.com/api/v1/login',

  //The custom subject that emits changes to the user (As defined above)
  userChangesEmitter: userChangesEmitter,

  //A Subject<void> that gets completed when the resume attempt is over (See 3️⃣)
  resumeDoneEmitter: resumeDoneEmitter,

  //(optional) A middleware callback to call right before a resume request succeeds
  resumeDoneMiddleware: async () => {
    //Do your things... You're already authenticated at this point
  },
})
```

[s-npm-version-image]: https://badgen.net/npm/v/authpal
[s-npm-url]: https://npmjs.org/package/authpal
[s-npm-install-size-image]: https://badgen.net/packagephobia/install/authpal
[s-npm-install-size-url]: https://packagephobia.com/result?p=authpal
[s-npm-downloads-image]: https://badgen.net/npm/dm/authpal
[s-npm-downloads-url]: https://npmcharts.com/compare/authpal?minimal=true
[c-npm-version-image]: https://badgen.net/npm/v/authpal-client
[c-npm-url]: https://npmjs.org/package/authpal-client
[c-n