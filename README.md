# Authpal

[![NPM Version][npm-version-image]][npm-url]
[![NPM Install Size][npm-install-size-image]][npm-install-size-url]
[![NPM Downloads][npm-downloads-image]][npm-downloads-url]

A node package to handle user authentication and authorization securely on both client and server.

**Built on top of express, passport and jwt.**

Its goal is to be simple to use yet up to security standards. And be reusable across different apps so you don't have to rewrite the same thing every time you build a web app.

It uses the **accessToken & refreshToken** combo.
The latter is stored in cookies and the former should be stored in memory _(let accessToken, not localStorage.accessToken)_.

For quick setup follow [1️⃣](#1️⃣-setup) and [2️⃣](#2️⃣-configs-concretely).  
Your greens 🥦 are pretty good to have but you don't necessarily have to read.

For Client Side Usage refer to [Authpal-client](https://github.com/eltharynd/authpal/tree/main/client)

</br>
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

For Server Side Usage refer to [Authpal](https://github.com/eltharynd/authpal)

[npm-downloads-image]: https://badgen.net/npm/dm/authpal
[npm-downloads-url]: https://npmcharts.com/compare/authpal?minimal=true
[npm-install-size-image]: https://badgen.net/packagephobia/install/authpal
[npm-install-size-url]: https://packagephobia.com/result?p=authpal
[npm-url]: https://npmjs.org/package/authpal
[npm-version-image]: https://badgen.net/npm/v/authpal
