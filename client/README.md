# Authpal Client

[![NPM Version][npm-version-image]][npm-url]
[![NPM Install Size][npm-install-size-image]][npm-install-size-url]
[![NPM Downloads][npm-downloads-image]][npm-downloads-url]

A node package to handle user authentication and authorization securely on both client and server.

**Built on top of express, passport and jwt.**

Its goal is to be simple to use yet up to security standards. And be reusable across different apps so you don't have to rewrite the same thing every time you build a web app.

It uses the **accessToken & refreshToken** combo.
The latter is stored in cookies and the former should be stored in memory _(let accessToken, not localStorage.accessToken)_.

For Server Side Usage refer to [Authpal](https://github.com/eltharynd/authpal)

----For quick setup follow [1️⃣](#1️⃣-setup) and [2️⃣](#2️⃣-configs-concretely).  
----Your greens 🥦 are pretty good to have but you don't necessarily have to read.

</br>
</br>
</br>

# Client Side Usage

# Server Side Usage

For Server Side Usage refer to [Authpal](https://github.com/eltharynd/authpal)

[npm-downloads-image]: https://badgen.net/npm/dm/authpal
[npm-downloads-url]: https://npmcharts.com/compare/authpal?minimal=true
[npm-install-size-image]: https://badgen.net/packagephobia/install/authpal
[npm-install-size-url]: https://packagephobia.com/result?p=authpal
[npm-url]: https://npmjs.org/package/authpal
[npm-version-image]: https://badgen.net/npm/v/authpal
