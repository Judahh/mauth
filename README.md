# MAuth

![Publish](https://github.com/Judahh/mauth/workflows/Publish/badge.svg)
[![npm version](https://badge.fury.io/js/%40midware%2Fmauth.svg)](https://badge.fury.io/js/%40midware%2Fmauth)
[![npm downloads](https://img.shields.io/npm/dt/%40midware%2Fmauth.svg)](https://img.shields.io/npm/dt/%40midware%2Fmauth.svg)

Authentication and Authorization Middleware

## Installation

This is a [Node.js](https://nodejs.org/en/) module available through the
[npm registry](https://www.npmjs.com/).

Before installing,
[download and install Node.js](https://nodejs.org/en/download/).

If this is a brand new project, make sure to create a `package.json` first with
the [`npm init` command](https://docs.npmjs.com/creating-a-package-json-file) or
[`yarn init` command](https://classic.yarnpkg.com/en/docs/cli/init/).

Installation is done using the
[`npm install` command](https://docs.npmjs.com/getting-started/installing-npm-packages-locally)
or [`yarn add` command](https://classic.yarnpkg.com/en/docs/cli/add):

```bash
$ npm install @midware/mauth
```

or

```bash
$ yarn add @midware/mauth
```

## Features

- Ready to use authorization middleware
- Ready to use authentication middleware
- Simple implementation

## Tests

To run the test suite, first install the dependencies, then run `npm test`:

```bash
$ npm install
$ npm test
```

or

```bash
$ yarn
$ yarn test
```

## Environment Variables:
GOOGLE_CLIENT_ID = Google Client Id
AUTH_HOST = Auth host URL to get keys
JWT_PRIVATE_KEY = RSA Private Key to generate JWT
JWT_PUBLIC_KEY = RSA Public Key to get JWT
AUTH_IDENTIFICATION = Credential id to connect to  Auth host
AUTH_PASSWORD = Credential KEY to connect to  Auth host
SERVICE_NAME = Project name
INSTANCE = Project instance name

## People

The original author of MAuth is [Judah Lima](https://github.com/Judahh)

[List of all contributors](https://github.com/Judahh/mauth/graphs/contributors)
