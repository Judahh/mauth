import { default as jsonCrypt } from './crypt.json';
const crypt = {
  hashSaltRounds: +(process.env.MAUTH_SALT_ROUNDS || jsonCrypt.hashSaltRounds),
  signOptions: {
    algorithm:
      process.env.MAUTH_SIGN_ALGORITHM || jsonCrypt.signOptions.algorithm,
    expiresIn:
      process.env.MAUTH_SIGN_EXPIRES_IN || jsonCrypt.signOptions.expiresIn,
  },
  signServiceOptions: {
    algorithm:
      process.env.MAUTH_SERVICE_ALGORITHM ||
      jsonCrypt.signServiceOptions.algorithm,
    expiresIn:
      process.env.MAUTH_SERVICE_EXPIRES_IN ||
      jsonCrypt.signServiceOptions.expiresIn,
  },
};

export default crypt;
