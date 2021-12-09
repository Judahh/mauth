import { setTimeout } from 'timers';
let bcrypt;
if (process.env.BCRYPT_USE_NODE?.toLocaleLowerCase() === 'true') {
  bcrypt = require('bcrypt');
} else {
  bcrypt = require('bcryptjs');
}
import cryptConfig from '../config/crypt';
import AuthService from './util/authService';
import { UnauthorizedError } from '.';
import Identification from './util/identification';
import { sendGet, sendPost } from './utils';
import ICrypt from './iCrypt';

export default class Key implements AuthService {
  private configREST = {
    headers: {
      Type: 'application/json',
      Accept: 'application/json',
    },
  };

  private crypt: ICrypt;

  async key(): Promise<string> {
    if (!this.host && this._publicKey) {
      return this._publicKey;
    } else if (this._publicKey && this.host) {
      if (!this.keyTimerRunning) {
        setTimeout(
          this.refreshKey.bind(this),
          process.env.AUTH_KEY_EXPIRES_IN_MS
            ? +process.env.AUTH_KEY_EXPIRES_IN_MS
            : 15 * 60 * 1000
        );
        this.keyTimerRunning = true;
      }
      return this._publicKey;
    } else {
      return this.getKey();
    }
  }
  async privateKey(): Promise<string | undefined> {
    return this._privateKey;
  }
  protected async getKey(): Promise<string> {
    const received = this.host
      ? ((await sendGet(
          this.host,
          '/signIn',
          undefined,
          await this.config()
        )) as {
          key: string;
        })
      : undefined;
    this._publicKey = received?.key as string;
    return this._publicKey;
  }
  protected async refreshKey(): Promise<void> {
    this.keyTimerRunning = false;
    await this.getKey();
  }

  protected static _instance: Key;

  protected constructor(crypt?: ICrypt) {
    this.keyTimerRunning = false;
    this.crypt = crypt ? crypt : bcrypt;
  }

  static getInstance(crypt?: ICrypt): Key {
    if (!this._instance) {
      this._instance = new this(crypt);
    }
    return this._instance;
  }
  protected host?: string = process.env.AUTH_HOST;
  protected _privateKey?: string = process.env.JWT_PRIVATE_KEY;
  protected _publicKey?: string = process.env.JWT_PUBLIC_KEY;
  protected keyTimerRunning: boolean;
  protected authToken;
  protected tokenTimerRunning;

  protected credential?: { type: string; identification: string; key: string } =
    process.env.SERVICE_NAME && process.env.SERVICE_KEY
      ? {
          type: 'SERVICE',
          identification: process.env.SERVICE_NAME,
          key: process.env.SERVICE_KEY,
        }
      : undefined;

  async config(): Promise<{
    headers: {
      authorization: string;
    };
  }> {
    return {
      ...this.configREST,
      headers: {
        authorization: `Bearer ${await this.token()}`,
      },
    };
  }
  protected async getToken(): Promise<string> {
    const received =
      this.host && this.credential
        ? ((await sendPost(
            this.host,
            '/signIn',
            this.credential,
            this.configREST
          )) as {
            token: string;
          })
        : undefined;
    this.authToken = received?.token;
    return this.authToken;
  }
  protected async refreshToken(): Promise<void> {
    this.tokenTimerRunning = false;
    await this.getToken();
  }
  async token(): Promise<string> {
    if (this.authToken) {
      if (!this.tokenTimerRunning) {
        setTimeout(
          this.refreshToken.bind(this),
          process.env.AUTH_TOKEN_EXPIRES_IN_MS
            ? +process.env.AUTH_TOKEN_EXPIRES_IN_MS
            : 15 * 24 * 60 * 60 * 1000
        );
        this.tokenTimerRunning = true;
      }
      return this.authToken;
    } else {
      return this.getToken();
    }
  }

  async verify(
    rIdentification: Identification,
    identifications: Identification[]
  ): Promise<void> {
    // console.log(rIdentification, identifications);
    if (this.crypt === undefined) {
      throw new Error('Crypt undefined');
    }
    for (const identification of identifications) {
      if (
        rIdentification.key &&
        identification.key &&
        identification.identification === rIdentification.identification
      )
        if (await this.crypt.compare(rIdentification.key, identification.key))
          return;
    }
    const error = new UnauthorizedError();
    throw error;
  }

  async generateHash(key: string): Promise<string> {
    // console.log('generateHash key:', key);
    if (this.crypt === undefined) {
      throw new Error('Crypt undefined');
    }
    return await this.crypt.hash(key, cryptConfig.hashSaltRounds);
  }
}
