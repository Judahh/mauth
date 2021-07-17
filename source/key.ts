import { setTimeout } from 'timers';
import axios from 'axios';
import bcrypt from 'bcrypt';
import { default as crypt } from '../config/crypt.json';
import AuthService from './util/authService';
import { UnauthorizedError } from '.';
import Identification from './util/identification';

export default class Key implements AuthService {
  async key(): Promise<string> {
    if (this.privateKey && this.publicKey) {
      return this.publicKey;
    } else if (this.publicKey) {
      if (!this.keyTimerRunning) {
        setTimeout(this.refreshKey.bind(this), 15 * 60 * 1000);
        this.keyTimerRunning = true;
      }
      return this.publicKey;
    } else {
      return this.getKey();
    }
  }
  protected async getKey(): Promise<string> {
    const host = process.env.AUTH_HOST;
    const received = await axios.get(host + '/key', await this.config());
    this.publicKey = received.data.key as string;
    return this.publicKey;
  }
  protected async refreshKey(): Promise<void> {
    this.keyTimerRunning = false;
    this.getKey();
  }

  protected static _instance: Key;

  protected constructor() {
    this.keyTimerRunning = false;
  }

  static getInstance(): Key {
    if (!this._instance) {
      this._instance = new this();
    }
    return this._instance;
  }
  protected privateKey?: string = process.env.JWT_PRIVATE_KEY;
  protected publicKey?: string = process.env.JWT_PUBLIC_KEY;
  protected keyTimerRunning: boolean;
  protected authToken;
  protected tokenTimerRunning;

  protected credential = {
    type: 'SERVICE',
    identification: process.env.AUTH_IDENTIFICATION,
    key: process.env.AUTH_PASSWORD,
  };

  async config(): Promise<{
    headers: {
      authorization: string;
    };
  }> {
    return {
      headers: {
        authorization: `Bearer ${await this.token()}`,
      },
    };
  }
  protected async getToken(): Promise<string> {
    const host = process.env.AUTH_HOST;
    const received = await axios.post(host + '/signIn', this.credential);
    this.authToken = received.data.token;
    return this.authToken;
  }
  protected async refreshToken(): Promise<void> {
    this.tokenTimerRunning = false;
    this.getToken();
  }
  async token(): Promise<string> {
    if (this.authToken) {
      if (!this.tokenTimerRunning) {
        setTimeout(this.refreshToken.bind(this), 15 * 24 * 60 * 60 * 1000);
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
    for (const identification of identifications) {
      if (
        rIdentification.key &&
        identification.key &&
        identification.identification === rIdentification.identification
      )
        if (await bcrypt.compare(rIdentification.key, identification.key))
          return;
    }
    const error = new UnauthorizedError();
    throw error;
  }

  generateHash(key: string): string {
    // console.log('generateHash key:', key);

    return bcrypt.hash(key, crypt.hashSaltRounds);
  }
}
