import { setTimeout } from 'timers';
import axios from 'axios';
import bcrypt from 'bcrypt';
import { default as crypt } from '../config/crypt.json';
import AuthService from './util/authService';

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
  private async getKey(): Promise<string> {
    const host = process.env.AUTH_HOST;
    const received = await axios.get(host + '/key', await this.config());
    this.publicKey = received.data.key as string;
    return this.publicKey;
  }
  private refreshKey() {
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
  private privateKey?: string = process.env.JWT_PRIVATE_KEY;
  private publicKey?: string = process.env.JWT_PUBLIC_KEY;
  private keyTimerRunning: boolean;
  private authToken;
  private tokenTimerRunning;

  private credential = {
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
  private async getToken(): Promise<string> {
    const host = process.env.AUTH_HOST;
    const received = await axios.post(host + '/signIn', this.credential);
    this.authToken = received.data.token;
    return this.authToken;
  }
  private refreshToken() {
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

  async verify(identification, identifications): Promise<void> {
    const error = new Error('Wrong User or Password.');
    error.name = 'Unauthorized';
    if (!(await this.compare(identification, identifications))) {
      // console.log('KeyService.compare FALSE');
      throw error;
    }
  }

  // async compare(
  //   rIdentification: IdentificationServiceSimpleModel,
  //   identifications: IdentificationServiceSimpleModel[]
  // ): Promise<boolean> {
  //   // console.log(rIdentification, identifications);
  //   for (const identification of identifications) {
  //     if (
  //       rIdentification.key &&
  //       identification.key &&
  //       identification.identification === rIdentification.identification
  //     )
  //       if (await this.compareKey(rIdentification.key, identification.key))
  //         return true;
  //   }
  //   return false;
  // }

  async compare(key: string, hash: string): Promise<boolean> {
    // console.log(key, hash);
    return bcrypt.compare(key, hash);
  }

  generateHash(key: string): string {
    // console.log('generateHash key:', key);

    return bcrypt.hash(key, crypt.hashSaltRounds);
  }
}
