// file deepcode ignore no-any: any needed
import jsonwebtoken from 'jsonwebtoken';
import Key from './key';
import cryptConfig from '../config/crypt';
import Identification from './util/identification';
import ICrypt from './iCrypt';
let bcrypt;
if (process.env.BCRYPT_USE_NODE?.toLocaleLowerCase() === 'true') {
  bcrypt = require('bcrypt');
} else {
  bcrypt = require('bcryptjs');
}

export default class JsonWebToken {
  protected static _instance: JsonWebToken;

  private crypt: ICrypt;
  protected constructor(crypt?: ICrypt) {
    this.crypt = crypt ? crypt : bcrypt;
  }

  static getInstance(crypt?: ICrypt): JsonWebToken {
    if (!this._instance) {
      this._instance = new this(crypt);
    }
    return this._instance;
  }

  async verify(token?: string, key?: string): Promise<Identification> {
    return new Promise(async (resolve, reject) => {
      try {
        key = key ? key : await Key.getInstance(this.crypt).key();
        jsonwebtoken.verify(token, key, (error, data) =>
          error ? reject(error) : resolve(data)
        );

        //! TODO: check permissions
      } catch (error) {
        reject(error);
      }
    });
  }

  async sign(payload: unknown, type?: string, key?: string): Promise<string> {
    return jsonwebtoken.sign(
      payload,
      key ? key : await Key.getInstance(this.crypt).privateKey(),
      type !== 'SERVICE'
        ? cryptConfig.signOptions
        : cryptConfig.signServiceOptions
    );
  }
}
