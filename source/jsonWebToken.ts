// file deepcode ignore no-any: any needed
import jsonwebtoken from 'jsonwebtoken';
import Key from './key';
import { default as crypt } from '../config/crypt.json';
import Identification from './util/identification';

export default class JsonWebToken {
  protected static _instance: JsonWebToken;

  // eslint-disable-next-line @typescript-eslint/no-empty-function
  protected constructor() {}

  static getInstance(): JsonWebToken {
    if (!this._instance) {
      this._instance = new this();
    }
    return this._instance;
  }

  async verify(token?: string, key?: string): Promise<Identification> {
    return new Promise(async (resolve, reject) => {
      try {
        key = key ? key : await Key.getInstance().key();
        jsonwebtoken.verify(token, key, (error, data) =>
          error ? reject(error) : resolve(data)
        );

        //! TODO: check permissions
      } catch (error) {
        reject(error);
      }
    });
  }

  sign(payload: unknown, type?: string, key?: string): string {
    return jsonwebtoken.sign(
      payload,
      key ? key : Key.getInstance().privateKey(),
      type !== 'SERVICE' ? crypt.signOptions : crypt.signServiceOptions
    );
  }
}
