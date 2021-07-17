import Permission from '../permission';
import JsonWebToken from '../jsonWebToken';

class Mauth {
  protected static _instance: Mauth;

  // eslint-disable-next-line @typescript-eslint/no-empty-function
  protected constructor() {}

  static getInstance(): Mauth {
    if (!this._instance) {
      this._instance = new this();
    }
    return this._instance;
  }
  async authentication(req, _res, fn) {
    if (req.headers.authorization) {
      req.authorization = req.headers.authorization.replace('Bearer ', '');
      try {
        const auth = await JsonWebToken.getInstance().verify(req.authorization);
        req.permissions = auth.permissions;
        await fn(auth);
      } catch (error) {
        error.name = 'Unauthorized';
        await fn(error);
      }
    } else {
      const error = new Error('Missing Credentials.');
      error.name = 'Unauthorized';
      await fn(error);
    }
  }

  async permission(req, _res, fn) {
    if (req.event && req.permissions) {
      try {
        const permission = await Permission.getInstance().permission(
          req.event,
          req.permissions
        );
        fn(permission);
      } catch (error) {
        error.name = 'Unauthorized';
        await fn(error);
      }
    } else {
      const error = new Error('Missing Permissions.');
      error.name = 'Unauthorized';
      await fn(error);
    }
  }
}

const mauth = Mauth.getInstance();

const authentication = mauth.authentication;
const permission = mauth.permission;

export { authentication, permission };
