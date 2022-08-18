import { request as aRequest } from './utils';
import JsonWebToken from './jsonWebToken';
import { AxiosRequestConfig } from 'axios';

const crud = {
  post: 'create',
  put: 'update',
  patch: 'update',
  get: 'read',
  delete: 'delete',
};

const request = async (
  method: string,
  host: string,
  domain: string,
  service: string,
  endpoint?: string,
  input?: unknown,
  config: AxiosRequestConfig = {},
  out?: unknown
): Promise<unknown> => {
  try {
    const user = {
      id: '000000000000000000000000',
      givenName: process.env.SERVICE_NAME,
      familyName: process.env.INSTANCE,
      identification: process.env.SERVICE_NAME,
      type: 'API',
      permissions: {
        auth: {
          signIn: ['all'],
        },
      },
      instances: ['all'],
    };
    user.permissions[domain] = {};
    user.permissions[domain][service] = [crud[method]];

    const token = await JsonWebToken.getInstance().sign(user);

    config.headers = {
      Type: 'application/json',
      Accept: 'application/json',
      Authorization: `Bearer ${token}`,
      ...(config.headers || {}),
    };

    if (host && host.length > 0) {
      const response = await aRequest(
        method,
        host,
        endpoint,
        input,
        config,
        out
      );
      return response;
    } else throw new Error('Missing Params');
  } catch (error: any) {
    error.data = out;
    throw error;
  }
};

export { request };
