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

const genPath = (
  name: string,
  value?: (number | string) | (number | string)[]
) => {
  return value !== undefined && value !== null
    ? Array.isArray(value)
      ? name +
        '%5B%5D=' +
        value.map((av) => encodeURI(av.toString())).join('&' + name + '%5B%5D=')
      : name + '=' + encodeURI(value.toString())
    : undefined;
};

const getPath = (oldPath?: string): string => {
  return oldPath !== undefined && oldPath !== null && oldPath?.length > 0
    ? `${oldPath}&`
    : '?';
};

const addPath = (oldPath?: string, addPath?: string) => {
  return addPath !== undefined && addPath !== null
    ? getPath(oldPath) + addPath
    : oldPath;
};

const request = async (
  method: string,
  host: string,
  domain: string,
  service: string,
  query?: unknown,
  input?: unknown,
  endpoint?: string,
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
        endpoint || `/${domain}/${service}${query || ''}`,
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

export { request, addPath, genPath, getPath };
