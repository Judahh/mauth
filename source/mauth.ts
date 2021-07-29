import Permission from './permission';
import JsonWebToken from './jsonWebToken';
import UnauthorizedError from './util/unauthorizedError';
import Verify from './util/verify';
import Identification from './util/identification';
import Headers from './util/headers';
import Query from './util/query';
import Params from './util/params';
import Event from './util/event';
import Permissions from './util/permissions';

export default class Mauth {
  protected verify: {
    [type: string]: Verify;
  };

  protected getPersonAndIdentifications: (
    // eslint-disable-next-line no-unused-vars
    identification: Identification
  ) => Promise<{
    person: { receivedItem: unknown };
    identifications: Identification[];
  }>;

  // eslint-disable-next-line @typescript-eslint/no-empty-function
  constructor(
    getPersonAndIdentifications: (
      // eslint-disable-next-line no-unused-vars
      identification: Identification
    ) => Promise<{
      person: { receivedItem: unknown };
      identifications: Identification[];
    }>,
    verify: {
      [type: string]: Verify;
    }
  ) {
    this.getPersonAndIdentifications = getPersonAndIdentifications;
    this.verify = verify;
  }

  static getBearerAuthentication(bearer?: string): string | undefined {
    const newBearer = bearer
      ? bearer.includes('Bearer ')
        ? bearer.replace('Bearer ', '')
        : bearer.includes('Bearer')
        ? bearer.replace('Bearer', '')
        : bearer
      : bearer;
    return newBearer && newBearer.length > 0 ? newBearer : undefined;
  }

  getAuthentication(req: {
    headers?: Headers;
    query?: Query;
  }): string | undefined {
    const bearer = req.headers
      ? Mauth.getBearerAuthentication(req.headers.authorization)
      : undefined;
    const token = req.query ? req.query.token : undefined;
    return bearer || token;
  }

  async selfRestriction(
    req: {
      authorization: string;
      query: Query;
      params?: Params;
    },
    _res: unknown,
    // eslint-disable-next-line no-unused-vars
    fn: (arg0: unknown) => Promise<unknown>
  ): Promise<void> {
    if (req.authorization) {
      try {
        const auth = await JsonWebToken.getInstance().verify(req.authorization);
        // console.log('authentication', auth);
        if (
          (req.query && req.query.id === auth.id) ||
          (req.params && req.params.filter === auth.id) ||
          (req.params && req.params.filter && req.params.filter.id === auth.id)
        )
          await fn(auth);
        else {
          const error = new Error('Missing ID or Wrong ID.');
          error.name = 'Unauthorized';
          await fn(error);
        }
      } catch (error) {
        // console.log('Error NAME:' + error.name);
        error.name = 'Unauthorized';
        await fn(error);
      }
    } else {
      const error = new Error('Missing Credentials.');
      error.name = 'Unauthorized';
      await fn(error);
    }
  }

  async signIn(
    identification: Identification,
    headers?: Headers
  ): Promise<unknown> {
    let personAndIdentifications;
    try {
      personAndIdentifications = await this.getPersonAndIdentifications(
        identification
      );
    } catch (error) {
      error = new Error('Unauthorized');
      error.name = 'Unauthorized';
      throw error;
    }
    const person = personAndIdentifications.person;
    const identifications = personAndIdentifications.identifications as {
      identification: string | undefined;
      key: string | undefined;
      type: string;
    }[];

    await this.verify[identification.type](
      identification,
      identifications,
      headers
    );

    const cleanPerson = JSON.parse(JSON.stringify(person.receivedItem));
    delete cleanPerson.instances;
    delete cleanPerson.identifications;
    cleanPerson.identification = identifications;
    return cleanPerson;
  }

  async checkToken(
    req: {
      query?: Query;
      headers?: Headers;
      authorization?: string;
      permissions?: Permissions;
      body?: Identification;
    },
    _res: unknown,
    // eslint-disable-next-line no-unused-vars
    fn: (arg0: unknown) => unknown
  ): Promise<void> {
    req.authorization = this.getAuthentication(req);
    if (req.authorization) {
      try {
        const auth = await JsonWebToken.getInstance().verify(req.authorization);
        req.permissions = auth.permissions;
        await fn(auth);
      } catch (error) {
        error.name = 'Unauthorized';
        await fn(error);
      }
    } else {
      await fn(new UnauthorizedError('Missing Credentials.'));
    }
  }

  async authentication(
    req: {
      query?: Query;
      headers?: Headers;
      authorization?: string;
      permissions?: Permissions;
      body?: Identification;
    },
    res: unknown,
    // eslint-disable-next-line no-unused-vars
    fn: (arg0: unknown) => unknown
  ): Promise<void> {
    if (
      (req.query && req.query.token) ||
      (req.headers && req.headers.authorization)
    ) {
      await this.checkToken(req, res, fn);
    } else if (req.body?.identification) {
      const identification = req.body;
      try {
        const person = await this.signIn(identification, req.headers);
        await fn(person);
      } catch (error) {
        await fn(error);
      }
    } else {
      await fn(new UnauthorizedError('Missing Credentials.'));
    }
  }

  async permission(
    req: { event: Event; permissions: Permissions },
    _res: unknown,
    // eslint-disable-next-line no-unused-vars
    fn: (arg0: unknown) => Promise<unknown>
  ): Promise<void> {
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
