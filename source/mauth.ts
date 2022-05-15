/* eslint-disable @typescript-eslint/no-explicit-any */
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
import ICrypt from './iCrypt';
import Sender from './util/sender';

export default class Mauth {
  protected verify?: {
    [type: string]: Verify;
  };
  protected keyless?: {
    [type: string]: Sender;
  };

  protected getPersonAndIdentifications?: (
    // eslint-disable-next-line no-unused-vars
    identification: Identification
  ) => Promise<{
    person: { receivedItem: unknown };
    identifications: Identification[];
  }>;

  private crypt?: ICrypt;

  // eslint-disable-next-line @typescript-eslint/no-empty-function
  constructor(
    getPersonAndIdentifications?: (
      // eslint-disable-next-line no-unused-vars
      identification: Identification
    ) => Promise<{
      person: { receivedItem: unknown };
      identifications: Identification[];
    }>,
    verify?: {
      [type: string]: Verify;
    },
    keyless?: {
      [type: string]: Sender;
    },
    crypt?: ICrypt
  ) {
    this.getPersonAndIdentifications = getPersonAndIdentifications;
    this.verify = verify;
    this.keyless = keyless;
    this.crypt = crypt;
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

  static checkAuthentication(req: {
    headers?: Headers;
    query?: Query;
    authorization?: string;
    auth?: string;
  }): string | undefined {
    return (
      req?.headers?.authorization ||
      req?.headers?.Authorization ||
      req?.headers?.token ||
      req?.headers?.Token ||
      req?.query?.token ||
      req?.authorization ||
      req?.auth
    );
  }

  static getAuthentication(req: {
    headers?: Headers;
    query?: Query;
    authorization?: string;
    auth?: string;
  }): string | undefined {
    const bearer = Mauth.getBearerAuthentication(
      Mauth.checkAuthentication(req)
    );
    return bearer;
  }

  async selfRestriction(
    req: {
      authorization: string;
      query: Query;
      params?: Params;
      method?: string;
    },
    _res: unknown,
    // eslint-disable-next-line no-unused-vars
    fn: (arg0: unknown) => Promise<unknown>
  ): Promise<void> {
    if (req.authorization) {
      try {
        const auth = await JsonWebToken.getInstance(this.crypt).verify(
          req.authorization
        );
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
      } catch (error: any) {
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
    let person;
    let identifications;
    try {
      if (this.getPersonAndIdentifications)
        personAndIdentifications = await this.getPersonAndIdentifications(
          identification
        );
      person = personAndIdentifications.person;
      identifications = personAndIdentifications.identifications as {
        identification: string | undefined;
        key: string | undefined;
        type: string;
      }[];
    } catch (error: any) {
      error = new Error('Unauthorized');
      error.name = 'Unauthorized';
      throw error;
    }

    if (this.verify)
      await this.verify[identification.type](
        identification,
        identifications,
        headers
      );

    const cleanPerson = person?.receivedItem
      ? JSON.parse(JSON.stringify(person?.receivedItem))
      : undefined;
    if (cleanPerson) {
      delete cleanPerson?.instances;
      delete cleanPerson?.identifications;
      cleanPerson.identification = identifications;
    }
    if (identification?.type?.toLocaleUpperCase()==='KEYLESS'){
      this.keyless?.[identification?.subType?.toLocaleUpperCase()||'']?.(cleanPerson, identification);
      return;
    }
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
    req.authorization = Mauth.getAuthentication(req);
    if (req.authorization) {
      try {
        const auth = await JsonWebToken.getInstance(this.crypt).verify(
          req.authorization
        );
        req.permissions = auth.permissions;
        await fn(auth);
      } catch (error: any) {
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
      method?: string;
    },
    res: unknown,
    // eslint-disable-next-line no-unused-vars
    fn: (arg0: unknown) => unknown
  ): Promise<void> {
    if (Mauth.checkAuthentication(req)) {
      await this.checkToken(req, res, fn);
    } else if (req.body?.identification) {
      const identification = req.body;
      try {
        const person: { identification: Array<{ key: unknown; id: unknown }> } =
          (await this.signIn(identification, req.headers)) as {
            identification: Array<{ key: unknown; id: unknown }>;
          };
        person.identification = person.identification.map((id) => {
          delete id.key;
          delete id.id;
          return id;
        });
        if (!req.headers) req.headers = { tokenid: '', picture: '' };
        req.headers.authorization = await JsonWebToken.getInstance(
          this.crypt
        ).sign(person, identification.type);
        await fn(person);
      } catch (error) {
        await fn(error);
      }
    } else {
      await fn(new UnauthorizedError('Missing Credentials.'));
    }
  }

  async permission(
    req: { event: Event; permissions: Permissions; method: string },
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
      } catch (error: any) {
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
