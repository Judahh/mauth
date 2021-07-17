class Mauth {
  protected verify: {
    [type: string]: string;
  } = { LOCAL: 'verifyLocal', SERVICE: 'verifyLocal', GOOGLE: 'verifyGoogle' };
  protected static _instance: Mauth;

  // eslint-disable-next-line @typescript-eslint/no-empty-function
  protected constructor() {}

  static getInstance(): Mauth {
    if (!this._instance) {
      this._instance = new this();
    }
    return this._instance;
  }

  protected async verifyGoogle(
    identification,
    identifications,
    headers
  ): Promise<void> {
    const error = new Error('GAccount error.');
    error.name = 'Unauthorized';
    // console.log('verifyGoogle');
    if (
      !(await this.journaly?.publish(
        'GoogleService.compare',
        identification,
        identifications,
        headers
      ))
    ) {
      // console.log('KeyService.compare FALSE');
      throw error;
    }
  }

  protected async verifyLocal(identification, identifications): Promise<void> {
    const error = new Error('Wrong User or Password.');
    error.name = 'Unauthorized';
    if (
      !(await this.journaly?.publish(
        'KeyService.compare',
        identification,
        identifications
      ))
    ) {
      // console.log('KeyService.compare FALSE');
      throw error;
    }
  }

  async removePassword(req, _res, fn) {
    try {
      await fn(
        await this.journaly?.publish('KeyService.removePasswords', req.body)
      );
      console.log(req.body);
    } catch (error) {
      // console.log('Error NAME:' + error.name);
      error.name = 'Unauthorized';
      await fn(error);
    }
  }

  getBearerAuthentication(bearer?: string) {
    const newBearer = bearer
      ? bearer.includes('Bearer ')
        ? bearer.replace('Bearer ', '')
        : bearer.includes('Bearer')
        ? bearer.replace('Bearer', '')
        : bearer
      : bearer;
    return newBearer && newBearer.length > 0 ? newBearer : undefined;
  }

  getAuthentication(req) {
    const bearer = req.headers
      ? this.getBearerAuthentication(req.headers.authorization)
      : undefined;
    const token = req.query ? req.query.token : undefined;
    return bearer || token;
  }
  async authentication(req, _res, fn) {
    if (
      (req.query && req.query.token) ||
      (req.headers && req.headers.authorization)
    ) {
      req.authorization = this.getAuthentication(req);
      const service = this.getClassName() + 'Service';
      // console.log(req.authorization);
      // console.log(req.headers);
      // console.log(req.query);
      req.headers.authorization = req.authorization;
      try {
        const auth = await this.journaly?.publish(
          service + '.authentication',
          req.authorization
        );
        // console.log('authentication', auth);
        req.permissions = auth.permissions;
        await fn(auth);
      } catch (error) {
        // console.log('Error NAME:' + error.name);
        error.name = 'Unauthorized';
        await fn(error);
      }
    } else if (req.body.identification) {
      const identification = req.body;
      const personAndIdentifications = await this.journaly?.publish(
        'PersonService.getPersonAndIdentifications',
        identification
      );
      const person = personAndIdentifications.person;
      const identifications = personAndIdentifications.identifications;
      try {
        await fn(
          await this[this.verify[identification.type]](
            identification,
            identifications,
            req.headers
          )
        );
      } catch (error) {
        await fn(error);
        return;
      }

      const cleanPerson = JSON.parse(JSON.stringify(person.receivedItem));
      delete cleanPerson.instances;
      delete cleanPerson.identifications;
      cleanPerson.identification = identifications;
      console.log(cleanPerson);
      await fn(cleanPerson);
    } else {
      const error = new Error('Missing Credentials.');
      error.name = 'Unauthorized';
      await fn(error);
    }
  }

  async permission(req, _res, fn) {
    // console.log('permission:', req.permissions);
    // console.log('event:', req.event);
    if (req.event && req.permissions) {
      const service = this.getClassName() + 'Service';
      // console.log(service);
      try {
        const permission = await this.journaly?.publish(
          service + '.permission',
          req.event,
          req.permissions
        );
        // console.log('permission', permission);
        fn(permission);
      } catch (error) {
        // console.log('Error NAME:' + error.name);
        error.name = 'Unauthorized';
        await fn(error);
      }
    } else {
      const error = new Error('Missing Permissions.');
      error.name = 'Unauthorized';
      await fn(error);
    }
  }

  async selfRestriction(req, _res, fn) {
    if (req.authorization) {
      const service = this.getClassName() + 'Service';
      // console.log(service);
      try {
        const auth = await this.journaly?.publish(
          service + '.authentication',
          req.authorization
        );
        // console.log('authentication', auth);
        if (
          (req.query && req.query.id === auth.id) ||
          (req['params'] && req['params'].filter === auth.id) ||
          (req['params'] &&
            req['params'].filter &&
            req['params'].filter.id === auth.id)
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
}
const mauth = Mauth.getInstance();

const authentication = mauth.authentication;
const permission = mauth.permission;

export { authentication, permission };
