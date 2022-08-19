// file deepcode ignore no-any: any needed for type inference
import { Operation } from 'flexiblepersistence';
import UnauthorizedError from './util/unauthorizedError';
import Event from './util/event';
import Permissions from './util/permissions';

export default class Permission {
  protected static _instance: Permission;
  getInstanceName(): string {
    return process.env.INSTANCE || 'auth';
  }

  getServiceName(): string {
    return process.env.SERVICE_NAME || 'AUTH';
  }

  // eslint-disable-next-line @typescript-eslint/no-empty-function
  protected constructor() {}

  static getInstance(): Permission {
    if (!this._instance) {
      this._instance = new this();
    }
    return this._instance;
  }

  formatPermissions(instancePermissions: any): any {
    for (const key in instancePermissions) {
      if (Object.hasOwnProperty.call(instancePermissions, key)) {
        instancePermissions[key.toLowerCase()] = instancePermissions[key];
      }
    }
    return instancePermissions;
  }

  permission(event: Event, permissions: Permissions): Promise<boolean> {
    return new Promise(async (resolve, reject) => {
      try {
        const instanceName = this.getInstanceName();
        const instance = this.formatPermissions(
          permissions['all'] || permissions[instanceName]
        );

        if (instance) {
          const service =
            instance['all'] || instance[event?.name?.toLowerCase?.()];
          if (service) {
            const operationName = Operation[event.operation];
            const operation =
              service.includes('all') || service.includes(operationName);
            if (operation) resolve(true);
          }
        }
        const error = new UnauthorizedError();
        reject(error);
      } catch (error) {
        reject(error);
      }
    });
  }
}
