import Permissions from './permissions';

type Identification = {
  id?: unknown;
  permissions?: Permissions;
  identification: string | undefined;
  key: string | undefined;
  type: string;
  subType?: string;
  subject?: string;
  text?: string;
  html?: string;
  url?: string;
  service?: {
    url?: string;
  };
  iat?: number;
  exp?: number;
};
export default Identification;
