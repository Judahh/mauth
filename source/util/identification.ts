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
};
export default Identification;
