import Permissions from './permissions';

type Identification = {
  id?: unknown;
  permissions?: Permissions;
  identification: string | undefined;
  key: string | undefined;
  type: string;
  subType?: string;
  text?: string;
  html?: string;
};
export default Identification;
