import Permissions from './permissions';

type Identification = {
  id?: unknown;
  permissions?: Permissions;
  identification: string | undefined;
  key: string | undefined;
  type: string;
};
export default Identification;
