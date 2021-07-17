import Identification from './identification';
import Headers from './headers';

type Verify = (
  // eslint-disable-next-line no-unused-vars
  identification: Identification,
  // eslint-disable-next-line no-unused-vars
  identifications: Identification[],
  // eslint-disable-next-line no-unused-vars
  headers?: Headers
) => Promise<void>;
export default Verify;
