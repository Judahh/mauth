import Identification from './identification';
import Headers from './headers';

type Sender = (
  person:any,
  identification:Identification,
) => Promise<void>;
export default Sender;
