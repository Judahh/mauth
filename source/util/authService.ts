import Identification from './identification';

/* eslint-disable no-unused-vars */
export default interface AuthService {
  verify(
    identification: Identification,
    identifications: Identification[],
    headers?: Headers
  ): Promise<void>;
}
