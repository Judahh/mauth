import AuthService from './util/authService';
import Identification from './util/identification';
import UnauthorizedError from './util/unauthorizedError';

export default class KeyLess implements AuthService {
  async verify(
    identification: Identification,
    identifications: Identification[]
  ): Promise<void> {
    console.log(identification);
    console.log(identifications);
    for (const rIdentification of identifications) {
      if (identification.identification === rIdentification.identification)
        return;
    }
    const error = new UnauthorizedError();
    throw error;
  }
}
