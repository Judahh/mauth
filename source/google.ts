import { OAuth2Client } from 'google-auth-library';
import AuthService from './util/authService';
import Headers from './util/headers';
import Identification from './util/identification';
import UnauthorizedError from './util/unauthorizedError';
import UpdatePicture from './util/updatePicture';

export default class Google implements AuthService {
  protected updatePicture: UpdatePicture;
  constructor(updatePicture: UpdatePicture) {
    this.updatePicture = updatePicture;
  }
  async verify(
    identification: Identification,
    identifications: Identification[],
    headers?: Headers
  ): Promise<void> {
    const error = new UnauthorizedError('GAccount error.');
    // console.log('verifyGoogle');
    if (!(await this.compare(identification, identifications, headers))) {
      // console.log('KeyService.compare FALSE');
      throw error;
    }
  }
  async checkPicture(
    identification: Identification,
    headers: Headers,
    item?: { picture?: string },
    payload?: { picture?: string }
  ): Promise<void> {
    if (payload && payload.picture && payload.picture !== headers.picture) {
      // console.log(payload.picture);
      if (item) {
        if (Array.isArray(item)) {
          for (const received of item) {
            received.picture = payload.picture;
          }
        } else item.picture = payload.picture;
      } else this.updatePicture(identification, payload.picture);
    }
  }
  async checkToken(
    identification: Identification,
    headers?: Headers,
    item?: { picture: string }
  ): Promise<boolean> {
    return new Promise(async (resolve) => {
      // console.log('checkToken');
      // console.log(identification);
      // console.log(headers);
      // console.log(item);
      if (headers && headers.tokenid) {
        const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
        const ticket = await client.verifyIdToken({
          idToken: headers.tokenid,
          audience: process.env.GOOGLE_CLIENT_ID,
          // Specify the CLIENT_ID of the app that accesses the backend
          // Or, if multiple clients access the backend:
          //[CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3]
        });
        const payload = ticket.getPayload();
        // console.log(process.env.GOOGLE_CLIENT_ID);
        // console.log(headers.tokenid);
        // console.log(headers);
        // console.log(payload);
        // console.log(identification);
        if (
          !(
            payload &&
            payload['email'] === identification.identification &&
            payload['email_verified']
          )
        )
          resolve(false);

        // console.log(payload);
        // console.log(item);
        this.checkPicture(identification, headers, item, payload);
        resolve(true);
        // const userid = payload['sub'];
        // If request specified a G Suite domain:
        //const domain = payload['hd'];
      }
      resolve(false);
    });
  }
  async compare(
    rIdentification: Identification,
    identifications: Identification[],
    headers?: Headers
  ): Promise<boolean> {
    for (const identification of identifications) {
      if (identification.identification === rIdentification.identification)
        if (await this.checkToken(rIdentification, headers)) return true;
    }
    return false;
  }
}
