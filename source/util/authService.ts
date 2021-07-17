/* eslint-disable no-unused-vars */
export default interface AuthService {
  verify(
    identification: unknown,
    identifications: unknown,
    headers: unknown
  ): Promise<void>;
}
