/* eslint-disable no-unused-vars */
export default interface ICrypt {
  compare(data: string, encrypted: string): Promise<boolean>;
  hash(data: string, hashSaltRounds: number): Promise<string>;
}
