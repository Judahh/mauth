export default class UnauthorizedError extends Error {
  constructor(message?: string) {
    super(message ? message : 'Unauthorized');
    this.name = 'Unauthorized';
  }
}
