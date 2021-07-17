type Verify = (
  // eslint-disable-next-line no-unused-vars
  identification: {
    identification: string | undefined;
    key: string | undefined;
    type: string;
  },
  // eslint-disable-next-line no-unused-vars
  identifications: {
    identification: string | undefined;
    key: string | undefined;
    type: string;
  }[],
  // eslint-disable-next-line no-unused-vars
  headers: {
    tokenid: string;
    picture: string;
  }
) => Promise<void>;
export default Verify;
