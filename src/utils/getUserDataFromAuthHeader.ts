import { authHeaderPrefix } from './authHeaderPrefix';
import * as jwt from 'jsonwebtoken';

export const getUserDataFromAuthHeader = (
  authHeader: string,
  fieldName: string,
) => {
  const authToken =
    authHeader.slice(0, authHeader.indexOf(authHeaderPrefix)) +
    authHeader.slice(
      authHeader.indexOf(authHeaderPrefix) + authHeaderPrefix.length,
    );
  const decodedToken = jwt.verify(authToken, process.env.SECRET_KEY);

  return decodedToken[fieldName];
};
