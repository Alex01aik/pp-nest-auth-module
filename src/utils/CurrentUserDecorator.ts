import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { getUserDataFromAuthHeader } from './getUserDataFromAuthHeader';

export const CurrentUser = createParamDecorator(
  (data: unknown, context: ExecutionContext) => {
    const ctx = GqlExecutionContext.create(context);
    const { headers } = ctx.getContext().req;
    const authHeader = headers.authorization;

    const id = getUserDataFromAuthHeader(authHeader, 'userId');
    const role = getUserDataFromAuthHeader(authHeader, 'role');
    return { id, role };
  },
);
