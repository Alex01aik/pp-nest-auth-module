import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { getUserDataFromAuthHeader } from '../utils/getUserDataFromAuthHeader';
import { Reflector } from '@nestjs/core';
import { UserRole } from '@prisma/client';

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(private reflector: Reflector) {}
  canActivate(context: ExecutionContext): boolean {
    const isAllowOwner = this.reflector.getAllAndOverride('isAllowOwner', [
      context.getHandler(),
      context.getClass(),
    ]);
    const ctx = GqlExecutionContext.create(context);
    const { headers } = ctx.getContext().req;
    const authHeader = headers.authorization;

    const role = getUserDataFromAuthHeader(authHeader, 'role');

    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(
      'roles',
      [context.getHandler(), context.getClass()],
    );

    if (!requiredRoles) {
      return true;
    }

    if (isAllowOwner) {
      const userId = getUserDataFromAuthHeader(authHeader, 'userId');
      const argUserId = ctx.getArgs().id ?? ctx.getArgs().userId;

      if (
        requiredRoles.some((rrole) => rrole === role) ||
        userId === argUserId
      ) {
        return true;
      }
    }

    return requiredRoles.some((rrole) => rrole === role);
  }
}
