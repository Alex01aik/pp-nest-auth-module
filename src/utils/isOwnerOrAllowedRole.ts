import { ForbiddenException } from "@nestjs/common/exceptions";
import { DefaultUserType } from "../common/interface/DefaultUser";

export const isOwnerOrAllowedRole = <User, UserRole>(
  objectUser: User & DefaultUserType,
  user: User & DefaultUserType,
  allowedRoles?: UserRole[]
) => {
  if (
    !(
      allowedRoles?.some((role) => role === user.role) ||
      objectUser.id === user.id
    )
  ) {
    throw new ForbiddenException();
  }
};
