import { SetMetadata } from "@nestjs/common";

export const Roles = <UserRole>(...roles: UserRole[]) =>
  SetMetadata("roles", roles);
