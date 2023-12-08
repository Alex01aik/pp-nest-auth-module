import { SetMetadata } from '@nestjs/common';

export const AllowOwner = () => SetMetadata('isAllowOwner', true);
