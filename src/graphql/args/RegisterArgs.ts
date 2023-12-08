import { Field, ArgsType } from '@nestjs/graphql';

@ArgsType()
export class RegisterArgs {
  @Field()
  email: string;

  @Field()
  password: string;
}
