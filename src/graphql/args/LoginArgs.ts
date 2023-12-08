import { Field, ArgsType } from '@nestjs/graphql';

@ArgsType()
export class LoginArgs {
  @Field()
  email: string;

  @Field()
  password: string;
}
