import { Resolver, Query, Mutation, Args } from '@nestjs/graphql';
import { LoginArgs } from './args/LoginArgs';
import { Tokens } from './outputs/Tokens';
import { RefreshArgs } from './args/RefreshArgs';
import { AuthService } from '../auth.service';
import {
  BadRequestException,
  Inject,
  UnauthorizedException,
} from '@nestjs/common';

@Resolver()
export class AuthResolver {
  constructor(
    private readonly authService: AuthService,
    @Inject('UserService') private readonly userService: any,
  ) {}
  @Query(() => Tokens)
  async login(@Args() args: LoginArgs): Promise<Tokens> {
    const user = await this.authService.validateUser(args.email, args.password);
    if (!user) {
      throw new UnauthorizedException();
    }
    const tokens = await this.authService.generateTokens(user);
    return tokens;
  }
  @Mutation(() => Tokens)
  async register(@Args() args: LoginArgs): Promise<Tokens> {
    const user = await this.authService.createUser(args);
    if (!user) {
      throw new BadRequestException();
    }
    const tokens = await this.authService.generateTokens(user);
    return tokens;
  }
  @Query(() => Tokens)
  async refresh(@Args() args: RefreshArgs): Promise<Tokens> {
    const userId = await this.authService.getUserIdByRefreshToken(args.token);
    const user = await this.userService.findById(userId);
    const tokens = await this.authService.generateTokens(user);
    return tokens;
  }
}
