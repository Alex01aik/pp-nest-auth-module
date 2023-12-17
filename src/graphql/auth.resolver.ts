import { Resolver, Query, Mutation, Args, Context } from '@nestjs/graphql';
import { LoginArgs } from './args/LoginArgs';
import { AccessToken } from './outputs/AccessToken';
import { AuthService } from '../auth.service';
import {
  BadRequestException,
  Inject,
  UnauthorizedException,
} from '@nestjs/common';

@Resolver()
export class AuthResolver<User> {
  constructor(
    private readonly authService: AuthService<User>,
    @Inject('UserService') private readonly userService: any,
  ) {}

  @Query(() => AccessToken)
  async login(
    @Args() args: LoginArgs,
    @Context() ctx: any,
  ): Promise<AccessToken> {
    const user = await this.authService.validateUser(args.email, args.password);
    if (!user) {
      throw new UnauthorizedException();
    }
    const tokens = await this.authService.generateTokens(user);
    ctx.res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
    });
    return { accessToken: tokens.refreshToken };
  }

  @Mutation(() => AccessToken)
  async register(
    @Args() args: LoginArgs,
    @Context() ctx: any,
  ): Promise<AccessToken> {
    const user = await this.authService.createUser(args);
    if (!user) {
      throw new BadRequestException();
    }
    const tokens = await this.authService.generateTokens(user);
    ctx.res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
    });
    return { accessToken: tokens.accessToken };
  }

  @Query(() => AccessToken)
  async refresh(@Context() ctx: any): Promise<AccessToken> {
    console.log();
    const userId = await this.authService.getUserIdByRefreshToken(
      ctx.req.cookies.refreshToken,
    );
    const user = await this.userService.findById(userId);
    const tokens = await this.authService.generateTokens(user);
    return { accessToken: tokens.accessToken };
  }
}
