import { DynamicModule, Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { AuthResolver } from './graphql/auth.resolver';
import { JwtStrategy } from './guard/jwt.strategy';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';

export type AuthProviders = {
  UserService: any;
  PrismaService: any;
};

@Module({})
export class AuthModule {
  static forRoot({ providers }: { providers: AuthProviders }): DynamicModule {
    return {
      module: AuthModule,
      imports: [
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.registerAsync({
          useFactory: async () => ({
            secret: process.env.SECRET_KEY,
          }),
        }),
      ],
      providers: [
        JwtStrategy,
        AuthService,
        AuthResolver,
        providers.PrismaService,
        {
          provide: 'UserService',
          useClass: providers.UserService,
        },
      ],
    };
  }
}
