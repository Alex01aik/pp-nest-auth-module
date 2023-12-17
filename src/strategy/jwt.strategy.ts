import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { AuthService } from "../auth.service";

@Injectable()
export class JwtStrategy<User> extends PassportStrategy(Strategy) {
  constructor(private readonly authService: AuthService<User>) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.SECRET_KEY,
    });
  }

  async validate(payload: any) {
    const user = await this.authService.findUserById(payload.userId);
    const expirationDate = new Date(payload.exp * 1000);
    const currentDate = new Date();

    if (expirationDate < currentDate || !user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
