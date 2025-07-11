import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  //TODO: POST Signup
  @Post('signup')
  async signup(@Body() signupData: SignupDto) {
    return this.authService.signup(signupData);
  }

  //TODO: POST Login
  @Post('login')
  async login(@Body() credentials: LoginDto) {
    return this.authService.login(credentials);
  }


  //TODO: POST Refresh Token
}
