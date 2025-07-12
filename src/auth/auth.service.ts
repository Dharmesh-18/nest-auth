import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dtos/login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-tokens.schema';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private UserModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private RefreshTokenModel: Model<RefreshToken>,
    private jwtService: JwtService,
  ) {}

  async signup(signupData: SignupDto) {
    const { email, password, name } = signupData;

    //TODO: Check if email is in use
    const existingUser = await this.UserModel.findOne({
      email,
    });
    if (existingUser) {
      throw new BadRequestException('Email is already in use');
    }

    //TODO: Hash password
    const hashedPassword = await bcrypt.hash(signupData.password, 10);

    //TODO: Create user document and save in mongoDB
    const createdUser = await this.UserModel.create({
      name,
      email,
      password: hashedPassword,
    });

    return {
      message: 'User created successfully',
      user: {
        id: createdUser._id,
        email: createdUser.email,
        name: createdUser.name,
      },
    };
  }

  async login(credentials: LoginDto) {
    const { email, password } = credentials;

    // TODO: Check if user exists
    const existingUser = await this.UserModel.findOne({ email });
    if (!existingUser) {
      throw new UnauthorizedException('User not found');
    }

    // TODO: compare password with existing password
    const isPasswordValid = await bcrypt.compare(
      password,
      existingUser.password,
    );
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    // TODO: Return JWT
    const tokens = await this.generateUserTokens(existingUser._id!.toString());

    return {
      message: 'Login successful',
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  async refreshTokens(refreshToken: string) {
    const token = await this.RefreshTokenModel.findOne({
      token: refreshToken,
      expiryDate: { $gte: new Date() },
    });
    if (!token) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
    return this.generateUserTokens(token.userId);
  }

  async changePassword(
    userId: string,
    oldPassword: string,
    newPassword: string,
  ) {
    // check if user exists
    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    // check if old password is correct
    const isOldPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isOldPasswordValid) {
      throw new UnauthorizedException('Old password is incorrect');
    }

    // check if new password is the same as old password
    if (oldPassword === newPassword) {
      throw new BadRequestException(
        'New password cannot be the same as old password',
      );
    }
    // hash new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    // update user password
    await this.UserModel.updateOne(
      { _id: userId },
      { password: hashedNewPassword },
    );

    return {
      message: 'Password changed successfully',
    };
  }

  // ------------------- Private methods for token generation --------------------
  async generateUserTokens(userId: string) {
    const accessToken = this.jwtService.sign({ userId }, { expiresIn: '1h' });
    const refreshToken = uuidv4();
    await this.storeRefreshToken(refreshToken, userId);

    return {
      accessToken,
      refreshToken,
    };
  }

  async storeRefreshToken(token: string, userId: string) {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);

    await this.RefreshTokenModel.updateOne(
      { userId },
      { token, expiryDate },
      { upsert: true },
    );
  }
}
