import { BadRequestException, Injectable } from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(@InjectModel(User.name) private UserModel: Model<User>) {}

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
}
