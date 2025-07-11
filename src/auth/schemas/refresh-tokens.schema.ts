import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';

@Schema()
export class RefreshToken extends Document {
  @Prop({ required: true })
  token: string;

  @Prop({ required: true, type: mongoose.Types.ObjectId })
  userId: string;

  @Prop({ required: true })
  expiryDate: Date;
}

export const RefreshTokenSchema = SchemaFactory.createForClass(RefreshToken);
