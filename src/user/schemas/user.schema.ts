import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

export enum UserRole {
  USER = 'user',
  ADMIN = 'admin',
}

@Schema()
export class User {
  @Prop({ required: true })
  username: string;

  @Prop({ required: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ default: false })
  isVerified: boolean;

  @Prop()
  verificationToken?: string;

  @Prop({ type: String, default: null })
  refreshToken?: string | null;

  @Prop({ default: false })
  isDeleted: boolean;

  @Prop({ enum: UserRole, default: UserRole.USER })
  role: UserRole;
}

export type UserDocument = User & Document & { _id: Types.ObjectId };

export const UserSchema = SchemaFactory.createForClass(User);
