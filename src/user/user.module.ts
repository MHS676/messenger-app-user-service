import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './schemas/user.schema';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { MessagingModule } from 'src/messaging/messaging.module'; // ✅ already imported

@Module({
  imports: [
    MessagingModule, // ✅ correctly imported
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
  ],
  controllers: [UserController],
  providers: [UserService], // ✅ REMOVE MessagingGateway from here
  exports: [UserService],
})
export class UserModule { }
