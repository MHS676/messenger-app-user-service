import {
    BadRequestException,
    Injectable,
    NotFoundException,
    UnauthorizedException,
    Logger,
    Inject,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { User, UserRole } from './schemas/user.schema';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { MessagingGateway } from '../messaging/messaging.gateway';
import { ClientProxy } from '@nestjs/microservices';

@Injectable()
export class UserService {
    private readonly logger = new Logger(UserService.name);

    constructor(
        @InjectModel(User.name) private readonly userModel: Model<User>,
        private readonly messagingGateway: MessagingGateway,
        @Inject('CHAT_SERVICE') private readonly chatClient: ClientProxy,
    ) { }

    private validatePasswordStrength(password: string) {
        const isValid = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/.test(password);
        if (!isValid) {
            throw new BadRequestException(
                'Password must contain 1 uppercase, 1 lowercase, 1 number and be 8+ characters.'
            );
        }
    }

    async create(dto: CreateUserDto): Promise<User> {
        const { username, email, password, role = UserRole.USER } = dto;
        const exists = await this.userModel.findOne({ $or: [{ username }, { email }] });
        if (exists) throw new BadRequestException('Username or email already exists.');

        if (dto.role && dto.role !== UserRole.USER) {
            throw new BadRequestException('Manual role setting not allowed');
        }

        this.validatePasswordStrength(password);
        const hashed = await bcrypt.hash(password, 10);

        return await new this.userModel({
            username,
            email,
            password: hashed,
            role,
        }).save();
    }

    async findByEmail(email: string): Promise<User> {
        const user = await this.userModel.findOne({ email, isDeleted: false });
        if (!user) throw new NotFoundException('User not found');
        return user;
    }

    async findById(id: string): Promise<User> {
        const user = await this.userModel.findOne({ _id: id, isDeleted: false });
        if (!user) throw new NotFoundException('User not found');
        return user;
    }

    async update(userId: string, dto: UpdateUserDto): Promise<User> {
        const updated = await this.userModel.findByIdAndUpdate(userId, dto, { new: true });
        if (!updated) throw new NotFoundException('User not found');
        this.logger.log(`User ${userId} updated profile.`);
        return updated;
    }

    async changePassword(userId: string, oldPassword: string, newPassword: string) {
        const user = await this.userModel.findById(userId);
        if (!user) throw new NotFoundException('User not found');

        const match = await bcrypt.compare(oldPassword, user.password);
        if (!match) throw new UnauthorizedException('Old password is incorrect');

        this.validatePasswordStrength(newPassword);
        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();
    }

    async setCurrentRefreshToken(userId: string, refreshToken: string): Promise<void> {
        await this.userModel.findByIdAndUpdate(userId, { refreshToken });
    }

    async removeRefreshToken(userId: string): Promise<void> {
        await this.userModel.findByIdAndUpdate(userId, { $unset: { refreshToken: '' } });
    }

    async softDelete(userId: string): Promise<void> {
        const user = await this.userModel.findById(userId);
        if (!user) throw new NotFoundException('User not found');
        user.isDeleted = true;
        await user.save();
    }

    async sendMessage(senderId: string, receiverId: string, content: string) {
        try {
            // 1. Save message via chat microservice
            await this.chatClient
                .send({ cmd: 'send_message' }, { senderId, receiverId, content })
                .toPromise();

            // 2. Then send message via WebSocket
            await this.messagingGateway.sendMessage(senderId, receiverId, content);

            return { success: true };
        } catch (err) {
            this.logger.error(`Send message failed: ${err.message}`, err.stack);
            throw new BadRequestException('Could not send message');
        }
    }

}
