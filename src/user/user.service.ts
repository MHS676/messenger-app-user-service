import {
    BadRequestException,
    Injectable,
    NotFoundException,
    UnauthorizedException,
    Logger,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';

import { User, UserRole } from './schemas/user.schema';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UserService {
    private readonly logger = new Logger(UserService.name);

    constructor(@InjectModel(User.name) private readonly userModel: Model<User>) { }

    private validatePasswordStrength(password: string) {
        const isValid = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/.test(password);
        if (!isValid) {
            throw new BadRequestException('Password too weak. It must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and be at least 8 characters long.');
        }
    }

    async create(createUserDto: CreateUserDto): Promise<User> {
        const { username, email, password, role = UserRole.USER } = createUserDto;

        const existingUser = await this.userModel.findOne({
            $or: [{ username }, { email }],
        });

        if (existingUser) {
            throw new BadRequestException('Username or email already exists.');
        }

        if (createUserDto.role && createUserDto.role !== UserRole.USER) {
            throw new BadRequestException('Cannot set role manually');
        }


        this.validatePasswordStrength(password);

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new this.userModel({
            username,
            email,
            password: hashedPassword,
            role,
        });

        return await newUser.save();
    }

    async findByEmail(email: string): Promise<User> {
        const user = await this.userModel.findOne({ email, isDeleted: false }).exec();
        if (!user) throw new NotFoundException('User not found');
        return user;
    }

    async findById(id: string): Promise<User> {
        const user = await this.userModel.findById({ id, isDeleted: false }).exec();
        if (!user) throw new NotFoundException('User not found');
        return user;
    }

    async update(userId: string, updateUserDto: UpdateUserDto): Promise<User> {
        const updated = await this.userModel.findByIdAndUpdate(userId, updateUserDto, {
            new: true,
        });
        if (!updated) throw new NotFoundException('User not found');
        this.logger.log(`User ${userId} profile updated.`);
        return updated;
    }

    async changePassword(userId: string, oldPassword: string, newPassword: string): Promise<void> {
        const user = await this.userModel.findById(userId);
        if (!user) throw new NotFoundException('User not found');

        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) throw new UnauthorizedException('Old password is incorrect');

        this.validatePasswordStrength(newPassword);

        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedNewPassword;
        await user.save();
        this.logger.log(`User ${userId} changed password.`);
    }

    async setCurrentRefreshToken(userId: string, refreshToken: string): Promise<void> {
        // Optionally hash refreshToken before storing
        await this.userModel.findByIdAndUpdate(userId, {
            refreshToken,
        });
    }

    async removeRefreshToken(userId: string): Promise<void> {
        await this.userModel.findByIdAndUpdate(userId, {
            $unset: { refreshToken: '' },
        });
    }

    async softDelete(userId: string): Promise<void> {
        const user = await this.userModel.findById(userId);
        if (!user) throw new NotFoundException('User not found');

        user.isDeleted = true;
        await user.save();
    }

}
