import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user/user.service';
import * as bcrypt from 'bcryptjs';
import { User, UserDocument } from 'src/user/schemas/user.schema';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { v4 as uuidv4 } from 'uuid';
import * as nodemailer from 'nodemailer';

@Injectable()
export class AuthService {
    async verifyEmailToken(token: string) {
        const user = await this.userModel.findOne({ verificationToken: token });
        if (!user) return null;

        user.isVerified = true;
        user.verificationToken = null;
        return user.save();
    }

    userModel: any;
    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
    ) { }

    async register(dto: RegisterDto) {
        const existingUser = await this.userModel.findOne({ email: dto.email });
        if (existingUser) {
            throw new BadRequestException('Email already exists');
        }

        const hashedPassword = await bcrypt.hash(dto.password, 10);
        const token = uuidv4();

        const createdUser = new this.userModel({
            email: dto.email,
            password: hashedPassword,
            isVerified: false,
            verificationToken: token,
        });

        await createdUser.save();

        await this.sendVerificationEmail(createdUser.email, token); // Then send email

        return { message: 'User registered. Please verify your email.' };
    }
    async sendVerificationEmail(email: string, token: string) {
        const transporter = nodemailer.createTransport({
            host: 'sandbox.smtp.mailtrap.io',
            port: 2525,
            auth: {
                user: 'your_mailtrap_user',
                pass: 'your_mailtrap_pass',
            },
        });

        const verificationUrl = `http://localhost:3000/auth/verify-email?token=${token}`;

        await transporter.sendMail({
            from: '"MyApp" <your_email@gmail.com>',
            to: email,
            subject: 'Email Verification',
            html: `<p>Click <a href="${verificationUrl}">here</a> to verify your email.</p>`,
        });
    }


    async validateUser(email: string, password: string) {
        const user = await this.userService.findByEmail(email);
        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const passwordValid = await bcrypt.compare(password, user.password);
        if (!passwordValid) {
            throw new UnauthorizedException('Invalid credentials');
        }

        return user;
    }

    async login(user: UserDocument) {
        const accessToken = await this.generateAccessToken(user);
        const refreshToken = await this.generateRefreshToken({
            sub: user._id.toString(),
            email: user.email,
            role: user.role,
        });

        await this.userService.setCurrentRefreshToken(user._id.toString(), refreshToken);

        return {
            accessToken,
            refreshToken,
        };
    }




    async refresh(refreshToken: string) {
        const payload = await this.verifyRefreshToken(refreshToken);
        const accessToken = await this.generateAccessToken(payload.sub);

        return { accessToken };
    }

    async logout(userId: string) {
        await this.userService.removeRefreshToken(userId);
    }


    async generateAccessToken(user: UserDocument): Promise<string> {
        const payload = {
            sub: user._id.toString(),
            email: user.email,
            role: user.role,
        };
        return this.jwtService.signAsync(payload, { expiresIn: '15m' });
    }




    async generateRefreshToken(payload: any): Promise<string> {
        return this.jwtService.signAsync(payload, { expiresIn: '7d' });
    }

    async verifyRefreshToken(token: string) {
        try {
            const payload = this.jwtService.verify(token);

            const user = await this.userService.findById(payload.sub);
            if (!user || !user.refreshToken) {
                throw new UnauthorizedException('Refresh token invalid');
            }

            const isTokenMatching = await bcrypt.compare(token, user.refreshToken);
            if (!isTokenMatching) {
                throw new UnauthorizedException('Refresh token mismatch');
            }

            return payload;
        } catch (error) {
            throw new UnauthorizedException('Refresh token expired or invalid');
        }
    }
}
