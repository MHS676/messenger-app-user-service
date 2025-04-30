import {
    Controller,
    Post,
    Body,
    Req,
    UseGuards,
    Request as ReqDecorator,
    BadRequestException,
    Query,
    Get,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { AuthGuard } from '@nestjs/passport';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { UserDocument } from 'src/user/schemas/user.schema';
import { Request as ExpressRequest } from 'express';

type AuthenticatedRequest = ExpressRequest & { user: UserDocument };

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post('login')
    @UseGuards(LocalAuthGuard)
    async login(@ReqDecorator() req: AuthenticatedRequest) {
        return this.authService.login(req.user);
    }

    @Post('refresh')
    async refresh(@Body('refreshToken') refreshToken: string) {
        return this.authService.refresh(refreshToken);
    }

    @Post('logout')
    @UseGuards(AuthGuard('jwt'))
    async logout(@Req() req: AuthenticatedRequest) {
        const user = req.user;
        await this.authService.logout(user._id.toString());
        return { message: 'Logged out successfully' };
    }

    @Get('verify-email')
    async verifyEmail(@Query('token') token: string) {
        const user = await this.authService.verifyEmailToken(token);
        if (!user) {
            throw new BadRequestException('Invalid or expired token');
        }

        return { message: 'Email verified successfully' };
    }

}
