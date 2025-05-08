import {
  Controller, Get, Patch, Post, Body, Request, UseGuards, Delete,
} from '@nestjs/common';
import { UserService } from './user.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from './schemas/user.schema';

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) { }

  @Post()
  async create(@Body() createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  async getProfile(@Request() req) {
    return this.userService.findById(req.user._id);
  }

  @UseGuards(JwtAuthGuard)
  @Patch()
  async updateProfile(@Request() req, @Body() updateUserDto: UpdateUserDto) {
    return this.userService.update(req.user._id, updateUserDto);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('change-password')
  async changePassword(@Request() req, @Body() dto: ChangePasswordDto) {
    await this.userService.changePassword(req.user._id, dto.oldPassword, dto.newPassword);
    return { message: 'Password changed successfully' };
  }

  @UseGuards(JwtAuthGuard)
  @Delete('soft-delete')
  async softDelete(@Request() req) {
    await this.userService.softDelete(req.user._id);
    return { message: 'User soft-deleted successfully' };
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Get('admin-only')
  @Roles(UserRole.ADMIN)
  getAdminResource() {
    return { message: 'Only admin can see this.' };
  }

  @UseGuards(JwtAuthGuard)
  @Post('send-message')
  async sendMessage(
    @Request() req,
    @Body('receiverId') receiverId: string,
    @Body('content') content: string,
  ) {
    const senderId = req.user._id;
    return this.userService.sendMessage(senderId, receiverId, content);
  }
}
