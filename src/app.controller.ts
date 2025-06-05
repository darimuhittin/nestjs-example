import { Controller, Get, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { CurrentUser } from './util/decorators';
import { AuthGuard } from './util/guards/auth.guard';
import { User } from './user.entity';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  // Protected routes - require authentication
  @Get('profile')
  @UseGuards(AuthGuard)
  getProfile(@CurrentUser() user: User): User {
    return user;
  }

  @Get('me')
  @UseGuards(AuthGuard)
  getCurrentUser(@CurrentUser() user: User): User {
    return user;
  }

  @Get('my-email')
  @UseGuards(AuthGuard)
  getCurrentUserEmail(@CurrentUser('email') email: string): { email: string } {
    return { email };
  }

  @Get('my-id')
  @UseGuards(AuthGuard)
  getCurrentUserId(@CurrentUser('id') userId: string): { id: string } {
    return { id: userId };
  }
}
