import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { User } from '../../user.entity';

interface RequestWithUser extends Request {
  user?: User;
}

export const CurrentUser = createParamDecorator(
  (
    data: keyof User,
    ctx: ExecutionContext,
  ): User | User[keyof User] | undefined => {
    const request = ctx.switchToHttp().getRequest<RequestWithUser>();

    return data ? request.user?.[data] : request.user;
  },
);
