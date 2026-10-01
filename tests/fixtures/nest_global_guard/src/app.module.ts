import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { JwtAuthGuard } from './jwt-auth.guard';
import { UsersController } from './users.controller';

// Guard GLOBAL: toda ruta exige autenticación salvo las marcadas con @Public().
@Module({
  controllers: [UsersController],
  providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }],
})
export class AppModule {}
