import { Controller, Delete, Get, Param } from '@nestjs/common';

@Controller('users')
export class UsersController {
  // Sin decorador de autorización local: lo cubre el APP_GUARD global.
  @Get(':id')
  findOne(@Param('id') id: string) { return { id }; }

  @Delete(':id')
  remove(@Param('id') id: string) { return { removed: id }; }
}
