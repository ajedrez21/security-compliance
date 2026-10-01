import { ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

export const IS_PUBLIC = 'isPublic';

// Guard GLOBAL de autenticación + autorización: default-deny.
// Una ruta solo se salta el guard con @Public(); el resto exige usuario autenticado y política por recurso.
@Injectable()
export class JwtAuthGuard {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, [context.getHandler(), context.getClass()]);
    if (isPublic) return true;
    const req = context.switchToHttp().getRequest();
    const user = req.user; // payload ya verificado (firma, iss, aud, exp) por la estrategia JWT
    if (!user) return false;
    // Política de acceso por objeto para /users/:id: el propio usuario o un administrador.
    if (req.params && req.params.id !== undefined) {
      return user.sub === req.params.id || (user.roles || []).includes('admin');
    }
    return true;
  }
}
