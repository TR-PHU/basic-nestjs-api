import { ConfigService } from '@nestjs/config';
import { AuthDTO } from './dto/auth.dto';
import { PrismaService } from './../prisma/prisma.service';
import { ForbiddenException, Injectable } from '@nestjs/common';
import { User } from '@prisma/client';
import { compare, genSalt, hash } from 'bcrypt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signUp(dto: AuthDTO) {
    // generate salt
    const salt = await genSalt(10);
    // hash password
    const hashPassword = await hash(dto.password, salt);
    // save user into db
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: hashPassword,
        },
      });
      const jwt = await this.signToken(user.id, user.email);
      return {
        user: {
          email: user.email,
        },
        accessToken: jwt.accessToken,
        expiresIn: jwt.expiresIn,
      };
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }
  async signIn(dto: AuthDTO) {
    // find the user by email
    // if user does not exist throw exception
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new ForbiddenException('Credential incorrect');
    }
    // compare password
    // if password incorrect throw exception
    const passwdMatches = await compare(dto.password, user.password);
    if (!passwdMatches) {
      throw new ForbiddenException('Credential incorrect');
    }

    const jwt = await this.signToken(user.id, user.email);
    return {
      user: {
        email: user.email,
      },
      accessToken: jwt.accessToken,
      expiresIn: jwt.expiresIn,
    };
  }
  async signToken(
    userId: number,
    email: string,
  ): Promise<{ accessToken: string; expiresIn: string }> {
    const payload = { sub: userId, email };

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: this.config.get('JWT_SECRET'),
    });

    return {
      accessToken: token,
      expiresIn: '15m',
    };
  }
}
