import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { JwtService } from "@nestjs/jwt";
import internal from "stream";

@Injectable({})
export class AuthService{
    constructor(
      private prisma: PrismaService, 
      private jwt: JwtService) {}
    
    async signup(dto: AuthDto){

        // generate password hash
        const hash = await argon.hash(dto.password);

        // save the user to db

        try {
            const user = await this.prisma.user.create({
                data: {
                  email: dto.email,
                  hash,
                },
              });

            delete user.hash;
        
            // return the saved user
            return user;
        }
        catch (error) {
            if (
              error instanceof
              PrismaClientKnownRequestError
            ) {
              if (error.code === 'P2002') {
                throw new ForbiddenException(
                  'Credentials taken',
                );
              }
            }
            throw error;
          }

        // return {
        //     msg: "This is sign up"
        // } 
    }

    async signin(dto: AuthDto){
         // find the user by email
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
        });

        // if user does not exist throw exception
        if (!user)
            throw new ForbiddenException(
                'Credentials incorrect',
            );

        // compare passwords
        const pwMatches = await argon.verify(user.hash, dto.password);
        if (!pwMatches)
            throw new ForbiddenException(
                'Credentials incorrect',
            );

        // return user
        delete user.hash;
        return user;

    }

    async signToken(
      userId: number,
      email: string
    ){
      const payload = {
        sub: userId,
        email
      }

      return this.jwt.signAsync(payload, {
        expiresIn: '15m',
        secret: ''
      })
    }
}