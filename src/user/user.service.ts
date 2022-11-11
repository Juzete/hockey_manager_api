import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import User from './user.entity';

@Injectable()
export class UserService {
  constructor(@InjectRepository(User) private userRepo: Repository<User>) {}

  async findById(id: any) {
    const user = await this.userRepo.findOne({ where: { id: id } });
    if (user) {
      return user;
    }

    throw new HttpException(
      'User with this ID does not exist',
      HttpStatus.NOT_FOUND,
    );
  }
}
