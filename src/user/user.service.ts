import { Injectable } from '@nestjs/common';

@Injectable()
export class UserService {
  async findById(id: string) {
    console.log(id);
  }
}
