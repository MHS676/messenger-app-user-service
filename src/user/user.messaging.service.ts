import { Inject, Injectable } from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';

@Injectable()
export class MessagingGateway {
    constructor(
        @Inject('REDIS_SERVICE') private readonly client: ClientProxy,
    ) { }

    async sendMessage(senderId: string, receiverId: string, content: string) {
        return this.client.send({ cmd: 'send_message' }, { senderId, receiverId, content }).toPromise();
    }
}
