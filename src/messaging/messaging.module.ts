import { Module } from '@nestjs/common';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { MessagingGateway } from './messaging.gateway';

@Module({
    imports: [
        ClientsModule.register([
            {
                name: 'CHAT_SERVICE',
                transport: Transport.TCP, // or Transport.RMQ, etc. based on what you're using
                options: {
                    host: '127.0.0.1',
                    port: 4001, // ✅ your actual chat service port
                },
            },
        ]),
    ],
    providers: [MessagingGateway],
    exports: [MessagingGateway, ClientsModule],
})
export class MessagingModule { }
