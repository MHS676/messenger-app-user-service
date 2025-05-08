import {
    WebSocketGateway,
    WebSocketServer,
    SubscribeMessage,
    MessageBody,
    ConnectedSocket,
    OnGatewayConnection,
    OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Inject, Injectable, Logger } from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';

@WebSocketGateway({
    cors: {
        origin: '*',
    },
})
@Injectable()
export class MessagingGateway implements OnGatewayConnection, OnGatewayDisconnect {
    @WebSocketServer()
    server: Server;

    private readonly logger = new Logger(MessagingGateway.name);

    constructor(@Inject('CHAT_SERVICE') private readonly client: ClientProxy) { }

    handleConnection(socket: Socket) {
        const userId = socket.handshake.query.userId as string;
        if (userId) {
            socket.join(userId); // Join user's personal room
            this.logger.log(`✅ Client connected: ${userId} | Socket ID: ${socket.id}`);
        } else {
            this.logger.warn(`❌ Connection attempt without userId`);
            socket.disconnect(true);
        }
    }

    handleDisconnect(socket: Socket) {
        this.logger.log(`🔌 Client disconnected: Socket ID = ${socket.id}`);
    }

    // Emit a WebSocket message to a specific user room
    async sendMessage(senderId: string, receiverId: string, content: string) {
        this.logger.log(`📨 Sending WebSocket message to ${receiverId}`);
        this.server.to(receiverId).emit('receive_message', { senderId, content });
        return { success: true };
    }

    // Microservice message forwarding
    async sendMessageToChatService(payload: any): Promise<any> {
        this.logger.log(`➡️ Forwarding message to chat service`);
        return this.client.send({ cmd: 'send_message' }, payload).toPromise();
    }

    // Optional: handle message received acknowledgment from client
    @SubscribeMessage('message_received_ack')
    handleMessageAck(@MessageBody() data: any, @ConnectedSocket() socket: Socket) {
        this.logger.log(`✅ ACK from ${socket.id}:`, data);
    }

    // Optional: handle typing events
    @SubscribeMessage('typing')
    handleTyping(@MessageBody() data: any) {
        const { senderId, receiverId, isTyping } = data;
        this.server.to(receiverId).emit('typing', { senderId, isTyping });
    }
}
