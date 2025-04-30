import { Injectable } from '@nestjs/common';
import { InjectConnection } from '@nestjs/mongoose';
import { Connection } from 'mongoose';

@Injectable()
export class IndexCleanerService {
    constructor(@InjectConnection() private readonly connection: Connection) { }

    async dropNameIndex() {
        try {
            await this.connection.collection('users').dropIndex('name_1');
            console.log('Dropped index: name_1');
        } catch (error) {
            console.error('Index drop failed:', error.message);
        }
    }
}
