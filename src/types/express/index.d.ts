import { UserDocument } from '../../src/user/schemas/user.schema';

declare namespace Express {
    export interface Request {
        user?: UserDocument;
    }
}
