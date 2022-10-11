import Router from 'koa-router';
import RSARouter from './ras_router';

const router = new Router();

router.use(RSARouter.routes());

export default router;
