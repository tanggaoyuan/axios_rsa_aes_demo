import Router from 'koa-router';
import HttpRsaAesHandle from '../util/HttpRsaAesHandle';

const httpHandle = new HttpRsaAesHandle();

const router = new Router();
router.prefix('/rsa');

router.get('/config', async ctx => {
  const data = {
    code: 0,
    gzip: httpHandle.gzip,
    encryption: httpHandle.encryption,
    key: null,
    white_list: httpHandle.white_list
  };

  if (httpHandle.encryption) {
    const ras = await httpHandle.generateRas(ctx);
    data.key = ras.encode64(ras.getPublicKeyString());
  }
  ctx.body = data;
});

router.post('/report', async (ctx, next) => {
  await next();
  try {
    const data = ctx.request.body?.data;
    if (!data) {
      ctx.body = {
        code: -1,
        message: '数据错误！'
      };
      return;
    }
    const ras = httpHandle.getRas(ctx);
    if (!ras) {
      ctx.body = {
        code: -2,
        message: 'ras 过期'
      };
      return;
    }

    const text = ras.decode64(data);

    const key = ras.decrypt(text);
    const aes = httpHandle.generateAes(ctx);
    const encryptionKey = ras.encryptByPublicKey(key, JSON.stringify({ key: aes.key, iv: aes.iv }));
    ctx.body = {
      code: 0,
      message: '上报成功！',
      data: ras.encode64(encryptionKey)
    };
  } catch (error) {
    console.log('error', error);
    ctx.body = {
      code: -1,
      message: '数据错误！'
    };
  }
});

router.post('/product', async (ctx, next) => {
  await next();
  try {
    const aesHandle = httpHandle.createAesHandle(ctx);

    const params = aesHandle.parseParams();

    ctx.body = aesHandle.encryptData({ code: 0, data: { name: '产品1', price: '20.0' }, params });
  } catch (error) {
    ctx.body = {
      code: -2,
      message: error
    };
  }
});

export default router;
