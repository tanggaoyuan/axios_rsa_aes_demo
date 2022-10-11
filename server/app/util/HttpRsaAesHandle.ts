import RSA from './Rsa';
import AES from './Aes';
import { pathToRegexp } from 'path-to-regexp';
import pako from 'pako';

class HttpRsaAesHandle {
    private rsaMap: Map<string, { expireTime: number, rsa: RSA }>;
    private aesMap: Map<string, { expireTime: number, aes: AES }>;

    public encryption: boolean;
    public gzip: boolean;
    public white_list: Array<string> = [];

    constructor(encryption = true, gzip = false) {
        this.encryption = encryption;
        this.gzip = gzip;

        this.rsaMap = new Map();
        this.aesMap = new Map();

        // 模拟加密过期
        setInterval(() => {
            const current = Date.now();
            this.rsaMap.forEach((value, key) => {
                if (value.expireTime - current < 0) {
                    this.rsaMap.delete(key);
                }
            });
            this.aesMap.forEach((value, key) => {
                if (value.expireTime - current < 0) {
                    this.aesMap.delete(key);
                }
            });
        }, 10000);
    }

    public async generateRas(ctx: any,) {
        const keys = await RSA.generateKeyPair();
        const rsa = new RSA(keys);
        const rsaId = `RSA_${Date.now()}`;
        this.rsaMap.set(rsaId, { expireTime: Date.now() + 20000, rsa });
        ctx.cookies.set('rsaId', rsaId);
        return rsa;
    }

    public getRas(ctx: any) {
        const rsaId = ctx.cookies.get('rsaId');
        const { rsa } = this.rsaMap.get(rsaId);
        return rsa;
    }

    public generateAes(ctx: any) {
        const aesId = `AES_${Date.now()}`;
        ctx.cookies.set('aesId', aesId);
        const aes = new AES();
        this.aesMap.set(aesId, { expireTime: Date.now() + 20000, aes });
        return aes;
    }

    public getAes(ctx: any) {
        const aesId = ctx.cookies.get('aesId');
        const { aes } = this.aesMap.get(aesId) || {};
        return aes;
    }

    public static compress(data: string) {
        const arr = Array.from(pako.gzip(data));
        let str = '';
        arr.forEach((item: number) => {
            str += String.fromCharCode(item);
        });
        return btoa(str);
    }

    public static decompression(data: string) {
        const arr = pako.ungzip(new Uint8Array(atob(data).split('').map(function (x) {
            return x.charCodeAt(0);
        })));
        let str = '';
        const chunk = 8 * 1024;
        const length = Math.ceil(arr.length / chunk);
        for (let i = 0; i < length; i++) {
            str += String.fromCharCode.apply(null, arr.slice(i * chunk, (i + 1) * chunk));
        }
        return str;
    }

    public createAesHandle(ctx: any) {
        const path = ctx.url.split('?')[0];

        const aes = this.getAes(ctx);

        let isWhite = false;
        for (const url of this.white_list) {
            const reg = pathToRegexp(url);
            isWhite = reg.test(path);
            if (isWhite) {
                break;
            }
        }

        const parseParams = () => {
            let data = ctx.request.body || {};
            let params = ctx.query || {};

            if (isWhite || !this.encryption && !this.gzip) {
                return { ...data, ...params };
            }

            data = data.data;
            params = params.data;

            if (this.gzip) {
                data = data ? HttpRsaAesHandle.decompression(data) : '';
                params = params ? HttpRsaAesHandle.decompression(params) : '';
            }

            if (this.encryption) {
                data = data ? aes.decrypt(data) : '';
                params = params ? aes.decrypt(params) : '';
            }

            data = data ? JSON.parse(data) : {};
            params = params ? JSON.parse(params) : {};

            return { ...data, ...params };
        };

        const encryptData = (data:any) => {
            if (isWhite || !this.gzip && !this.encryption) {
                return data;
            }
            let text = JSON.stringify(data);
            if (this.encryption) {
                text = aes.encrypt(text);
            }
            if (this.gzip) {
                text = HttpRsaAesHandle.compress(text);
            }
            return text;
        };

        return {
            parseParams,
            encryptData
        };
    }
}

export default HttpRsaAesHandle;
