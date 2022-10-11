import AxiosChain from '@tanggaoyuan/axios_chain';
import { pathToRegexp } from 'path-to-regexp';
import pako from 'pako';
import AES from './Aes';
import RSA from './Rsa';

const chain = new AxiosChain();

class HttpRsaAesHandle {
    private config: { gzip: boolean; key: string; encryption: boolean; aes: string; iv: string, white_list: Array<string> };
    private currentRun: Promise<{ decryptData: (data: any) => any, encryptParams: (data: Record<any, any>) => string | Record<any, any> }>;
    private isExpired = true;

    public setExpired(isExpired: boolean) {
        this.currentRun = isExpired ? null : this.currentRun;
        this.isExpired = isExpired;
    }

    public createHandle(path: string) {
        if (!this.currentRun) {
            this.currentRun = (async () => {
                if (this.isExpired) {
                    const keys = await RSA.generateKeyPair();
                    const ras = new RSA(keys);

                    const response = await chain.get('/rsa/config').disableInterceptor().retry(3);
                    this.config = response.data;

                    if (this.config.encryption) {
                        const encryptionKey = ras.encode64(ras.encryptByPublicKey(ras.decode64(this.config.key), ras.getPublicKeyString()));
                        const result = await chain.post('/rsa/report').retry(3).disableInterceptor().send({ data: encryptionKey });
                        const data = JSON.parse(ras.decrypt(ras.decode64(result.data.data)));
                        this.config = { ...this.config, aes: data.key, iv: data.iv };
                    }

                    this.isExpired = false;
                }

                const { encryption, iv, gzip, aes: aesKey } = this.config;

                const aes = iv ? new AES(aesKey, iv) : null;

                let isWhite = false;

                for (const url of this.config.white_list) {
                    const reg = pathToRegexp(url);
                    isWhite = reg.test(path);
                    if (isWhite) {
                        break;
                    }
                }

                const decryptData = (data: any) => {
                    if (!data || isWhite || !encryption && !gzip) {
                        return data;
                    }

                    if (gzip) {
                        data = HttpRsaAesHandle.decompression(data);
                    }

                    if (encryption) {
                        data = aes?.decrypt(data);
                    }

                    return JSON.parse(data);
                };

                const encryptParams = (data: Record<any, any>) => {
                    if (!data || isWhite || !gzip && !encryption) {
                        return data;
                    }
                    let text = JSON.stringify(data);
                    if (encryption) {
                        text = aes?.encrypt(text);
                    }

                    if (gzip) {
                        text = HttpRsaAesHandle.compress(text);
                    }
                    return { data: text };
                };

                return { encryptParams, decryptData };
            })();
        }

        return this.currentRun;
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
}

const handle = new HttpRsaAesHandle();

chain.use(async (config) => {
    const aesHandle = await handle.createHandle(config.url);

    const tempData = config.data;
    const tempParams = config.params;

    if (config.data) {
        config.data = aesHandle.encryptParams(config.data);
    }
    if (config.params) {
        config.params = aesHandle.encryptParams(config.params);
    }

    return (promise) => promise.then((response) => {
        if (response.data.code === -2) {
            handle.setExpired(true);
            return chain.request({
                ...config,
                data: tempData,
                params: tempParams
            });
        }
        if (response.data) {
            response.data = aesHandle.decryptData(response.data);
        }
        return response;
    });
});

chain.use(() => (promise) => promise.then((response) => {
    if (response.status === 200 && response.data.code === 0) {
        return response;
    }
    return Promise.reject(response.data);
}));

export default chain;
