import { util, random, cipher } from 'node-forge';

class AES {
    public key: string;
    public iv: string;

    constructor(key?: string, iv?: string) {
        this.key = key || random.getBytesSync(16);
        this.iv = iv || random.getBytesSync(16);
    }

    public encrypt(text: string) {
        const aes = cipher.createCipher('AES-CBC', this.key);
        aes.start({ iv: this.iv });
        aes.update(util.createBuffer(text, 'utf8'));
        aes.finish();
        return aes.output.toHex();
    }

    public decrypt(text: string) {
        const aes = cipher.createDecipher('AES-CBC', this.key);
        aes.start({ iv: this.iv });
        const bit = new util.ByteStringBuffer(util.hexToBytes(text));
        aes.update(bit);
        aes.finish();
        return aes.output.toString();
    }
}

export default AES;
