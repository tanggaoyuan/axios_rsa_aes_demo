/* eslint-disable no-shadow */
import { pki, util, md } from 'node-forge';

const shaOption = {
  'RSA-OAEP-SHA1': {
    md: md.sha1.create(),
    hlen: 20
  },
  'RSA-OAEP-SHA256': {
    md: md.sha256.create(),
    hlen: 32
  },
  'RSA-OAEP-SHA384': {
    md: md.sha384.create(),
    hlen: 48
  },
  'RSA-OAEP-SHA512': {
    md: md.sha512.create(),
    hlen: 64
  }
};

type RsaModeType = 'RSAES-PKCS1-V1_5' | 'RSA-OAEP-SHA1' | 'RSA-OAEP-SHA256' | 'RSA-OAEP-SHA384' | 'RSA-OAEP-SHA512'

class RSA {
  private privateKey: pki.rsa.KeyPair['privateKey'];
  private publicKey: pki.rsa.KeyPair['publicKey'];
  private n: number;

  constructor(keys: pki.rsa.KeyPair | {
    publicKey: string;
    privateKey: string;
  }, n = 1024) {
    this.n = n;
    if (typeof keys.privateKey === 'string') {
      this.privateKey = pki.privateKeyFromPem(keys.privateKey);
    } else {
      this.privateKey = keys.privateKey;
    }
    if (typeof keys.publicKey === 'string') {
      this.publicKey = pki.publicKeyFromPem(keys.publicKey);
    } else {
      this.publicKey = keys.publicKey;
    }
  }

  public static generateKeyPair(n = 1024) {
    return new Promise<pki.rsa.KeyPair>((resolve, reject) => {
      pki.rsa.generateKeyPair({ bits: n, workerScript: '/prime.worker.min.js' }, (err, keys) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(keys);
      });
    });
  }

  public getPublicKeyString() {
    return pki.publicKeyToRSAPublicKeyPem(this.publicKey, 72);
  }

  public getPrivateKeyString() {
    return pki.privateKeyToPem(this.privateKey, 72);
  }

  public encryptByPublicKey(key: string | pki.rsa.KeyPair['publicKey'], text: string, mode?: RsaModeType) {
    let publicKey: pki.rsa.PublicKey;
    if (typeof key === 'string') {
      publicKey = pki.publicKeyFromPem(key);
    } else {
      publicKey = key;
    }

    let encryptText = '';

    const k = this.n / 8;

    if (mode && mode.includes('RSA-OAEP')) {
      const { md, hlen } = shaOption[mode];
      const length = k - 2 * hlen - 2;
      const frequency = Math.ceil(text.length / length);
      for (let index = 0; index < frequency; index++) {
        encryptText += publicKey.encrypt(text.slice(index * length, (index + 1) * length), 'RSA-OAEP', { md });
      }
      return encryptText;
    }

    const length = k - 11;
    const frequency = Math.ceil(text.length / length);
    for (let index = 0; index < frequency; index++) {
      encryptText += publicKey.encrypt(text.slice(index * length, (index + 1) * length), 'RSAES-PKCS1-V1_5');
    }
    return encryptText;
  }

  public decryptByPrivateKey(key: string | pki.rsa.KeyPair['privateKey'], text: string, mode?: RsaModeType) {
    let privateKey: pki.rsa.PrivateKey;
    if (typeof key === 'string') {
      privateKey = pki.privateKeyFromPem(key);
    } else {
      privateKey = key;
    }

    const k = this.n / 8;

    let decryptText = '';
    const frequency = text.length / k;

    if (mode && mode.includes('RSA-OAEP')) {
      const { md } = shaOption[mode] || {};
      for (let i = 0; i < frequency; i++) {
        decryptText += privateKey.decrypt(text.slice(i * k, (i + 1) * k), 'RSA-OAEP', { md });
      }
      return decryptText;
    }

    for (let i = 0; i < frequency; i++) {
      decryptText += privateKey.decrypt(text.slice(i * k, (i + 1) * k));
    }
    return decryptText;
  }

  public encrypt(text: string, mode?: RsaModeType) {
    return this.encryptByPublicKey(this.publicKey, text, mode);
  }

  public decrypt(text: string, mode?: RsaModeType) {
    return this.decryptByPrivateKey(this.privateKey, text, mode);
  }

  public decode64(value: string) {
    return util.decode64(value);
  }

  public encode64(value: string) {
    return util.encode64(value);
  }
}

export default RSA;
