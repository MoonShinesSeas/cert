package certificate;

import java.security.PrivateKey;
import it.unisa.dia.gas.jpbc.Element;

// BLS 私钥实现
public class BLSPrivateKey implements PrivateKey {
    private final Element key;

    public BLSPrivateKey(Element key) {
        this.key = key;
    }

    public Element getKey() {
        return key;
    }

    @Override
    public String getAlgorithm() {
        return X509CertificateConstants.KEY_ALGORITHM; // 自定义算法名称
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        return key.toBytes(); // 直接序列化 Element 的字节
    }

}
