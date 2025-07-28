package certificate;

// BLS 公钥实现
import java.security.PublicKey;

import it.unisa.dia.gas.jpbc.Element;

public class BLSPublicKey implements PublicKey {
    private final Element key;

    public BLSPublicKey(Element key) {
        this.key = key;
    }

    public Element getKey() {
        return key;
    }

    @Override
    public String getAlgorithm() {
        return X509CertificateConstants.KEY_ALGORITHM;
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        return key.toBytes();
    }
}