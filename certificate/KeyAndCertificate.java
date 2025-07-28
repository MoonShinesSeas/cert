package certificate;
import java.security.cert.X509Certificate;

import it.unisa.dia.gas.jpbc.Element;

public class KeyAndCertificate {
    /**
     * 私钥
     */
    private Element privateKey;
    /**
     * 公钥
     */
    private Element publicKey;
    /**
     * 证书
     */
    private X509Certificate certificate;

    public KeyAndCertificate(Element privateKey, Element publicKey, X509Certificate certificate) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.certificate = certificate;
    }

    public Element getPrivateKey() {
        return this.privateKey;
    }

    public void setPrivateKey(Element privateKey) {
        this.privateKey = privateKey;
    }

    public Element getPublicKey() {
        return this.publicKey;
    }

    public void setPublicKey(Element publicKey) {
        this.publicKey = publicKey;
    }

    public X509Certificate getX509Certificate() {
        return this.certificate;
    }

    public void setX509Certificate(X509Certificate certificate) {
        this.certificate = certificate;
    }
}
