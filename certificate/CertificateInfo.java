package certificate;

import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;

public class CertificateInfo {
    /**
     * 证书序列号
     */
    private BigInteger serial;
    /**
     * 颁发者
     */
    private X500Name issuer;
    /**
     * 主体
     */
    private X500Name subject;
    /**
     * 颁发时间
     */
    private Date notBefore;
    /**
     * 到期时间
     */
    private Date notAfter;
    /**
     * 加密算法
     */
    private String keyAlgorithm;
    /**
     * 签名算法
     */
    private String signAlgorithm;

    private boolean isCA;
    private int pathLenConstraint = -1;

    public void setCA(boolean isCA) {
        this.isCA = isCA;
    }

    public boolean isCA() {
        return isCA;
    }

    public void setPathLenConstraint(int pathLenConstraint) {
        this.pathLenConstraint = pathLenConstraint;
    }

    public int getPathLenConstraint() {
        return pathLenConstraint;
    }

    public void setSerial(BigInteger serial) {
        this.serial = serial;
    }

    public BigInteger getSerial() {
        return this.serial;
    }

    public void setIssuer(X500Name issuer) {
        this.issuer = issuer;
    }

    public X500Name getIssuer() {
        return this.issuer;
    }

    public void setSubject(X500Name subject) {
        this.subject = subject;
    }

    public X500Name getSubject() {
        return this.subject;
    }

    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    public Date getNotBefore() {
        return this.notBefore;
    }

    public void setNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }

    public Date getNotAfter() {
        return this.notAfter;
    }

    public void setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    public String getKeyAlgorithm() {
        return this.keyAlgorithm;
    }

    public void setSignAlgorithm(String signAlgorithm) {
        this.signAlgorithm = signAlgorithm;
    }

    public String getSignAlgorithm() {
        return this.signAlgorithm;
    }

}
