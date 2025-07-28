package certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.provider.PKIXCertPathValidatorSpi;

import bls.BLS;
import it.unisa.dia.gas.jpbc.Element;

import java.security.PublicKey;
import java.security.cert.*;
import java.util.List;

public class BLSCertPathValidator extends PKIXCertPathValidatorSpi {
    @Override
    public CertPathValidatorResult engineValidate(
            CertPath certPath,
            CertPathParameters params) throws CertPathValidatorException {
        // 强制转换为PKIX参数
        PKIXParameters pkixParams = (PKIXParameters) params;

        // 遍历证书链，手动验证签名
        List<X509Certificate> certs = (List<X509Certificate>) certPath.getCertificates();
        try {
            for (int i = 0; i < certs.size(); i++) {
                X509Certificate cert = certs.get(i);
                X509Certificate issuerCert = (i == certs.size() - 1)
                        ? getTrustAnchorCert(pkixParams) // 获取信任锚证书
                        : certs.get(i + 1);

                // 手动验证签名（使用BLS算法）
                verifyBLSSignature(cert, issuerCert);
            }
            // Get the end entity's public key for the result
            X509Certificate endEntityCert = certs.get(0);
            PublicKey subjectPublicKey = endEntityCert.getPublicKey();

            // 返回验证结果
            return new PKIXCertPathValidatorResult(
                    pkixParams.getTrustAnchors().iterator().next(),
                    null,
                    subjectPublicKey);
        } catch (Exception e) {
            throw new CertPathValidatorException(e.getMessage(), e);
        }
    }

    private X509Certificate getTrustAnchorCert(PKIXParameters params) {
        return params.getTrustAnchors().iterator().next().getTrustedCert();
    }

    private void verifyBLSSignature(X509Certificate cert, X509Certificate issuerCert)
            throws Exception {
        // 从颁发者证书中提取BLS公钥
        Element issuerPublicKey = BLS.decodePublicKey(issuerCert.getPublicKey().getEncoded());

        // 获取 DER 编码的 TBS 数据（直接使用字节数组，不转为字符串）
        byte[] tbsData = cert.getTBSCertificate();
        // 提取证书签名并解码 DER Octet String
        byte[] signature = cert.getSignature();
        ASN1InputStream asn = new ASN1InputStream(signature);
        ASN1Primitive asn1 = asn.readObject();
        byte[] sigBytes = ((DEROctetString) asn1).getOctets(); // 提取原始签名字节
        Element sig = BLS.PemToSig(sigBytes); // 使用 BLS 库方法解码
        asn.close();

        if (!BLS.verify(sig, issuerPublicKey, new String(tbsData))) {
            throw new CertPathValidatorException("BLS签名验证失败");
        }
    }
}