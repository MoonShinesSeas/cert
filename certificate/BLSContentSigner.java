package certificate;

import it.unisa.dia.gas.jpbc.Element;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;

import bls.BLS;


public class BLSContentSigner implements ContentSigner {
    private final Element privateKey;
    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    public BLSContentSigner(Element privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return new AlgorithmIdentifier(Common.oid);
    }

    @Override
    public OutputStream getOutputStream() {
        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        try {
            // 获取 DER 编码的 TBS 数据（直接使用字节数组，不转为字符串）
            byte[] tbsData = outputStream.toByteArray();
            // 使用 BLS 对原始字节进行签名（而非字符串）
            Element sig = BLS.sign(new String(tbsData),privateKey);
            // 将签名结果包装为 DER 编码的 Octet String
            return new DEROctetString(sig.toBytes()).getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
