package bls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import com.alibaba.fastjson.JSON;

import certificate.Common;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class BLS {
    static Pairing pairing = PairingFactory.getPairing("a.properties");
    static String g1_String = "LzsPlRBJW971TyZZoIOOojjPZMI2IfonqgV1GD8mVCqScD0cC0MTMSNimm4gWhcmomGZk2qwWwr2uJqD7U/GCpGT/9uP3DzBW0A4X/bb2KFaH/7li5UNFxM5jx0P91fNwoKEi9uQkM3TfaspNatF22eDzAO0XSR1llMDIjWREGI=";

    static String value = null;

    // 将 Base64 解码为 Element（G1群）
    public static Element encodeg1(String g1) {
        byte[] bytes = Base64.getDecoder().decode(g1);
        return pairing.getG1().newElementFromBytes(bytes); // 解码到 G1
    }

    public static Element GeneratePrivateKey() {
        Element sk = pairing.getZr().newRandomElement();
        return sk;
    }

    public static Element GeneratePublicKey(Element sk) {
        Element g1 = encodeg1(g1_String);

        Element pk = g1.duplicate().mulZn(sk);
        return pk;
    }

    public static Element sign(String msg, Element sk) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] m = digest.digest(msg.getBytes(StandardCharsets.UTF_8)); // 使用SHA-256
            Element h = null;
            h = pairing.getG2().newElementFromHash(m, 0, m.length).getImmutable();// hash->G2

            Element sig = h.duplicate().mulZn(sk);// sig=h*sk
            return sig;
        } catch (Exception e) {
            System.out.println("Sign Error" + e.getMessage());
            return null;
        }
    }

    // 验证签名
    public static Boolean verify(Element sig, Element pk, String msg) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] m = digest.digest(msg.getBytes(StandardCharsets.UTF_8)); // 使用SHA-256
            Element h = null;
            h = pairing.getG2().newElementFromHash(m, 0, m.length).getImmutable();// hash->G2
            Element g1 = encodeg1(g1_String);

            Element pl = pairing.pairing(g1, sig);// e(g_1,h*sk)=e(g_1,sig)=e(h,pk)=e(g_1*sk,h)
            Element pr = pairing.pairing(pk, h);

            if (pl.isEqual(pr))
                return true;
            return false;
        } catch (Exception e) {
            System.out.println("Verify Error" + e.getMessage());
            return false;
        }
    }

    // 签名聚合m-m签名
    public static Element AggregateSignatures(List<Element> signatures) {
        Element aggregatedSignature = pairing.getG2().newZeroElement();
        for (Element sig : signatures) {
            aggregatedSignature.add(sig);
        }
        return aggregatedSignature;
    }

    // 聚合公钥m-m签名
    public static Element AggregatePublicKey(List<Element> pks) {
        Element aggregatedPublicKeys = pairing.getG1().newZeroElement();
        for (Element pk : pks) {
            pk = pk.getImmutable();
            aggregatedPublicKeys.add(pk);
        }
        return aggregatedPublicKeys;
    }

    // 聚合签名验证方法，多个消息
    public static Boolean AggregateVerifyDifferentMessages(Element aggregatedSignature, List<Element> publicKeys,
            List<String> messages) {
        if (publicKeys == null || messages == null || publicKeys.size() != messages.size()) {
            throw new IllegalArgumentException("公钥和消息列表必须非空且长度一致");
        }

        Element gt = pairing.getGT().newOneElement(); // 初始化为GT群的单位元
        Element g1 = encodeg1(g1_String); // G1群的生成元

        for (int i = 0; i < publicKeys.size(); i++) {
            Element pk = publicKeys.get(i);
            String msg = messages.get(i);

            // 计算当前消息的哈希到G2群
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] m = digest.digest(msg.getBytes(StandardCharsets.UTF_8)); // 使用SHA-256
                Element h = null;
                h = pairing.getG2().newElementFromHash(m, 0, m.length).getImmutable();// hash->G2
                // 计算配对e(pk_i, h_i)并累乘到乘积
                Element e = pairing.pairing(pk, h);
                gt = gt.mul(e);
            } catch (Exception e) {
                System.out.println("Verify Error" + e.getMessage());
                return false;
            }
        }

        // 计算左边的配对e(g1, 聚合签名)
        Element left = pairing.pairing(g1, aggregatedSignature);

        return left.isEqual(gt);
    }

    // 私钥格式化
    public static String SkToPem(Element element) {
        ByteArrayOutputStream pemStream = new ByteArrayOutputStream();
        try {
            pemStream.write(("-----BEGIN PRIVATE KEY-----\n").getBytes());
            byte[] elementBytes = element.toBytes();
            String base64Encoded = Base64.getEncoder().encodeToString(elementBytes);
            int lineLength = 64;
            for (int i = 0; i < base64Encoded.length(); i += lineLength) {
                int endIndex = Math.min(i + lineLength, base64Encoded.length());
                pemStream.write((base64Encoded.substring(i, endIndex) + "\n").getBytes());
            }
            pemStream.write(("-----END PRIVATE KEY-----\n").getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new String(pemStream.toByteArray());
    }

    // 公钥格式化
    public static String PkToPem(Element element) {
        ByteArrayOutputStream pemStream = new ByteArrayOutputStream();
        try {
            pemStream.write(("-----BEGIN PUBLIC KEY-----\n").getBytes());
            byte[] elementBytes = element.toBytes();
            String base64Encoded = Base64.getEncoder().encodeToString(elementBytes);
            int lineLength = 64;
            for (int i = 0; i < base64Encoded.length(); i += lineLength) {
                int endIndex = Math.min(i + lineLength, base64Encoded.length());
                pemStream.write((base64Encoded.substring(i, endIndex) + "\n").getBytes());
            }
            pemStream.write(("-----END PUBLIC KEY-----\n").getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new String(pemStream.toByteArray());
    }

    // pem格式转公钥
    public static Element PemToPk(String pem) {
        // 去除 PEM 格式的头尾标记
        String base64Content = pem.replace("-----BEGIN PUBLIC KEY-----\n", "")
                .replace("-----END PUBLIC KEY-----\n", "")
                .replaceAll("\\s", "");
        byte[] decodedBytes = Base64.getDecoder().decode(base64Content);

        return pairing.getG1().newElementFromBytes(decodedBytes);
    }

    public static Element byteToPk(byte[] pk) {
        return pairing.getG1().newElementFromBytes(pk);
    }

    public static Element PemToSk(String pem) {
        // 去除 PEM 格式的头尾标记
        String base64Content = pem.replace("-----BEGIN PRIVATE KEY-----\n", "")
                .replace("-----END PRIVATE KEY-----\n", "")
                .replaceAll("\\s", "");
        byte[] decodedBytes = Base64.getDecoder().decode(base64Content);

        return pairing.getZr().newElementFromBytes(decodedBytes);
    }

    // 读取 BLS 私钥
    public static Element PemToSk(InputStream inputStream) throws IOException {
        String pem = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        String base64 = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        Element keyElement = pairing.getZr().newElementFromBytes(keyBytes);
        return keyElement;
    }

    // 将PEM格式的签名转换为Element
    public static Element PemToSig(String pem) {
        String base64Content = pem.replace("-----BEGIN SIGNATURE-----\n", "")
                .replace("-----END SIGNATURE-----\n", "")
                .replaceAll("\\s", "");
        byte[] decodedBytes = Base64.getDecoder().decode(base64Content);
        return pairing.getG2().newElementFromBytes(decodedBytes);
    }

    // 新增方法：支持直接解析 byte[] 类型的签名数据
    public static Element PemToSig(byte[] pem) {
        return pairing.getG2().newElementFromBytes(pem);
    }

    // 将签名转换为PEM格式
    public static String SigToPem(Element sig) {
        ByteArrayOutputStream pemStream = new ByteArrayOutputStream();
        try {
            pemStream.write(("-----BEGIN SIGNATURE-----\n").getBytes());
            byte[] sigBytes = sig.toBytes();
            String base64Encoded = Base64.getEncoder().encodeToString(sigBytes);
            int lineLength = 64;
            for (int i = 0; i < base64Encoded.length(); i += lineLength) {
                int endIndex = Math.min(i + lineLength, base64Encoded.length());
                pemStream.write((base64Encoded.substring(i, endIndex) + "\n").getBytes());
            }
            pemStream.write(("-----END SIGNATURE-----\n").getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new String(pemStream.toByteArray());
    }

    public static SubjectPublicKeyInfo encodePublicKey(Element pk) throws IOException {
        // 1. 获取BLS公钥的原始字节
        byte[] bytes = pk.toBytes();

        // 2. 直接包装为BIT STRING（未使用位数为0）
        DERBitString bitStr = new DERBitString(bytes, 0);

        // 4. 定义BLS算法标识符
        AlgorithmIdentifier algId = new AlgorithmIdentifier(Common.oid);

        // 5. 构建SubjectPublicKeyInfo
        return new SubjectPublicKeyInfo(algId, bitStr);
    }

    public static Element decodePublicKey(byte[] publicKey) throws Exception {
        // 手动解析DER编码
        ASN1InputStream asn = new ASN1InputStream(publicKey);
        ASN1Sequence seq = (ASN1Sequence) asn.readObject();
        asn.close();
        // 提取算法标识符
        AlgorithmIdentifier oid = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        if (!oid.getAlgorithm().equals(Common.oid)) {
            throw new IllegalArgumentException("证书公钥算法不是BLS");
        }

        // 提取BIT STRING
        DERBitString bitStr = (DERBitString) seq.getObjectAt(1);
        byte[] bytes = bitStr.getOctets();

        // 转换为BLS的Element类型
        return pairing.getG1().newElementFromBytes(bytes);
    }

    // VRF部分
    // Proof类
    public static class Proof {
        public final String challenge; // Base64编码的Zr元素
        public final String response; // Base64编码的Zr元素
        public final String y; // Base64编码的G1元素

        public Proof(String challenge, String response, String y) {
            this.challenge = challenge;
            this.response = response;
            this.y = y;
        }
    }

    // 安全地将消息哈希到G1曲线
    public static Element hashToG1Curve(String hash) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(hash.getBytes(StandardCharsets.UTF_8));
            return pairing.getG1().newElementFromHash(hashBytes, 0, hashBytes.length);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not supported", e);
        }
    }

    // 安全哈希函数（SHA-256）
    private static Element hashToZrCurveSecure(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            return pairing.getZr().newElementFromHash(hashBytes, 0, hashBytes.length);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not supported", e);
        }
    }

    /**
     * SHA256散列函数
     *
     * @param str
     * @return
     */
    public static String SHA256(String str) {
        MessageDigest messageDigest;
        String encodeStr = "";
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(str.getBytes("UTF-8"));
            encodeStr = byte2Hex(messageDigest.digest());
        } catch (Exception e) {
            System.out.println("getSHA256 is error" + e.getMessage());
        }
        return encodeStr;
    }

    private static String byte2Hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        String temp;
        for (int i = 0; i < bytes.length; i++) {
            temp = Integer.toHexString(bytes[i] & 0xFF);
            if (temp.length() == 1) {
                builder.append("0");
            }
            builder.append(temp);
        }
        return builder.toString();
    }

    // 挑战生成方法
    public static Element getChallenge(Element G, Element H, Element y, Element K, Element publicKey, String hash) {
        // 使用 Base64 编码元素内容
        String GBase64 = Base64.getEncoder().encodeToString(G.toBytes());
        String HBase64 = Base64.getEncoder().encodeToString(H.toBytes());
        String YBase64 = Base64.getEncoder().encodeToString(y.toBytes());
        String KBase64 = Base64.getEncoder().encodeToString(K.toBytes());
        String pkBase64 = Base64.getEncoder().encodeToString(publicKey.toBytes());
        String hashBase64 = Base64.getEncoder().encodeToString(hash.getBytes());
        String input = GBase64 + HBase64 + YBase64 + KBase64 + pkBase64 + hashBase64;

        // 使用 SHA-256 替代不安全的 toString()
        return hashToZrCurveSecure(input);
    }

    // 计算响应Zr
    public static Element response(Element sk, Element challenge, Element r) {
        return r.add(challenge.mulZn(sk));// k+c*sk
    }

    public static String getProof(String hash, Element pk, Element sk) {
        Element sk_immutable = sk.getImmutable();
        // 1.计算y=sk*h
        Element h = hashToG1Curve(hash).getImmutable();
        Element y = h.mulZn(sk).getImmutable();

        // 随机标量k
        Element k = pairing.getZr().newRandomElement().getImmutable();
        Element g = base64ToG1Element(g1_String).getImmutable();
        // 临时点K=kg
        Element K = g.mulZn(k).getImmutable();
        // 挑战
        Element challenge = getChallenge(g, h, y, K, pk, hash).getImmutable();
        // 响应
        Element response = response(sk_immutable, challenge, k).getImmutable();

        value = SHA256(y.toString());// 用于比较的输出值
        // 5. 构建可序列化的Proof
        Proof proof = new Proof(
                elementToBase64(challenge),
                elementToBase64(response),
                elementToBase64(y));
        return JSON.toJSONString(proof);
    }

    public static void verify(Element pk, String hash, String data, String value) {
        Element h = hashToG1Curve(hash).getImmutable();
        Element g = base64ToG1Element(g1_String).getImmutable();
        Proof proof = JSON.parseObject(data, Proof.class);
        // 解码元素
        Element challenge = base64ToZrElement(proof.challenge).getImmutable();
        Element s = base64ToZrElement(proof.response).getImmutable();
        Element y = base64ToG1Element(proof.y).getImmutable();
        Element g_s = g.duplicate().mulZn(s);
        Element pk_c = pk.duplicate().mulZn(challenge);
        Element U = g_s.duplicate().sub(pk_c).getImmutable();// g*s-pk*c=g*(k+c*sk)-g*sk*c=g*k

        Element challenge_prime = getChallenge(g, h, y, U, pk, hash);
        System.out.println("VRF Challenge verify " + challenge_prime.isEqual(challenge));

        System.out.println(value.equals(SHA256(y.toString())));
    }

    // 辅助方法
    private static String elementToBase64(Element element) {
        return Base64.getEncoder().encodeToString(element.toBytes());
    }

    public static Element base64ToG1Element(String base64) {
        byte[] bytes = Base64.getDecoder().decode(base64);
        return pairing.getG1().newElementFromBytes(bytes);
    }

    public static Element base64ToZrElement(String base64) {
        byte[] bytes = Base64.getDecoder().decode(base64);
        return pairing.getZr().newElementFromBytes(bytes);
    }

    public static void main(String[] args) {
        Element sk = GeneratePrivateKey();
        Element pk = GeneratePublicKey(sk);
        String msg = "hello";
        String msg1 = "hello1";
        String msg2 = "hello2";
        String msg3 = "hello3";
        List<String> messages = new ArrayList<>();
        messages.add(msg1);
        messages.add(msg2);
        messages.add(msg3);
        // 普通签名
        Element sig = sign(msg, sk);
        System.out.println("normal msg verify " + verify(sig, pk, msg));
        System.out.println("normal msg1 verify " + verify(sig, pk, msg1));
        // m-m聚合签名
        List<Element> publicKeys = new ArrayList<>();
        List<Element> signatures = new ArrayList<>();
        // 生成多个私钥、公钥和签名
        Element sk1 = BLS.GeneratePrivateKey();
        Element pk1 = BLS.GeneratePublicKey(sk1);
        Element sk2 = BLS.GeneratePrivateKey();
        Element pk2 = BLS.GeneratePublicKey(sk2);
        Element sk3 = BLS.GeneratePrivateKey();
        Element pk3 = BLS.GeneratePublicKey(sk3);

        publicKeys.add(pk2);
        publicKeys.add(pk1);
        publicKeys.add(pk3);

        Element sig1 = sign(msg, sk1);
        Element sig2 = sign(msg, sk2);
        Element sig3 = sign(msg, sk3);

        signatures.add(sig1);
        signatures.add(sig2);
        signatures.add(sig3);

        Element agg_sig = AggregateSignatures(signatures);
        Element agg_pk = AggregatePublicKey(publicKeys);
        System.out.println("aggregate msg verify " + verify(agg_sig, agg_pk, msg));
        System.out.println("aggregate msg1 verify " + verify(agg_sig, agg_pk, msg1));
        // 普通聚合
        signatures.clear();
        publicKeys.clear();

        sig1 = sign(msg1, sk1);
        sig2 = sign(msg2, sk2);
        sig3 = sign(msg3, sk3);

        signatures.add(sig1);
        signatures.add(sig2);
        signatures.add(sig3);

        publicKeys.add(pk1);
        publicKeys.add(pk2);
        publicKeys.add(pk3);

        agg_sig = AggregateSignatures(signatures);

        System.out.println(
                "aggregate messages verify " + AggregateVerifyDifferentMessages(agg_sig, publicKeys, messages));
        messages.clear();
        messages.add(msg3);
        messages.add(msg2);
        messages.add(msg1);
        System.out.println(
                "aggregate messages backend verify " + AggregateVerifyDifferentMessages(agg_sig, publicKeys, messages));

        // VRF
        String public_key = "-----BEGIN PUBLIC KEY-----\n" + //
                "CwyLY8kX8UfFXvowCkFe5PwGrBa75kv9OLlLkqCz947jBAyxYWCDXCbS7gRZmMje\n" + //
                "gULsy7eJBWM57TePBgWIqQT2XfNIGA8as7oDoc+ywDHblyjUV0ZVkdffY93lP6GJ\n" + //
                "JYW0xLWo6xYOMJHkKb+qT9j03yv0B24Dyp+LycuOb0U=\n" + //
                "-----END PUBLIC KEY-----\n";
        String private_key = "-----BEGIN PRIVATE KEY-----\n" + //
                "Z9dzZadGrODs94f4ReBI1660ybw=\n" + //
                "-----END PRIVATE KEY-----\n";
        String private_key1 = "-----BEGIN PRIVATE KEY-----\n" + //
                "fjfOrdn6VxHalsjSE0WtJ7eXo2g=\n" + //
                "-----END PRIVATE KEY-----\n";
        String hash = "5303d2990c139992bdb5a22aa1dac4f2719755304e45bac03ca4a1f1688c909e";
        String proof = getProof(hash, PemToPk(public_key), PemToSk(private_key));
        verify(PemToPk(public_key), hash, proof, value);

        proof = getProof(hash, PemToPk(public_key), PemToSk(private_key1));
        verify(PemToPk(public_key), hash, proof, value);
    }
}