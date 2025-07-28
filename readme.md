        // G1生成元坐标（非压缩格式：04 + x + y）
        String g1XHex = "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
        String g1YHex = "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

        // 构建非压缩格式的字节数组：0x04 || x || y
        byte[] prefix = new byte[] { 0x04 };
        byte[] g1XBytes = hexStringToByteArray(g1XHex);
        byte[] g1YBytes = hexStringToByteArray(g1YHex);

        // 拼接完整字节数组
        byte[] g1FullBytes = new byte[1 + g1XBytes.length + g1YBytes.length];
        System.arraycopy(prefix, 0, g1FullBytes, 0, 1);
        System.arraycopy(g1XBytes, 0, g1FullBytes, 1, g1XBytes.length);
        System.arraycopy(g1YBytes, 0, g1FullBytes, 1 + g1XBytes.length, g1YBytes.length);

        // 设置 G1 生成元
        Element g1 = pairing.getG1().newElement();
        g1.setFromBytes(g1FullBytes);
        g1 = g1.getImmutable();
        // System.out.println("G1生成元加载成功: " + g1);

        // G2生成元坐标（非压缩格式：04 + x0 + x1 + y0 + y1）
        String g2X0Hex = "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
        String g2X1Hex = "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e";
        String g2Y0Hex = "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801";
        String g2Y1Hex = "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

        // 转换为字节数组
        byte[] prefixG2 = new byte[] { 0x04 };
        byte[] g2X0Bytes = hexStringToByteArray(g2X0Hex);
        byte[] g2X1Bytes = hexStringToByteArray(g2X1Hex);
        byte[] g2Y0Bytes = hexStringToByteArray(g2Y0Hex);
        byte[] g2Y1Bytes = hexStringToByteArray(g2Y1Hex);

        // 拼接完整字节数组：04 || x0 || x1 || y0 || y1
        byte[] g2FullBytes = new byte[1 + g2X0Bytes.length + g2X1Bytes.length + g2Y0Bytes.length + g2Y1Bytes.length];
        int pos = 0;
        System.arraycopy(prefixG2, 0, g2FullBytes, pos, 1);
        pos += 1;
        System.arraycopy(g2X0Bytes, 0, g2FullBytes, pos, g2X0Bytes.length);
        pos += g2X0Bytes.length;
        System.arraycopy(g2X1Bytes, 0, g2FullBytes, pos, g2X1Bytes.length);
        pos += g2X1Bytes.length;
        System.arraycopy(g2Y0Bytes, 0, g2FullBytes, pos, g2Y0Bytes.length);
        pos += g2Y0Bytes.length;
        System.arraycopy(g2Y1Bytes, 0, g2FullBytes, pos, g2Y1Bytes.length);

        // 设置 G2 生成元
        Element g2 = pairing.getG2().newElement();
        g2.setFromBytes(g2FullBytes);
        g2 = g2.getImmutable();
        // System.out.println("G2生成元加载成功: " + g2);

        Element sk = pairing.getZr().newRandomElement();
        Element pk = g1.duplicate().mulZn(sk);

        String msg = "hello";
        String msg1 = "msg";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] m = digest.digest(msg.getBytes(StandardCharsets.UTF_8)); // 使用SHA-256
            Element h = null;
            h = pairing.getG2().newElementFromHash(m, 0, m.length);// hash->G2
            Element sig = h.duplicate().mulZn(sk);// sig=h*sk

            byte[] m1 = digest.digest(msg1.getBytes(StandardCharsets.UTF_8)); // 使用SHA-256
            Element h1 = null;
            h1 = pairing.getG2().newElementFromHash(m1, 0, m1.length).getImmutable();// hash->G2

            pk = pk.getImmutable();
            sig = sig.getImmutable();
            Element pl = pairing.pairing(g1, sig);// e(g_1,h*sk)=e(g_1,sig)=e(h,pk)=e(h,g_1*sk)
            Element pr = pairing.pairing(pk, h);
            System.out.println(pl);
            System.out.println(pr);
            if (pl.isEqual(pr))
                System.out.println("通过");
        } catch (Exception e) {
            System.out.println("SHA-256 NOT SUPPORT");
        }


         private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
