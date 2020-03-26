package org.example;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.interfaces.PwHash;
import com.goterl.lazycode.lazysodium.interfaces.SecretStream;
import com.sun.jna.NativeLong;

import java.io.*;

public class UnApkm {

    public byte[] getBytes(InputStream i, int num) throws IOException {
        byte[] data = new byte[(int) num];
        int nRead = 0;
        nRead = i.read(data, 0, data.length);
        return data;
    }

    int byteToInt(byte[] b) {
        int v1 = 0, v2 = 0, v3 = 0;
        int v0 = b.length;

        while (v1 < v0) {
            byte be = b[v1];

            v2 |= (be & 0xff) << v3;

            v3 += 8;
            v1 += 1;
        }
        return v2;
    }

    private static final String HEXES = "0123456789ABCDEF";

    static String getHex(byte[] raw) {
        int max = Math.min(100, raw.length);
        final StringBuilder hex = new StringBuilder(2 * max);
        for (int i = 0; i < max; i++) {
            byte b = raw[i]; //raw[raw.length-i-1];
            hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
        }
        return hex.toString();
    }

    public UnApkm(String filein, String fileout) {
        try {
            InputStream i = new FileInputStream(new File(filein));

            byte first = getBytes(i, 1)[0];
            if (first > 0xff) {
                throw new Exception("help me what is this");
            }

            byte alg = getBytes(i, 1)[0];
            if (alg > 2 || alg < 1) {
                throw new Exception("incorrect algo");
            }

            PwHash.Alg algo = PwHash.Alg.valueOf(alg);

            long opsLimit = (long) byteToInt(getBytes(i, 8));
            int memLimit = byteToInt(getBytes(i, 8));

            if (memLimit < 0 || memLimit > 0x20000000) {
                throw new Exception("too much memory aaah");
            }

            byte[] en = getBytes(i, 8);
            long chunkSize = byteToInt(en);

            byte[] salt = getBytes(i, 16);
            byte[] pwHashBytes = getBytes(i, 24);

            LazySodiumJava lazySodium = new LazySodiumJava(new SodiumJava());

            byte[] outputHash = new byte[32];
            lazySodium.cryptoPwHash(outputHash, 32, "#$%@#dfas4d00fFSDF9GSD56$^53$%7WRGF3dzzqasD!@".getBytes(), 0x2d, salt, opsLimit, new NativeLong(memLimit), algo);

            SecretStream.State state = new SecretStream.State();
            lazySodium.cryptoSecretStreamInitPull(state, pwHashBytes, outputHash);


            long c = chunkSize;

            long chunkSizePlusPadding = c + 0x11;
            byte[] cipherChunk = new byte[(int) chunkSizePlusPadding];


            File file = new File(fileout);
            FileOutputStream fos = null;
            fos = new FileOutputStream(file);
            int bytesRead = 0;
            while (bytesRead != -1) {
                bytesRead = i.read(cipherChunk);
                if (bytesRead == -1) break;

                int tagSize = 1;

                chunkSizePlusPadding = c;

                byte[] decryptedChunk = new byte[(int) chunkSizePlusPadding];
                byte[] tag = new byte[tagSize];

                boolean success = lazySodium.cryptoSecretStreamPull(state, decryptedChunk, tag, cipherChunk, bytesRead);

                if (!success) {
                    throw new Exception("decrypto error");
                }

                fos.write(decryptedChunk);

                for (int j = 0; j < cipherChunk.length; j++) {
                    cipherChunk[j] = 0;
                }

            }
            if (fos != null) {
                fos.close();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java -jar unapkm.jar <input .apkm file> <output.apks file>\n\nDefault output file is <input file>.apks\n\nenjoy!!!");
            return;
        }
        String f = args[0];
        String out = f + ".apks";
        if (args.length > 1)
            out = args[1];

        new UnApkm(f, out);
    }
}
