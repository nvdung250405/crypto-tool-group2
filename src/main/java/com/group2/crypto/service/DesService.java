package com.group2.crypto.service;

import com.group2.crypto.model.*;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class DesService {

    // Standard DES tables (0-indexed)
    private static final byte[] IP = {
            57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
            56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6
    };

    private static final byte[] FP = {
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25,
            32, 0, 40, 8, 48, 16, 56, 24
    };

    private static final byte[] E_TABLE = {
            31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8,
            7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16,
            15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24,
            23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0
    };

    private static final byte[] P_TABLE = {
            15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
            1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24
    };

    private static final byte[][][] S_BOXES = {
            { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                    { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                    { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                    { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } },
            { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                    { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                    { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                    { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } },
            { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                    { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                    { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                    { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } },
            { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                    { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                    { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                    { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } },
            { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                    { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                    { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                    { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } },
            { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                    { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                    { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                    { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } },
            { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                    { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                    { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                    { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } },
            { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                    { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                    { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                    { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } }
    };

    private static final byte[] PC2_TABLE = {
            13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3,
            25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39,
            50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
    };

    private static final byte[] SHIFTS = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

    public DesResponse process(DesRequest request) {
        if ("EXAM_FEISTEL".equalsIgnoreCase(request.getOpType())) {
            return processExamFeistel(request);
        }

        DesResponse response = new DesResponse();
        response.setInputData(request.getData());
        response.setInputKey(request.getKey());
        response.setMode(request.getMode());

        try {
            String cleanData = request.getData().replaceAll("\\s+", "").toUpperCase();
            String cleanKey = request.getKey().replaceAll("\\s+", "").toUpperCase();
            String dataBin = hexToBinary(cleanData);
            String keyBin = hexToBinary(cleanKey);

            if (dataBin.length() != 64 || keyBin.length() != 64) {
                response.setErrorMessage("Dữ liệu và khóa phải đủ 64-bit (16 ký tự hex).");
                return response;
            }

            List<String> transcript = new ArrayList<>();
            transcript.add("BÀI TẬP MÃ HÓA DES - TRÍCH XUẤT");
            transcript.add("INPUT: K = " + cleanKey + ", M = " + cleanData);
            transcript.add("");
            transcript.add("Phần 1: Sinh các khóa Ki từ khóa K");

            transcript.add("BÀI 1: Tính hoán vị PC-1 đối với K");
            transcript.add("K = " + keyBin + " (2)");
            transcript.add("  = " + cleanKey + " (16)");

            String permutedKey = PC1(keyBin);
            transcript.add("PC-1(K) = " + permutedKey + " (2)");
            transcript.add("        = " + binaryToHex(permutedKey) + " (16)");

            String[] cd0 = SPLIT_KEY(permutedKey);
            String c0 = cd0[0];
            String d0 = cd0[1];
            transcript.add("C0 = " + c0 + " (2) = " + binaryToHex(c0) + " (16)");
            transcript.add("D0 = " + d0 + " (2) = " + binaryToHex(d0) + " (16)");

            transcript.add("");
            transcript.add("Bài 2: Tính các giá trị dịch vòng Ci, Di");
            String[] subkeys = new String[16];
            String currentC = c0;
            String currentD = d0;
            for (int i = 0; i < 16; i++) {
                currentC = ShiftLeft(currentC, SHIFTS[i]);
                currentD = ShiftLeft(currentD, SHIFTS[i]);
                subkeys[i] = PC2(currentC, currentD);
                transcript.add(String.format("%d: C%d = %s (2) = %s (16), D%d = %s (2) = %s (16)",
                        i + 1, i + 1, currentC, binaryToHex(currentC), i + 1, currentD, binaryToHex(currentD)));
            }

            transcript.add("");
            transcript.add("Bài 3: Tính khóa Ki cho vòng lặp thứ i");
            // Re-run for transcript accuracy
            currentC = c0;
            currentD = d0;
            for (int i = 0; i < 16; i++) {
                currentC = ShiftLeft(currentC, SHIFTS[i]);
                currentD = ShiftLeft(currentD, SHIFTS[i]);
                String ki = PC2(currentC, currentD);
                transcript.add((i + 1) + ":");
                transcript.add(String.format("C%dD%d = %s (2) = %s (16)", i + 1, i + 1, currentC + currentD,
                        binaryToHex(currentC + currentD)));
                transcript.add(String.format("K%d = PC-2(C%dD%d) = %s (2) = %s (16)", i + 1, i + 1, i + 1, ki,
                        binaryToHex(ki)));
            }

            transcript.add("");
            transcript.add("Phần 2: Mã hóa");

            String resultBin;
            if ("encrypt".equalsIgnoreCase(request.getMode())) {
                resultBin = DES(dataBin, subkeys, transcript);
            } else {
                // Decryption transcript logic simpler
                transcript.add("Bắt đầu giải mã (đảo ngược subkeys)...");
                String[] reversed = new String[16];
                for (int i = 0; i < 16; i++)
                    reversed[i] = subkeys[15 - i];
                resultBin = DES(dataBin, reversed, new ArrayList<>()); // No transcript for decrypt to keep it clean
            }

            response.setResult(binaryToHex(resultBin));
            response.setTranscript(transcript);

        } catch (NumberFormatException e) {
            response.setErrorMessage("Lỗi: Định dạng Hex không hợp lệ (chỉ chứa 0-9, A-F).");
        } catch (Exception e) {
            response.setErrorMessage("Lỗi xử lý: " + e.getMessage());
        }

        return response;
    }

    private String DES(String data, String[] subkeys, List<String> transcript) {
        transcript.add("Bài 4: Tính hoán vị IP đối với bản tin M");
        transcript.add("M = " + data + " (2) = " + binaryToHex(data) + " (16)");

        String ipOut = IP(data);
        transcript.add("IP(M) = " + ipOut + " (2) = " + binaryToHex(ipOut) + " (16)");

        String[] lr = SPLIT(ipOut);
        String l = lr[0];
        String r = lr[1];
        transcript.add("L0 = " + l + " (2) = " + binaryToHex(l) + " (16)");
        transcript.add("R0 = " + r + " (2) = " + binaryToHex(r) + " (16)");

        for (int i = 0; i < 16; i++) {
            transcript.add("");
            transcript.add("Chi tiết vòng lặp " + (i + 1) + ":");
            String prevL = l;
            String prevR = r;

            // E
            String expanded = E(prevR);
            transcript.add("Bài 5: Tính hàm mở rộng nửa phải E[R" + i + "]");
            transcript.add("R" + i + " = " + prevR + " (2) = " + binaryToHex(prevR) + " (16)");
            transcript.add("E[R" + i + "] = " + expanded + " (2) = " + binaryToHex(expanded) + " (16)");

            // XOR
            String xored = XOR(expanded, subkeys[i]);
            transcript.add("Bài 6: Thực hiện xor E[R" + i + "] với khóa K" + (i + 1));
            transcript.add("K" + (i + 1) + " = " + subkeys[i] + " (2) = " + binaryToHex(subkeys[i]) + " (16)");
            transcript.add("A" + (i + 1) + " = K" + (i + 1) + " xor E[R" + i + "] = " + xored + " (2) = "
                    + binaryToHex(xored) + " (16)");

            // S-Box
            transcript.add("Bài 7: Thực hiện phép thế S-box đối với A" + (i + 1));
            String b = SUB(xored);
            // Log details for each S-box
            for (int k = 0; k < 8; k++) {
                String block = xored.substring(k * 6, (k + 1) * 6);
                int row = Integer.parseInt("" + block.charAt(0) + block.charAt(5), 2);
                int col = Integer.parseInt(block.substring(1, 5), 2);
                int val = S_BOXES[k][row][col];
                String outBin = String.format("%4s", Integer.toBinaryString(val)).replace(' ', '0');
                transcript.add(String.format(" S%d(%s) -> [%d] [%d] -> %d (%s)", k + 1, block, row, col, val, outBin));
            }
            transcript.add("B" + (i + 1) + " = SUB(A" + (i + 1) + ") = " + b + " (2) = " + binaryToHex(b) + " (16)");

            // P
            String pOut = P(b);
            transcript.add("Bài 8: Thực hiện phép hoán vị P-box đối với B" + (i + 1));
            transcript.add(
                    "F" + (i + 1) + " = P-box(B" + (i + 1) + ") = " + pOut + " (2) = " + binaryToHex(pOut) + " (16)");

            // Update L, R
            l = prevR;
            r = XOR(prevL, pOut);

            transcript.add("Bài 9: Thực hiện vòng lặp " + (i + 1));
            transcript.add("L" + (i + 1) + " = R" + i + " = " + l + " (2) = " + binaryToHex(l) + " (16)");
            transcript.add(
                    "R" + (i + 1) + " = L" + i + " xor F" + (i + 1) + " = " + r + " (2) = " + binaryToHex(r) + " (16)");
        }

        String preOutput = r + l;
        transcript.add("");
        transcript.add("Bài 11: Thực hiện hoán vị cuối cùng IP-1");
        transcript.add("R16L16 = " + preOutput + " (2) = " + binaryToHex(preOutput) + " (16)");

        String result = IP_INV(preOutput);
        transcript.add("C = IP-1(R16L16) = " + result + " (2) = " + binaryToHex(result) + " (16)");

        return result;
    }

    private String hexToBinary(String hex) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hex.length(); i++) {
            int val = Integer.parseInt(hex.substring(i, i + 1), 16);
            sb.append(String.format("%4s", Integer.toBinaryString(val)).replace(' ', '0'));
        }
        return sb.toString();
    }

    private String binaryToHex(String bin) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bin.length(); i += 4) {
            int val = Integer.parseInt(bin.substring(i, i + 4), 2);
            sb.append(Integer.toHexString(val).toUpperCase());
        }
        return sb.toString();
    }

    private String IP(String x) {
        StringBuilder sb = new StringBuilder();
        for (byte b : IP) {
            sb.append(x.charAt(b));
        }
        return sb.toString();
    }

    private String[] SPLIT(String x) {
        return new String[] { x.substring(0, 32), x.substring(32) };
    }

    private String E(String R) {
        StringBuilder sb = new StringBuilder();
        for (byte b : E_TABLE) {
            sb.append(R.charAt(b));
        }
        return sb.toString();
    }

    private String XOR(String s1, String s2) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s1.length(); i++) {
            sb.append(s1.charAt(i) == s2.charAt(i) ? '0' : '1');
        }
        return sb.toString();
    }

    private String SUB(String XR1K) {
        StringBuilder sb = new StringBuilder();
        for (int j = 0; j < 8; j++) {
            String block = XR1K.substring(j * 6, (j + 1) * 6);
            int row = Integer.parseInt("" + block.charAt(0) + block.charAt(5), 2);
            int col = Integer.parseInt(block.substring(1, 5), 2);
            int val = S_BOXES[j][row][col];
            String outBin = String.format("%4s", Integer.toBinaryString(val)).replace(' ', '0');
            sb.append(outBin);
        }
        return sb.toString();
    }

    private String P(String SXR1K) {
        StringBuilder sb = new StringBuilder();
        for (byte b : P_TABLE) {
            sb.append(SXR1K.charAt(b));
        }
        return sb.toString();
    }

    private String PC1(String K) {
        StringBuilder sb = new StringBuilder();
        for (byte b : PC1_TABLE_STD) {
            sb.append(K.charAt(b));
        }
        return sb.toString();
    }

    private String[] SPLIT_KEY(String K1) {
        return new String[] { K1.substring(0, 28), K1.substring(28) };
    }

    private String ShiftLeft(String x, int n) {
        return x.substring(n) + x.substring(0, n);
    }

    private String PC2(String C, String D) {
        String cd = C + D;
        StringBuilder sb = new StringBuilder();
        for (byte b : PC2_TABLE) {
            sb.append(cd.charAt(b));
        }
        return sb.toString();
    }

    private String IP_INV(String x) {
        StringBuilder sb = new StringBuilder();
        for (byte b : FP) {
            sb.append(x.charAt(b));
        }
        return sb.toString();
    }

    // Standard PC-1 Choice Table (64 -> 56 bits)
    private static final byte[] PC1_TABLE_STD = {
            56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1,
            58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38,
            30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36,
            28, 20, 12, 4, 27, 19, 11, 3
    };

    private DesResponse processExamFeistel(DesRequest request) {
        DesResponse response = new DesResponse();
        response.setInputData(request.getData());
        response.setInputKey(request.getKey());
        response.setMode("encrypt");

        List<String> transcript = new ArrayList<>();
        try {
            String cleanData = request.getData().replaceAll("\\s+", "").toUpperCase();
            String cleanKey = request.getKey().replaceAll("\\s+", "").toUpperCase();

            if (cleanData.length() != 8) {
                response.setErrorMessage("Nửa phải R_{i-1} phải đủ 32-bit (8 ký tự hex).");
                return response;
            }
            if (cleanKey.length() != 12) {
                response.setErrorMessage("Khóa vòng K_i phải đủ 48-bit (12 ký tự hex).");
                return response;
            }

            String rBin = hexToBinary(cleanData);
            String kBin = hexToBinary(cleanKey);

            transcript.add("GIẢI BÀI TẬP VÒNG LẶP DES (HÀM FEISTEL)");
            transcript.add("Thông số đầu vào:");
            transcript.add(String.format("  - Nửa phải R_{i-1} = %s (Hex) = %s (Binary)", cleanData, rBin));
            transcript.add(String.format("  - Khóa vòng K_i   = %s (Hex) = %s (Binary)", cleanKey, kBin));
            transcript.add("");

            // 1) Expansion E
            String eBin = E(rBin);
            String eHex = binaryToHex(eBin);
            transcript.add("1) Kết quả mở rộng nửa phải R_{i-1}, ký hiệu là E:");
            transcript.add("   Phép mở rộng E biến đổi 32 bit của R_{i-1} thành 48 bit bằng cách nhân bản một số vị trí bit theo bảng chọn E.");
            transcript.add(String.format("   E = E(R_{i-1}) = %s (Binary)", eBin));
            transcript.add(String.format("                  = %s (Hex)", eHex));
            transcript.add("");

            // 2) XOR
            String aBin = XOR(eBin, kBin);
            String aHex = binaryToHex(aBin);
            transcript.add("2) Kết quả phép XOR (E, K_i), ký hiệu là A:");
            transcript.add("   A = E ⊕ K_i");
            transcript.add(String.format("   E   = %s (Binary) = %s (Hex)", eBin, eHex));
            transcript.add(String.format("   K_i = %s (Binary) = %s (Hex)", kBin, cleanKey));
            transcript.add(String.format("   A   = %s (Binary) = %s (Hex)", aBin, aHex));
            transcript.add("");

            // 3) S-Box
            transcript.add("3) Kết quả phép thế S-box(A), ký hiệu là B:");
            transcript.add("   Chia chuỗi A (48 bit) thành 8 khối con, mỗi khối 6 bit: A = B1.B2.B3.B4.B5.B6.B7.B8");
            transcript.add("   Với mỗi khối con B_j (6 bit):");
            transcript.add("     - Bit đầu (bit 0) và bit cuối (bit 5) ghép lại để xác định Hàng (0-3).");
            transcript.add("     - 4 bit ở giữa (bit 1-4) xác định Cột (0-15).");
            transcript.add("     - Tra bảng S-box tương ứng S_j để tìm giá trị thay thế (4 bit).");
            transcript.add("");

            StringBuilder bBinBuilder = new StringBuilder();
            for (int j = 0; j < 8; j++) {
                String block = aBin.substring(j * 6, (j + 1) * 6);
                int row = Integer.parseInt("" + block.charAt(0) + block.charAt(5), 2);
                int col = Integer.parseInt(block.substring(1, 5), 2);
                int val = S_BOXES[j][row][col];
                String outBin = String.format("%4s", Integer.toBinaryString(val)).replace(' ', '0');
                bBinBuilder.append(outBin);
                
                transcript.add(String.format("   - Khối B_%d (bits %d-%d): %s", j + 1, j * 6 + 1, (j + 1) * 6, block));
                transcript.add(String.format("     + Hàng: %s%s = %d", block.charAt(0), block.charAt(5), row));
                transcript.add(String.format("     + Cột: %s = %d", block.substring(1, 5), col));
                transcript.add(String.format("     + Tra bảng S%d: S%d[%d][%d] = %d (Hex: %s, Binary: %s)", j + 1, j + 1, row, col, val, Integer.toHexString(val).toUpperCase(), outBin));
            }
            String bBin = bBinBuilder.toString();
            String bHex = binaryToHex(bBin);
            transcript.add("");
            transcript.add("   => Kết quả ghép các khối thế S-box:");
            transcript.add(String.format("   B = %s (Binary)", bBin));
            transcript.add(String.format("     = %s (Hex)", bHex));

            response.setResult(bHex);
            response.setTranscript(transcript);
        } catch (NumberFormatException e) {
            response.setErrorMessage("Lỗi: Định dạng Hex không hợp lệ (chỉ chứa 0-9, A-F).");
        } catch (Exception e) {
            response.setErrorMessage("Lỗi xử lý: " + e.getMessage());
        }
        return response;
    }
}
